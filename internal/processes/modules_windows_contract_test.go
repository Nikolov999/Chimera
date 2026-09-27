package processes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWindowsModuleCandidatesPreserveStableIdentity(t *testing.T) {
	items := []Process{
		{ID: "proc-a", PID: 101, Name: "alpha.exe", ExecutablePath: `C:\Program Files\Alpha\alpha.exe`, StartTime: "2026-08-20T20:00:01Z"},
		{ID: "proc-b", PID: 202, Name: "beta.exe", ExecutablePath: `C:\Windows\System32\beta.exe`},
	}
	got, err := makeWindowsModuleCandidates(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].CandidateID != "proc-a" || got[1].CandidateID != "proc-b" {
		t.Fatalf("candidate identity was not preserved: %#v", got)
	}
	if got[0].ExecutablePath != items[0].ExecutablePath || got[0].StartTime != items[0].StartTime || got[1].PID != 202 {
		t.Fatalf("candidate executable/PID contract changed: %#v", got)
	}
	raw, err := marshalWindowsModuleCandidates(got)
	if err != nil {
		t.Fatal(err)
	}
	var envelope windowsModuleCandidateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 1 || len(envelope.Items) != 2 || envelope.Items[0].CandidateID != "proc-a" {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
}

func TestWindowsModuleCandidateBatchesAreBoundedAndOrdered(t *testing.T) {
	items := make([]Process, 0, 61)
	for i := 1; i <= 61; i++ {
		items = append(items, Process{ID: "proc-" + string(rune(0x1000+i)), PID: i, Name: "p"})
	}
	candidates, err := makeWindowsModuleCandidates(items)
	if err != nil {
		t.Fatal(err)
	}
	batches := chunkWindowsModuleCandidates(candidates, 24)
	if len(batches) != 3 || len(batches[0]) != 24 || len(batches[1]) != 24 || len(batches[2]) != 13 {
		t.Fatalf("unexpected batch shape: %d / %d / %d / %d", len(batches), len(batches[0]), len(batches[1]), len(batches[2]))
	}
	flat := make([]windowsModuleCandidate, 0, len(candidates))
	for _, batch := range batches {
		flat = append(flat, batch...)
	}
	for i := range candidates {
		if flat[i].CandidateID != candidates[i].CandidateID || flat[i].PID != candidates[i].PID {
			t.Fatalf("batching reordered candidate %d", i)
		}
	}
}

func TestWindowsModuleEnumerationPayloadRejectsStructuralDrift(t *testing.T) {
	batch := []windowsModuleCandidate{{CandidateID: "a", PID: 11}, {CandidateID: "b", PID: 22}}
	valid := windowsModuleEnumerationPayload{
		Rows: []windowsModuleRow{{CandidateID: "a", PID: 11, Path: `C:\Windows\System32\a.dll`}},
		Processes: []windowsModuleProcessRow{
			{CandidateID: "a", PID: 11, State: "OBSERVED", ModuleCount: 1},
			{CandidateID: "b", PID: 22, State: "ACCESS_DENIED", ModuleCount: 0},
		},
	}
	if err := validateWindowsModuleEnumerationPayload(valid, batch); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}

	missing := valid
	missing.Processes = missing.Processes[:1]
	if err := validateWindowsModuleEnumerationPayload(missing, batch); err == nil || !strings.Contains(err.Error(), "process status") {
		t.Fatalf("missing candidate status was not rejected: %v", err)
	}

	unknown := valid
	unknown.Rows = []windowsModuleRow{{CandidateID: "other", PID: 11, Path: `C:\x.dll`}}
	if err := validateWindowsModuleEnumerationPayload(unknown, batch); err == nil || !strings.Contains(err.Error(), "unknown candidate_id") {
		t.Fatalf("unknown module candidate was not rejected: %v", err)
	}
}

func TestWindowsModuleLateBatchFailurePreservesCompletedEvidence(t *testing.T) {
	batches := [][]windowsModuleCandidate{
		{{CandidateID: "first", PID: 100}},
		{{CandidateID: "late", PID: 200}},
	}
	acc := newWindowsModuleEnumerationAccumulator(2)
	first := windowsModuleEnumerationPayload{
		Rows:      []windowsModuleRow{{CandidateID: "first", PID: 100, Path: `C:\Windows\System32\kernel32.dll`, Name: "kernel32.dll", BaseAddress: "0x7ffb0000"}},
		Processes: []windowsModuleProcessRow{{CandidateID: "first", PID: 100, State: "OBSERVED", ModuleCount: 1}},
	}
	if err := acc.Apply(first, batches[0]); err != nil {
		t.Fatal(err)
	}
	acc.MarkUnavailable(batches[1], "enumeration batch 2 reached its bounded deadline; evidence from other batches was preserved")

	if len(acc.Rows) != 1 || acc.Rows[0].CandidateID != "first" {
		t.Fatalf("completed first-batch rows were lost: %#v", acc.Rows)
	}
	if acc.Status["first"].State != "OBSERVED" {
		t.Fatalf("completed first-batch status was overwritten: %#v", acc.Status["first"])
	}
	if acc.Status["late"].State != "PROVIDER_UNAVAILABLE" || !strings.Contains(acc.Status["late"].Reason, "preserved") {
		t.Fatalf("late timeout not isolated: %#v", acc.Status["late"])
	}
}

func TestWindowsModuleProcessStatesRemainSpecific(t *testing.T) {
	cases := map[string]string{
		"OBSERVED":             "OBSERVED",
		"PROCESS_EXITED":       "PROCESS_EXITED",
		"ACCESS_DENIED":        "ACCESS_DENIED",
		"PROTECTED_PROCESS":    "PROTECTED_PROCESS",
		"WOW64_ARCH_MISMATCH":  "WOW64_ARCH_MISMATCH",
		"ENUMERATION_FAILED":   "ENUMERATION_FAILED",
		"PROVIDER_UNAVAILABLE": "PROVIDER_UNAVAILABLE",
		"DENIED":               "ACCESS_DENIED",
		"MISSING":              "PROCESS_EXITED",
	}
	for in, want := range cases {
		if got := normalizeWindowsModuleProcessState(in); got != want {
			t.Fatalf("normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestWindowsModuleEnrichmentPrioritizesHighCoveragePaths(t *testing.T) {
	paths := []string{
		`C:\Rare\one.dll`,
		`C:\Windows\System32\common.dll`,
		`C:\Windows\System32\common.dll`,
		`C:\Windows\System32\common.dll`,
		`C:\Other\two.dll`,
		`C:\Other\two.dll`,
	}
	got := makeWindowsModuleEnrichmentCandidates(paths, 2)
	if len(got) != 2 {
		t.Fatalf("unexpected candidate count: %d", len(got))
	}
	if !strings.EqualFold(got[0].Path, `C:\Windows\System32\common.dll`) || !strings.EqualFold(got[1].Path, `C:\Other\two.dll`) {
		t.Fatalf("coverage ordering is wrong: %#v", got)
	}
}

func TestWindowsModuleEnrichmentPayloadRequiresOneRowPerCandidate(t *testing.T) {
	batch := []windowsModuleEnrichmentCandidate{{CandidateID: "m1", Path: `C:\a.dll`}, {CandidateID: "m2", Path: `C:\b.dll`}}
	payload := windowsModuleEnrichmentPayload{Rows: []windowsModuleEnrichmentRow{
		{CandidateID: "m1", Path: `C:\a.dll`, SignatureState: "SIGNED_VALID", DirectoryState: "OBSERVED"},
		{CandidateID: "m2", Path: `C:\b.dll`, SignatureState: "UNKNOWN", DirectoryState: "UNKNOWN"},
	}}
	if err := validateWindowsModuleEnrichmentPayload(payload, batch); err != nil {
		t.Fatalf("valid enrichment payload rejected: %v", err)
	}
	payload.Rows = payload.Rows[:1]
	if err := validateWindowsModuleEnrichmentPayload(payload, batch); err == nil || !strings.Contains(err.Error(), "2 candidate") {
		t.Fatalf("missing enrichment row was not rejected: %v", err)
	}
}

func TestWindowsModuleBatchTelemetryIsDeterministic(t *testing.T) {
	items := []windowsModuleBatchTelemetry{
		{Stage: "enumeration", Index: 1, Candidates: 24, Completed: 20, Denied: 2, Exited: 1, Failed: 1, Elapsed: 110 * time.Millisecond},
		{Stage: "enumeration", Index: 2, Candidates: 24, Failed: 24, TimedOut: true, Elapsed: 900 * time.Millisecond},
	}
	got := formatWindowsModuleBatchTelemetry(items)
	for _, part := range []string{"batches=2", "candidates=48", "completed=20", "denied=2", "exited=1", "failed=25", "timed_out=1", "elapsed=1.01s"} {
		if !strings.Contains(got, part) {
			t.Fatalf("telemetry %q missing %q", got, part)
		}
	}
}

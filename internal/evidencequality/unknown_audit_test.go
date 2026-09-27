package evidencequality

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix42UnknownAuditUsesExactPrimaryClasses(t *testing.T) {
	cases := []struct {
		ruleID   string
		observed string
		reason   string
		want     UnknownPrimaryClass
	}{
		{"CHM-FS-100", "required evidence dependencies missing: executable ACL", "", UnknownRequiredEvidenceMissing},
		{"CHM-FS-101", "provider evidence is unavailable", "invalid provider JSON: unexpected token", UnknownPrimaryProductDefect},
		{"CHM-PRC-101", "module evidence unresolved", "access denied reading protected process", UnknownPrimaryPermission},
		{"CHM-CTR-101", "container posture incomplete", "docker CLI is unavailable", UnknownPrimaryOptionalAbsent},
		{"CHM-ID-101", "optional control state unresolved", "registry value is absent; no deterministic Windows default is inferred", UnknownEnvironmentalAbsence},
		{"CHM-ID-102", "password state is not safely observable for 2 of 2 account(s)", "", UnknownSafeCollectionBoundary},
		{"CHM-NET-101", "profile default: 3 endpoint(s) cannot be mapped to a classified service role, so exposure intent cannot be determined defensibly", "", UnknownUnsupportedState},
		{"CHM-CTR-102", "control is not applicable on this platform", "", UnknownPrimaryNotApplicable},
		{"CHM-PRC-102", "process evidence unresolved", "process exited during collection", UnknownTemporalRace},
		{"CHM-ID-103", "2 of 2 eligible account(s) lack a reliable last-logon timestamp", "", UnknownOtherExplained},
	}
	findings := make([]assessment.Finding, 0, len(cases))
	for _, tc := range cases {
		f := assessment.Finding{RuleID: tc.ruleID, Category: "test", Status: assessment.StatusUnknown, ObservedState: tc.observed}
		if tc.reason != "" {
			f.Evidence = []assessment.EvidenceRef{{Key: "test.item.proc-1", State: evidence.StateUnavailable, Reason: tc.reason}}
		}
		findings = append(findings, f)
	}

	audit := AuditUnknownFindings(findings)
	if err := audit.Validate(len(cases)); err != nil {
		t.Fatal(err)
	}
	got := map[string]UnknownPrimaryClass{}
	for _, entry := range audit.Entries {
		got[entry.RuleID] = entry.Classification
	}
	for _, tc := range cases {
		if got[tc.ruleID] != tc.want {
			t.Fatalf("%s classification=%s want=%s", tc.ruleID, got[tc.ruleID], tc.want)
		}
	}
	if audit.Summary.ProductDefect != 1 || audit.Summary.SafeCollectionBoundary != 1 || audit.Summary.TemporalRace != 1 {
		t.Fatalf("summary=%#v", audit.Summary)
	}
	for i := range findings {
		if findings[i].Status != assessment.StatusUnknown {
			t.Fatalf("Fix42 mutated %s to %s", findings[i].RuleID, findings[i].Status)
		}
	}
}

func TestFix42UnknownAuditGroupsDependenciesAndAffectedCounts(t *testing.T) {
	f := assessment.Finding{
		RuleID: "CHM-NET-003", Category: "network", Status: assessment.StatusUnknown,
		ObservedState: "profile default: 18 specific non-loopback endpoint(s) could not be mapped to a classified service role, so exposure intent cannot be determined defensibly",
		Evidence: []assessment.EvidenceRef{
			{Key: "network.endpoint.net-aaa", State: evidence.StateObserved},
			{Key: "network.endpoint.net-bbb", State: evidence.StateObserved},
			{Key: "service.exposure.svc-ccc", State: evidence.StateObserved},
		},
	}
	audit := AuditUnknownFindings([]assessment.Finding{f})
	if err := audit.Validate(1); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 1 {
		t.Fatalf("entries=%#v", audit.Entries)
	}
	e := audit.Entries[0]
	if e.RuleFamily != "CHM-NET" || e.AffectedCount != 18 || e.FindingCount != 1 || e.Classification != UnknownUnsupportedState {
		t.Fatalf("entry=%#v", e)
	}
	wantDeps := map[string]bool{"network.endpoint.*": true, "service.exposure.*": true}
	for _, dep := range e.EvidenceDependencies {
		delete(wantDeps, dep)
	}
	if len(wantDeps) != 0 {
		t.Fatalf("dependencies=%#v missing=%#v", e.EvidenceDependencies, wantDeps)
	}
	if e.RootCauseID == "" || e.Reason == "" {
		t.Fatalf("root/reason missing: %#v", e)
	}
}

func TestFix42UnknownAuditCollapsesSameRuleRootCause(t *testing.T) {
	base := assessment.Finding{
		RuleID: "CHM-CTR-001", Category: "containers", Status: assessment.StatusUnknown,
		ObservedState: "privileged mode assessment is incomplete because a local runtime provider is unavailable",
		Evidence:      []assessment.EvidenceRef{{Key: "container.source.docker-security", State: evidence.StateUnavailable, Reason: "docker CLI is unavailable"}},
	}
	audit := AuditUnknownFindings([]assessment.Finding{base, base})
	if err := audit.Validate(2); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 1 || audit.Entries[0].FindingCount != 2 || audit.Entries[0].AffectedCount != 2 {
		t.Fatalf("audit=%#v", audit)
	}
}

func TestFix42UnknownAuditUsesComponentReasonForProcessTrust(t *testing.T) {
	f := assessment.Finding{
		RuleID: "CHM-PRC-003", Category: "process", Status: assessment.StatusUnknown,
		ObservedState: "no explicit privileged executable trust failures; 4 of 4 trust state(s) unresolved",
		Evidence: []assessment.EvidenceRef{{
			Key: "process.item.proc-abc", State: evidence.StateObserved,
			Value: map[string]any{"trust": map[string]any{"reason": "windows-process-authenticode: context deadline exceeded"}},
		}},
	}
	audit := AuditUnknownFindings([]assessment.Finding{f})
	if audit.Summary.ProductDefect != 1 || audit.Entries[0].Classification != UnknownPrimaryProductDefect {
		t.Fatalf("audit=%#v", audit)
	}
	if audit.Entries[0].RootCauseID == "" {
		t.Fatalf("missing root cause: %#v", audit.Entries[0])
	}
}

func TestFix58AuthenticodeSafeBoundaryIsNotProductDefect(t *testing.T) {
	for _, reason := range []string{
		"safe collection boundary: Authenticode enrichment ended before this executable candidate was reached",
		"safe collection boundary: Authenticode enrichment preserved 42 of 60 unique executable result(s) before its bounded stage ended",
	} {
		class, _ := unknownPrimaryFromText(reason)
		if class != UnknownSafeCollectionBoundary {
			t.Fatalf("reason %q classified %q want %q", reason, class, UnknownSafeCollectionBoundary)
		}
	}
}

func TestFix58AuthenticodeActualProviderFailureRemainsProductDefect(t *testing.T) {
	class, _ := unknownPrimaryFromText("windows-process-authenticode class=provider_failure: windows-process-authenticode failed (exit code 42)")
	if class != UnknownPrimaryProductDefect {
		t.Fatalf("class=%q want %q", class, UnknownPrimaryProductDefect)
	}
}

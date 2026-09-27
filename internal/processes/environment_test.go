package processes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestInspectEnvironmentEntriesRedactsValues(t *testing.T) {
	ctx := inspectEnvironmentEntries([]string{
		"LD_PRELOAD=/tmp/secret-hook.so",
		"HTTPS_PROXY=http://alice:supersecret@proxy.example:8080",
		"NODE_OPTIONS=--inspect=0.0.0.0:9229 --require /tmp/bootstrap.js",
		"AWS_SECRET_ACCESS_KEY=TOPSECRET",
	}, "linux", "test")
	ctx.PID = 42
	ctx.ProcessID = "proc-test"

	if !ctx.ValuesRedacted || ctx.RelevantVariables != 3 || ctx.HighRiskIndicators < 2 {
		t.Fatalf("unexpected redacted environment summary: %#v", ctx)
	}
	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, forbidden := range []string{"secret-hook.so", "supersecret", "0.0.0.0:9229", "bootstrap.js", "TOPSECRET"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("serialized environment leaked value %q: %s", forbidden, text)
		}
	}
	if strings.Contains(text, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("unrelated credential variable name should not be retained: %s", text)
	}
}

func TestClassifyEnvironmentLoaderPathMetadata(t *testing.T) {
	ind, ok := classifyEnvironmentVariable("LD_LIBRARY_PATH", ":./plugins:/tmp/override:/usr/lib", "linux")
	if !ok {
		t.Fatal("LD_LIBRARY_PATH was not classified")
	}
	if ind.Category != "LOADER_PATH" || ind.RiskClass != "HIGH" || ind.ComponentCount != 4 || ind.EmptyComponents != 1 || ind.RelativeComponents != 2 || ind.TemporaryComponents != 1 {
		t.Fatalf("unexpected loader path metadata: %#v", ind)
	}
}

func TestClassifyEnvironmentIgnoresDisabledProfiling(t *testing.T) {
	if _, ok := classifyEnvironmentVariable("COR_ENABLE_PROFILING", "0", "windows"); ok {
		t.Fatal("disabled profiling must not be retained as an active hook")
	}
	ind, ok := classifyEnvironmentVariable("CORECLR_ENABLE_PROFILING", "true", "windows")
	if !ok || ind.Category != "STARTUP_HOOK" || ind.RiskClass != "HIGH" {
		t.Fatalf("enabled profiling not classified: %#v ok=%t", ind, ok)
	}
}

func TestNormalizeEnvironmentIndicatorsDeterministic(t *testing.T) {
	in := []EnvironmentIndicator{
		{Name: "https_proxy", Category: "proxy_override", RiskClass: "contextual", NonEmpty: true},
		{Name: "LD_PRELOAD", Category: "LOADER_HOOK", RiskClass: "HIGH", NonEmpty: true},
		{Name: "HTTPS_PROXY", Category: "PROXY_OVERRIDE", RiskClass: "CONTEXTUAL", NonEmpty: true},
	}
	out := normalizeEnvironmentIndicators(in)
	if len(out) != 2 || out[0].Name != "HTTPS_PROXY" || out[1].Name != "LD_PRELOAD" {
		t.Fatalf("unexpected normalized order/dedup: %#v", out)
	}
}

func TestSummaryCountsRuntimeEnvironment(t *testing.T) {
	items := []Process{{PID: 1, Name: "a"}, {PID: 2, Name: "b"}}
	envs := []RuntimeEnvironmentContext{
		{PID: 1, State: "OBSERVED", RelevantVariables: 2, LoaderHooks: 1, RuntimeSearchPaths: 1, HighRiskIndicators: 1, ValuesRedacted: true},
		{PID: 2, State: "UNKNOWN", ProxyOverrides: 1, TLSKeyLogging: true, ValuesRedacted: true},
	}
	s := summarize(items, nil, nil, nil, nil, nil, envs)
	if s.EnvironmentObserved != 1 || s.EnvironmentUnknown != 1 || s.EnvironmentOverrides != 1 || s.EnvironmentHighRisk != 1 || s.LoaderEnvironmentHooks != 1 || s.RuntimeSearchOverrides != 1 || s.RuntimeProxyOverrides != 1 || s.TLSKeyLoggingContexts != 1 {
		t.Fatalf("unexpected environment summary: %#v", s)
	}
}

func TestInventoryValidationRequiresRedaction(t *testing.T) {
	items := normalize([]Process{{PID: 42, PPID: 1, Name: "agent", SessionID: "1", CommandLine: CommandLineMetadata{Redacted: true}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}})
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: time.Now().UTC(), Processes: items,
		RuntimeEnvironment: []RuntimeEnvironmentContext{{ProcessID: items[0].ID, PID: 42, Platform: "linux", State: "OBSERVED", Posture: "NONE", ValuesRedacted: false, Source: "test", Confidence: evidence.ConfidenceHigh}},
	}
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "not redacted") {
		t.Fatalf("expected redaction validation error, got %v", err)
	}
}

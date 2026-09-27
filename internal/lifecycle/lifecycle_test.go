package lifecycle

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/software"
)

func TestEvaluateEOLAndSupportedSeries(t *testing.T) {
	at := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	loaded := intelligence.Loaded{
		Metadata: intelligence.Metadata{Version: "test", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Store: intelligence.Store{Lifecycles: []intelligence.LifecycleRecord{
			{ID: "python-3-9", SourceID: "python", TargetKinds: []string{"runtime"}, Product: "Python", Aliases: []string{"Python"}, Family: "python", VersionSeries: "3.9", EndOfSupport: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "EOL", Reference: "https://example.test/python"},
			{ID: "python-3-10", SourceID: "python", TargetKinds: []string{"runtime"}, Product: "Python", Aliases: []string{"Python"}, Family: "python", VersionSeries: "3.10", EndOfSupport: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "EOL", Reference: "https://example.test/python"},
		}},
	}
	inv := software.Inventory{CollectedAt: at, Runtimes: []software.RuntimeItem{
		{ID: "a", Family: "python", Product: "Python", Version: "3.9.18", Confidence: evidence.ConfidenceExact},
		{ID: "b", Family: "python", Product: "Python", Version: "3.10.14", Confidence: evidence.ConfidenceHigh},
	}}
	got := Evaluate(overview.Overview{}, inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Candidates != 2 || got.Summary.WithIntelligence != 2 || got.Summary.EndOfLife != 1 || got.Summary.Supported != 1 || got.Summary.NoIntelligence != 0 {
		t.Fatalf("unexpected summary: %#v", got.Summary)
	}
}

func TestEvaluateOSBrowserAndNoIntelligence(t *testing.T) {
	at := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	loaded := intelligence.Loaded{
		Metadata: intelligence.Metadata{Version: "test", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Store: intelligence.Store{Lifecycles: []intelligence.LifecycleRecord{
			{ID: "win10", SourceID: "ms", TargetKinds: []string{"os"}, Product: "Windows 10 22H2", NameContains: []string{"Windows 10"}, Family: "windows", VersionSeries: "10.0.19045", EndOfSupport: time.Date(2025, 10, 14, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "EOL", Reference: "https://example.test/windows"},
			{ID: "ff102", SourceID: "mozilla", TargetKinds: []string{"browser"}, Product: "Mozilla Firefox ESR", Aliases: []string{"Mozilla Firefox ESR"}, Family: "firefox", VersionSeries: "102", EndOfSupport: time.Date(2023, 9, 26, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "UNSUPPORTED", Reference: "https://example.test/firefox"},
		}},
	}
	o := overview.Overview{CollectedAt: at, OS: "Microsoft Windows 10 Pro", OSVersion: "10.0.19045"}
	inv := software.Inventory{CollectedAt: at, Browsers: []software.BrowserItem{
		{ID: "ff", Family: "firefox", Product: "Mozilla Firefox ESR", Version: "102.15.1", Confidence: evidence.ConfidenceExact},
	}, Items: []software.Item{{ID: "unmatched", Product: "Example", PackageID: "example", Version: "1.0", Confidence: evidence.ConfidenceExact}}}
	got := Evaluate(o, inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Candidates != 3 || got.Summary.EndOfLife != 1 || got.Summary.Unsupported != 1 || got.Summary.NoIntelligence != 1 {
		t.Fatalf("unexpected summary: %#v", got.Summary)
	}
}

func TestVersionSeriesUsesBoundary(t *testing.T) {
	if seriesMatches("3.90.1", "3.9") {
		t.Fatal("3.9 series matched 3.90")
	}
	if !seriesMatches("3.9.20", "3.9") {
		t.Fatal("3.9 series did not match 3.9.20")
	}
}

func TestEvaluateInstalledSoftwareLifecycleByExactAlias(t *testing.T) {
	at := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	loaded := intelligence.Loaded{
		Metadata: intelligence.Metadata{Version: "test", Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		Store: intelligence.Store{Lifecycles: []intelligence.LifecycleRecord{
			{ID: "openssl-111", SourceID: "openssl", TargetKinds: []string{"installed-software"}, Product: "OpenSSL", Aliases: []string{"libssl1.1"}, VersionSeries: "1.1.1", EndOfSupport: time.Date(2023, 9, 11, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "EOL", Reference: "https://example.test/openssl"},
		}},
	}
	inv := software.Inventory{CollectedAt: at, Items: []software.Item{
		{ID: "ssl", Product: "libssl1.1", PackageID: "libssl1.1:amd64", Version: "1.1.1w", Confidence: evidence.ConfidenceExact},
		{ID: "false-positive", Product: "libssl1.1-helper", PackageID: "libssl1.1-helper", Version: "1.1.1w", Confidence: evidence.ConfidenceExact},
	}}
	got := Evaluate(overview.Overview{}, inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Candidates != 2 || got.Summary.WithIntelligence != 1 || got.Summary.EndOfLife != 1 || got.Summary.NoIntelligence != 1 {
		t.Fatalf("unexpected installed-software lifecycle summary: %#v", got.Summary)
	}
	if got.Evaluations[0].CandidateRef != "software.item.ssl" {
		t.Fatalf("unexpected lifecycle candidate: %#v", got.Evaluations[0])
	}
}

func TestPost117Fix07BuiltinLifecycleCoverage(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	inv := software.Inventory{CollectedAt: at, Runtimes: []software.RuntimeItem{
		{ID: "node20", Family: "nodejs", Product: "Node.js", Version: "20.19.4", Confidence: evidence.ConfidenceExact},
		{ID: "node22", Family: "nodejs", Product: "Node.js", Version: "22.20.0", Confidence: evidence.ConfidenceExact},
		{ID: "dotnet8", Family: "dotnet", Product: "Microsoft.NETCore.App", Version: "8.0.29", Confidence: evidence.ConfidenceExact},
		{ID: "ossl33", Family: "openssl", Product: "OpenSSL", Version: "3.3.4", Confidence: evidence.ConfidenceExact},
		{ID: "ossl34", Family: "openssl", Product: "OpenSSL", Version: "3.4.5", Confidence: evidence.ConfidenceExact},
		{ID: "php81", Family: "php", Product: "PHP", Version: "8.1.34", Confidence: evidence.ConfidenceExact},
		{ID: "php82", Family: "php", Product: "PHP", Version: "8.2.33", Confidence: evidence.ConfidenceExact},
	}, Items: []software.Item{
		{ID: "pg13", Product: "PostgreSQL", PackageID: "postgresql-13", Version: "13.23", Confidence: evidence.ConfidenceExact},
		{ID: "pg14", Product: "PostgreSQL", PackageID: "postgresql-14", Version: "14.23", Confidence: evidence.ConfidenceExact},
	}}
	got := Evaluate(overview.Overview{}, inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Candidates != 9 || got.Summary.WithIntelligence != 9 || got.Summary.NoIntelligence != 0 {
		t.Fatalf("unexpected Fix07 lifecycle coverage summary: %#v", got.Summary)
	}
	statusByRef := map[string]Status{}
	for _, ev := range got.Evaluations {
		statusByRef[ev.CandidateRef] = ev.Status
	}
	want := map[string]Status{
		"software.runtime.node20":  StatusEOL,
		"software.runtime.node22":  StatusSupported,
		"software.runtime.dotnet8": StatusSupported,
		"software.runtime.ossl33":  StatusEOL,
		"software.runtime.ossl34":  StatusSupported,
		"software.runtime.php81":   StatusEOL,
		"software.runtime.php82":   StatusSupported,
		"software.item.pg13":       StatusEOL,
		"software.item.pg14":       StatusSupported,
	}
	for ref, expected := range want {
		if gotStatus := statusByRef[ref]; gotStatus != expected {
			t.Fatalf("%s status=%s want %s (all=%#v)", ref, gotStatus, expected, got.Evaluations)
		}
	}
}

func TestPost117Fix07WindowsAndDebianLifecycleBoundaries(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		o    overview.Overview
		want Status
	}{
		{name: "windows11-23h2-pro", o: overview.Overview{CollectedAt: at, OS: "Microsoft Windows 11 Pro", OSVersion: "10.0.22631"}, want: StatusEOL},
		{name: "windows11-24h2-pro", o: overview.Overview{CollectedAt: at, OS: "Microsoft Windows 11 Pro", OSVersion: "10.0.26100"}, want: StatusSupported},
		{name: "debian11", o: overview.Overview{CollectedAt: at, OS: "Debian GNU/Linux 11 (bullseye)", OSVersion: "11"}, want: StatusSupported},
		{name: "debian10", o: overview.Overview{CollectedAt: at, OS: "Debian GNU/Linux 10 (buster)", OSVersion: "10"}, want: StatusEOL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.o, software.Inventory{CollectedAt: at}, loaded)
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			if got.Summary.WithIntelligence != 1 || len(got.Evaluations) != 1 {
				t.Fatalf("expected one lifecycle evaluation, got %#v", got)
			}
			if got.Evaluations[0].Status != tc.want {
				t.Fatalf("status=%s want %s: %#v", got.Evaluations[0].Status, tc.want, got.Evaluations[0])
			}
		})
	}
}

func TestEndOfSupportDateIsInclusive(t *testing.T) {
	loaded := intelligence.Loaded{
		Metadata: intelligence.Metadata{Version: "test", Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		Store: intelligence.Store{Lifecycles: []intelligence.LifecycleRecord{
			{ID: "date-boundary", SourceID: "vendor", TargetKinds: []string{"runtime"}, Product: "Example Runtime", Aliases: []string{"Example Runtime"}, Family: "example", VersionSeries: "1", EndOfSupport: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), StatusAfterEnd: "EOL", Reference: "https://example.test/lifecycle"},
		}},
	}
	inv := software.Inventory{Runtimes: []software.RuntimeItem{{ID: "example", Family: "example", Product: "Example Runtime", Version: "1.2.3", Confidence: evidence.ConfidenceExact}}}

	inv.CollectedAt = time.Date(2026, 8, 20, 23, 59, 59, 0, time.UTC)
	onEndDate := Evaluate(overview.Overview{}, inv, loaded)
	if len(onEndDate.Evaluations) != 1 || onEndDate.Evaluations[0].Status != StatusSupported {
		t.Fatalf("support should remain active through the published EOS date: %#v", onEndDate)
	}

	inv.CollectedAt = time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	afterEndDate := Evaluate(overview.Overview{}, inv, loaded)
	if len(afterEndDate.Evaluations) != 1 || afterEndDate.Evaluations[0].Status != StatusEOL {
		t.Fatalf("support should end at the start of the day after EOS: %#v", afterEndDate)
	}
}

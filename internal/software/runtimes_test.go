package software

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseDotNetRuntimes(t *testing.T) {
	got := parseDotNetRuntimes("Microsoft.NETCore.App 8.0.19 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\nMicrosoft.AspNetCore.App 8.0.19 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]")
	if len(got) != 2 {
		t.Fatalf("expected 2 runtimes, got %d: %#v", len(got), got)
	}
	if got[0].Product != "Microsoft.NETCore.App" || got[0].Version != "8.0.19" || got[0].InstallPath == "UNKNOWN" {
		t.Fatalf("bad runtime parse: %#v", got[0])
	}
}

func TestParseGoVersion(t *testing.T) {
	got := parseGo("go version go1.24.6 linux/amd64")
	if len(got) != 1 || got[0].Version != "1.24.6" || got[0].Architecture != "amd64" {
		t.Fatalf("bad Go parse: %#v", got)
	}
}

func TestParsePerlVersion(t *testing.T) {
	got := parsePerl("This is perl 5, version 36, subversion 0 (v5.36.0) built for x86_64-linux-gnu-thread-multi")
	if len(got) != 1 || got[0].Version != "5.36.0" {
		t.Fatalf("bad Perl parse: %#v", got)
	}
}

func TestNormalizeRuntimesDeterministicAndExplicit(t *testing.T) {
	in := []RuntimeItem{
		{Family: "python", Kind: "interpreter", Product: "Python", Version: "v3.12.1", Executable: "python3", ExecutablePath: "/usr/bin/python3", InstallPath: "/usr/bin", Distribution: "Python", CollectionSource: "fixture", Confidence: evidence.ConfidenceHigh},
		{Family: "python", Kind: "interpreter", Product: "Python", Version: "3.12.1", Executable: "python3", ExecutablePath: "/usr/bin/python3", InstallPath: "/usr/bin", Distribution: "Python", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact},
		{Family: "nodejs", Kind: "runtime", Product: "Node.js", Version: "20.15.0", Executable: "node", ExecutablePath: "/usr/bin/node", InstallPath: "/usr/bin", Distribution: "Node.js", CollectionSource: "fixture", Confidence: evidence.ConfidenceHigh},
	}
	out := normalizeRuntimes(in)
	if len(out) != 2 {
		t.Fatalf("expected duplicate collapse, got %d: %#v", len(out), out)
	}
	for _, r := range out {
		if r.ID == "" || r.Family == "" || r.Kind == "" || r.Product == "" || r.Version == "" || r.Architecture == "" || r.Executable == "" || r.ExecutablePath == "" || r.InstallPath == "" || r.Distribution == "" || r.CollectionSource == "" || r.Confidence == "" {
			t.Fatalf("incomplete normalized runtime: %#v", r)
		}
	}
}

func testTime() time.Time { return time.Date(2026, 8, 18, 19, 0, 0, 0, time.UTC) }

func TestRuntimeEvidenceContract(t *testing.T) {
	inv := Inventory{
		CollectedAt:    testTime(),
		Platform:       "linux",
		Architecture:   "amd64",
		Items:          []Item{},
		Sources:        []SourceStatus{{ID: "dpkg", State: evidence.StateObserved, Source: "fixture", ItemCount: 0}},
		Runtimes:       normalizeRuntimes([]RuntimeItem{{Family: "python", Kind: "interpreter", Product: "Python", Version: "3.12.1", Architecture: "amd64", Executable: "python3", ExecutablePath: "/usr/bin/python3", InstallPath: "/usr/bin", Distribution: "Python", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact}}),
		RuntimeSources: []SourceStatus{{ID: "python3", State: evidence.StateObserved, Source: "fixture", ItemCount: 1}},
	}
	obs := buildEvidence(inv)
	if err := evidence.ValidateAll(obs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range obs {
		if len(o.Key) > len("software.runtime.") && o.Key[:len("software.runtime.")] == "software.runtime." {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing runtime evidence")
	}
}

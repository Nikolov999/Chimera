package software

import (
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestAttributionCandidatesMergeTargetsByPath(t *testing.T) {
	p := filepath.Clean(filepath.Join(string(filepath.Separator), "opt", "chimera", "bin", "runtime"))
	inv := Inventory{
		Runtimes: []RuntimeItem{
			{ID: "rt-a", Product: "Runtime A", ExecutablePath: p},
			{ID: "rt-b", Product: "Runtime B", ExecutablePath: p},
		},
		Infrastructure: []InfrastructureItem{
			{ID: "infra-a", Product: "Server A", ExecutablePaths: []string{p}},
		},
	}
	got := attributionCandidates(&inv)
	if len(got) != 1 {
		t.Fatalf("expected one path attribution candidate, got %#v", got)
	}
	if len(got[0].Targets) != 3 || len(got[0].Refs) != 3 {
		t.Fatalf("expected merged target/evidence references, got %#v", got[0])
	}
}

func TestMatchInstalledPathUsesBoundaryAndLongestRoot(t *testing.T) {
	sep := string(filepath.Separator)
	root := filepath.Clean(sep + filepath.Join("opt", "app"))
	nested := filepath.Join(root, "runtime")
	items := []Item{
		{Kind: "application", Product: "App", PackageID: "app", InstallPath: root, Confidence: evidence.ConfidenceHigh},
		{Kind: "package", Product: "Runtime", PackageID: "runtime", InstallPath: nested, Confidence: evidence.ConfidenceExact},
	}
	got := matchInstalledPath(filepath.Join(nested, "bin", "tool"), items)
	if got == nil || got.PackageID != "runtime" {
		t.Fatalf("expected longest installation root match, got %#v", got)
	}
	if bad := matchInstalledPath(root+"lication"+sep+"tool", items); bad != nil {
		t.Fatalf("path-boundary false positive: %#v", bad)
	}
}

func TestResultFromItemPreservesApplicationVersusPackage(t *testing.T) {
	app := Item{Kind: "application", Product: "Example", PackageID: "example", Version: "1", PackageSource: "fixture", InstallPath: "/fixture", Confidence: evidence.ConfidenceHigh}
	got := resultFromItem(&app, "fixture", "prefix", "fixture", evidence.ConfidenceExact)
	if got.Ownership != OwnershipApplication || got.ProviderState != evidence.StateObserved || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected application attribution: %#v", got)
	}
	pkg := app
	pkg.Kind = "package"
	got = resultFromItem(&pkg, "fixture", "native", "fixture", evidence.ConfidenceExact)
	if got.Ownership != OwnershipPackage {
		t.Fatalf("unexpected package attribution: %#v", got)
	}
}

func TestPortableCandidatePathIsConservative(t *testing.T) {
	if portableCandidatePath(filepath.Clean(filepath.Join(string(filepath.Separator), "usr", "bin", "ssh"))) {
		t.Fatal("system binary must not be classified as a portable candidate")
	}
	if !portableCandidatePath(filepath.Join(t.TempDir(), "Downloads", "portable-tool")) {
		t.Fatal("per-user/download-like path should be retained as a portable candidate")
	}
}

package processes

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeLoadedModulesDeduplicatesAndSorts(t *testing.T) {
	mods := []LoadedModule{
		{Path: "/usr/lib/libz.so.1", TrustState: "package_managed", TrustBasis: "test", DirectoryState: "observed", Source: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/usr/lib/liba.so.1", TrustState: "UNKNOWN", TrustBasis: "test", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceMedium},
		{Path: "/usr/lib/libz.so.1", TrustState: "PACKAGE_MANAGED", TrustBasis: "better", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceExact},
	}
	got := normalizeLoadedModules(mods, "linux")
	if len(got) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(got))
	}
	if got[0].Path != "/usr/lib/liba.so.1" || got[1].Path != "/usr/lib/libz.so.1" {
		t.Fatalf("modules not sorted: %#v", got)
	}
	if got[1].Confidence != evidence.ConfidenceExact || got[1].TrustState != "PACKAGE_MANAGED" {
		t.Fatalf("higher-confidence duplicate was not retained: %#v", got[1])
	}
}

func TestModuleTrustMismatchRequiresStrongProcessTrust(t *testing.T) {
	if !moduleTrustMismatch("PACKAGE_MANAGED", "UNMANAGED", false) {
		t.Fatal("expected package-managed process + unmanaged module mismatch")
	}
	if !moduleTrustMismatch("SIGNED_VALID", "UNSIGNED", false) {
		t.Fatal("expected signed process + unsigned module mismatch")
	}
	if moduleTrustMismatch("UNKNOWN", "UNMANAGED", false) {
		t.Fatal("unknown process trust must not invent a mismatch")
	}
	if moduleTrustMismatch("PACKAGE_MANAGED", "PACKAGE_MANAGED", false) {
		t.Fatal("matching managed provenance should not mismatch")
	}
	if !moduleTrustMismatch("UNKNOWN", "UNKNOWN", true) {
		t.Fatal("deleted backing must always be treated as a trust mismatch")
	}
}

func TestSummarizeLoadedModules(t *testing.T) {
	c := LoadedModuleContext{Modules: []LoadedModule{
		{Path: "/a", TrustState: "SIGNATURE_INVALID", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/b", TrustState: "UNSIGNED", DirectoryState: "OBSERVED", DirectoryWritable: true, TrustMismatch: true, Source: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/c", TrustState: "UNMANAGED", DirectoryState: "OBSERVED", DeletedBacking: true, Source: "test", Confidence: evidence.ConfidenceHigh},
	}}
	c.ModuleCount = len(c.Modules)
	summarizeLoadedModules(&c)
	if c.ExplicitTrustFailures != 1 || c.UnsignedModules != 1 || c.UnmanagedModules != 1 || c.DeletedMappings != 1 || c.WritableLocationModules != 1 || c.TrustMismatches != 1 {
		t.Fatalf("unexpected module summary: %#v", c)
	}
}

func TestNormalizeLoadedModulesLinuxMatchesValidationOrdering(t *testing.T) {
	mods := []LoadedModule{
		{Path: "/usr/lib/Zeta.so", TrustState: "PACKAGE_MANAGED", TrustBasis: "test", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/usr/lib/alpha.so", TrustState: "PACKAGE_MANAGED", TrustBasis: "test", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/usr/lib/Alpha.so", TrustState: "PACKAGE_MANAGED", TrustBasis: "test", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceHigh},
	}
	got := normalizeLoadedModules(mods, "linux")
	if len(got) != 3 {
		t.Fatalf("expected Linux case-distinct paths to remain distinct, got %d", len(got))
	}
	last := ""
	for _, m := range got {
		key := strings.ToLower(filepath.Clean(m.Path))
		if last != "" && key < last {
			t.Fatalf("Linux loaded-module ordering does not match validation key: %#v", got)
		}
		last = key
	}
}

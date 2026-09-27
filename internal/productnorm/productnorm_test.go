package productnorm

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/software"
)

func TestNormalizeInventoryUsesExactPackageAlias(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	inv := software.Inventory{
		CollectedAt: time.Date(2026, 8, 18, 19, 0, 0, 0, time.UTC),
		Items:       []software.Item{{ID: "xz1", Kind: "package", Product: "xz-utils", PackageID: "xz-utils", Version: "5.6.1", PackageSource: "dpkg:xz-utils", Confidence: evidence.ConfidenceExact}},
	}
	got := NormalizeInventory(inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Matched != 1 || got.Summary.Unmatched != 0 {
		t.Fatalf("unexpected summary: %#v", got.Summary)
	}
	m := got.Matches[0]
	if m.ProductID != "tukaani-xz" || m.MatchMethod != "exact-package-alias" || !m.VersionComparable || m.VersionScheme != "debian" {
		t.Fatalf("unexpected match: %#v", m)
	}
}

func TestNormalizeInventoryRejectsSubstringOnlyMatch(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	inv := software.Inventory{
		CollectedAt: time.Now().UTC(),
		Items:       []software.Item{{ID: "fake", Kind: "package", Product: "my-xz-utils-helper", PackageID: "my-xz-utils-helper", Version: "1.0", PackageSource: "dpkg:my-xz-utils-helper", Confidence: evidence.ConfidenceExact}},
	}
	got := NormalizeInventory(inv, loaded)
	if got.Summary.Matched != 0 || got.Summary.Unmatched != 1 || got.Matches[0].State != StateUnmatched {
		t.Fatalf("substring-only identity was incorrectly accepted: %#v", got)
	}
}

func TestNormalizeInventoryRequiresEcosystemCompatibility(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	inv := software.Inventory{
		CollectedAt: time.Now().UTC(),
		Items:       []software.Item{{ID: "maven-name-in-dpkg", Kind: "package", Product: "log4j-core", PackageID: "log4j-core", Version: "2.14.1", PackageSource: "dpkg:log4j-core", Confidence: evidence.ConfidenceExact}},
	}
	got := NormalizeInventory(inv, loaded)
	if got.Summary.Matched != 0 {
		t.Fatalf("cross-ecosystem alias should not match: %#v", got)
	}
}

func TestCompareDebianVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:5.6.1-2", "5.6.1-99", 1},
		{"5.6.1~rc1-1", "5.6.1-1", -1},
		{"5.6.1-1", "5.6.1-1", 0},
	}
	for _, tc := range cases {
		got, err := CompareVersions("dpkg", tc.a, tc.b)
		if err != nil {
			t.Fatal(err)
		}
		if sign(got) != tc.want {
			t.Fatalf("compare %q %q = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareMavenPreRelease(t *testing.T) {
	got, err := CompareVersions("maven", "2.0-beta9", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if got >= 0 {
		t.Fatalf("beta should sort before final, got %d", got)
	}
	got, err = CompareVersions("maven", "2.14.1", "2.15.0")
	if err != nil {
		t.Fatal(err)
	}
	if got >= 0 {
		t.Fatalf("2.14.1 should sort before 2.15.0, got %d", got)
	}
}

func TestUnsupportedComparatorFailsClosed(t *testing.T) {
	if _, err := CompareVersions("mystery", "1", "2"); err == nil {
		t.Fatal("expected unsupported comparator error")
	}
}

func TestMatchCandidateByExactCPE(t *testing.T) {
	products := []intelligence.ProductMapping{{ID: "demo", Ecosystem: "native-package", Vendor: "Vendor", Product: "Demo", CPEs: []string{"cpe:2.3:a:vendor:demo:*:*:*:*:*:*:*:*"}}}
	m := matchCandidate(Candidate{Ref: "test.cpe", Kind: "installed-software", Product: "unrelated local label", Version: "1.2.3", Ecosystem: "dpkg", CPEs: []string{"CPE:2.3:A:VENDOR:DEMO:*:*:*:*:*:*:*:*"}, Confidence: evidence.ConfidenceExact}, products)
	if m.State != StateMatched || m.ProductID != "demo" || m.MatchMethod != "exact-cpe" || len(m.CanonicalCPEs) != 1 {
		t.Fatalf("unexpected exact CPE match: %#v", m)
	}
}

func TestMatchCandidateByExactPURL(t *testing.T) {
	products := []intelligence.ProductMapping{{ID: "log4j", Ecosystem: "maven", Product: "Log4j Core", PURLs: []string{"pkg:maven/org.apache.logging.log4j/log4j-core"}}}
	m := matchCandidate(Candidate{Ref: "test.purl", Kind: "package", Product: "unknown local display", PackageID: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Version: "2.14.1", Ecosystem: "maven", PURLs: []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, Confidence: evidence.ConfidenceExact}, products)
	if m.State != StateMatched || m.ProductID != "log4j" || m.MatchMethod != "exact-purl" || len(m.CanonicalPURLs) != 1 {
		t.Fatalf("unexpected exact PURL match: %#v", m)
	}
}

func TestAmbiguousExactAliasesFailClosed(t *testing.T) {
	products := []intelligence.ProductMapping{
		{ID: "a", Ecosystem: "native-package", Product: "A", Aliases: []string{"same-name"}},
		{ID: "b", Ecosystem: "native-package", Product: "B", Aliases: []string{"same-name"}},
	}
	m := matchCandidate(Candidate{Ref: "test.ambiguous", Kind: "package", Product: "same-name", PackageID: "same-name", Version: "1", Ecosystem: "dpkg", Confidence: evidence.ConfidenceExact}, products)
	if m.State != StateAmbiguous || m.ProductID != "" || len(m.Alternatives) != 2 {
		t.Fatalf("ambiguous identity should fail closed: %#v", m)
	}
}

func sign(v int) int {
	if v < 0 {
		return -1
	}
	if v > 0 {
		return 1
	}
	return 0
}

func TestPost117Fix12DotNetFrameworkIdentityIsolation(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	loaded, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	inv := software.Inventory{
		CollectedAt:  time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Platform:     "windows",
		Architecture: "amd64",
		Runtimes: []software.RuntimeItem{
			{ID: "core", Family: "dotnet", Kind: "framework-runtime", Product: "Microsoft.NETCore.App", Version: "8.0.29", Confidence: evidence.ConfidenceExact},
			{ID: "aspnet", Family: "dotnet", Kind: "framework-runtime", Product: "Microsoft.AspNetCore.App", Version: "8.0.29", Confidence: evidence.ConfidenceExact},
			{ID: "desktop", Family: "dotnet", Kind: "framework-runtime", Product: "Microsoft.WindowsDesktop.App", Version: "8.0.29", Confidence: evidence.ConfidenceExact},
			{ID: "sdk", Family: "dotnet", Kind: "toolchain", Product: ".NET SDK", Version: "8.0.424", Confidence: evidence.ConfidenceExact},
		},
	}
	got := NormalizeInventory(inv, loaded)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Matched != 4 || got.Summary.Ambiguous != 0 {
		t.Fatalf(".NET framework identities should map exactly without ambiguity: %#v", got.Summary)
	}
	want := map[string]string{
		"Microsoft.NETCore.App":        "dotnet-runtime",
		"Microsoft.AspNetCore.App":     "dotnet-aspnetcore-runtime",
		"Microsoft.WindowsDesktop.App": "dotnet-windowsdesktop-runtime",
		".NET SDK":                     "dotnet-sdk",
	}
	for _, match := range got.Matches {
		if match.CandidatePlatform != "windows" {
			t.Fatalf("candidate platform was not preserved: %#v", match)
		}
		if id, ok := want[match.CanonicalProduct]; !ok || id != match.ProductID {
			t.Fatalf("unexpected .NET mapping: %#v", match)
		}
	}
}

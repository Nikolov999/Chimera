package releasecontract

import "testing"

func TestV1CoreContractEachSupportedPlatform(t *testing.T) {
	wantCounts := map[string]int{"linux": 222, "windows": 219, "darwin": 216}
	for _, platform := range SupportedPlatforms() {
		t.Run(platform, func(t *testing.T) {
			if err := ValidateCoreForPlatform(platform); err != nil {
				t.Fatal(err)
			}
			c := CurrentForPlatform(platform)
			manifest, ok := PlatformManifestFor(platform)
			if !ok {
				t.Fatalf("missing manifest for %s", platform)
			}
			if c.Schema != SchemaVersion || c.ContractVersion != ContractVersion || c.ReleaseVersion != ReleaseVersion || c.Platform != platform {
				t.Fatalf("unexpected release contract: %#v", c)
			}
			if c.RuleCount != wantCounts[platform] || c.RuleCount != manifest.RuleCount {
				t.Fatalf("%s rule count=%d manifest=%d want=%d", platform, c.RuleCount, manifest.RuleCount, wantCounts[platform])
			}
			if c.CatalogDigest != manifest.CatalogDigest {
				t.Fatalf("%s digest=%s want=%s", platform, c.CatalogDigest, manifest.CatalogDigest)
			}
			if len(c.RequiredCommands) != 37 || len(c.RuleCategories) < 16 || len(c.Profiles) != 6 {
				t.Fatalf("incomplete v1 contract: %#v", c)
			}
		})
	}
}

func TestV1CoreContractRejectsUnknownPlatform(t *testing.T) {
	if err := ValidateCoreForPlatform("plan9"); err == nil {
		t.Fatal("expected unsupported platform contract failure")
	}
}

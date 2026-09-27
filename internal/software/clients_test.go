package software

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func fixtureItem(product, packageID, version string) Item {
	item := Item{Kind: "application", Product: product, PackageID: packageID, Version: version, Architecture: "amd64", PackageSource: "fixture", InstallPath: "/fixture", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact}
	return normalizeItems([]Item{item})[0]
}

func TestBrowserChannelsRemainDistinct(t *testing.T) {
	items := []Item{
		fixtureItem("Google Chrome", "google-chrome-stable", "140.0.1"),
		fixtureItem("Google Chrome Beta", "google-chrome-beta", "141.0.2"),
		fixtureItem("Mozilla Firefox ESR", "firefox-esr", "128.12"),
	}
	got := classifyBrowsers(items, "windows")
	seen := map[string]BrowserItem{}
	for _, b := range got {
		seen[b.Family+":"+b.Channel] = b
	}
	if seen["chrome:stable"].Version != "140.0.1" || seen["chrome:beta"].Version != "141.0.2" {
		t.Fatalf("chrome channels were not kept distinct: %#v", got)
	}
	if seen["firefox:esr"].Product != "Mozilla Firefox ESR" {
		t.Fatalf("missing Firefox ESR classification: %#v", got)
	}
}

func TestBrowserMatchingRejectsHelpers(t *testing.T) {
	items := []Item{fixtureItem("Google Chrome Helper", "google-chrome-helper", "1")}
	if got := classifyBrowsers(items, "windows"); len(got) != 0 {
		t.Fatalf("helper package was classified as browser: %#v", got)
	}
}

func TestHighRiskClientClassification(t *testing.T) {
	items := []Item{
		fixtureItem("Adobe Acrobat Reader DC", "acrobat-reader", "24.1"),
		fixtureItem("Microsoft 365 Apps for enterprise - en-us", "office16", "16.0"),
		fixtureItem("Mozilla Thunderbird", "thunderbird", "128.0"),
		fixtureItem("7-Zip 24.08 (x64 edition)", "7-Zip", "24.08"),
	}
	got := classifyHighRiskClients(items, "windows")
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.Family] = true
		if c.ID == "" || c.Version == "" || c.Architecture == "" || c.PackageID == "" || c.InstallPath == "" || c.CollectionSource == "" || c.Confidence == "" || len(c.ContentSurfaces) == 0 || len(c.DetectionSources) == 0 {
			t.Fatalf("incomplete client record: %#v", c)
		}
	}
	for _, family := range []string{"adobe-acrobat", "microsoft-office", "thunderbird", "7zip"} {
		if !seen[family] {
			t.Fatalf("missing %s classification: %#v", family, got)
		}
	}
}

func TestClientStableIDsDeterministic(t *testing.T) {
	a := stableClientID("browser", "chrome", "stable", "Google Chrome")
	b := stableClientID("browser", "chrome", "stable", "Google Chrome")
	if a != b || len(a) != 27 {
		t.Fatalf("unstable or malformed client id: %q %q", a, b)
	}
}

func TestAppleMailIsDarwinOnly(t *testing.T) {
	items := []Item{fixtureItem("Mail", "mail", "1")}
	if got := classifyHighRiskClients(items, "linux"); len(got) != 0 {
		t.Fatalf("generic Linux mail package was classified as Apple Mail: %#v", got)
	}
	got := classifyHighRiskClients(items, "darwin")
	if len(got) != 1 || got[0].Family != "apple-mail" {
		t.Fatalf("expected Darwin Mail classification: %#v", got)
	}
}

func TestClientPrefixMatchingRejectsUpdaterAndPackageFragments(t *testing.T) {
	items := []Item{
		fixtureItem("Adobe Acrobat Update Service", "acrobat-update", "1"),
		fixtureItem("libreoffice-common", "libreoffice-common", "24.2"),
	}
	// Make the Linux package nature explicit for the LibreOffice fragment.
	items[1].Kind = "package"
	if got := classifyHighRiskClients(items, "windows"); len(got) != 0 {
		t.Fatalf("supporting components were classified as high-risk clients: %#v", got)
	}
}

func TestClientClassifierStatePreservesUnavailableEvidence(t *testing.T) {
	state, _ := clientClassifierState([]SourceStatus{{ID: "fixture", State: evidence.StateUnavailable, Source: "fixture", Reason: "provider missing"}})
	if state != evidence.StateUnavailable {
		t.Fatalf("expected unavailable classifier state, got %s", state)
	}
	state, _ = clientClassifierState([]SourceStatus{{ID: "fixture-a", State: evidence.StateDegraded}, {ID: "fixture-b", State: evidence.StateObserved}})
	if state != evidence.StateObserved {
		t.Fatalf("one usable provider should keep classifier observable, got %s", state)
	}
}

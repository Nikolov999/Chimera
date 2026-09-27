package kernel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestDriverIdentityMatchIsExactNotSubstring(t *testing.T) {
	e := driverIntelEntry{FileNames: []string{"gdrv.sys"}, ServiceNames: []string{"gdrv"}}
	if basis, ok := driverIdentityMatches(driverCandidate{Name: "gdrv", Path: `C:\Windows\System32\drivers\gdrv.sys`}, e); !ok || basis != "EXACT_FILE_NAME+EXACT_SERVICE_NAME" {
		t.Fatalf("expected exact dual identity match, got basis=%q ok=%v", basis, ok)
	}
	if basis, ok := driverIdentityMatches(driverCandidate{Name: "not-gdrv-helper", Path: `C:\Temp\not-gdrv.sys.bak`}, e); ok {
		t.Fatalf("substring-like identity must not match, got %q", basis)
	}
}

func TestCorrelateVulnerableDriverPreservesUnresolvedState(t *testing.T) {
	candidates := []driverCandidate{{
		Name: "RTCore64", Path: `C:\Windows\System32\drivers\RTCore64.sys`, Version: "1.0.0.0",
		Installed: true, Loaded: true, CollectionState: evidence.StateObserved,
		Source: "synthetic local driver inventory", ExposureState: "UNKNOWN", ExposureReason: exposureReasonFromLoad(true), Confidence: evidence.ConfidenceHigh,
	}}
	entries := []driverIntelEntry{{ID: "CHM-DRV-T", Platform: "windows", FileNames: []string{"rtcore64.sys"}, ServiceNames: []string{"rtcore64"}, Vulnerabilities: []string{"CVE-TEST"}}}
	got := correlateVulnerableDrivers(candidates, entries)
	if len(got) != 1 {
		t.Fatalf("expected one match, got %d", len(got))
	}
	v := got[0]
	if v.InstalledState != "INSTALLED" || v.LoadState != "LOADED" || v.ExposureState != "UNKNOWN" {
		t.Fatalf("unexpected presence/exposure state: %#v", v)
	}
	if v.ResolutionState != "IDENTITY_MATCH_REQUIRES_CONFIRMATION" {
		t.Fatalf("identity-only match must remain unresolved, got %q", v.ResolutionState)
	}
	if v.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("dual exact identity should be high-confidence identity correlation, got %q", v.Confidence)
	}
}

func TestMergeDriverCandidatesCombinesInstalledAndLoaded(t *testing.T) {
	loaded := driverCandidate{Name: "gdrv", Path: `C:\Windows\System32\drivers\gdrv.sys`, Loaded: true, CollectionState: evidence.StateObserved, Source: "loaded", Confidence: evidence.ConfidenceHigh}
	installed := driverCandidate{Name: "gdrv", Path: `C:\Windows\System32\drivers\gdrv.sys`, Installed: true, CollectionState: evidence.StateObserved, Source: "installed", Confidence: evidence.ConfidenceHigh}
	got := mergeDriverCandidates([]driverCandidate{loaded}, []driverCandidate{installed})
	if len(got) != 1 || !got[0].Loaded || !got[0].Installed {
		t.Fatalf("expected merged installed+loaded candidate: %#v", got)
	}
	if got[0].ExposureState != "UNKNOWN" {
		t.Fatalf("loaded candidate exposure must remain unproven, got %q", got[0].ExposureState)
	}
}

func TestFingerprintDriverBoundedLocalSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "driver.sys")
	if err := os.WriteFile(p, []byte("chimera-phase017"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := VulnerableDriverAssessment{DriverPath: p}
	fingerprintDriver(&v)
	if v.FingerprintState != "OBSERVED" || len(v.SHA256) != 64 {
		t.Fatalf("expected observed SHA-256 fingerprint, got %#v", v)
	}
}

func TestCatalogStableIDsAndExactAliases(t *testing.T) {
	seenID := map[string]bool{}
	seenAlias := map[string]string{}
	for _, e := range vulnerableDriverCatalog() {
		if e.ID == "" || e.Platform == "" || len(e.Vulnerabilities) == 0 {
			t.Fatalf("incomplete intelligence entry: %#v", e)
		}
		if seenID[e.ID] {
			t.Fatalf("duplicate intelligence id %q", e.ID)
		}
		seenID[e.ID] = true
		for _, a := range append(append([]string{}, e.FileNames...), e.ServiceNames...) {
			k := e.Platform + ":" + stringLower(a)
			if prior, ok := seenAlias[k]; ok && prior != e.ID {
				t.Fatalf("alias %q overlaps %s and %s", a, prior, e.ID)
			}
			seenAlias[k] = e.ID
		}
	}
}

func stringLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] = b[i] + ('a' - 'A')
		}
	}
	return string(b)
}

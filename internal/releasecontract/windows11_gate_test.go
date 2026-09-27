package releasecontract_test

import (
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cisalign"
	"github.com/Nikolov999/chimera/internal/releasecontract"
)

func TestFix20Windows11ReleaseProjectionIsFrozenAndSelfConsistent(t *testing.T) {
	const platform = "windows"
	if err := releasecontract.ValidateCoreForPlatform(platform); err != nil {
		t.Fatal(err)
	}
	contract := releasecontract.CurrentForPlatform(platform)
	if contract.RuleCount != 219 {
		t.Fatalf("Windows v1 rule count=%d want=219", contract.RuleCount)
	}
	if strings.TrimSpace(contract.CatalogDigest) == "" {
		t.Fatal("Windows v1 catalogue digest is empty")
	}

	rules := assessment.ImplementedRulesForPlatform(platform)
	if len(rules) != contract.RuleCount {
		t.Fatalf("Windows runtime catalogue=%d contract=%d", len(rules), contract.RuleCount)
	}
	if err := cisalign.ValidateCatalogForPlatform(platform, rules); err != nil {
		t.Fatal(err)
	}
	seenWindowsKernel := false
	for _, m := range cisalign.MappingsForPlatform(platform) {
		if strings.HasPrefix(m.RuleID, "CHM-KRN-LNX-") || strings.HasPrefix(m.RuleID, "CHM-KRN-MAC-") {
			t.Fatalf("foreign platform kernel mapping leaked into Windows gate: %s", m.RuleID)
		}
		if strings.HasPrefix(m.RuleID, "CHM-KRN-WIN-") {
			seenWindowsKernel = true
		}
	}
	if !seenWindowsKernel {
		t.Fatal("Windows CIS projection contains no Windows kernel mapping")
	}
}

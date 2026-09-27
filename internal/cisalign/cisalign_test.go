package cisalign

import (
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
)

func TestPhase109CanonicalCatalogValidatesAllPlatformMappings(t *testing.T) {
	if err := ValidateCanonicalCatalog(); err != nil {
		t.Fatal(err)
	}
	if len(Mappings()) != 230 {
		t.Fatalf("canonical mapped rule count=%d want=230", len(Mappings()))
	}
	if len(Concepts()) != 17 {
		t.Fatalf("concept count=%d want=17", len(Concepts()))
	}
}

func TestPhase109CatalogValidatesEachPlatformProjection(t *testing.T) {
	for _, platform := range []string{"linux", "windows", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			rules := assessment.ImplementedRulesForPlatform(platform)
			if err := ValidateCatalogForPlatform(platform, rules); err != nil {
				t.Fatal(err)
			}
			mapped := MappingsForPlatform(platform)
			if len(mapped) != len(rules)-5 {
				t.Fatalf("mapped rule count=%d want=%d", len(mapped), len(rules)-5)
			}
			for _, m := range mapped {
				if strings.HasPrefix(m.RuleID, "CHM-CORE-") {
					t.Fatalf("observability-only core rule unexpectedly mapped: %#v", m)
				}
				if strings.HasPrefix(m.RuleID, "CHM-KRN-LNX-") && platform != "linux" {
					t.Fatalf("Linux-only mapping leaked into %s: %#v", platform, m)
				}
				if strings.HasPrefix(m.RuleID, "CHM-KRN-WIN-") && platform != "windows" {
					t.Fatalf("Windows-only mapping leaked into %s: %#v", platform, m)
				}
				if strings.HasPrefix(m.RuleID, "CHM-KRN-MAC-") && platform != "darwin" {
					t.Fatalf("macOS-only mapping leaked into %s: %#v", platform, m)
				}
			}
		})
	}
}

func TestPhase109EvaluatePreservesFailureAndPartialCoverage(t *testing.T) {
	rules := assessment.ImplementedRules()
	findings := []assessment.Finding{
		{ID: "f1", RuleID: "CHM-FW-001", Status: assessment.StatusPass, Applicability: assessment.Applicable},
		{ID: "f2", RuleID: "CHM-FW-002", Status: assessment.StatusFail, Applicability: assessment.Applicable},
	}
	result, err := Evaluate(findings, rules)
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != SchemaVersion || result.CatalogVersion != CatalogVersion {
		t.Fatalf("unexpected mapping contract: %#v", result)
	}
	if result.Framework.OfficialBenchmark || result.Framework.CertificationClaim {
		t.Fatalf("must not claim benchmark/certification status: %#v", result.Framework)
	}
	var firewall ConceptResult
	found := false
	for _, c := range result.Concepts {
		if c.Concept.ID == "CHM-CIS-CONCEPT-06" {
			firewall = c
			found = true
			break
		}
	}
	if !found {
		t.Fatal("firewall concept missing")
	}
	if firewall.State != StateFail || firewall.Coverage != "PARTIAL" || firewall.Counts.Evaluated != 2 || firewall.Counts.Fail != 1 {
		t.Fatalf("unexpected firewall concept evaluation: %#v", firewall)
	}
}

func TestPhase109WindowsEvaluationUsesWindowsKernelProjection(t *testing.T) {
	result, err := EvaluateForPlatform("windows", nil, assessment.ImplementedRulesForPlatform("windows"))
	if err != nil {
		t.Fatal(err)
	}
	var platform ConceptResult
	for _, c := range result.Concepts {
		if c.Concept.ID == "CHM-CIS-CONCEPT-01" {
			platform = c
			break
		}
	}
	if platform.Counts.Mapped != 11 {
		t.Fatalf("Windows secure-platform mapping count=%d want=11", platform.Counts.Mapped)
	}
	for _, id := range platform.MappedRuleIDs {
		if strings.HasPrefix(id, "CHM-KRN-LNX-") || strings.HasPrefix(id, "CHM-KRN-MAC-") {
			t.Fatalf("foreign platform kernel mapping leaked into Windows projection: %s", id)
		}
	}
}

func TestPhase109NotApplicableDoesNotBecomePass(t *testing.T) {
	result, err := Evaluate([]assessment.Finding{{ID: "f", RuleID: "CHM-COR-001", Status: assessment.StatusPass, Applicability: assessment.NotApplicable}}, assessment.ImplementedRules())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range result.Concepts {
		if c.Concept.ID != "CHM-CIS-CONCEPT-17" {
			continue
		}
		if c.State != StateNotApplicable || c.Counts.NotApplicable != 1 || c.Coverage != "PARTIAL" {
			t.Fatalf("unexpected not-applicable semantics: %#v", c)
		}
		return
	}
	t.Fatal("correlation concept missing")
}

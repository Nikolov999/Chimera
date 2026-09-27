package assessment

import (
	"fmt"
	"sort"
	"strings"
)

// ServiceSchedulerPackVersion identifies the enterprise rule pack
// spanning services, daemons, launch jobs, and scheduled execution. The pack
// is intentionally an assessment-only composition layer: collectors remain
// independent and read-only, while rule IDs remain stable across the public
// findings contract.
const ServiceSchedulerPackVersion = "chimera.rules/service-scheduler-v1-phase051"

// serviceSchedulerStableRuleIDs is the frozen public ID inventory.
// Adding a later rule is allowed only by intentionally extending this list;
// renumbering or silently dropping an existing ID is treated as a contract
// regression by ValidateServiceSchedulerRulePack and its tests.
var serviceSchedulerStableRuleIDs = []string{
	"CHM-SCH-001",
	"CHM-SCH-002",
	"CHM-SCH-003",
	"CHM-SCH-004",
	"CHM-SCH-005",
	"CHM-SVC-001",
	"CHM-SVC-002",
	"CHM-SVC-003",
	"CHM-SVC-004",
	"CHM-SVC-005",
	"CHM-SVC-006",
	"CHM-SVC-007",
	"CHM-SVC-008",
	"CHM-SVC-009",
	"CHM-SVC-010",
	"CHM-SVC-011",
	"CHM-SVC-012",
	"CHM-SVC-013",
	"CHM-SVC-014",
	"CHM-SVC-015",
	"CHM-SVC-016",
	"CHM-SVC-017",
	"CHM-SVC-018",
	"CHM-SVC-019",
	"CHM-SVC-020",
	"CHM-SVC-021",
	"CHM-SVC-022",
	"CHM-SVC-023",
	"CHM-SVC-024",
	"CHM-SVC-025",
	"CHM-SVC-026",
	"CHM-SVC-027",
	"CHM-SVC-028",
	"CHM-SVC-029",
}

// ServiceSchedulerRulePack returns the consolidated enterprise
// checks. It preserves the established CHM-SVC and CHM-SCH finding identities
// while giving scans one deterministic composition point for this workflow
// lane. No collector execution or host mutation occurs here.
func ServiceSchedulerRulePack() []Rule {
	rules := append([]Rule(nil), ServiceRules()...)
	rules = append(rules, ScheduledRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// ServiceSchedulerRuleIDs returns a defensive copy of the stable ID
// inventory so callers/tests can assert contract continuity without mutating
// the package-level manifest.
func ServiceSchedulerRuleIDs() []string {
	ids := append([]string(nil), serviceSchedulerStableRuleIDs...)
	sort.Strings(ids)
	return ids
}

// ValidateServiceSchedulerRulePack enforces the enterprise contract:
// every frozen ID exists exactly once, no unregistered ID silently enters the
// pack, rule/category prefixes agree, and each rule satisfies the base rule
// model. This catches accidental rule renumbering before it can break finding
// history, suppressions, exports, or downstream IRONCLAD integrations.
func ValidateServiceSchedulerRulePack(rules []Rule) error {
	expected := make(map[string]struct{}, len(serviceSchedulerStableRuleIDs))
	for _, id := range serviceSchedulerStableRuleIDs {
		expected[id] = struct{}{}
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("service/scheduler rule %q invalid: %w", rule.ID, err)
		}
		if _, ok := expected[rule.ID]; !ok {
			return fmt.Errorf("unregistered service/scheduler rule id %q", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate service/scheduler rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}

		switch {
		case strings.HasPrefix(rule.ID, "CHM-SVC-"):
			if rule.Category != "service" {
				return fmt.Errorf("service rule %q must use category service, got %q", rule.ID, rule.Category)
			}
		case strings.HasPrefix(rule.ID, "CHM-SCH-"):
			if rule.Category != "scheduled" {
				return fmt.Errorf("scheduled rule %q must use category scheduled, got %q", rule.ID, rule.Category)
			}
		default:
			return fmt.Errorf("rule %q is outside the service/scheduler namespace", rule.ID)
		}
	}

	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("stable service/scheduler rule id %q is missing", id)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("service/scheduler rule count mismatch: got %d want %d", len(seen), len(expected))
	}
	return nil
}

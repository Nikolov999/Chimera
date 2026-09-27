package assessment

import (
	"fmt"
	"sort"
	"strings"
)

// NetworkExposurePackVersion identifies the consolidated network and
// firewall assessment pack. The pack is evaluation-only: it composes the
// existing read-only network, service-context, remote-management, SSH, SMB,
// and local-firewall rules without performing collection or network activity.
const NetworkExposurePackVersion = "chimera.rules/network-firewall-v1-phase063"

// networkExposureStableRuleIDs freezes the public rule identities.
// These IDs are consumed by finding history, suppressions, exports, and
// downstream IRONCLAD integrations, so accidental removal or renumbering is a
// contract regression.
var networkExposureStableRuleIDs = []string{
	"CHM-FW-001",
	"CHM-FW-002",
	"CHM-FW-003",
	"CHM-FW-004",
	"CHM-FW-005",
	"CHM-FW-006",
	"CHM-FW-007",
	"CHM-FW-008",
	"CHM-NET-001",
	"CHM-NET-002",
	"CHM-NET-003",
	"CHM-NET-004",
	"CHM-NET-005",
	"CHM-NET-006",
	"CHM-NET-007",
	"CHM-NET-008",
	"CHM-NET-009",
	"CHM-NET-010",
	"CHM-NET-011",
	"CHM-NET-012",
	"CHM-NET-013",
	"CHM-NET-014",
	"CHM-NET-015",
	"CHM-NET-016",
	"CHM-NET-017",
	"CHM-NET-018",
	"CHM-NET-019",
	"CHM-NET-020",
	"CHM-NET-021",
	"CHM-NET-022",
	"CHM-NET-023",
	"CHM-NET-024",
	"CHM-NET-025",
	"CHM-NET-026",
	"CHM-NET-027",
	"CHM-NET-028",
	"CHM-NET-029",
}

// NetworkExposureRulePack is the single composition point for the
// network/firewall workflow lane. NetworkRules already consumes normalized
// listener ownership plus service-role/path context where available, while
// FirewallRules consumes listener ownership and per-listener firewall
// correlation. Keeping both families in one deterministic pack guarantees that
// scans evaluate exposure and its local control boundary together.
func NetworkExposureRulePack() []Rule {
	rules := append([]Rule(nil), NetworkRules()...)
	rules = append(rules, FirewallRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// NetworkExposureRuleIDs returns a defensive copy of the frozen // rule-ID inventory.
func NetworkExposureRuleIDs() []string {
	ids := append([]string(nil), networkExposureStableRuleIDs...)
	sort.Strings(ids)
	return ids
}

// ValidateNetworkExposureRulePack enforces the public rule contract:
// every frozen ID exists exactly once, no unregistered ID enters the pack, the
// ID namespace agrees with the rule category, and every rule satisfies the
// base finding/rule model.
func ValidateNetworkExposureRulePack(rules []Rule) error {
	expected := make(map[string]struct{}, len(networkExposureStableRuleIDs))
	for _, id := range networkExposureStableRuleIDs {
		expected[id] = struct{}{}
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("network/firewall rule %q invalid: %w", rule.ID, err)
		}
		if _, ok := expected[rule.ID]; !ok {
			return fmt.Errorf("unregistered network/firewall rule id %q", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate network/firewall rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}

		switch {
		case strings.HasPrefix(rule.ID, "CHM-NET-"):
			if rule.Category != "network" {
				return fmt.Errorf("network rule %q must use category network, got %q", rule.ID, rule.Category)
			}
		case strings.HasPrefix(rule.ID, "CHM-FW-"):
			if rule.Category != "firewall" {
				return fmt.Errorf("firewall rule %q must use category firewall, got %q", rule.ID, rule.Category)
			}
		default:
			return fmt.Errorf("rule %q is outside the network/firewall namespace", rule.ID)
		}
	}

	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("stable network/firewall rule id %q is missing", id)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("network/firewall rule count mismatch: got %d want %d", len(seen), len(expected))
	}
	return nil
}

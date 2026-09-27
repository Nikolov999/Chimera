package assessment

import (
	"fmt"
	"sort"
	"strings"
)

// IdentityAuthenticationPackVersion identifies the consolidated
// account and authentication posture rule pack. The pack is evaluation-only:
// it composes the existing read-only account, Windows security-policy,
// credential-protection, Linux sudo/PAM, macOS authorization, and SSH key
// posture checks without collecting additional host data or performing
// authentication activity.
const IdentityAuthenticationPackVersion = "chimera.rules/identity-authentication-v1-phase073"

// identityAuthenticationStableRuleIDs freezes the public identity
// finding namespace. These IDs are consumed by finding history, suppressions,
// exports, assessment diffs, and downstream IRONCLAD integrations. Accidental
// removal or renumbering is therefore a public-contract regression.
var identityAuthenticationStableRuleIDs = []string{
	"CHM-ID-001",
	"CHM-ID-002",
	"CHM-ID-003",
	"CHM-ID-004",
	"CHM-ID-005",
	"CHM-ID-006",
	"CHM-ID-007",
	"CHM-ID-008",
	"CHM-ID-009",
	"CHM-ID-010",
	"CHM-ID-011",
	"CHM-ID-012",
	"CHM-ID-013",
	"CHM-ID-014",
	"CHM-ID-015",
	"CHM-ID-016",
	"CHM-ID-017",
	"CHM-ID-018",
	"CHM-ID-019",
	"CHM-ID-020",
	"CHM-ID-021",
	"CHM-ID-022",
	"CHM-ID-023",
	"CHM-ID-024",
	"CHM-ID-025",
	"CHM-ID-026",
	"CHM-ID-027",
	"CHM-ID-028",
	"CHM-ID-029",
	"CHM-ID-030",
	"CHM-ID-031",
	"CHM-ID-032",
	"CHM-ID-033",
	"CHM-ID-034",
	"CHM-ID-035",
	"CHM-ID-036",
	"CHM-ID-037",
	"CHM-ID-038",
	"CHM-ID-039",
	"CHM-ID-040",
	"CHM-ID-041",
	"CHM-ID-042",
	"CHM-ID-043",
}

// IdentityAuthenticationRulePack is the single composition point
// for local account and authentication posture. All component evaluators retain
// their existing platform applicability semantics. Profile processing remains
// outside the pack and continues to apply the identity-category severity floors
// and applicability decisions without modifying normalized evidence.
func IdentityAuthenticationRulePack() []Rule {
	rules := append([]Rule(nil), PrivilegedAccountRules()...)
	rules = append(rules, PasswordlessAccountRules()...)
	rules = append(rules, WindowsLocalSecurityRules()...)
	rules = append(rules, WindowsCredentialProtectionRules()...)
	rules = append(rules, LinuxSudoRules()...)
	rules = append(rules, LinuxAuthenticationRules()...)
	rules = append(rules, MacOSAuthorizationRules()...)
	rules = append(rules, SSHKeyPostureRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// IdentityAuthenticationRuleIDs returns a defensive copy of the frozen Phase
// 073 CHM-ID manifest.
func IdentityAuthenticationRuleIDs() []string {
	ids := append([]string(nil), identityAuthenticationStableRuleIDs...)
	sort.Strings(ids)
	return ids
}

// ValidateIdentityAuthenticationRulePack enforces the public
// identity contract: every frozen CHM-ID exists exactly once, no unregistered
// identity ID enters the pack, all rules remain in the identity category, and
// every rule satisfies the normalized rule model.
func ValidateIdentityAuthenticationRulePack(rules []Rule) error {
	expected := make(map[string]struct{}, len(identityAuthenticationStableRuleIDs))
	for _, id := range identityAuthenticationStableRuleIDs {
		expected[id] = struct{}{}
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("identity/authentication rule %q invalid: %w", rule.ID, err)
		}
		if _, ok := expected[rule.ID]; !ok {
			return fmt.Errorf("unregistered identity/authentication rule id %q", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate identity/authentication rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if !strings.HasPrefix(rule.ID, "CHM-ID-") {
			return fmt.Errorf("rule %q is outside the identity/authentication namespace", rule.ID)
		}
		if rule.Category != "identity" {
			return fmt.Errorf("identity rule %q must use category identity, got %q", rule.ID, rule.Category)
		}
	}

	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("stable identity/authentication rule id %q is missing", id)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("identity/authentication rule count mismatch: got %d want %d", len(seen), len(expected))
	}
	return nil
}

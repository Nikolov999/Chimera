package assessment

import (
	"fmt"
	"sort"
	"strings"
)

// PersistenceSecretPackVersion identifies the consolidated
// persistence and secret-storage posture pack. The pack is assessment-only: it
// composes existing normalized evidence evaluators and never collects secret
// values, executes persistence targets, authenticates, or mutates host state.
const PersistenceSecretPackVersion = "chimera.rules/persistence-secrets-v1-phase104"

// persistenceSecretStableRuleIDs freezes the public persistence and
// secret-storage finding namespace. These IDs are consumed by finding history,
// suppressions, exports, assessment diffs, and downstream integrations, so
// accidental removal or renumbering is a public-contract regression.
var persistenceSecretStableRuleIDs = []string{
	"CHM-PER-001", "CHM-PER-002", "CHM-PER-003", "CHM-PER-004", "CHM-PER-005",
	"CHM-SEC-001", "CHM-SEC-002", "CHM-SEC-003", "CHM-SEC-004", "CHM-SEC-005",
	"CHM-SEC-006", "CHM-SEC-007",
}

// PersistenceSecretRulePack is the single composition point for
// persistence and secret-storage posture. It preserves the existing rules from
// Phases 097-103, provides deterministic ordering, and adds no collector-side
// behavior or additional secret-content access.
func PersistenceSecretRulePack() []Rule {
	rules := append([]Rule(nil), PersistencePathIntegrityRules()...)
	rules = append(rules, SecretStorageRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// PersistenceSecretRuleIDs returns a defensive, sorted copy of the frozen
// CHM-PER/CHM-SEC manifest.
func PersistenceSecretRuleIDs() []string {
	ids := append([]string(nil), persistenceSecretStableRuleIDs...)
	sort.Strings(ids)
	return ids
}

// ValidatePersistenceSecretRulePack enforces the public contract:
// every frozen ID exists exactly once, no unregistered persistence/secret ID
// enters the pack, namespace/category mappings remain correct, and every rule
// satisfies Chimera's normalized rule model.
func ValidatePersistenceSecretRulePack(rules []Rule) error {
	expected := make(map[string]struct{}, len(persistenceSecretStableRuleIDs))
	for _, id := range persistenceSecretStableRuleIDs {
		expected[id] = struct{}{}
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("persistence/secret rule %q invalid: %w", rule.ID, err)
		}
		if _, ok := expected[rule.ID]; !ok {
			return fmt.Errorf("unregistered persistence/secret rule id %q", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate persistence/secret rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}

		switch {
		case strings.HasPrefix(rule.ID, "CHM-PER-"):
			if rule.Category != "persistence" {
				return fmt.Errorf("persistence rule %q must use category persistence, got %q", rule.ID, rule.Category)
			}
		case strings.HasPrefix(rule.ID, "CHM-SEC-"):
			if rule.Category != "secrets" {
				return fmt.Errorf("secret-storage rule %q must use category secrets, got %q", rule.ID, rule.Category)
			}
		default:
			return fmt.Errorf("rule %q is outside the persistence/secret namespace", rule.ID)
		}
	}

	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("stable persistence/secret rule id %q is missing", id)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("persistence/secret rule count mismatch: got %d want %d", len(seen), len(expected))
	}
	return nil
}

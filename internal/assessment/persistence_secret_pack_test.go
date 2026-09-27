package assessment

import "testing"

func TestPhase104PersistenceSecretRulePackContract(t *testing.T) {
	rules := PersistenceSecretRulePack()
	if err := ValidatePersistenceSecretRulePack(rules); err != nil {
		t.Fatal(err)
	}
	if PersistenceSecretPackVersion != "chimera.rules/persistence-secrets-v1-phase104" {
		t.Fatalf("pack version=%q", PersistenceSecretPackVersion)
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("rule set version=%q", RuleSetVersion)
	}
	ids := PersistenceSecretRuleIDs()
	if len(ids) != 12 || len(rules) != len(ids) {
		t.Fatalf("unexpected rule count: ids=%d rules=%d", len(ids), len(rules))
	}
	for i := range rules {
		if rules[i].ID != ids[i] {
			t.Fatalf("deterministic rule order mismatch at %d: got %q want %q", i, rules[i].ID, ids[i])
		}
	}
}

func TestPhase104PersistenceSecretPackRejectsMissingDuplicateAndForeignRules(t *testing.T) {
	base := PersistenceSecretRulePack()
	if len(base) < 2 {
		t.Fatal("test requires populated pack")
	}

	missing := append([]Rule(nil), base[1:]...)
	if err := ValidatePersistenceSecretRulePack(missing); err == nil {
		t.Fatal("expected missing stable ID to fail validation")
	}

	duplicate := append([]Rule(nil), base...)
	duplicate = append(duplicate, base[0])
	if err := ValidatePersistenceSecretRulePack(duplicate); err == nil {
		t.Fatal("expected duplicate stable ID to fail validation")
	}

	foreign := append([]Rule(nil), base...)
	foreign[0] = CoreRules()[0]
	if err := ValidatePersistenceSecretRulePack(foreign); err == nil {
		t.Fatal("expected foreign rule ID to fail validation")
	}
}

func TestImplementedRulesUsesPhase104PackExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, rule := range ImplementedRules() {
		counts[rule.ID]++
	}
	for _, id := range PersistenceSecretRuleIDs() {
		if counts[id] != 1 {
			t.Fatalf("%s count=%d", id, counts[id])
		}
	}
}

package assessment

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPhase073IdentityAuthenticationPackStableContract(t *testing.T) {
	rules := IdentityAuthenticationRulePack()
	if err := ValidateIdentityAuthenticationRulePack(rules); err != nil {
		t.Fatalf("ValidateIdentityAuthenticationRulePack: %v", err)
	}
	if got, want := len(rules), 43; got != want {
		t.Fatalf("rule count=%d want %d", got, want)
	}
	gotIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		gotIDs = append(gotIDs, rule.ID)
	}
	sort.Strings(gotIDs)
	if wantIDs := IdentityAuthenticationRuleIDs(); !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("stable ID inventory drift\ngot:  %v\nwant: %v", gotIDs, wantIDs)
	}
}

func TestPhase073ImplementedRulesUseConsolidatedPackExactlyOnce(t *testing.T) {
	pack := make(map[string]struct{})
	for _, id := range IdentityAuthenticationRuleIDs() {
		pack[id] = struct{}{}
	}
	counts := make(map[string]int)
	for _, rule := range ImplementedRules() {
		if _, ok := pack[rule.ID]; ok {
			counts[rule.ID]++
		}
	}
	for id := range pack {
		if counts[id] != 1 {
			t.Fatalf("implemented catalog contains %s %d time(s), want exactly 1", id, counts[id])
		}
	}
}

func TestPhase073PackRejectsStableIDAndCategoryDrift(t *testing.T) {
	rules := IdentityAuthenticationRulePack()

	missing := append([]Rule(nil), rules[1:]...)
	if err := ValidateIdentityAuthenticationRulePack(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing stable ID error=%v", err)
	}

	drifted := append([]Rule(nil), rules...)
	drifted[0].Category = "accounts"
	if err := ValidateIdentityAuthenticationRulePack(drifted); err == nil || !strings.Contains(err.Error(), "must use category identity") {
		t.Fatalf("category drift error=%v", err)
	}

	renumbered := append([]Rule(nil), rules...)
	renumbered[0].ID = "CHM-ID-999"
	if err := ValidateIdentityAuthenticationRulePack(renumbered); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("renumbered ID error=%v", err)
	}
}

func TestPhase073PackPreservesComponentRuleEvaluators(t *testing.T) {
	components := [][]Rule{
		PrivilegedAccountRules(),
		PasswordlessAccountRules(),
		WindowsLocalSecurityRules(),
		WindowsCredentialProtectionRules(),
		LinuxSudoRules(),
		LinuxAuthenticationRules(),
		MacOSAuthorizationRules(),
		SSHKeyPostureRules(),
	}
	pack := make(map[string]Rule, len(IdentityAuthenticationRulePack()))
	for _, rule := range IdentityAuthenticationRulePack() {
		pack[rule.ID] = rule
	}
	for _, family := range components {
		for _, original := range family {
			got, ok := pack[original.ID]
			if !ok {
				t.Fatalf("component rule %s missing from pack", original.ID)
			}
			if got.Title != original.Title || got.Severity != original.Severity || got.AffectedObject != original.AffectedObject {
				t.Fatalf("component rule %s contract changed in pack", original.ID)
			}
		}
	}
}

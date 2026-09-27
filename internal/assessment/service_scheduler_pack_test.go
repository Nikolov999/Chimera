package assessment

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPhase051ServiceSchedulerPackStableContract(t *testing.T) {
	rules := ServiceSchedulerRulePack()
	if err := ValidateServiceSchedulerRulePack(rules); err != nil {
		t.Fatalf("ValidateServiceSchedulerRulePack: %v", err)
	}
	if got, want := len(rules), 34; got != want {
		t.Fatalf("rule count=%d want %d", got, want)
	}
	gotIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		gotIDs = append(gotIDs, rule.ID)
	}
	sort.Strings(gotIDs)
	if wantIDs := ServiceSchedulerRuleIDs(); !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("stable ID inventory drift\ngot:  %v\nwant: %v", gotIDs, wantIDs)
	}
}

func TestPhase051ImplementedRulesUseConsolidatedPackExactlyOnce(t *testing.T) {
	pack := make(map[string]struct{})
	for _, id := range ServiceSchedulerRuleIDs() {
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

func TestPhase051PackRejectsStableIDAndCategoryDrift(t *testing.T) {
	rules := ServiceSchedulerRulePack()

	missing := append([]Rule(nil), rules[1:]...)
	if err := ValidateServiceSchedulerRulePack(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing stable ID error=%v", err)
	}

	drifted := append([]Rule(nil), rules...)
	drifted[0].Category = "service"
	if err := ValidateServiceSchedulerRulePack(drifted); err == nil || !strings.Contains(err.Error(), "must use category") {
		t.Fatalf("category drift error=%v", err)
	}

	renumbered := append([]Rule(nil), rules...)
	renumbered[0].ID = "CHM-SCH-999"
	if err := ValidateServiceSchedulerRulePack(renumbered); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("renumbered ID error=%v", err)
	}
}

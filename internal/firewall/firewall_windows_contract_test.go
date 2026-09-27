package firewall

import (
	"strings"
	"testing"
)

func TestFix45BaseDecoderIsolatesMalformedRule(t *testing.T) {
	raw := `{
		"ProfilesObserved":true,
		"RulesObserved":true,
		"ServiceObserved":true,
		"ServiceStatus":"Running",
		"RuleCount":3,
		"InboundEnabledRuleCount":3,
		"RulesTruncated":false,
		"Profiles":[{"Name":"Private","Enabled":true}],
		"Rules":[
			{"CorrelationID":"good-1","Name":"good-1","Action":"Allow","Direction":"Inbound","Profile":"Private"},
			{"CorrelationID":"broken","Name":{"unexpected":true}},
			{"CorrelationID":"good-2","Name":"good-2","Action":"Block","Direction":"Inbound","Profile":"Public"}
		],
		"StageErrors":[]
	}`
	p, err := decodeWindowsFirewallBasePayload([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 || p.MalformedRecords != 1 {
		t.Fatalf("malformed rule should be isolated: %#v", p)
	}
	if !p.ProfilesObserved || !p.RulesObserved || p.RuleCount != 3 {
		t.Fatalf("base stage metadata was lost: %#v", p)
	}
}

func TestFix45FilterDecoderPreservesGoodRecords(t *testing.T) {
	raw := `{
		"PortComplete":true,
		"AddressComplete":true,
		"InterfaceComplete":true,
		"ApplicationComplete":true,
		"ServiceComplete":true,
		"Records":[
			{"RuleID":"one","Protocol":"TCP","LocalPort":"443"},
			{"RuleID":{"bad":true},"Protocol":"UDP"},
			{"RuleID":"two","Protocol":"UDP","LocalPort":"53"}
		],
		"StageErrors":[]
	}`
	p, err := decodeWindowsFirewallFilterPayload([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Records) != 2 || p.MalformedRecords != 1 {
		t.Fatalf("malformed filter should be isolated: %#v", p)
	}
	if p.complete() {
		t.Fatal("malformed filter record must make enrichment incomplete")
	}
}

func TestFix45StageReasonNamesExactStage(t *testing.T) {
	got := windowsFirewallStageReason([]winFirewallStageError{{Stage: "filter_port", Command: "Get-NetFirewallPortFilter", Type: "RuntimeException", Message: "boom"}})
	for _, want := range []string{"stage=FILTER_PORT", "command=Get-NetFirewallPortFilter", "type=RuntimeException", "reason=boom"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestFix45FilterCompleteRequiresEveryBulkStage(t *testing.T) {
	p := winFirewallFilterPayload{PortComplete: true, AddressComplete: true, InterfaceComplete: true, ApplicationComplete: true, ServiceComplete: true}
	if !p.complete() {
		t.Fatal("all filter stages should be complete")
	}
	p.ServiceComplete = false
	if p.complete() {
		t.Fatal("one incomplete filter stage must make enrichment incomplete")
	}
}

func TestFix48HotfixPowerShell51SingletonStageErrorDoesNotPoisonBaseDecode(t *testing.T) {
	raw := `{
		"ProfilesObserved":true,
		"RulesObserved":true,
		"ServiceObserved":true,
		"ServiceStatus":"Running",
		"RuleCount":1,
		"InboundEnabledRuleCount":1,
		"RulesTruncated":false,
		"Profiles":{"Name":"Private","Enabled":true},
		"Rules":{"CorrelationID":"rule-1","Name":"rule-1","Action":"Allow","Direction":"Inbound","Profile":"Private"},
		"StageErrors":{"Stage":"PROFILE_ACTIVITY","Command":"Get-NetConnectionProfile","Type":"RuntimeException","Message":"activity unavailable"}
	}`
	p, err := decodeWindowsFirewallBasePayload([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !p.ProfilesObserved || !p.RulesObserved || len(p.Profiles) != 1 || len(p.Rules) != 1 {
		t.Fatalf("usable base evidence was lost: %#v", p)
	}
	if len(p.StageErrors) != 1 || p.StageErrors[0].Stage != "PROFILE_ACTIVITY" {
		t.Fatalf("singleton stage error was not normalized: %#v", p.StageErrors)
	}
}

func TestFix48HotfixPowerShell51SingletonStageErrorDoesNotPoisonFilterDecode(t *testing.T) {
	raw := `{
		"PortComplete":true,
		"AddressComplete":true,
		"InterfaceComplete":true,
		"ApplicationComplete":true,
		"ServiceComplete":false,
		"Records":{"RuleID":"rule-1","Protocol":"TCP","LocalPort":"443"},
		"StageErrors":{"Stage":"FILTER_SERVICE","Command":"Get-NetFirewallServiceFilter","Type":"RuntimeException","Message":"service filter unavailable"}
	}`
	p, err := decodeWindowsFirewallFilterPayload([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Records) != 1 || len(p.StageErrors) != 1 || p.StageErrors[0].Stage != "FILTER_SERVICE" {
		t.Fatalf("PowerShell 5.1 singleton shapes were not preserved: %#v", p)
	}
	if p.complete() {
		t.Fatal("failed filter stage must keep enrichment incomplete")
	}
}

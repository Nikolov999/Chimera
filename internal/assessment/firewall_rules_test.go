package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	fwinv "github.com/Nikolov999/chimera/internal/firewall"
)

func firewallRuleIndex(provider fwinv.ProviderStatus, policies ...fwinv.Policy) Index {
	at := time.Now().UTC()
	obs := []evidence.Observation{evidence.NewObserved("firewall.provider."+provider.ID, provider, "test", at, evidence.ConfidenceExact)}
	for i, p := range policies {
		obs = append(obs, evidence.NewObserved("firewall.policy.test-"+string(rune('a'+i)), p, "test", at, evidence.ConfidenceExact))
	}
	return NewIndex(obs)
}

func firewallRuleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range FirewallRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing firewall rule %s", id)
	return Rule{}
}

func TestFirewallRulesCatalog(t *testing.T) {
	want := map[string]bool{"CHM-FW-001": false, "CHM-FW-002": false, "CHM-FW-003": false, "CHM-FW-004": false, "CHM-FW-005": false, "CHM-FW-006": false, "CHM-FW-007": false, "CHM-FW-008": false}
	for _, r := range FirewallRules() {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid firewall rule %s: %v", r.ID, err)
		}
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("unexpected firewall rule %s", r.ID)
		}
		if want[r.ID] {
			t.Fatalf("duplicate firewall rule %s", r.ID)
		}
		want[r.ID] = true
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("missing firewall rule %s", id)
		}
	}
}

func TestFirewallEnabledRule(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-001")
	for _, tc := range []struct {
		name, enabled string
		want          Status
	}{
		{"enabled", "ENABLED", StatusPass},
		{"mixed", "MIXED", StatusWarn},
		{"disabled", "DISABLED", StatusFail},
		{"unknown", "UNKNOWN", StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx := firewallRuleIndex(fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: tc.enabled, Source: "test"})
			if got := r.Evaluate(idx); got.Status != tc.want {
				t.Fatalf("status=%s want=%s observed=%s", got.Status, tc.want, got.ObservedState)
			}
		})
	}
}

func TestFirewallEnabledRuleAllowsInactiveAlternativeProvider(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("firewall.provider.nftables", fwinv.ProviderStatus{ID: "nftables", Name: "nftables", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"}, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("firewall.provider.ufw", fwinv.ProviderStatus{ID: "ufw", Name: "UFW", State: evidence.StateObserved, Enabled: "DISABLED", Source: "test"}, "test", at, evidence.ConfidenceExact),
	})
	if got := firewallRuleByID(t, "CHM-FW-001").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("inactive alternative provider must not override active provider: %#v", got)
	}
}

func TestFirewallDefaultInboundRule(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-002")
	p := fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"}
	restrictive := fwinv.Policy{Provider: "test", Scope: "global", Enabled: "ENABLED", DefaultInbound: "DROP", Source: "test", Confidence: evidence.ConfidenceExact}
	permissive := restrictive
	permissive.DefaultInbound = "ACCEPT"
	unknown := restrictive
	unknown.DefaultInbound = "UNKNOWN"
	if got := r.Evaluate(firewallRuleIndex(p, restrictive)); got.Status != StatusPass {
		t.Fatalf("restrictive status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.Evaluate(firewallRuleIndex(p, permissive)); got.Status != StatusFail {
		t.Fatalf("permissive status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.Evaluate(firewallRuleIndex(p, unknown)); got.Status != StatusUnknown {
		t.Fatalf("unknown status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestFirewallAllowAllRequiresPermissiveDefaultAndZeroKnownRules(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-003")
	p := fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"}
	allowAll := fwinv.Policy{Provider: "test", Scope: "global", Enabled: "ENABLED", DefaultInbound: "ALLOW", RuleCountKnown: true, RuleCount: 0, Source: "test", Confidence: evidence.ConfidenceExact}
	if got := r.Evaluate(firewallRuleIndex(p, allowAll)); got.Status != StatusFail {
		t.Fatalf("allow-all status=%s observed=%s", got.Status, got.ObservedState)
	}
	filtered := allowAll
	filtered.RuleCount = 7
	if got := r.Evaluate(firewallRuleIndex(p, filtered)); got.Status != StatusPass {
		t.Fatalf("non-empty ruleset status=%s observed=%s", got.Status, got.ObservedState)
	}
	unresolved := allowAll
	unresolved.RuleCountKnown = false
	if got := r.Evaluate(firewallRuleIndex(p, unresolved)); got.Status != StatusUnknown {
		t.Fatalf("unknown rule-count status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestFirewallRulesNotApplicableWhenObservedFirewallIsDisabled(t *testing.T) {
	p := fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: "DISABLED", Source: "test"}
	idx := firewallRuleIndex(p)
	for _, id := range []string{"CHM-FW-002", "CHM-FW-003"} {
		got := firewallRuleByID(t, id).Evaluate(idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable {
			t.Fatalf("%s = %#v", id, got)
		}
	}
}

func TestImplementedRulesIncludePhase059FirewallPackExactlyOnce(t *testing.T) {
	counts := map[string]int{"CHM-FW-001": 0, "CHM-FW-002": 0, "CHM-FW-003": 0, "CHM-FW-004": 0, "CHM-FW-005": 0, "CHM-FW-006": 0, "CHM-FW-007": 0, "CHM-FW-008": 0}
	for _, r := range ImplementedRules() {
		if _, ok := counts[r.ID]; ok {
			counts[r.ID]++
		}
	}
	for id, n := range counts {
		if n != 1 {
			t.Fatalf("implemented rule %s count=%d want=1", id, n)
		}
	}
}

func TestFirewallListenerCoverageRule(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-004")
	at := time.Now().UTC()
	mk := func(id, state string, c evidence.Confidence) evidence.Observation {
		v := fwinv.ListenerCoverage{ID: "fwcov-" + id, EndpointID: id, Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 443, BindingClass: "ALL_INTERFACES", State: state, Basis: "test", Source: "test", Confidence: c}
		return evidence.NewObserved("firewall.listener_coverage."+id, v, "test", at, c)
	}
	for _, tc := range []struct {
		name string
		obs  []evidence.Observation
		want Status
	}{
		{"present", []evidence.Observation{mk("a", fwinv.CoveragePresent, evidence.ConfidenceHigh)}, StatusPass},
		{"absent", []evidence.Observation{mk("a", fwinv.CoverageAbsent, evidence.ConfidenceHigh)}, StatusFail},
		{"ambiguous", []evidence.Observation{mk("a", fwinv.CoverageAmbiguous, evidence.ConfidenceMedium)}, StatusWarn},
		{"unavailable", []evidence.Observation{mk("a", fwinv.CoverageUnavailable, evidence.ConfidenceLow)}, StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Evaluate(NewIndex(tc.obs)); got.Status != tc.want {
				t.Fatalf("status=%s want=%s observed=%s", got.Status, tc.want, got.ObservedState)
			}
		})
	}
}

func firewallRestrictionIndex(rules ...fwinv.RestrictionRule) Index {
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("firewall.provider.test", fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"}, "test", at, evidence.ConfidenceExact),
	}
	for i, r := range rules {
		if r.ID == "" {
			r.ID = "r" + string(rune('a'+i))
		}
		if r.Provider == "" {
			r.Provider = "test"
		}
		if r.Direction == "" {
			r.Direction = "INBOUND"
		}
		if r.Action == "" {
			r.Action = "ALLOW"
		}
		if r.Protocol == "" {
			r.Protocol = "TCP"
		}
		if r.Enabled == "" {
			r.Enabled = "ENABLED"
		}
		if r.Source == "" {
			r.Source = "test"
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceExact
		}
		obs = append(obs, evidence.NewObserved("firewall.restriction."+r.ID, r, "test", at, r.Confidence))
	}
	return NewIndex(obs)
}

func TestFirewallBroadRemoteSourceRulePhase059(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-005")
	broad := fwinv.RestrictionRule{RemoteAddresses: []string{"ANY"}, LocalPorts: []fwinv.PortRange{{Start: 443, End: 443}}}
	if got := r.Evaluate(firewallRestrictionIndex(broad)); got.Status != StatusFail {
		t.Fatalf("broad status=%s observed=%s", got.Status, got.ObservedState)
	}
	moderate := broad
	moderate.RemoteAddresses = []string{"10.0.0.0/8"}
	if got := r.Evaluate(firewallRestrictionIndex(moderate)); got.Status != StatusWarn {
		t.Fatalf("moderate status=%s observed=%s", got.Status, got.ObservedState)
	}
	narrow := broad
	narrow.RemoteAddresses = []string{"10.20.30.0/24"}
	if got := r.Evaluate(firewallRestrictionIndex(narrow)); got.Status != StatusPass {
		t.Fatalf("narrow status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestFirewallAnyInterfaceExceptionRulePhase059(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-006")
	global := fwinv.RestrictionRule{RemoteAddresses: []string{"ANY"}, LocalPorts: []fwinv.PortRange{{Start: 8080, End: 8080}}}
	if got := r.Evaluate(firewallRestrictionIndex(global)); got.Status != StatusWarn {
		t.Fatalf("global status=%s observed=%s", got.Status, got.ObservedState)
	}
	local := global
	local.Interfaces = []string{"eth0"}
	local.RemoteAddresses = []string{"10.1.2.0/24"}
	if got := r.Evaluate(firewallRestrictionIndex(local)); got.Status != StatusPass {
		t.Fatalf("local status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestFirewallBroadManagementExceptionRulePhase059(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-007")
	broadSSH := fwinv.RestrictionRule{LocalPorts: []fwinv.PortRange{{Start: 22, End: 22}}, RemoteAddresses: []string{"ANY"}}
	if got := r.Evaluate(firewallRestrictionIndex(broadSSH)); got.Status != StatusFail {
		t.Fatalf("broad management status=%s observed=%s", got.Status, got.ObservedState)
	}
	narrowRDP := fwinv.RestrictionRule{LocalPorts: []fwinv.PortRange{{Start: 3389, End: 3389}}, RemoteAddresses: []string{"192.0.2.10/32"}}
	if got := r.Evaluate(firewallRestrictionIndex(narrowRDP)); got.Status != StatusPass {
		t.Fatalf("narrow management status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestFirewallPermissivePolicyConflictRulePhase059(t *testing.T) {
	r := firewallRuleByID(t, "CHM-FW-008")
	provider := fwinv.ProviderStatus{ID: "test", Name: "test", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"}
	restrictive := fwinv.Policy{Provider: "test", Scope: "private", Enabled: "ENABLED", DefaultInbound: "BLOCK", Source: "test", Confidence: evidence.ConfidenceExact}
	permissive := fwinv.Policy{Provider: "test", Scope: "public", Enabled: "ENABLED", DefaultInbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceExact}
	if got := r.Evaluate(firewallRuleIndex(provider, restrictive, permissive)); got.Status != StatusFail {
		t.Fatalf("conflict status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.Evaluate(firewallRuleIndex(provider, restrictive)); got.Status != StatusPass {
		t.Fatalf("restrictive status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestRemoteScopeClassPhase059(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"ANY"}, "BROAD"},
		{[]string{"0.0.0.0/0"}, "BROAD"},
		{[]string{"10.0.0.0/8"}, "MODERATE"},
		{[]string{"10.20.0.0/16"}, "NARROW"},
		{[]string{"2001:db8::/32"}, "NARROW"},
		{nil, "UNKNOWN"},
		{[]string{"LocalSubnet"}, "NARROW"},
		{[]string{"Internet"}, "BROAD"},
		{[]string{"Intranet"}, "MODERATE"},
		{[]string{"CustomProviderSet"}, "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := remoteScopeClass(tc.in); got != tc.want {
			t.Fatalf("remoteScopeClass(%v)=%s want=%s", tc.in, got, tc.want)
		}
	}
}

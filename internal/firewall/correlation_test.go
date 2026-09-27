package firewall

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
)

func testNetworkEndpoint(id, addr string, port uint16) netinv.Endpoint {
	class := "NON_LOOPBACK"
	wild := false
	loop := false
	if addr == "0.0.0.0" || addr == "::" {
		class, wild = "ALL_INTERFACES", true
	}
	if addr == "127.0.0.1" || addr == "::1" {
		class, loop = "LOOPBACK", true
	}
	return netinv.Endpoint{
		ID: id, Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: addr, LocalPort: port,
		InterfaceBinding: netinv.Binding{Class: class, IsWildcard: wild, IsLoopback: loop},
		Owner:            netinv.Owner{PID: 42, ProcessName: "svc", Executable: "/usr/bin/svc", ServiceName: "svc.service", State: "OBSERVED"},
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
}

func baseFirewall(provider ProviderStatus, policies ...Policy) Inventory {
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: time.Now().UTC()}
	addProvider(&inv, provider)
	for _, p := range policies {
		addPolicy(&inv, p)
	}
	inv.Policies = normalizePolicies(inv.Policies)
	inv.Providers = normalizeProviders(inv.Providers, inv.Policies)
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	inv.Summary = summarize(inv.Providers, inv.Policies, inv.Restrictions, nil)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func TestListenerCoverageRestrictiveDefaultWithoutExceptionsIsPresent(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "iptables", Name: "iptables", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 0},
		Policy{Provider: "iptables", Scope: "ipv4", Enabled: "ENABLED", DefaultInbound: "DROP", RuleCountKnown: true, RuleCount: 0, Source: "test", Confidence: evidence.ConfidenceExact},
	)
	net := netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-a", "0.0.0.0", 443)}}
	got := inv.WithListenerCoverage(net)
	if len(got.ListenerCoverage) != 1 || got.ListenerCoverage[0].State != CoveragePresent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerCoveragePermissiveDefaultWithoutRulesIsAbsent(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "iptables", Name: "iptables", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 0},
		Policy{Provider: "iptables", Scope: "ipv4", Enabled: "ENABLED", DefaultInbound: "ACCEPT", RuleCountKnown: true, RuleCount: 0, Source: "test", Confidence: evidence.ConfidenceExact},
	)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-a", "0.0.0.0", 8080)}})
	if got.ListenerCoverage[0].State != CoverageAbsent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

func TestListenerCoverageSourceScopedAllowIsPresent(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "iptables", Name: "iptables", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 1},
		Policy{Provider: "iptables", Scope: "ipv4", Enabled: "ENABLED", DefaultInbound: "DROP", RuleCountKnown: true, RuleCount: 1, Source: "test", Confidence: evidence.ConfidenceExact},
	)
	addRestriction(&inv, RestrictionRule{Provider: "iptables", Scope: "ipv4/INPUT", Direction: "INBOUND", Action: "ALLOW", Protocol: "TCP", LocalPorts: []PortRange{{Start: 22, End: 22}}, RemoteAddresses: []string{"10.0.0.0/8"}, Enabled: "ENABLED", Source: "test", Confidence: evidence.ConfidenceExact})
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-ssh", "0.0.0.0", 22)}})
	if got.ListenerCoverage[0].State != CoveragePresent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

func TestListenerCoverageUnrestrictedAllowIsAbsent(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "iptables", Name: "iptables", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 1},
		Policy{Provider: "iptables", Scope: "ipv4", Enabled: "ENABLED", DefaultInbound: "DROP", RuleCountKnown: true, RuleCount: 1, Source: "test", Confidence: evidence.ConfidenceExact},
	)
	addRestriction(&inv, RestrictionRule{Provider: "iptables", Scope: "ipv4/INPUT", Direction: "INBOUND", Action: "ALLOW", Protocol: "TCP", LocalPorts: []PortRange{{Start: 8080, End: 8080}}, RemoteAddresses: []string{"ANY"}, Enabled: "ENABLED", Source: "test", Confidence: evidence.ConfidenceExact})
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-web", "0.0.0.0", 8080)}})
	if got.ListenerCoverage[0].State != CoverageAbsent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

func TestListenerCoverageUnknownExceptionIsAmbiguous(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "ufw", Name: "UFW", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 4},
		Policy{Provider: "ufw", Scope: "global", Enabled: "ENABLED", DefaultInbound: "DENY", RuleCountKnown: true, RuleCount: 4, Source: "test", Confidence: evidence.ConfidenceHigh},
	)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-x", "0.0.0.0", 9090)}})
	if got.ListenerCoverage[0].State != CoverageAmbiguous {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

func TestListenerCoverageUnavailableAndLoopbackHandling(t *testing.T) {
	inv := baseFirewall(ProviderStatus{ID: "nftables", Name: "nftables", State: evidence.StateDenied, Enabled: "UNKNOWN", Source: "test", Reason: "permission denied"})
	net := netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-ext", "0.0.0.0", 8443), testNetworkEndpoint("net-loop", "127.0.0.1", 9000)}}
	got := inv.WithListenerCoverage(net)
	if len(got.ListenerCoverage) != 1 || got.ListenerCoverage[0].EndpointID != "net-ext" || got.ListenerCoverage[0].State != CoverageUnavailable {
		t.Fatalf("coverage=%#v", got.ListenerCoverage)
	}
}

func TestWindowsEffectiveRestrictiveDefaultWithCompleteRules(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 500, RestrictionCountKnown: true, RestrictionCount: 120, RestrictionSetComplete: true},
		Policy{Provider: "windows-defender-firewall", Scope: "Private", Enabled: "ENABLED", DefaultInbound: "BLOCK", DefaultOutbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh, Attributes: []Attribute{{Name: "active_state", Value: "ACTIVE"}, {Name: "active_interfaces", Value: "Ethernet"}}},
		Policy{Provider: "windows-defender-firewall", Scope: "Public", Enabled: "ENABLED", DefaultInbound: "BLOCK", DefaultOutbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh, Attributes: []Attribute{{Name: "active_state", Value: "INACTIVE"}}},
	)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-win", "0.0.0.0", 3389)}})
	if len(got.ListenerCoverage) != 1 || got.ListenerCoverage[0].State != CoveragePresent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage)
	}
}

func TestWindowsUnrelatedProfileRuleDoesNotForceAmbiguous(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 500, RestrictionCountKnown: true, RestrictionCount: 1, RestrictionSetComplete: true},
		Policy{Provider: "windows-defender-firewall", Scope: "Private", Enabled: "ENABLED", DefaultInbound: "BLOCK", DefaultOutbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh, Attributes: []Attribute{{Name: "active_state", Value: "ACTIVE"}}},
	)
	addRestriction(&inv, RestrictionRule{Provider: "windows-defender-firewall", Scope: "Public", Direction: "INBOUND", Action: "ALLOW", Protocol: "TCP", LocalPorts: []PortRange{{Start: 445, End: 445}}, RemoteAddresses: []string{"ANY"}, Enabled: "ENABLED", Source: "test", Confidence: evidence.ConfidenceHigh})
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-win-2", "0.0.0.0", 3389)}})
	if got.ListenerCoverage[0].State != CoveragePresent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

func TestWindowsMatchingInactiveProfileRuleDoesNotApply(t *testing.T) {
	inv := baseFirewall(
		ProviderStatus{ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test", RuleCountKnown: true, RuleCount: 500, RestrictionCountKnown: true, RestrictionCount: 1, RestrictionSetComplete: true},
		Policy{Provider: "windows-defender-firewall", Scope: "Private", Enabled: "ENABLED", DefaultInbound: "BLOCK", DefaultOutbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh, Attributes: []Attribute{{Name: "active_state", Value: "ACTIVE"}}},
		Policy{Provider: "windows-defender-firewall", Scope: "Public", Enabled: "ENABLED", DefaultInbound: "BLOCK", DefaultOutbound: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh, Attributes: []Attribute{{Name: "active_state", Value: "INACTIVE"}}},
	)
	addRestriction(&inv, RestrictionRule{Provider: "windows-defender-firewall", Scope: "Public", Direction: "INBOUND", Action: "ALLOW", Protocol: "TCP", LocalPorts: []PortRange{{Start: 3389, End: 3389}}, RemoteAddresses: []string{"ANY"}, Enabled: "ENABLED", Source: "test", Confidence: evidence.ConfidenceHigh})
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	got := inv.WithListenerCoverage(netinv.Inventory{Endpoints: []netinv.Endpoint{testNetworkEndpoint("net-win-3", "0.0.0.0", 3389)}})
	if got.ListenerCoverage[0].State != CoveragePresent {
		t.Fatalf("coverage=%#v", got.ListenerCoverage[0])
	}
}

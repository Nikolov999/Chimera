package assessment

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	fwinv "github.com/Nikolov999/chimera/internal/firewall"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestPhase063NetworkExposurePackStableContract(t *testing.T) {
	rules := NetworkExposureRulePack()
	if err := ValidateNetworkExposureRulePack(rules); err != nil {
		t.Fatalf("ValidateNetworkExposureRulePack: %v", err)
	}
	if got, want := len(rules), 37; got != want {
		t.Fatalf("rule count=%d want %d", got, want)
	}
	gotIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		gotIDs = append(gotIDs, rule.ID)
	}
	sort.Strings(gotIDs)
	if wantIDs := NetworkExposureRuleIDs(); !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("stable ID inventory drift\ngot:  %v\nwant: %v", gotIDs, wantIDs)
	}
}

func TestPhase063ImplementedRulesUseConsolidatedPackExactlyOnce(t *testing.T) {
	pack := make(map[string]struct{})
	for _, id := range NetworkExposureRuleIDs() {
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

func TestPhase063PackRejectsStableIDAndCategoryDrift(t *testing.T) {
	rules := NetworkExposureRulePack()

	missing := append([]Rule(nil), rules[1:]...)
	if err := ValidateNetworkExposureRulePack(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing stable ID error=%v", err)
	}

	drifted := append([]Rule(nil), rules...)
	drifted[0].Category = "network"
	if err := ValidateNetworkExposureRulePack(drifted); err == nil || !strings.Contains(err.Error(), "must use category") {
		t.Fatalf("category drift error=%v", err)
	}

	renumbered := append([]Rule(nil), rules...)
	renumbered[0].ID = "CHM-FW-999"
	if err := ValidateNetworkExposureRulePack(renumbered); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("renumbered ID error=%v", err)
	}
}

func TestPhase063SensitiveExposureRetainsProcessAndServiceContext(t *testing.T) {
	at := time.Now().UTC()
	ep := netinv.Endpoint{
		ID: "ep-ssh", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4",
		LocalAddress: "0.0.0.0", LocalPort: 22,
		InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true},
		Owner:            netinv.Owner{PID: 4242, ProcessName: "sshd", ServiceName: "ssh.service", State: "OBSERVED"},
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	svc := services.Service{
		ID: "svc-ssh", Name: "ssh.service", DisplayName: "OpenSSH server", Executable: "sshd",
		ExecutablePath: "/usr/sbin/sshd", RuntimePID: 4242,
	}
	posture := services.ServiceExposurePosture{
		Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "SSH", Role: "REMOTE_ADMIN",
		RemoteCapable: true, Activity: "RUNNING", NetworkReachability: "NOT_ASSESSED",
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("network.endpoint."+ep.ID, ep, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item."+svc.ID, svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.exposure."+svc.ID, posture, "test", at, evidence.ConfidenceHigh),
	})

	var ssh Rule
	for _, r := range NetworkExposureRulePack() {
		if r.ID == "CHM-NET-008" {
			ssh = r
			break
		}
	}
	if ssh.ID == "" {
		t.Fatal("CHM-NET-008 missing from consolidated pack")
	}
	got := ssh.Evaluate(idx)
	if got.Status != StatusWarn {
		t.Fatalf("status=%s observed=%s", got.Status, got.ObservedState)
	}
	joined := strings.Join(got.EvidenceKeys, "\n")
	if !strings.Contains(joined, "network.endpoint."+ep.ID) || !strings.Contains(joined, "service.item."+svc.ID) || !strings.Contains(joined, "service.exposure."+svc.ID) {
		t.Fatalf("process/service context not retained in evidence keys: %v", got.EvidenceKeys)
	}
}

func TestPhase063FirewallCoverageRetainsListenerOwnerContext(t *testing.T) {
	at := time.Now().UTC()
	coverage := fwinv.ListenerCoverage{
		ID: "fwcov-ssh", EndpointID: "ep-ssh", Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 22,
		BindingClass: "ALL_INTERFACES", State: fwinv.CoverageAbsent, Basis: "no matching restrictive inbound rule",
		ProcessName: "sshd", ServiceName: "ssh.service", Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("firewall.listener_coverage."+coverage.EndpointID, coverage, "test", at, evidence.ConfidenceHigh),
	})

	var rule Rule
	for _, r := range NetworkExposureRulePack() {
		if r.ID == "CHM-FW-004" {
			rule = r
			break
		}
	}
	if rule.ID == "" {
		t.Fatal("CHM-FW-004 missing from consolidated pack")
	}
	got := rule.Evaluate(idx)
	if got.Status != StatusFail {
		t.Fatalf("status=%s observed=%s", got.Status, got.ObservedState)
	}
	if !strings.Contains(strings.ToLower(got.ObservedState), "listener") {
		t.Fatalf("unexpected coverage finding text: %s", got.ObservedState)
	}
}

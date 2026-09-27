package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func phase053NetworkIndex(ep netinv.Endpoint, svc services.Service, p services.ServiceExposurePosture) Index {
	at := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	return NewIndex([]evidence.Observation{
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.inventory.summary", netinv.Summary{Endpoints: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.source.fixture", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.endpoint."+ep.ID, ep, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item."+svc.ID, svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.exposure."+svc.ID, p, "test", at, evidence.ConfidenceHigh),
	})
}

func phase053Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range NetworkRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing network rule %s", id)
	return Rule{}
}

func TestPhase053WildcardWebServerIsProfileAware(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "WEB_SERVER", Role: "WEB_SERVER", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-nginx", Name: "nginx.service", RuntimePID: 4242, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-web", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 443, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 4242, ServiceName: "nginx.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := phase053NetworkIndex(ep, svc, p)
	r := phase053Rule(t, "CHM-NET-001")
	if r.EvaluateProfile == nil {
		t.Fatal("wildcard rule must be profile-aware")
	}
	if got := r.EvaluateProfile("workstation", idx); got.Status != StatusWarn {
		t.Fatalf("workstation wildcard web server should warn: %#v", got)
	}
	if got := r.EvaluateProfile("server", idx); got.Status != StatusPass {
		t.Fatalf("server wildcard web server should fit the server role: %#v", got)
	}
	if got := r.EvaluateProfile("high-security", idx); got.Status != StatusWarn {
		t.Fatalf("high-security profile must require explicit justification: %#v", got)
	}
}

func TestPhase053PublicDeveloperInterfaceWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "JUPYTER", Role: "DEVELOPER_INTERFACE", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-jupyter", Name: "jupyter.service", RuntimePID: 2222, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-jupyter", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "8.8.8.8", LocalPort: 8888, InterfaceBinding: netinv.Binding{Class: "NON_LOOPBACK"}, Owner: netinv.Owner{PID: 2222, ServiceName: "jupyter.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := phase053NetworkIndex(ep, svc, p)
	got := phase053Rule(t, "CHM-NET-002").EvaluateProfile("developer", idx)
	if got.Status != StatusWarn || got.Applicability != Applicable {
		t.Fatalf("public developer interface should warn: %#v", got)
	}
}

func TestPhase053PrivateSSHCanFitWorkstation(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "SSH", Role: "REMOTE_ADMIN", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-ssh", Name: "ssh.service", RuntimePID: 22, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-ssh", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "192.168.1.5", LocalPort: 22, InterfaceBinding: netinv.Binding{Class: "NON_LOOPBACK"}, Owner: netinv.Owner{PID: 22, ServiceName: "ssh.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := phase053NetworkIndex(ep, svc, p)
	got := phase053Rule(t, "CHM-NET-003").EvaluateProfile("workstation", idx)
	if got.Status != StatusPass {
		t.Fatalf("specific private SSH binding should not be blanket-flagged for workstation profile: %#v", got)
	}
}

func TestPhase053UnknownServiceRoleRemainsUnknown(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	ep := netinv.Endpoint{ID: "net-unknown", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 9999, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 9999, ProcessName: "customd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.source.fixture", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.endpoint."+ep.ID, ep, "test", at, evidence.ConfidenceHigh),
	})
	got := phase053Rule(t, "CHM-NET-001").EvaluateProfile("default", idx)
	if got.Status != StatusUnknown || got.Confidence != evidence.ConfidenceLow {
		t.Fatalf("unclassified service role must remain unknown: %#v", got)
	}
}

func TestPhase055NetworkRulesAreStableAndUnique(t *testing.T) {
	want := map[string]bool{"CHM-NET-001": false, "CHM-NET-002": false, "CHM-NET-003": false, "CHM-NET-004": false, "CHM-NET-005": false, "CHM-NET-006": false, "CHM-NET-007": false, "CHM-NET-008": false, "CHM-NET-009": false, "CHM-NET-010": false, "CHM-NET-011": false, "CHM-NET-012": false, "CHM-NET-013": false, "CHM-NET-014": false, "CHM-NET-015": false, "CHM-NET-016": false, "CHM-NET-017": false, "CHM-NET-018": false, "CHM-NET-019": false, "CHM-NET-020": false, "CHM-NET-021": false, "CHM-NET-022": false, "CHM-NET-023": false, "CHM-NET-024": false, "CHM-NET-025": false, "CHM-NET-026": false, "CHM-NET-027": false, "CHM-NET-028": false, "CHM-NET-029": false}
	for _, r := range NetworkRules() {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid network rule %s: %v", r.ID, err)
		}
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("unexpected network rule %s", r.ID)
		}
		if want[r.ID] {
			t.Fatalf("duplicate network rule %s", r.ID)
		}
		want[r.ID] = true
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("missing network rule %s", id)
		}
	}
}

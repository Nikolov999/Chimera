package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func phase054Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range SensitiveServiceExposureRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing rule %s", id)
	return Rule{}
}

func phase054NetworkOnlyIndex(ep netinv.Endpoint) Index {
	at := time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	return NewIndex([]evidence.Observation{
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.inventory.summary", netinv.Summary{Endpoints: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.source.fixture", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.endpoint."+ep.ID, ep, "test", at, ep.Confidence),
	})
}

func TestPhase054DatabaseExternalBindWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "DATABASE", Role: "DATABASE", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-postgres", Name: "postgresql.service", RuntimePID: 5432, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-db", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 5432, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 5432, ProcessName: "postgres", ServiceName: "postgresql.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase054Rule(t, "CHM-NET-004").Evaluate(phase053NetworkIndex(ep, svc, p))
	if got.Status != StatusWarn || got.Confidence != evidence.ConfidenceHigh || got.Applicability != Applicable {
		t.Fatalf("external database listener should warn with high confidence: %#v", got)
	}
}

func TestPhase054DatabaseLoopbackPasses(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "DATABASE", Role: "DATABASE", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-postgres", Name: "postgresql.service", RuntimePID: 5432, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-db-local", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "127.0.0.1", LocalPort: 5432, InterfaceBinding: netinv.Binding{Class: "LOOPBACK", IsLoopback: true}, Owner: netinv.Owner{PID: 5432, ProcessName: "postgres", ServiceName: "postgresql.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase054Rule(t, "CHM-NET-004").Evaluate(phase053NetworkIndex(ep, svc, p))
	if got.Status != StatusPass {
		t.Fatalf("loopback database listener should pass: %#v", got)
	}
}

func TestPhase054SSHExternalBindWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "SSH", Role: "REMOTE_ADMIN", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-ssh", Name: "ssh.service", RuntimePID: 22, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-ssh", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "192.168.1.20", LocalPort: 22, InterfaceBinding: netinv.Binding{Class: "NON_LOOPBACK"}, Owner: netinv.Owner{PID: 22, ProcessName: "sshd", ServiceName: "ssh.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase054Rule(t, "CHM-NET-008").Evaluate(phase053NetworkIndex(ep, svc, p)); got.Status != StatusWarn {
		t.Fatalf("external SSH listener should warn: %#v", got)
	}
}

func TestPhase054DockerAPIMatchesOwnerAndPort(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-docker", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 2375, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 444, ProcessName: "dockerd", Executable: "/usr/bin/dockerd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase054Rule(t, "CHM-NET-009").Evaluate(phase054NetworkOnlyIndex(ep))
	if got.Status != StatusWarn || got.Confidence != evidence.ConfidenceMedium {
		t.Fatalf("Docker API owner+port match should warn at medium confidence: %#v", got)
	}
}

func TestPhase054DoesNotTreatPortAloneAsDockerAPI(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-custom", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 2375, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 555, ProcessName: "customd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase054Rule(t, "CHM-NET-009").Evaluate(phase054NetworkOnlyIndex(ep)); got.Status != StatusPass {
		t.Fatalf("port alone must not identify Docker API: %#v", got)
	}
}

func TestPhase054OrchestrationAPIWarns(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-kube", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "10.0.0.10", LocalPort: 6443, InterfaceBinding: netinv.Binding{Class: "NON_LOOPBACK"}, Owner: netinv.Owner{PID: 600, ProcessName: "kube-apiserver", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase054Rule(t, "CHM-NET-010").Evaluate(phase054NetworkOnlyIndex(ep)); got.Status != StatusWarn {
		t.Fatalf("orchestration API should warn: %#v", got)
	}
}

func TestPhase054DebugPortRequiresMatchingOwner(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-node-debug", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 9229, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 700, ProcessName: "node", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase054Rule(t, "CHM-NET-011").Evaluate(phase054NetworkOnlyIndex(ep)); got.Status != StatusWarn {
		t.Fatalf("Node inspector owner+port should warn: %#v", got)
	}
}

func TestPhase054JupyterDevelopmentInterfaceWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "JUPYTER", Role: "DEVELOPER_INTERFACE", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-jupyter", Name: "jupyter.service", RuntimePID: 8888, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-jupyter", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV6", LocalAddress: "::", LocalPort: 8888, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 8888, ProcessName: "jupyter", ServiceName: "jupyter.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase054Rule(t, "CHM-NET-012").Evaluate(phase053NetworkIndex(ep, svc, p)); got.Status != StatusWarn {
		t.Fatalf("Jupyter development interface should warn: %#v", got)
	}
}

func TestPhase054SensitiveRuleIDsAreStableAndUnique(t *testing.T) {
	want := map[string]bool{
		"CHM-NET-004": false, "CHM-NET-005": false, "CHM-NET-006": false,
		"CHM-NET-007": false, "CHM-NET-008": false, "CHM-NET-009": false,
		"CHM-NET-010": false, "CHM-NET-011": false, "CHM-NET-012": false,
	}
	for _, r := range SensitiveServiceExposureRules() {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %s: %v", r.ID, err)
		}
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("unexpected rule %s", r.ID)
		}
		if want[r.ID] {
			t.Fatalf("duplicate rule %s", r.ID)
		}
		want[r.ID] = true
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("missing rule %s", id)
		}
	}
}

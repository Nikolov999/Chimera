package remotemgmt

import (
	"context"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestDeriveRemoteManagementSurfaceCorrelatesListenerAndFirewall(t *testing.T) {
	svc := services.Service{ID: "svc-ssh", Name: "sshd.service", Manager: "systemd", Account: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "PRIVILEGED", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Exposure: &services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "SSH", Role: "REMOTE_ADMIN", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}}
	ep := netinv.Endpoint{ID: "net-ssh", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 22, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 1, ProcessName: "sshd", ServiceName: "sshd.service", State: "OBSERVED", Source: "test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	cov := firewall.ListenerCoverage{ID: "fwc-1", EndpointID: ep.ID, Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 22, BindingClass: "ALL_INTERFACES", State: firewall.CoverageAbsent, Basis: "test", Source: "test", Confidence: evidence.ConfidenceHigh}
	report := Report{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: time.Now().UTC(), SSHSecurity: SSHSecurity{Schema: sshSecuritySchemaVersion, State: sshStateNotApplicable}, SMBSecurity: SMBSecurity{Schema: smbSecuritySchemaVersion, State: smbStateNotApplicable, Platform: "linux"}}
	report.Surfaces = deriveSurfaces(services.Inventory{Services: []services.Service{svc}}, netinv.Inventory{Endpoints: []netinv.Endpoint{ep}}, firewall.Inventory{ListenerCoverage: []firewall.ListenerCoverage{cov}}, nil)
	report.Controls = nil
	report.Summary = summarize(report.Surfaces, nil)
	report.Evidence = buildEvidence(report)
	if len(report.Surfaces) != 1 {
		t.Fatalf("surfaces=%d", len(report.Surfaces))
	}
	s := report.Surfaces[0]
	if s.Family != "SSH" || s.ConfiguredState != "ENABLED" || s.RuntimeState != "ACTIVE" || s.BindingState != "ALL_INTERFACES" || s.FirewallCoverage != firewall.CoverageAbsent {
		t.Fatalf("surface=%#v", s)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestCollectContract(t *testing.T) {
	r := Collect(context.Background(), services.Inventory{}, netinv.Inventory{}, firewall.Inventory{})
	if r.Schema != SchemaVersion || r.CollectorVersion != CollectorVersion {
		t.Fatalf("identity=%#v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

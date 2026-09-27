package assessment

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func phase055Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range LegacyProtocolExposureRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing rule %s", id)
	return Rule{}
}

func TestPhase055TelnetExternalBindWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "TELNET", Role: "REMOTE_ADMIN", RemoteCapable: true, Legacy: true, Deprecated: true, CleartextCapable: true, InsecureByDesign: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-telnet", Name: "telnet.service", RuntimePID: 2323, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-telnet", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 23, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 2323, ProcessName: "telnetd", ServiceName: "telnet.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase055Rule(t, "CHM-NET-013").Evaluate(phase053NetworkIndex(ep, svc, p))
	if got.Status != StatusWarn || got.Confidence != evidence.ConfidenceHigh || got.Applicability != Applicable {
		t.Fatalf("external Telnet listener should warn with high confidence: %#v", got)
	}
}

func TestPhase055RSHLoopbackPasses(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "RSH_FAMILY", Role: "REMOTE_ADMIN", RemoteCapable: true, Legacy: true, Deprecated: true, CleartextCapable: true, InsecureByDesign: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-rsh", Name: "rsh.service", RuntimePID: 1514, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-rsh", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "127.0.0.1", LocalPort: 514, InterfaceBinding: netinv.Binding{Class: "LOOPBACK", IsLoopback: true}, Owner: netinv.Owner{PID: 1514, ProcessName: "rshd", ServiceName: "rsh.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase055Rule(t, "CHM-NET-013").Evaluate(phase053NetworkIndex(ep, svc, p)); got.Status != StatusPass {
		t.Fatalf("loopback-only rsh-family listener should pass exposure constraint: %#v", got)
	}
}

func TestPhase055FTPExternalBindWarnsWithoutClaimingCleartextUse(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "FTP", Role: "FILE_TRANSFER", RemoteCapable: true, Legacy: true, CleartextCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-vsftpd", Name: "vsftpd.service", RuntimePID: 2121, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-ftp", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "192.168.56.5", LocalPort: 21, InterfaceBinding: netinv.Binding{Class: "NON_LOOPBACK"}, Owner: netinv.Owner{PID: 2121, ProcessName: "vsftpd", ServiceName: "vsftpd.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase055Rule(t, "CHM-NET-014").Evaluate(phase053NetworkIndex(ep, svc, p))
	if got.Status != StatusWarn {
		t.Fatalf("external FTP-class listener should warn: %#v", got)
	}
	if got.ObservedState == "" {
		t.Fatal("must explain its observational limitation")
	}
}

func TestPhase055TFTPExternalOwnerIdentityWarnsAtMediumConfidence(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-tftp", Protocol: "UDP", TransportState: "BOUND", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 69, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 6069, ProcessName: "tftpd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase055Rule(t, "CHM-NET-014").Evaluate(phase054NetworkOnlyIndex(ep))
	if got.Status != StatusWarn || got.Confidence != evidence.ConfidenceMedium {
		t.Fatalf("owner-identified TFTP listener should warn at medium confidence: %#v", got)
	}
}

func TestPhase055PortAloneDoesNotIdentifyLegacyProtocol(t *testing.T) {
	ep := netinv.Endpoint{ID: "net-custom23", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 23, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 2300, ProcessName: "customd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase055Rule(t, "CHM-NET-013").Evaluate(phase054NetworkOnlyIndex(ep)); got.Status != StatusPass {
		t.Fatalf("port number alone must not identify Telnet: %#v", got)
	}
}

func TestPhase055LegacyInformationServiceWarns(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "FINGER", Role: "LEGACY_INFORMATION", RemoteCapable: true, Legacy: true, Deprecated: true, CleartextCapable: true, InsecureByDesign: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-finger", Name: "finger.service", RuntimePID: 7979, Exposure: &p}
	ep := netinv.Endpoint{ID: "net-finger", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV6", LocalAddress: "::", LocalPort: 79, InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{PID: 7979, ProcessName: "fingerd", ServiceName: "finger.service", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	if got := phase055Rule(t, "CHM-NET-015").Evaluate(phase053NetworkIndex(ep, svc, p)); got.Status != StatusWarn {
		t.Fatalf("externally bound finger service should warn: %#v", got)
	}
}

func TestPhase055LegacyProtocolRuleIDsAreStableAndUnique(t *testing.T) {
	want := map[string]bool{"CHM-NET-013": false, "CHM-NET-014": false, "CHM-NET-015": false}
	for _, r := range LegacyProtocolExposureRules() {
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

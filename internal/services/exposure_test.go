package services

import "testing"

func TestPhase048ClassifiesLegacyRemoteServicesWithoutClaimingReachability(t *testing.T) {
	svc := Service{Name: "telnet.service", Manager: "systemd", StartMode: "enabled", RuntimeState: "running"}
	p := classifyOneServiceExposure(svc)
	if p.State != "CLASSIFIED" || p.Family != "TELNET" || p.Role != "REMOTE_ADMIN" || !p.RemoteCapable || !p.Legacy || !p.Deprecated || !p.CleartextCapable || !p.InsecureByDesign {
		t.Fatalf("unexpected telnet classification: %#v", p)
	}
	if p.Activity != "ACTIVE" || p.NetworkReachability != "NOT_ASSESSED" {
		t.Fatalf("phase 048 must classify activity without asserting network reachability: %#v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid exposure posture rejected: %v", err)
	}
}

func TestPhase048ClassifiesFTPConservatively(t *testing.T) {
	p := classifyOneServiceExposure(Service{Name: "vsftpd.service", StartMode: "enabled", RuntimeState: "stopped"})
	if p.Family != "FTP" || !p.RemoteCapable || !p.Legacy || !p.CleartextCapable || p.InsecureByDesign {
		t.Fatalf("FTP should be cleartext-capable without asserting insecure transport is active: %#v", p)
	}
	if p.Activity != "ENABLED_INACTIVE" {
		t.Fatalf("unexpected activity: %s", p.Activity)
	}
}

func TestPhase048UsesExecutableIdentityWhenServiceNameIsGeneric(t *testing.T) {
	p := classifyOneServiceExposure(Service{Name: "vendor-daemon", ExecutablePath: `C:\\Windows\\System32\\tlntsvr.exe`, RuntimeState: "running"})
	if p.Family != "TELNET" {
		t.Fatalf("expected executable identity to classify telnet family: %#v", p)
	}
}

func TestPhase048LeavesUnknownServicesUnclassified(t *testing.T) {
	p := classifyOneServiceExposure(Service{Name: "vendor-agent.service", StartMode: "enabled", RuntimeState: "running"})
	if p.State != "UNCLASSIFIED" || p.RemoteCapable || p.Family != "UNKNOWN" || p.NetworkReachability != "NOT_ASSESSED" {
		t.Fatalf("unknown service must not be guessed into a remote class: %#v", p)
	}
}

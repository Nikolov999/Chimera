package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

func phase048ExposureIndex(svc services.Service, p services.ServiceExposurePosture) Index {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	return NewIndex([]evidence.Observation{
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", services.Summary{Services: 1, ExposureClassified: 1, RemoteCapable: 1, ActiveRemoteCapable: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.source.linux_systemd", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item."+svc.ID, svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.exposure."+svc.ID, p, "test", at, evidence.ConfidenceHigh),
	})
}

func TestPhase048LegacyInsecureServiceRuleFailsForActiveTelnet(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "TELNET", Role: "REMOTE_ADMIN", RemoteCapable: true, Legacy: true, Deprecated: true, CleartextCapable: true, InsecureByDesign: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-telnet", Name: "telnet.service", Manager: "systemd", Account: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "ROOT", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Exposure: &p}
	idx := phase048ExposureIndex(svc, p)
	var rule Rule
	for _, r := range ServiceExposureRules() {
		if r.ID == "CHM-SVC-027" {
			rule = r
		}
	}
	got := rule.Evaluate(idx)
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("expected active telnet to fail legacy/insecure rule: %#v", got)
	}
}

func TestPhase048FTPWarnsWithoutClaimingCleartextIsEnabled(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "FTP", Role: "FILE_TRANSFER", RemoteCapable: true, Legacy: true, CleartextCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-ftp", Name: "vsftpd.service", Manager: "systemd", Account: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "ROOT", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Exposure: &p}
	idx := phase048ExposureIndex(svc, p)
	var rule Rule
	for _, r := range ServiceExposureRules() {
		if r.ID == "CHM-SVC-028" {
			rule = r
		}
	}
	got := rule.Evaluate(idx)
	if got.Status != StatusWarn || got.Applicability != Applicable {
		t.Fatalf("expected FTP-class capability warning: %#v", got)
	}
	if got.ObservedState == "" {
		t.Fatal("expected conservative observed-state explanation")
	}
}

func TestPhase048ProfileAwareRemoteServiceRule(t *testing.T) {
	p := services.ServiceExposurePosture{Schema: services.ServiceExposureSchemaVersion, State: "CLASSIFIED", Family: "WEB_SERVER", Role: "WEB_SERVER", RemoteCapable: true, Activity: "ACTIVE", NetworkReachability: "NOT_ASSESSED"}
	svc := services.Service{ID: "svc-nginx", Name: "nginx.service", Manager: "systemd", Account: "www-data", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "SERVICE_ACCOUNT", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Exposure: &p}
	idx := phase048ExposureIndex(svc, p)
	var rule Rule
	for _, r := range ServiceExposureRules() {
		if r.ID == "CHM-SVC-029" {
			rule = r
		}
	}
	if rule.EvaluateProfile == nil {
		t.Fatal("profile-fit rule must expose profile-aware evaluation")
	}
	if got := rule.EvaluateProfile("workstation", idx); got.Status != StatusWarn {
		t.Fatalf("workstation should flag active web-server role: %#v", got)
	}
	if got := rule.EvaluateProfile("server", idx); got.Status != StatusPass {
		t.Fatalf("server profile should accept web-server role: %#v", got)
	}
	if got := rule.EvaluateProfile("high-security", idx); got.Status != StatusWarn {
		t.Fatalf("high-security profile should require justification for remote role: %#v", got)
	}
}

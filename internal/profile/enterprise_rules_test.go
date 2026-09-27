package profile

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestPhase110EnterpriseExpectedServicePolicy(t *testing.T) {
	p := Descriptor{
		Schema: SchemaVersion, Name: "prod", Description: "prod", Custom: true, Extends: "server", BehaviorProfile: "server", DefaultApplicable: true,
		ServicePolicyMode: ServiceModeAllowlist,
		ExpectedServices:  []ExpectedService{{Name: "nginx", State: "RUNNING", Required: true}},
		AllowedExceptions: []AllowedException{{Kind: "service", Match: "metrics-*", Reason: "approved telemetry"}},
	}
	rules := enterprisePolicyRules(p)
	if len(rules) != 1 || rules[0].ID != "CHM-ENT-001" {
		t.Fatalf("unexpected enterprise service rules: %#v", rules)
	}
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("service.inventory.count", 2, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.item.nginx", services.Service{Name: "nginx", Manager: "systemd", RuntimeState: "running", StartMode: "enabled"}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.metrics", services.Service{Name: "metrics-agent", Manager: "systemd", RuntimeState: "running", StartMode: "enabled"}, "test", at, evidence.ConfidenceHigh),
	}
	got := rules[0].Evaluate(assessment.NewIndex(obs))
	if got.Status != assessment.StatusPass {
		t.Fatalf("expected service policy pass, got %#v", got)
	}
	obs = append(obs, evidence.NewObserved("service.item.telnet", services.Service{Name: "telnet", Manager: "systemd", RuntimeState: "running", StartMode: "enabled"}, "test", at, evidence.ConfidenceHigh))
	got = rules[0].Evaluate(assessment.NewIndex(obs))
	if got.Status != assessment.StatusFail {
		t.Fatalf("expected unapproved service to fail, got %#v", got)
	}
}

func TestPhase110EnterpriseExpectedPortPolicy(t *testing.T) {
	p := Descriptor{
		Schema: SchemaVersion, Name: "prod", Description: "prod", Custom: true, Extends: "server", BehaviorProfile: "server", DefaultApplicable: true,
		PortPolicyMode:    PortModeAllowlist,
		ExpectedPorts:     []ExpectedPort{{Protocol: "TCP", Port: 443, Binding: "EXTERNAL", Required: true}},
		AllowedExceptions: []AllowedException{{Kind: "port", Match: "tcp/9100", Reason: "approved local exporter"}},
	}
	rules := enterprisePolicyRules(p)
	if len(rules) != 1 || rules[0].ID != "CHM-ENT-002" {
		t.Fatalf("unexpected enterprise port rules: %#v", rules)
	}
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("network.inventory.count", 2, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.endpoint.https", netinv.Endpoint{Protocol: "TCP", LocalPort: 443, LocalAddress: "0.0.0.0", InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES"}}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.endpoint.metrics", netinv.Endpoint{Protocol: "TCP", LocalPort: 9100, LocalAddress: "127.0.0.1", InterfaceBinding: netinv.Binding{Class: "LOOPBACK"}}, "test", at, evidence.ConfidenceHigh),
	}
	got := rules[0].Evaluate(assessment.NewIndex(obs))
	if got.Status != assessment.StatusPass {
		t.Fatalf("expected port policy pass, got %#v", got)
	}
	obs = append(obs, evidence.NewObserved("network.endpoint.debug", netinv.Endpoint{Protocol: "TCP", LocalPort: 9222, LocalAddress: "0.0.0.0", InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES"}}, "test", at, evidence.ConfidenceHigh))
	got = rules[0].Evaluate(assessment.NewIndex(obs))
	if got.Status != assessment.StatusFail {
		t.Fatalf("expected unapproved port to fail, got %#v", got)
	}
}

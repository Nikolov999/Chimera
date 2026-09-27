package prioritization

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/vulnerability"
)

func testFinding(id, rule string, severity assessment.Severity, status assessment.Status, object string, keys ...string) assessment.Finding {
	now := time.Unix(1700000000, 0).UTC()
	refs := make([]assessment.EvidenceRef, 0, len(keys))
	for _, key := range keys {
		refs = append(refs, assessment.EvidenceRef{Key: key, State: evidence.StateObserved, Value: true, Source: "test", CollectedAt: now, Confidence: evidence.ConfidenceHigh})
	}
	return assessment.Finding{
		ID: id, RuleID: rule, Title: rule, Status: status, Severity: severity,
		Confidence: evidence.ConfidenceHigh, Category: "correlation", Platform: "linux",
		AffectedObject: object, ObservedState: "weak", ExpectedState: "hardened", Evidence: refs,
		Risk: "risk", Remediation: "fix", CollectionSource: "test", FirstObserved: now,
		AssessmentTimestamp: now, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
}

func TestFindingPrioritySeparatesSeverityFromContext(t *testing.T) {
	plain := testFinding("F1", "CHM-TEST-001", assessment.SeverityHigh, assessment.StatusFail, "service.test", "service.item.demo")
	compound := testFinding("F2", "CHM-COR-001", assessment.SeverityHigh, assessment.StatusFail, "correlation.service.privileged_writable_external", "service.item.demo", "process.privilege.demo", "network.endpoint.demo", "service.path_integrity.demo")

	got := Compute([]assessment.Finding{plain, compound}, nil)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("finding priorities=%d", len(got.Findings))
	}
	if got.Findings[0].FindingID != "F2" || got.Findings[0].Score <= got.Findings[1].Score {
		t.Fatalf("compound context did not outrank plain finding: %#v", got.Findings)
	}
	if got.Findings[0].Severity != assessment.SeverityHigh {
		t.Fatalf("raw severity was rewritten: %#v", got.Findings[0])
	}
}

func TestSuppressedFindingKeepsScoreButLosesActionableRank(t *testing.T) {
	f := testFinding("F1", "CHM-COR-002", assessment.SeverityHigh, assessment.StatusFail, "correlation.process.elevated_weak_path_external", "process.item.10", "process.privilege.10", "network.endpoint.10")
	f.Suppression = assessment.SuppressionSuppressed
	f.Suppressions = []assessment.SuppressionRecord{{ID: "SUP-1"}}
	got := Compute([]assessment.Finding{f}, nil)
	p := got.Findings[0]
	if p.Score == 0 || p.Actionable || p.Rank != 0 || !p.Suppressed {
		t.Fatalf("unexpected suppressed priority: %#v", p)
	}
}

func TestVulnerabilityReachabilityRaisesPriorityDeterministically(t *testing.T) {
	reach := &vulnerability.ReachabilityResult{Contexts: []vulnerability.ReachabilityContext{
		{CorrelationID: "C1", VulnerabilityID: "CVE-2026-0001", CandidateRef: "pkg:a", Running: vulnerability.ContextAbsent, ServiceBacked: vulnerability.ContextAbsent, Listening: vulnerability.ContextAbsent, Privileged: vulnerability.ContextAbsent, Tier: "INSTALLED_ONLY"},
		{CorrelationID: "C2", VulnerabilityID: "CVE-2026-0002", CandidateRef: "pkg:b", Running: vulnerability.ContextPresent, ServiceBacked: vulnerability.ContextPresent, Listening: vulnerability.ContextPresent, Privileged: vulnerability.ContextPresent, Tier: "LISTENING_PRIVILEGED"},
	}}
	got := Compute(nil, reach)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Vulnerabilities[0].CorrelationID != "C2" || got.Vulnerabilities[0].Score <= got.Vulnerabilities[1].Score {
		t.Fatalf("runtime/exposure context did not affect priority: %#v", got.Vulnerabilities)
	}
	if got.Vulnerabilities[0].Rank != 1 || got.Vulnerabilities[1].Rank != 2 {
		t.Fatalf("unexpected vulnerability ranks: %#v", got.Vulnerabilities)
	}
}

func TestPassAndNotApplicableDoNotReceivePriority(t *testing.T) {
	pass := testFinding("F1", "CHM-TEST-001", assessment.SeverityCritical, assessment.StatusPass, "kernel.test", "kernel.hardening")
	na := testFinding("F2", "CHM-TEST-002", assessment.SeverityCritical, assessment.StatusFail, "kernel.test2", "kernel.hardening")
	na.Applicability = assessment.NotApplicable
	got := Compute([]assessment.Finding{pass, na}, nil)
	for _, p := range got.Findings {
		if p.Score != 0 || p.Band != BandNone || p.Rank != 0 || p.Actionable {
			t.Fatalf("inactive finding received priority: %#v", p)
		}
	}
}

func TestVulnerabilityLoopbackListenerIsNotScoredAsNetworkExposure(t *testing.T) {
	reach := &vulnerability.ReachabilityResult{Contexts: []vulnerability.ReachabilityContext{{
		CorrelationID: "C-loop", VulnerabilityID: "CVE-2026-1000", CandidateRef: "pkg:loop",
		Running: vulnerability.ContextPresent, ServiceBacked: vulnerability.ContextPresent,
		Listening: vulnerability.ContextPresent, Privileged: vulnerability.ContextAbsent, Tier: "LISTENING",
		Listeners: []vulnerability.ListenerContext{{Protocol: "tcp", LocalAddress: "127.0.0.1", Port: 8080, PID: 42, Exposure: "LOOPBACK"}},
	}}}
	got := Compute(nil, reach)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	p := got.Vulnerabilities[0]
	if hasFactor(p.Factors, "network_exposure") {
		t.Fatalf("loopback-only listener received network exposure points: %#v", p)
	}
	if !hasFactor(p.Factors, "local_listener_presence") {
		t.Fatalf("loopback listener context was not retained: %#v", p)
	}
	if p.Score != 54 { // 35 affected + 12 running + 7 service-backed
		t.Fatalf("loopback priority score=%d want 54: %#v", p.Score, p)
	}
}

func TestVulnerabilityExternalListenerWithoutFirewallRestrictionGetsControlWeakness(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	coverage := firewall.ListenerCoverage{
		ID: "fwc-1", EndpointID: "net-1", Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 8443,
		BindingClass: "ALL_INTERFACES", State: firewall.CoverageAbsent, Basis: "fixture absent",
		Source: "test firewall correlation", Confidence: evidence.ConfidenceExact,
	}
	fwFinding := testFinding("F-fw", "CHM-FW-004", assessment.SeverityHigh, assessment.StatusFail, "firewall.listener_coverage", "firewall.listener_coverage.net-1")
	fwFinding.Evidence[0].Value = coverage
	fwFinding.Evidence[0].CollectedAt = at

	reach := &vulnerability.ReachabilityResult{Contexts: []vulnerability.ReachabilityContext{{
		CorrelationID: "C-ext", VulnerabilityID: "CVE-2026-1001", CandidateRef: "pkg:ext",
		Running: vulnerability.ContextPresent, ServiceBacked: vulnerability.ContextPresent,
		Listening: vulnerability.ContextPresent, Privileged: vulnerability.ContextPresent, Tier: "PRIVILEGED_LISTENER",
		Listeners: []vulnerability.ListenerContext{{Protocol: "tcp", LocalAddress: "0.0.0.0", Port: 8443, PID: 43, Exposure: "ALL_INTERFACES"}},
	}}}
	got := Compute([]assessment.Finding{fwFinding}, reach)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	p := got.Vulnerabilities[0]
	if !hasFactor(p.Factors, "network_exposure") || !hasFactor(p.Factors, "firewall_control_weakness") {
		t.Fatalf("missing exposure/firewall factors: %#v", p)
	}
	if p.Score != 100 || p.Band != BandCritical {
		t.Fatalf("external unprotected privileged vulnerability priority=%#v", p)
	}
}

func TestVulnerabilityExternalListenerWithFirewallRestrictionDoesNotGetWeaknessPoints(t *testing.T) {
	coverage := firewall.ListenerCoverage{
		ID: "fwc-2", EndpointID: "net-2", Protocol: "TCP", LocalAddress: "192.0.2.10", LocalPort: 443,
		BindingClass: "NON_LOOPBACK", State: firewall.CoveragePresent, Basis: "fixture present",
		Source: "test firewall correlation", Confidence: evidence.ConfidenceHigh,
	}
	fwFinding := testFinding("F-fw-present", "CHM-FW-004", assessment.SeverityHigh, assessment.StatusPass, "firewall.listener_coverage", "firewall.listener_coverage.net-2")
	fwFinding.Evidence[0].Value = coverage

	reach := &vulnerability.ReachabilityResult{Contexts: []vulnerability.ReachabilityContext{{
		CorrelationID: "C-present", VulnerabilityID: "CVE-2026-1002", CandidateRef: "pkg:present",
		Running: vulnerability.ContextPresent, ServiceBacked: vulnerability.ContextPresent,
		Listening: vulnerability.ContextPresent, Privileged: vulnerability.ContextAbsent, Tier: "LISTENING",
		Listeners: []vulnerability.ListenerContext{{Protocol: "tcp", LocalAddress: "192.0.2.10", Port: 443, PID: 44, Exposure: "INTERFACE_BOUND"}},
	}}}
	got := Compute([]assessment.Finding{fwFinding}, reach)
	p := got.Vulnerabilities[0]
	if !hasFactor(p.Factors, "network_exposure") {
		t.Fatalf("non-loopback listener did not receive exposure context: %#v", p)
	}
	if hasFactor(p.Factors, "firewall_control_weakness") {
		t.Fatalf("protected listener received firewall weakness points: %#v", p)
	}
	if p.Score != 74 { // 35 affected + 12 running + 7 service-backed + 20 external
		t.Fatalf("protected external priority score=%d want 74: %#v", p.Score, p)
	}
}

func hasFactor(factors []Factor, name string) bool {
	for _, f := range factors {
		if f.Name == name {
			return true
		}
	}
	return false
}

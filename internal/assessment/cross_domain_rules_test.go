package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/processes"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestPhase107CrossDomainPackContract(t *testing.T) {
	rules := CrossDomainCorrelationRules()
	if err := ValidateCrossDomainCorrelationRulePack(rules); err != nil {
		t.Fatal(err)
	}
	if CrossDomainCorrelationPackVersion != "chimera.rules/cross-domain-v1-phase107" {
		t.Fatalf("pack version=%q", CrossDomainCorrelationPackVersion)
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("rule set version=%q", RuleSetVersion)
	}
	seen := map[string]bool{}
	for _, r := range ImplementedRules() {
		seen[r.ID] = true
	}
	for _, id := range crossDomainRuleIDs {
		if !seen[id] {
			t.Fatalf("implemented catalog missing %s", id)
		}
	}
}

func TestPhase107PrivilegedWritableServiceExternalCorrelation(t *testing.T) {
	at := time.Now().UTC()
	obs := phase107Fixture(at, false)
	r := mustRule(t, CrossDomainCorrelationRules(), "CHM-COR-001")
	got := r.Evaluate(NewIndex(obs))
	if got.Status != StatusFail || got.Applicability != Applicable || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
	want := []string{"service.item.svc-web", "service.path_integrity.svc-web", "process.item.proc-web", "process.permission.proc-web", "process.privilege.proc-web", "account.item.acct-root", "filesystem.executable.fs-web", "network.endpoint.net-web"}
	for _, key := range want {
		if !containsCorrelationString(got.EvidenceKeys, key) {
			t.Fatalf("missing correlated evidence key %s in %#v", key, got.EvidenceKeys)
		}
	}
}

func TestPhase107LoopbackDoesNotTriggerExternalServiceCorrelation(t *testing.T) {
	at := time.Now().UTC()
	obs := phase107Fixture(at, true)
	r := mustRule(t, CrossDomainCorrelationRules(), "CHM-COR-001")
	got := r.Evaluate(NewIndex(obs))
	if got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("unexpected loopback evaluation: %#v", got)
	}
}

func TestPhase107ElevatedWeakProcessExternalCorrelation(t *testing.T) {
	at := time.Now().UTC()
	obs := phase107Fixture(at, false)
	r := mustRule(t, CrossDomainCorrelationRules(), "CHM-COR-002")
	got := r.Evaluate(NewIndex(obs))
	if got.Status != StatusFail || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected process correlation: %#v", got)
	}
}

func TestPhase107PrivilegedInteractiveServiceIdentityCorrelation(t *testing.T) {
	at := time.Now().UTC()
	obs := phase107Fixture(at, false)
	r := mustRule(t, CrossDomainCorrelationRules(), "CHM-COR-003")
	got := r.Evaluate(NewIndex(obs))
	if got.Status != StatusWarn || got.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("unexpected identity correlation: %#v", got)
	}
	if !containsCorrelationString(got.EvidenceKeys, "account.item.acct-root") || !containsCorrelationString(got.EvidenceKeys, "network.endpoint.net-web") {
		t.Fatalf("identity/network evidence was not retained: %#v", got.EvidenceKeys)
	}
}

func TestPhase107CorrelationFailsClosedWhenInventoryMissing(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("service.inventory.count", 0, "test", at, evidence.ConfidenceExact)})
	got := mustRule(t, CrossDomainCorrelationRules(), "CHM-COR-001").Evaluate(idx)
	if got.Status != StatusUnknown || got.Applicability != Undetermined {
		t.Fatalf("unexpected missing-inventory evaluation: %#v", got)
	}
}

func phase107Fixture(at time.Time, loopback bool) []evidence.Observation {
	svc := services.Service{
		ID: "svc-web", Name: "websvc", Manager: "systemd", Executable: "/opt/acme/websvc", ExecutablePath: "/opt/acme/websvc",
		Account: "root", StartMode: "ENABLED", RuntimePID: 4242, RuntimeState: "RUNNING", PrivilegeContext: "ROOT",
		ConfigurationSource: "/etc/systemd/system/websvc.service", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	path := services.ServicePathIntegrity{
		State: "COMPLETE", Privileged: true, PrivilegeBasis: "ROOT",
		Executable:             services.PathPosture{State: "OBSERVED", Path: "/opt/acme/websvc", LowerPrivilegeWritable: true, Principals: []string{"users"}},
		ExecutableDirectory:    services.PathPosture{State: "OBSERVED", Path: "/opt/acme"},
		Configuration:          services.PathPosture{State: "OBSERVED", Path: "/etc/systemd/system/websvc.service"},
		ConfigurationDirectory: services.PathPosture{State: "OBSERVED", Path: "/etc/systemd/system"},
		SearchResolution:       "ABSOLUTE", SearchPathState: "NOT_APPLICABLE", WeakRoles: []string{"EXECUTABLE"},
	}
	proc := processes.Process{
		ID: "proc-web", PID: 4242, PPID: 1, Name: "websvc", Executable: "/opt/acme/websvc", ExecutablePath: "/opt/acme/websvc",
		Principal: processes.Principal{User: "root", UserID: "0", Elevated: true, Context: "ROOT"},
		SessionID: "0", PrivilegeContext: "ROOT", RuntimeState: "RUNNING",
		CommandLine: processes.CommandLineMetadata{Available: true, Redacted: true, Source: "test"},
		Trust:       processes.TrustContext{State: "UNKNOWN", Basis: "test"}, Isolation: processes.IsolationSummary{State: "UNKNOWN"},
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	permission := processes.PathPermissionContext{
		ProcessID: "proc-web", Platform: "linux", PID: 4242, Path: "/opt/acme/websvc", State: "WEAK",
		UntrustedExecutableWrite: true, BroadExecutableWrite: true, Reasons: []string{"group writable"}, Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	privilege := processes.RuntimePrivilegeContext{
		ProcessID: "proc-web", PID: 4242, Platform: "linux", State: "OBSERVED", AccountClass: "ROOT", EffectiveUserID: "0",
		PrivilegeSetState: "OBSERVED", ElevatedUserContext: true, Source: "test", Confidence: evidence.ConfidenceExact,
	}
	account := accounts.Account{
		ID: "acct-root", Name: "root", Principal: "root", UID: "0", GID: "0", AccountType: "SERVICE", EnabledState: "ENABLED",
		LoginCapability: "LOGIN_CAPABLE", Privileged: true, PrivilegeBasis: []string{"uid 0"}, ServiceAccount: true, ServiceBasis: []string{"websvc"},
		Authentication:   accounts.AuthenticationMetadata{State: "OBSERVED", PasswordState: "SET", PasswordRequired: "YES", PasswordExpires: "NO", PasswordChangeable: "YES", Source: "test"},
		CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	file := fsinv.ExecutableRecord{
		ID: "fs-web", Path: "/opt/acme/websvc", ResolvedPath: "/opt/acme/websvc", Directory: "/opt/acme", State: evidence.StateObserved,
		Exists: true, Regular: true, Executable: true, PermissionModel: "POSIX_MODE", GroupWritable: true, BroadlyWritable: true, UntrustedWrite: true,
		DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	binding := netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}
	address := "0.0.0.0"
	if loopback {
		binding = netinv.Binding{Class: "LOOPBACK", IsLoopback: true}
		address = "127.0.0.1"
	}
	endpoint := netinv.Endpoint{
		ID: "net-web", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: address, LocalPort: 8443,
		InterfaceBinding: binding, Owner: netinv.Owner{PID: 4242, ProcessName: "websvc", ServiceName: "websvc", State: "OBSERVED", Source: "test"},
		CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	return []evidence.Observation{
		evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.item.svc-web", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.path_integrity.svc-web", path, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("process.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("process.item.proc-web", proc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("process.permission.proc-web", permission, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("process.privilege.proc-web", privilege, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.item.acct-root", account, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("filesystem.executable.fs-web", file, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.endpoint.net-web", endpoint, "test", at, evidence.ConfidenceExact),
	}
}

func containsCorrelationString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/persistence"
)

func persistenceObservation(e persistence.Entry) evidence.Observation {
	return evidence.NewObserved("persistence.entry."+e.ID, e, "test", time.Now().UTC(), evidence.ConfidenceHigh)
}

func basePersistenceEntry() persistence.Entry {
	na := persistence.PathPosture{State: evidence.StateNotApplicable, CollectionSource: "test", Confidence: evidence.ConfidenceExact, Reason: "not represented"}
	safe := persistence.PathPosture{Path: "/usr/bin/demo", State: evidence.StateObserved, Exists: true, OwnerID: "0", GroupID: "0", PermissionModel: "POSIX mode/uid/gid", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	dir := safe
	dir.Path = "/usr/bin"
	dir.Directory = true
	return persistence.Entry{ID: "per-test", Name: "demo", Mechanism: "SYSTEMD_SERVICE", Manager: "systemd", Scope: "SYSTEM", EnabledState: "ENABLED", RuntimeState: "RUNNING", Account: "root", PrivilegeContext: "ROOT", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, PathIntegrity: persistence.PathIntegrity{State: evidence.StateObserved, Privileged: true, PrivilegeBasis: "ROOT", Executable: safe, ExecutableDirectory: dir, ReferencedScript: na, ReferencedScriptDirectory: na, Definition: safe, DefinitionDirectory: dir}}
}

func TestPhase097PrivilegedExecutableWeaknessFails(t *testing.T) {
	e := basePersistenceEntry()
	e.PathIntegrity.Executable.UntrustedWrite = true
	e.PathIntegrity.Executable.BroadlyWritable = true
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got Status
	for _, x := range f {
		if x.RuleID == "CHM-PER-001" {
			got = x.Status
		}
	}
	if len(f) != 5 || got != StatusFail {
		t.Fatalf("unexpected findings: %#v", f)
	}
}

func TestPhase097DefinitionWeaknessFails(t *testing.T) {
	e := basePersistenceEntry()
	e.PathIntegrity.Definition.UntrustedWrite = true
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got Status
	for _, x := range f {
		if x.RuleID == "CHM-PER-002" {
			got = x.Status
		}
	}
	if len(f) != 5 || got != StatusFail {
		t.Fatalf("unexpected findings: %#v", f)
	}
}

func TestPhase097UnresolvedPrivilegedPathIsUnknown(t *testing.T) {
	e := basePersistenceEntry()
	e.PathIntegrity.Executable.State = evidence.StateUnavailable
	e.PathIntegrity.Executable.Reason = "denied"
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got Status
	for _, x := range f {
		if x.RuleID == "CHM-PER-001" {
			got = x.Status
		}
	}
	if len(f) != 5 || got != StatusUnknown {
		t.Fatalf("unexpected findings: %#v", f)
	}
}

func TestPhase098WeakHighPrivilegeCorrelationIsCriticalFail(t *testing.T) {
	e := basePersistenceEntry()
	e.PathIntegrity.Executable.UntrustedWrite = true
	e.PathIntegrity.Executable.BroadlyWritable = true
	e.PathIntegrity.WeakRoles = []string{"executable"}
	e.PrivilegeCorrelation = persistence.PrivilegeCorrelation{
		State: evidence.StateObserved, ExecutionLevel: "HIGH_PRIVILEGE", HighPrivilege: true,
		AccountMatchState: "MATCHED", AccountID: "acct-admin", Principal: "root",
		PrivilegeBasis: []string{"NORMALIZED_ACCOUNT_PRIVILEGED"}, WeakPath: true, WeakRoles: []string{"executable"},
		RiskContext: "WEAK_HIGH_PRIVILEGE_PERSISTENCE", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{persistenceObservation(e), evidence.NewObserved("persistence.privilege."+e.ID, e.PrivilegeCorrelation, "test", time.Now().UTC(), evidence.ConfidenceHigh)}
	f, err := EvaluateRules(PersistencePathIntegrityRules(), obs, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	for _, x := range f {
		if x.RuleID == "CHM-PER-003" {
			got = x
		}
	}
	if got.Status != StatusFail || got.Severity != SeverityCritical {
		t.Fatalf("expected critical correlation failure, got %#v", got)
	}
}

func TestPhase098UnresolvedWeakExecutionIsUnknown(t *testing.T) {
	e := basePersistenceEntry()
	e.PathIntegrity.Privileged = false
	e.PathIntegrity.PrivilegeBasis = "USER"
	e.PathIntegrity.Executable.UntrustedWrite = true
	e.PathIntegrity.WeakRoles = []string{"executable"}
	e.PrivilegeCorrelation = persistence.PrivilegeCorrelation{
		State: evidence.StateUnavailable, ExecutionLevel: "UNKNOWN", AccountMatchState: "UNRESOLVED",
		WeakPath: true, WeakRoles: []string{"executable"}, RiskContext: "PRIVILEGE_UNRESOLVED",
		CollectionSource: "test", Confidence: evidence.ConfidenceMedium, Reason: "account unresolved",
	}
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range f {
		if x.RuleID == "CHM-PER-003" && x.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN, got %#v", x)
		}
	}
}

func TestPhase099SystemStartupWeakControlFails(t *testing.T) {
	e := basePersistenceEntry()
	e.Mechanism = "SYSTEMD_AUTOSTART"
	e.Scope = "SYSTEM"
	e.PathIntegrity.Definition.UntrustedWrite = true
	e.PathIntegrity.Definition.BroadlyWritable = true
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range f {
		if x.RuleID == "CHM-PER-004" {
			if x.Status != StatusFail || x.Severity != SeverityHigh {
				t.Fatalf("unexpected system startup finding: %#v", x)
			}
			return
		}
	}
	t.Fatal("CHM-PER-004 not emitted")
}

func TestPhase099UserOwnedAutostartDoesNotFailOnlyForOwnerWrite(t *testing.T) {
	e := basePersistenceEntry()
	e.Mechanism = "XDG_AUTOSTART"
	e.Scope = "USER"
	e.PrivilegeContext = "USER"
	e.PathIntegrity.Privileged = false
	e.PathIntegrity.PrivilegeBasis = "USER"
	e.PathIntegrity.Definition.OwnerID = "1000"
	e.PathIntegrity.Definition.UntrustedWrite = true
	e.PathIntegrity.Definition.BroadlyWritable = false
	e.PathIntegrity.Definition.WritePrincipals = []string{"owner-uid:1000"}
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range f {
		if x.RuleID == "CHM-PER-005" {
			if x.Status != StatusPass {
				t.Fatalf("normal owner-controlled user autostart must not fail: %#v", x)
			}
			return
		}
	}
	t.Fatal("CHM-PER-005 not emitted")
}

func TestPhase099UserAutostartBroadWriteFails(t *testing.T) {
	e := basePersistenceEntry()
	e.Mechanism = "LOGIN_ITEM"
	e.Scope = "USER"
	e.PrivilegeContext = "USER"
	e.PathIntegrity.Privileged = false
	e.PathIntegrity.PrivilegeBasis = "USER"
	e.PathIntegrity.Definition.BroadlyWritable = true
	e.PathIntegrity.Definition.UntrustedWrite = true
	e.PathIntegrity.Definition.WritePrincipals = []string{"other"}
	f, err := EvaluateRules(PersistencePathIntegrityRules(), []evidence.Observation{persistenceObservation(e)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range f {
		if x.RuleID == "CHM-PER-005" {
			if x.Status != StatusFail || x.Severity != SeverityMedium {
				t.Fatalf("unexpected user startup finding: %#v", x)
			}
			return
		}
	}
	t.Fatal("CHM-PER-005 not emitted")
}

func TestPhase099ImplementedRulesIncludeStartupExposureExactlyOnce(t *testing.T) {
	seen := map[string]int{}
	for _, r := range ImplementedRules() {
		if r.ID == "CHM-PER-004" || r.ID == "CHM-PER-005" {
			seen[r.ID]++
		}
	}
	if seen["CHM-PER-004"] != 1 || seen["CHM-PER-005"] != 1 {
		t.Fatalf("rules not registered exactly once: %#v", seen)
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("unexpected rule-set version %q", RuleSetVersion)
	}
}

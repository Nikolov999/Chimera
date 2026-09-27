package services

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeAndValidateInventory(t *testing.T) {
	at := time.Date(2026, 8, 19, 7, 0, 0, 0, time.UTC)
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Services: []Service{
			{Name: "demo.service", Manager: "systemd", ExecutablePath: "/opt/demo/bin/demo", Account: "root", StartMode: "enabled", RuntimePID: 12, RuntimeState: "running", PrivilegeContext: "root", DefinitionPath: "/etc/systemd/system/demo.service", ConfigurationSource: "/etc/systemd/system/demo.service", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
			{Name: "alpha.service", Manager: "systemd", Account: "svc", StartMode: "disabled", RuntimeState: "stopped", PrivilegeContext: "service_account", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
		},
		Sources: []SourceStatus{{ID: "test", State: evidence.StateObserved, Source: "test source", ItemCount: 2}},
	}
	inv.Services = normalize(inv.Services)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Summary = summarize(inv.Services)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Services[0].Name != "alpha.service" || inv.Services[1].Name != "demo.service" {
		t.Fatalf("records not deterministically ordered: %#v", inv.Services)
	}
	if inv.Summary.Services != 2 || inv.Summary.Running != 1 || inv.Summary.Stopped != 1 || inv.Summary.Enabled != 1 || inv.Summary.Disabled != 1 || inv.Summary.Privileged != 1 {
		t.Fatalf("unexpected summary: %#v", inv.Summary)
	}
	if len(inv.Evidence) != 7 {
		t.Fatalf("expected 7 evidence records, got %d", len(inv.Evidence))
	}
}

func TestStableIDIncludesConfigurationProvenance(t *testing.T) {
	a := Service{Name: "same", Manager: "launchd", ConfigurationSource: "/Library/LaunchDaemons/a.plist"}
	b := Service{Name: "same", Manager: "launchd", ConfigurationSource: "/System/Library/LaunchDaemons/a.plist"}
	if stableID(a) == stableID(b) {
		t.Fatal("service IDs must distinguish separate configuration definitions")
	}
}

func TestValidateRejectsDuplicateEvidence(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Evidence: []evidence.Observation{
			evidence.NewObserved("dup", true, "test", at, evidence.ConfidenceExact),
			evidence.NewObserved("dup", false, "test", at, evidence.ConfidenceExact),
		},
	}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected duplicate evidence validation failure")
	}
}

func TestPhase046LaunchdMetadataNormalizesAndValidates(t *testing.T) {
	at := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	lh := &LaunchdHardening{
		State: "complete", DefinitionOwner: "0", DefinitionMode: "0644",
		ExecutableState: "observed", ExecutableOwner: "0", ExecutableMode: "0755",
		ExecutableParentState: "observed", ExecutableParentOwner: "0", ExecutableParentMode: "0755",
		ProgramAbsolute: true, EnvironmentVariableNames: []string{"PATH", "PATH"}, EnvironmentValuesRedacted: true,
	}
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "darwin", Architecture: "arm64", CollectedAt: at,
		Services: []Service{{
			Name: "com.example.demo", Manager: "launchd", ServiceType: "LaunchDaemon", ExecutablePath: "/usr/local/bin/demo",
			Account: "root", StartMode: "run_at_load", RuntimeState: "running", PrivilegeContext: "root",
			DefinitionPath: "/Library/LaunchDaemons/com.example.demo.plist", ConfigurationSource: "/Library/LaunchDaemons/com.example.demo.plist",
			CollectionSource: "test", Confidence: evidence.ConfidenceHigh, LaunchdHardening: lh,
		}},
		Sources: []SourceStatus{{ID: "darwin-launchd-hardening", State: evidence.StateObserved, Source: "test", ItemCount: 1}},
	}
	inv.Services = normalize(inv.Services)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Summary = summarize(inv.Services)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Summary.LaunchdHardeningAssessed != 1 {
		t.Fatalf("unexpected launchd summary: %#v", inv.Summary)
	}
	seen := false
	for _, obs := range inv.Evidence {
		if strings.HasPrefix(obs.Key, "service.launchd.") {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("expected service.launchd.<id> evidence")
	}
}

func TestFix39WindowsCoverageSeparatesOptionalAndFailureStates(t *testing.T) {
	sec := &WindowsSecurity{
		State:                         "DEGRADED",
		ExecutableResolution:          "QUOTED_OR_ABSOLUTE",
		ExecutableACL:                 WindowsACLPosture{State: "OBSERVED"},
		ExecutableDirectoryACL:        WindowsACLPosture{State: "DENIED", Reason: "access denied"},
		ServiceACL:                    WindowsServiceACLPosture{State: "OBSERVED", ControlOnly: true, Rights: []string{"RP"}},
		RegistryState:                 "OBSERVED",
		RegistryACL:                   WindowsACLPosture{State: "DEGRADED", Reason: "partial ACL"},
		ServiceDLLACL:                 WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: WindowsACLPosture{State: "NOT_APPLICABLE"},
		AccountAdminState:             "NO",
	}
	sec.refreshComponents()
	pi := &ServicePathIntegrity{
		State: "COMPLETE", PrivilegeBasis: "SYSTEM",
		Executable: PathPosture{State: "OBSERVED"}, ExecutableDirectory: PathPosture{State: "OBSERVED"},
		Configuration: PathPosture{State: "OBSERVED"}, ConfigurationDirectory: PathPosture{State: "NOT_APPLICABLE"},
		SearchResolution: "QUOTED_OR_ABSOLUTE", SearchPathState: "OBSERVED",
	}
	svc := Service{
		Name: "Demo", Manager: "windows-service-control-manager", Account: "LocalSystem", StartMode: "AUTOMATIC", RuntimeState: "RUNNING",
		PrivilegeContext: "SYSTEM", DefinitionPath: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`, ConfigurationSource: "SCM",
		CollectionSource: "test", ExecutablePath: `C:\Windows\System32\demo.exe`, Confidence: evidence.ConfidenceHigh,
		WindowsSecurity: sec, PathIntegrity: pi,
	}
	svc = normalize([]Service{svc})[0]
	summary := summarize([]Service{svc})
	c := summary.WindowsSecurityCoverage
	if c.BaseConfiguration.Observed != 1 || c.ExecutablePath.Observed != 1 || c.ExecutableACL.Observed != 1 || c.ExecutableDirectoryACL.Denied != 1 {
		t.Fatalf("required component coverage mismatch: %#v", c)
	}
	if c.RegistryACL.Degraded != 1 || c.ServiceDLL.NotApplicable != 1 || c.RecoveryCommand.NotApplicable != 1 || c.Account.Observed != 1 || c.PathIntegrity.Observed != 1 {
		t.Fatalf("failure/optional component coverage mismatch: %#v", c)
	}
	if summary.WindowsSecurityDegraded != 1 || summary.PathIntegrityComplete != 1 {
		t.Fatalf("aggregate coverage mismatch: %#v", summary)
	}
}

func TestFix39ServiceInventoryFingerprintIgnoresRuntimeState(t *testing.T) {
	base := Service{Name: "Demo", Manager: "windows-service-control-manager", DefinitionPath: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`, ConfigurationSource: "SCM"}
	a := base
	a.RuntimeState = "RUNNING"
	b := base
	b.RuntimeState = "STOPPED"
	if serviceInventoryFingerprint([]Service{a}) != serviceInventoryFingerprint([]Service{b}) {
		t.Fatal("base service inventory fingerprint must ignore dynamic runtime state")
	}
}

func TestFix39PathIntegrityOptionalNotApplicableDoesNotDegrade(t *testing.T) {
	na := PathPosture{State: "NOT_APPLICABLE"}
	pi := &ServicePathIntegrity{
		State: "COMPLETE", PrivilegeBasis: "SYSTEM",
		Executable: PathPosture{State: "OBSERVED"}, ExecutableDirectory: PathPosture{State: "OBSERVED"},
		Configuration: PathPosture{State: "OBSERVED"}, ConfigurationDirectory: PathPosture{State: "NOT_APPLICABLE"},
		ServiceDLL: &na, ServiceDLLDirectory: &na, RecoveryExecutable: &na, RecoveryExecutableDirectory: &na,
		SearchResolution: "QUOTED_OR_ABSOLUTE", SearchPathState: "OBSERVED",
	}
	pi.normalize()
	if pi.State != "COMPLETE" {
		t.Fatalf("truly optional absent components must not degrade path integrity: %#v", pi)
	}
}

func TestFix39PathIntegrityConfiguredOptionalFailureDegrades(t *testing.T) {
	denied := PathPosture{State: "DENIED", Path: `C:\Windows\System32\demo.dll`, Reason: "access denied"}
	na := PathPosture{State: "NOT_APPLICABLE"}
	pi := &ServicePathIntegrity{
		State: "COMPLETE", PrivilegeBasis: "SYSTEM",
		Executable: PathPosture{State: "OBSERVED"}, ExecutableDirectory: PathPosture{State: "OBSERVED"},
		Configuration: PathPosture{State: "OBSERVED"}, ConfigurationDirectory: PathPosture{State: "NOT_APPLICABLE"},
		ServiceDLL: &denied, ServiceDLLDirectory: &na, RecoveryExecutable: &na, RecoveryExecutableDirectory: &na,
		SearchResolution: "QUOTED_OR_ABSOLUTE", SearchPathState: "OBSERVED",
	}
	pi.normalize()
	if pi.State != "DEGRADED" || pi.ServiceDLL == nil || pi.ServiceDLL.State != "DENIED" {
		t.Fatalf("configured optional component denial must remain explicit and degrade aggregate path integrity: %#v", pi)
	}
}

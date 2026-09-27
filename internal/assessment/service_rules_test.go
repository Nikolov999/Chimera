package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestServiceRulesDetectPhase044WindowsWeaknesses(t *testing.T) {
	at := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	sec := services.WindowsSecurity{
		State:                         "COMPLETE",
		UnquotedExecutablePath:        true,
		ExecutableACL:                 services.WindowsACLPosture{State: "OBSERVED", BroadWriteGranted: true, Principals: []string{"S-1-5-32-545"}, Rights: []string{"Modify"}},
		ExecutableDirectoryACL:        services.WindowsACLPosture{State: "OBSERVED"},
		ServiceDLLACL:                 services.WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        services.WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceACL:                    services.WindowsServiceACLPosture{State: "OBSERVED", Weak: true, Dangerous: true, Principals: []string{"AU"}, Rights: []string{"DC"}},
		AccountAdminState:             "YES",
		RegistryState:                 "OBSERVED",
		InteractiveProcess:            true,
		FailureCommandPresent:         true,
		FailureExecutablePath:         `C:\Program Files\Vendor\recover.exe`,
		FailureExecutableUnquoted:     true,
		FailureExecutableACL:          services.WindowsACLPosture{State: "OBSERVED"},
		FailureExecutableDirectoryACL: services.WindowsACLPosture{State: "OBSERVED"},
	}
	svc := services.Service{
		ID: "svc-test", Name: "Demo", Manager: "windows-service-control-manager", ExecutablePath: `C:\Program Files\Vendor\agent.exe`,
		Account: `HOST\svc-admin`, StartMode: "AUTOMATIC", RuntimeState: "RUNNING", PrivilegeContext: "SERVICE_ACCOUNT",
		ConfigurationSource: "SCM", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, WindowsSecurity: &sec,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "windows", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", services.Summary{Services: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.source.windows_service_security", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc-test", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.security.svc-test", sec, "test", at, evidence.ConfidenceHigh),
	})

	want := map[string]Status{
		"CHM-SVC-001": StatusWarn,
		"CHM-SVC-002": StatusFail,
		"CHM-SVC-003": StatusPass,
		"CHM-SVC-004": StatusFail,
		"CHM-SVC-005": StatusWarn,
		"CHM-SVC-006": StatusFail,
		"CHM-SVC-007": StatusFail,
	}
	for _, rule := range ServiceRules() {
		if rule.ID > "CHM-SVC-007" {
			continue
		}
		got := rule.Evaluate(idx)
		if got.Status != want[rule.ID] {
			t.Fatalf("%s status=%s want %s; evaluation=%#v", rule.ID, got.Status, want[rule.ID], got)
		}
		if got.Applicability != Applicable {
			t.Fatalf("%s applicability=%s", rule.ID, got.Applicability)
		}
	}
}

func TestServiceRulesAreNotApplicableOffWindows(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact),
	})
	for _, rule := range ServiceRules() {
		if rule.ID > "CHM-SVC-007" {
			continue
		}
		got := rule.Evaluate(idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable || got.Confidence != evidence.ConfidenceExact {
			t.Fatalf("%s should be exactly not applicable off Windows: %#v", rule.ID, got)
		}
	}
}

func TestServiceRulesDoNotClaimPassWhenWindowsSecurityProviderUnavailable(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "windows", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewState("service.source.windows_service_security", evidence.StateDenied, "test", at, evidence.ConfidenceLow, "access denied"),
	})
	for _, rule := range ServiceRules() {
		if rule.ID > "CHM-SVC-007" {
			continue
		}
		got := rule.Evaluate(idx)
		if got.Status != StatusUnknown || got.Applicability != Undetermined {
			t.Fatalf("%s should remain unknown when security evidence is unavailable: %#v", rule.ID, got)
		}
	}
}

func TestServiceRulesDetectPhase045SystemdWeaknesses(t *testing.T) {
	at := time.Date(2026, 8, 19, 8, 45, 0, 0, time.UTC)
	sec := services.SystemdHardening{
		State: "COMPLETE", User: "root", Group: "root", UserConfigured: false, GroupConfigured: false,
		DynamicUser: "NO", NoNewPrivileges: "NO", ProtectSystem: "NO", ProtectHome: "NO", PrivateTmp: "NO",
		PrivateDevices: "NO", PrivateNetwork: "NO", CapabilityBoundingSetState: "UNRESTRICTED",
		CapabilityBoundingSet: []string{"cap_dac_override", "cap_sys_admin", "cap_sys_module", "cap_sys_ptrace", "cap_sys_rawio"},
		AmbientCapabilities:   []string{"cap_sys_admin"}, RestrictNamespacesState: "UNRESTRICTED",
		ProtectKernelTunables: "NO", ProtectKernelModules: "NO", ProtectControlGroups: "NO",
		RestrictSUIDSGID: "NO", LockPersonality: "NO", MemoryDenyWriteExecute: "NO", UMask: "0022",
	}
	svc := services.Service{
		ID: "svc-linux", Name: "demo.service", Manager: "systemd", ExecutablePath: "/usr/local/bin/demo",
		Account: "root", AccountGroup: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "ROOT",
		ConfigurationSource: "/etc/systemd/system/demo.service", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
		SystemdHardening: &sec,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", services.Summary{Services: 1, Running: 1, Enabled: 1, Privileged: 1, SystemdHardeningAssessed: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.source.linux_systemd_hardening", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc-linux", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.systemd.svc-linux", sec, "test", at, evidence.ConfidenceHigh),
	})
	want := map[string]Status{
		"CHM-SVC-008": StatusWarn,
		"CHM-SVC-009": StatusWarn,
		"CHM-SVC-010": StatusWarn,
		"CHM-SVC-011": StatusWarn,
		"CHM-SVC-012": StatusFail,
		"CHM-SVC-013": StatusWarn,
		"CHM-SVC-014": StatusFail,
		"CHM-SVC-015": StatusWarn,
	}
	for _, rule := range ServiceRules() {
		if rule.ID < "CHM-SVC-008" || rule.ID > "CHM-SVC-015" {
			continue
		}
		got := rule.Evaluate(idx)
		if got.Status != want[rule.ID] {
			t.Fatalf("%s status=%s want %s; evaluation=%#v", rule.ID, got.Status, want[rule.ID], got)
		}
		if got.Applicability != Applicable {
			t.Fatalf("%s applicability=%s", rule.ID, got.Applicability)
		}
	}
}

func TestPhase045SystemdRulesNotApplicableOffLinux(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("service.platform", "windows", "test", at, evidence.ConfidenceExact)})
	for _, rule := range SystemdServiceRules() {
		got := rule.Evaluate(idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable || got.Confidence != evidence.ConfidenceExact {
			t.Fatalf("%s should be exactly not applicable off Linux: %#v", rule.ID, got)
		}
	}
}

func TestPhase045SystemdRulesRemainUnknownWhenProviderUnavailable(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewState("service.source.linux_systemd_hardening", evidence.StateUnavailable, "test", at, evidence.ConfidenceLow, "systemctl unavailable"),
	})
	for _, rule := range SystemdServiceRules() {
		got := rule.Evaluate(idx)
		if got.Status != StatusUnknown || got.Applicability != Undetermined {
			t.Fatalf("%s should remain unknown when systemd hardening evidence is unavailable: %#v", rule.ID, got)
		}
	}
}

func TestServiceRulesDetectPhase046LaunchdWeaknesses(t *testing.T) {
	at := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	sec := services.LaunchdHardening{
		State: "COMPLETE", DefinitionOwner: "501", DefinitionMode: "0666", DefinitionBroadlyWritable: true,
		ExecutableState: "OBSERVED", ExecutableOwner: "501", ExecutableMode: "0777", ExecutableBroadlyWritable: true,
		ExecutableParentState: "OBSERVED", ExecutableParentOwner: "501", ExecutableParentMode: "0777", ExecutableParentBroadlyWritable: true,
		ProgramAbsolute: false, PrivilegedWeakPath: true, EnvironmentVariableNames: []string{"DYLD_INSERT_LIBRARIES"},
		DangerousEnvironmentKeys: []string{"DYLD_INSERT_LIBRARIES"}, EnvironmentValuesRedacted: true,
		DangerousConfiguration: []string{"relative-program-path", "privileged-weak-executable-location", "root-launch-agent"},
	}
	svc := services.Service{
		ID: "svc-darwin", Name: "com.example.bad", Manager: "launchd", ServiceType: "LaunchAgent", ExecutablePath: "tmp/tool",
		Account: "root", StartMode: "RUN_AT_LOAD", RuntimeState: "RUNNING", PrivilegeContext: "ROOT",
		ConfigurationSource: "/Library/LaunchAgents/com.example.bad.plist", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
		LaunchdHardening: &sec,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "darwin", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", services.Summary{Services: 1, Running: 1, Enabled: 1, Privileged: 1, LaunchdHardeningAssessed: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.source.darwin_launchd_hardening", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc-darwin", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.launchd.svc-darwin", sec, "test", at, evidence.ConfidenceHigh),
	})
	want := map[string]Status{
		"CHM-SVC-016": StatusFail, "CHM-SVC-017": StatusFail, "CHM-SVC-018": StatusFail,
		"CHM-SVC-019": StatusFail, "CHM-SVC-020": StatusFail, "CHM-SVC-021": StatusWarn, "CHM-SVC-022": StatusFail,
	}
	for _, rule := range LaunchdServiceRules() {
		got := rule.Evaluate(idx)
		if got.Status != want[rule.ID] {
			t.Fatalf("%s status=%s want %s; evaluation=%#v", rule.ID, got.Status, want[rule.ID], got)
		}
		if got.Applicability != Applicable {
			t.Fatalf("%s applicability=%s", rule.ID, got.Applicability)
		}
	}
}

func TestPhase046LaunchdRulesNotApplicableOffDarwin(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact)})
	for _, rule := range LaunchdServiceRules() {
		got := rule.Evaluate(idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable || got.Confidence != evidence.ConfidenceExact {
			t.Fatalf("%s should be exactly not applicable off macOS: %#v", rule.ID, got)
		}
	}
}

func TestPhase046LaunchdRulesRemainUnknownWhenProviderUnavailable(t *testing.T) {
	at := time.Now().UTC()
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "darwin", "test", at, evidence.ConfidenceExact),
		evidence.NewState("service.source.darwin_launchd_hardening", evidence.StateUnavailable, "test", at, evidence.ConfidenceLow, "launchd metadata unavailable"),
	})
	for _, rule := range LaunchdServiceRules() {
		got := rule.Evaluate(idx)
		if got.Status != StatusUnknown || got.Applicability != Undetermined {
			t.Fatalf("%s should remain unknown when launchd hardening evidence is unavailable: %#v", rule.ID, got)
		}
	}
}

func TestPhase047ServicePrivilegeToPathCorrelation(t *testing.T) {
	at := time.Date(2026, 8, 19, 9, 15, 0, 0, time.UTC)
	pi := services.ServicePathIntegrity{
		State: "COMPLETE", Privileged: true, PrivilegeBasis: "ROOT",
		Executable:             services.PathPosture{State: "OBSERVED", Path: "/opt/demo/bin/demo", LowerPrivilegeWritable: false},
		ExecutableDirectory:    services.PathPosture{State: "OBSERVED", Path: "/opt/demo/bin", LowerPrivilegeWritable: true},
		Configuration:          services.PathPosture{State: "OBSERVED", Path: "/etc/systemd/system/demo.service", LowerPrivilegeWritable: true},
		ConfigurationDirectory: services.PathPosture{State: "OBSERVED", Path: "/etc/systemd/system"},
		SearchResolution:       "ABSOLUTE", SearchPathState: "OBSERVED", SearchPathWritable: true,
		SearchEvidence: []string{"executable-parent-directory"}, WeakRoles: []string{"configuration", "executable-directory", "search-path"},
	}
	svc := services.Service{
		ID: "svc-phase047", Name: "demo.service", Manager: "systemd", ExecutablePath: "/opt/demo/bin/demo",
		Account: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "ROOT",
		DefinitionPath: "/etc/systemd/system/demo.service", ConfigurationSource: "/etc/systemd/system/demo.service",
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh, PathIntegrity: &pi,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", services.Summary{Services: 1, Privileged: 1, PathIntegrityAssessed: 1, PrivilegedPathAssessed: 1, PrivilegedWeakExecutable: 1, PrivilegedWeakConfiguration: 1, PrivilegedWeakSearchPath: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.source.linux_service_path_integrity", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc-phase047", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.path_integrity.svc-phase047", pi, "test", at, evidence.ConfidenceHigh),
	})
	want := map[string]Status{
		"CHM-SVC-023": StatusFail,
		"CHM-SVC-024": StatusFail,
		"CHM-SVC-025": StatusFail,
		"CHM-SVC-026": StatusFail,
	}
	for _, rule := range ServicePathCorrelationRules() {
		got := rule.Evaluate(idx)
		if got.Status != want[rule.ID] {
			t.Fatalf("%s status=%s want=%s eval=%#v", rule.ID, got.Status, want[rule.ID], got)
		}
		if got.Applicability != Applicable || got.Confidence == evidence.ConfidenceLow {
			t.Fatalf("%s unexpected applicability/confidence: %#v", rule.ID, got)
		}
	}
}

func TestPhase047SearchCorrelationRemainsUnknownWhenResolutionEvidenceMissing(t *testing.T) {
	at := time.Now().UTC()
	pi := services.ServicePathIntegrity{
		State: "DEGRADED", Privileged: true, PrivilegeBasis: "SYSTEM",
		Executable:             services.PathPosture{State: "OBSERVED", Path: `C:\Program Files\Demo\demo.exe`},
		ExecutableDirectory:    services.PathPosture{State: "UNAVAILABLE", Path: `C:\Program Files\Demo`},
		Configuration:          services.PathPosture{State: "OBSERVED", Path: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`},
		ConfigurationDirectory: services.PathPosture{State: "NOT_APPLICABLE"},
		SearchResolution:       "UNQUOTED", SearchPathState: "UNAVAILABLE",
		Degraded: []string{"unquoted service path candidate-directory ACL state unresolved"},
	}
	svc := services.Service{ID: "svc-win047", Name: "Demo", Manager: "windows-service-control-manager", Account: "LocalSystem", StartMode: "AUTOMATIC", RuntimeState: "RUNNING", PrivilegeContext: "SYSTEM", ConfigurationSource: "SCM", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, PathIntegrity: &pi}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.source.windows_service_path_integrity", map[string]any{"state": "DEGRADED", "item_count": 1}, "test", at, evidence.ConfidenceMedium),
		evidence.NewObserved("service.item.svc-win047", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.path_integrity.svc-win047", pi, "test", at, evidence.ConfidenceMedium),
	})
	var rule Rule
	for _, candidate := range ServicePathCorrelationRules() {
		if candidate.ID == "CHM-SVC-025" {
			rule = candidate
			break
		}
	}
	got := rule.Evaluate(idx)
	if got.Status != StatusUnknown || got.Applicability != Applicable {
		t.Fatalf("expected unresolved search path to remain UNKNOWN: %#v", got)
	}
}

func TestFix32ServiceObjectControlOnlyIsWarnNotWeakFail(t *testing.T) {
	at := time.Date(2026, 8, 20, 19, 30, 0, 0, time.UTC)
	sec := services.WindowsSecurity{
		State:                         "COMPLETE",
		ExecutableACL:                 services.WindowsACLPosture{State: "OBSERVED"},
		ExecutableDirectoryACL:        services.WindowsACLPosture{State: "OBSERVED"},
		ServiceDLLACL:                 services.WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        services.WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceACL:                    services.WindowsServiceACLPosture{State: "OBSERVED", ControlOnly: true, Principals: []string{"S-1-5-11"}, Rights: []string{"RP", "WP"}},
		AccountAdminState:             "NO",
		RegistryState:                 "OBSERVED",
		RegistryACL:                   services.WindowsACLPosture{State: "OBSERVED"},
		FailureExecutableACL:          services.WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: services.WindowsACLPosture{State: "NOT_APPLICABLE"},
	}
	svc := services.Service{
		ID: "svc-control", Name: "ControlOnly", Manager: "windows-service-control-manager",
		ExecutablePath: `C:\Windows\System32\svchost.exe`, Account: "LocalSystem",
		ConfigurationSource: "SCM", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
		WindowsSecurity: &sec,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("service.platform", "windows", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.source.windows_service_security", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc-control", svc, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("service.security.svc-control", sec, "test", at, evidence.ConfidenceHigh),
	})
	var rule Rule
	for _, candidate := range ServiceRules() {
		if candidate.ID == "CHM-SVC-004" {
			rule = candidate
			break
		}
	}
	if rule.ID == "" {
		t.Fatal("CHM-SVC-004 not found")
	}
	got := rule.Evaluate(idx)
	if got.Status != StatusWarn {
		t.Fatalf("control-only service ACL status=%s want WARN; evaluation=%#v", got.Status, got)
	}
}

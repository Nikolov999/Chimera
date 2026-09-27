package assessment

import (
	"strconv"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/processes"
)

func TestProcessRulesAreConcreteAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range ProcessRules() {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid process rule %s: %v", r.ID, err)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate process rule %s", r.ID)
		}
		seen[r.ID] = true
	}
	for _, id := range []string{"CHM-PRC-001", "CHM-PRC-002", "CHM-PRC-003", "CHM-PRC-004", "CHM-PRC-005", "CHM-PRC-006", "CHM-PRC-007", "CHM-PRC-008", "CHM-PRC-009", "CHM-PRC-010", "CHM-PRC-011", "CHM-PRC-012", "CHM-PRC-013", "CHM-PRC-014", "CHM-PRC-015", "CHM-PRC-016", "CHM-PRC-017", "CHM-PRC-018", "CHM-PRC-019", "CHM-PRC-020", "CHM-PRC-021", "CHM-PRC-022", "CHM-PRC-023"} {
		if !seen[id] {
			t.Fatalf("missing implemented process rule %s", id)
		}
	}
}

func TestProcessExplicitTrustFailureRuleFailsOnInvalidSignature(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-001")
	now := time.Now().UTC()
	p := processes.Process{
		ID: "proc-test", PID: 100, PPID: 1, Name: "bad.exe", Executable: "bad.exe", ExecutablePath: `C:\\Temp\\bad.exe`,
		Principal: processes.Principal{User: "user", UserID: "S-1-test"}, SessionID: "1", PrivilegeContext: "STANDARD", RuntimeState: "RUNNING",
		CommandLine: processes.CommandLineMetadata{Redacted: true, Source: "test"},
		Trust:       processes.TrustContext{State: "SIGNATURE_UNTRUSTED", Basis: "test signature verifier", Signature: "INVALID"},
		Isolation:   processes.IsolationSummary{State: "UNKNOWN"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "windows", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable || len(findings[0].Evidence) != 1 {
		t.Fatalf("unexpected trust-failure finding: %#v", findings[0])
	}
}

func TestUnsignedRuleUsesObservedPlatformAndWarns(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-002")
	now := time.Now().UTC()
	p := testProcess(120, false, "UNSIGNED")
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "windows", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("unexpected unsigned result: %#v", findings[0])
	}

	obs[0] = evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact)
	findings, err = EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusPass || findings[0].Applicability != NotApplicable {
		t.Fatalf("Linux signature rule should be not applicable: %#v", findings[0])
	}
}

func TestPrivilegedProcessProvenanceRuleWarnsOnUnmanagedRootExecutable(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-004")
	now := time.Now().UTC()
	good := testProcess(200, true, "PACKAGE_MANAGED")
	bad := testProcess(201, true, "UNMANAGED")
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 2, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+good.ID, good, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.item."+bad.ID, bad, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || len(findings[0].Evidence) != 1 {
		t.Fatalf("unmanaged privileged executable not detected: %#v", findings[0])
	}
}

func TestPrivilegedProcessTrustRulePreservesUnknown(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-003")
	now := time.Now().UTC()
	p := testProcess(202, true, "UNKNOWN")
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusUnknown || findings[0].Applicability != Applicable {
		t.Fatalf("unknown privileged provenance should remain unknown: %#v", findings[0])
	}
}

func testProcess(pid int, elevated bool, trust string) processes.Process {
	return processes.Process{
		ID: "proc-test-" + strconv.Itoa(pid), PID: pid, PPID: 1, Name: "proc", Executable: "proc", ExecutablePath: "/usr/bin/proc",
		Principal: processes.Principal{User: "user", UserID: "1000", Elevated: elevated}, SessionID: "1", PrivilegeContext: "STANDARD", RuntimeState: "RUNNING",
		CommandLine: processes.CommandLineMetadata{Redacted: true, Source: "test"}, Trust: processes.TrustContext{State: trust, Basis: "test"},
		Isolation: processes.IsolationSummary{State: "UNKNOWN"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
}

func TestPrivilegedCriticalExecutionLocationRuleFailsOnTemporaryPath(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-005")
	now := time.Now().UTC()
	p := testProcess(300, true, "PACKAGE_MANAGED")
	p.ExecutablePath = "/tmp/privileged-agent"
	loc := processes.LocationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK", Temporary: true, UserWritable: true, WeakControl: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+p.ID, loc, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable || len(findings[0].Evidence) != 1 {
		t.Fatalf("temporary privileged execution was not failed: %#v", findings[0])
	}
}

func TestPrivilegedWeakExecutionLocationRuleWarnsOnUserWritablePath(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-006")
	now := time.Now().UTC()
	p := testProcess(301, true, "PACKAGE_MANAGED")
	p.ExecutablePath = "/home/alice/bin/admin-helper"
	loc := processes.LocationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK", UserWritable: true, WeakControl: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+p.ID, loc, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("user-writable privileged execution was not warned: %#v", findings[0])
	}
}

func TestSensitiveExecutionLocationRuleWarnsWithoutPrivilege(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-007")
	now := time.Now().UTC()
	p := testProcess(302, false, "PACKAGE_MANAGED")
	p.Name = "sshd"
	p.Executable = "sshd"
	p.ExecutablePath = "/home/alice/sshd"
	loc := processes.LocationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK", UserWritable: true, WeakControl: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+p.ID, loc, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("weak sensitive execution location was not warned: %#v", findings[0])
	}
}

func TestExecutionLocationRulePreservesUnknownWhenPathMissing(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-005")
	now := time.Now().UTC()
	p := testProcess(303, true, "PACKAGE_MANAGED")
	p.ExecutablePath = ""
	loc := processes.LocationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "UNKNOWN", Source: "test", Confidence: evidence.ConfidenceLow}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+p.ID, loc, "test", now, evidence.ConfidenceLow),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusUnknown {
		t.Fatalf("missing path should remain unknown: %#v", findings[0])
	}
}

func TestPrivilegedExecutablePermissionRuleFailsOnUntrustedWrite(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-008")
	now := time.Now().UTC()
	p := testProcess(401, true, "PACKAGE_MANAGED")
	perm := processes.PathPermissionContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK",
		Executable:               processes.PermissionNode{Path: p.ExecutablePath, Kind: "EXECUTABLE", State: "OBSERVED", ACLSource: "test", UntrustedWrite: true, BroadWrite: true},
		UntrustedExecutableWrite: true, BroadExecutableWrite: true, Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.permission."+p.ID, perm, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("untrusted privileged executable write was not failed: %#v", findings[0])
	}
}

func TestPrivilegedParentPermissionRuleFailsOnWritableParent(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-009")
	now := time.Now().UTC()
	p := testProcess(402, true, "PACKAGE_MANAGED")
	perm := processes.PathPermissionContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK",
		Executable:           processes.PermissionNode{Path: p.ExecutablePath, Kind: "EXECUTABLE", State: "OBSERVED", ACLSource: "test"},
		Parents:              []processes.PermissionNode{{Path: "/usr/local/bin", Kind: "DIRECTORY", State: "OBSERVED", ACLSource: "test", UntrustedWrite: true, BroadWrite: true}},
		UntrustedParentWrite: true, BroadParentWrite: true, Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.permission."+p.ID, perm, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("writable privileged parent directory was not failed: %#v", findings[0])
	}
}

func TestSensitiveProcessPermissionRuleWarnsOnBroadWrite(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-010")
	now := time.Now().UTC()
	p := testProcess(403, false, "PACKAGE_MANAGED")
	p.Name = "sshd"
	p.Executable = "sshd"
	perm := processes.PathPermissionContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "WEAK",
		Executable:           processes.PermissionNode{Path: p.ExecutablePath, Kind: "EXECUTABLE", State: "OBSERVED", ACLSource: "test", BroadWrite: true, UntrustedWrite: true},
		BroadExecutableWrite: true, UntrustedExecutableWrite: true, Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.permission."+p.ID, perm, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("broad-write sensitive process path was not warned: %#v", findings[0])
	}
}

func TestPrivilegedPermissionRulePreservesUnknown(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-008")
	now := time.Now().UTC()
	p := testProcess(404, true, "PACKAGE_MANAGED")
	perm := processes.PathPermissionContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: p.ExecutablePath, State: "UNKNOWN",
		Executable: processes.PermissionNode{Path: p.ExecutablePath, Kind: "EXECUTABLE", State: "UNKNOWN", ACLSource: "test", Reason: "denied"},
		Source:     "test", Confidence: evidence.ConfidenceLow,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.permission."+p.ID, perm, "test", now, evidence.ConfidenceLow),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusUnknown {
		t.Fatalf("unresolved privileged permission state should remain unknown: %#v", findings[0])
	}
}

func TestEffectiveIdentityTransitionRuleWarns(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-011")
	now := time.Now().UTC()
	p := testProcess(501, true, "PACKAGE_MANAGED")
	ctx := processes.RuntimePrivilegeContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "EXCESS", AccountClass: "ROOT",
		RealUserID: "1000", EffectiveUserID: "0", RealGroupID: "1000", EffectiveGroupID: "1000",
		IdentityTransition: true, PrivilegeSetState: "OBSERVED", ExcessSignals: []string{"effective-root-identity-transition"},
		Source: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.privilege."+p.ID, ctx, "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("identity transition should warn: %#v", findings[0])
	}
}

func TestHighImpactRuntimePrivilegeRuleWarnsOnNonRootCapability(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-012")
	now := time.Now().UTC()
	p := testProcess(502, false, "PACKAGE_MANAGED")
	ctx := processes.RuntimePrivilegeContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "EXCESS", AccountClass: "USER",
		RealUserID: "1000", EffectiveUserID: "1000", PrivilegeSetState: "OBSERVED",
		EffectiveCapabilities: []string{"CAP_SYS_ADMIN"}, HighImpactPrivileges: []string{"CAP_SYS_ADMIN"},
		ExcessSignals: []string{"non-root-high-impact-effective-capabilities"}, Source: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.privilege."+p.ID, ctx, "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("high-impact non-root capability should warn: %#v", findings[0])
	}
}

func TestWindowsTokenIntegrityRuleFailsOnSystemIntegrityMismatch(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-013")
	now := time.Now().UTC()
	p := testProcess(503, true, "SIGNED_VALID")
	ctx := processes.RuntimePrivilegeContext{
		ProcessID: p.ID, PID: p.PID, Platform: "windows", State: "EXCESS", AccountClass: "USER",
		IntegrityLevel: "SYSTEM", TokenElevation: "ELEVATED", ElevationType: "FULL", PrivilegeSetState: "OBSERVED",
		ExcessSignals: []string{"system-integrity-non-system-account"}, Source: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "windows", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.privilege."+p.ID, ctx, "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("SYSTEM integrity mismatch should fail: %#v", findings[0])
	}
}

func TestWindowsTokenIntegrityRuleIsNotApplicableOnLinux(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-013")
	now := time.Now().UTC()
	obs := []evidence.Observation{evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact)}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusPass || findings[0].Applicability != NotApplicable {
		t.Fatalf("Windows integrity rule should be not applicable on Linux: %#v", findings[0])
	}
}

func TestWritableExecutableMemoryRuleFailsPrivilegedNonJIT(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-014")
	now := time.Now().UTC()
	p := testProcess(601, true, "PACKAGE_MANAGED")
	mem := processes.ExecutionMemoryContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", RegionsObserved: 12, ExecutableRegions: 4, WritableExecutableRegions: 1, FileBackedExecutableRegions: 3, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.memory."+p.ID, mem, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("privileged non-JIT W+X mapping should fail: %#v", findings[0])
	}
}

func TestWritableExecutableMemoryRuleWarnsJITContext(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-014")
	now := time.Now().UTC()
	p := testProcess(602, false, "PACKAGE_MANAGED")
	p.Name = "java"
	mem := processes.ExecutionMemoryContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", RegionsObserved: 30, ExecutableRegions: 9, WritableExecutableRegions: 2, AnonymousExecutableRegions: 2, JITLikeContext: true, JITBasis: []string{"java-runtime"}, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.memory."+p.ID, mem, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn {
		t.Fatalf("JIT-context W+X mapping should be contextual warning: %#v", findings[0])
	}
}

func TestAnonymousExecutableMemoryRuleWarnsWithoutMalwareLabel(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-015")
	now := time.Now().UTC()
	p := testProcess(603, false, "PACKAGE_MANAGED")
	mem := processes.ExecutionMemoryContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", RegionsObserved: 10, ExecutableRegions: 2, AnonymousExecutableRegions: 1, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.memory."+p.ID, mem, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("anonymous executable mapping should warn for review: %#v", findings[0])
	}
}

func TestExecutableMemoryRulesPreserveUnsupportedPlatform(t *testing.T) {
	now := time.Now().UTC()
	p := testProcess(604, false, "SIGNED_VALID")
	mem := processes.ExecutionMemoryContext{ProcessID: p.ID, PID: p.PID, Platform: "darwin", State: "UNSUPPORTED", Source: "test", Confidence: evidence.ConfidenceExact, Reason: "provider unavailable"}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "darwin", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.memory."+p.ID, mem, "test", now, evidence.ConfidenceExact),
	}
	for _, id := range []string{"CHM-PRC-014", "CHM-PRC-015"} {
		r := mustRule(t, ProcessRules(), id)
		findings, err := EvaluateRules([]Rule{r}, obs, now)
		if err != nil {
			t.Fatal(err)
		}
		if findings[0].Status != StatusPass || findings[0].Applicability != NotApplicable {
			t.Fatalf("%s should preserve unsupported provider as not applicable: %#v", id, findings[0])
		}
	}
}

func TestLoadedModuleTrustRuleFailsOnDeletedBacking(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-016")
	now := time.Now().UTC()
	p := testProcess(701, true, "PACKAGE_MANAGED")
	mods := processes.LoadedModuleContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", ModuleCount: 1, DeletedMappings: 1,
		Modules: []processes.LoadedModule{{Path: "/usr/lib/libbad.so", Name: "libbad.so", DeletedBacking: true, TrustState: "UNKNOWN", TrustBasis: "test", DirectoryState: "OBSERVED", Source: "test", Confidence: evidence.ConfidenceHigh}},
		Source:  "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.modules."+p.ID, mods, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("deleted module backing was not failed: %#v", findings[0])
	}
}

func TestLoadedModuleWritableLocationFailsForPrivilegedProcess(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-017")
	now := time.Now().UTC()
	p := testProcess(702, true, "SIGNED_VALID")
	mods := processes.LoadedModuleContext{
		ProcessID: p.ID, PID: p.PID, Platform: "windows", State: "OBSERVED", ModuleCount: 1, WritableLocationModules: 1,
		Modules: []processes.LoadedModule{{Path: `C:\Users\Public\plugin.dll`, Name: "plugin.dll", TrustState: "SIGNED_VALID", TrustBasis: "test", DirectoryState: "WEAK", DirectoryWritable: true, Source: "test", Confidence: evidence.ConfidenceHigh}},
		Source:  "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "windows", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.modules."+p.ID, mods, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("privileged writable module location was not failed: %#v", findings[0])
	}
}

func TestLoadedModuleProvenanceMismatchWarnsForStandardProcess(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-018")
	now := time.Now().UTC()
	p := testProcess(703, false, "PACKAGE_MANAGED")
	mods := processes.LoadedModuleContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", ModuleCount: 1, TrustMismatches: 1,
		Modules: []processes.LoadedModule{{Path: "/opt/local/plugin.so", Name: "plugin.so", TrustState: "UNMANAGED", TrustBasis: "test", DirectoryState: "OBSERVED", TrustMismatch: true, Source: "test", Confidence: evidence.ConfidenceHigh}},
		Source:  "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.modules."+p.ID, mods, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn {
		t.Fatalf("standard-process provenance mismatch should warn: %#v", findings[0])
	}
}

func TestPrivilegedRuntimeEnvironmentRuleFailsOnLoaderHook(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-019")
	now := time.Now().UTC()
	p := testProcess(801, true, "SIGNED_VALID")
	env := processes.RuntimeEnvironmentContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", Posture: "HIGH_RISK_HOOKS_PRESENT", RelevantVariables: 1, LoaderHooks: 1, HighRiskIndicators: 1, ValuesRedacted: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.environment."+p.ID, env, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("privileged loader hook should fail: %#v", findings[0])
	}
}

func TestSensitiveRuntimeEnvironmentRuleWarnsForNonPrivilegedSSHD(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-020")
	now := time.Now().UTC()
	p := testProcess(802, false, "PACKAGE_MANAGED")
	p.Name = "sshd"
	env := processes.RuntimeEnvironmentContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", Posture: "OVERRIDES_PRESENT", DebugControls: 1, RelevantVariables: 1, ValuesRedacted: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.environment."+p.ID, env, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn {
		t.Fatalf("non-privileged sensitive debug control should warn: %#v", findings[0])
	}
}

func TestUnsafeRuntimeSearchPathRuleFailsPrivilegedWeakComponent(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-021")
	now := time.Now().UTC()
	p := testProcess(803, true, "PACKAGE_MANAGED")
	env := processes.RuntimeEnvironmentContext{
		ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", Posture: "HIGH_RISK_HOOKS_PRESENT", RelevantVariables: 1, HighRiskIndicators: 1, ValuesRedacted: true, Source: "test", Confidence: evidence.ConfidenceHigh,
		Indicators: []processes.EnvironmentIndicator{{Name: "LD_LIBRARY_PATH", Category: "LOADER_PATH", RiskClass: "HIGH", NonEmpty: true, ComponentCount: 2, RelativeComponents: 1, TemporaryComponents: 1}},
	}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.environment."+p.ID, env, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("privileged weak runtime search path should fail: %#v", findings[0])
	}
}

func TestUncontainedHighRiskRuntimeRuleFailsPrivilegedHostContext(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-022")
	now := time.Now().UTC()
	p := testProcess(804, true, "SIGNED_VALID")
	env := processes.RuntimeEnvironmentContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", Posture: "HIGH_RISK_HOOKS_PRESENT", LoaderHooks: 1, HighRiskIndicators: 1, ValuesRedacted: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	iso := processes.IsolationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", State: "OBSERVED", IsolationState: "HOST", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.environment."+p.ID, env, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.isolation."+p.ID, iso, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("privileged high-risk hook in host context should fail: %#v", findings[0])
	}
}

func TestCompoundPrivilegedRuntimeBoundaryRuleFailsTwoIndependentWeaknesses(t *testing.T) {
	r := mustRule(t, ProcessRules(), "CHM-PRC-023")
	now := time.Now().UTC()
	p := testProcess(805, true, "SIGNATURE_UNTRUSTED")
	loc := processes.LocationContext{ProcessID: p.ID, PID: p.PID, Platform: "linux", Path: "/tmp/tool", State: "WEAK", Temporary: true, UserWritable: true, WeakControl: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+p.ID, p, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+p.ID, loc, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("compound privileged runtime weakness should fail: %#v", findings[0])
	}
}

func TestFix65PrivilegedUserspaceRulesExcludeLinuxKernelThreads(t *testing.T) {
	now := time.Now().UTC()
	kthreadd := testProcess(2, true, "UNKNOWN")
	kthreadd.PPID = 0
	kthreadd.Executable = "kthreadd"
	kthreadd.ExecutablePath = ""
	kthreadd.CollectionSource = "Linux procfs"
	kthreadd.CommandLine = processes.CommandLineMetadata{Available: true, ArgumentCount: 0, ByteCount: 0, Redacted: true, Source: "Linux procfs"}
	worker := testProcess(50, true, "UNKNOWN")
	worker.PPID = 2
	worker.Executable = "kworker/0:1"
	worker.ExecutablePath = ""
	worker.CollectionSource = "Linux procfs"
	worker.CommandLine = processes.CommandLineMetadata{Available: true, ArgumentCount: 0, ByteCount: 0, Redacted: true, Source: "Linux procfs"}
	user := testProcess(900, true, "PACKAGE_MANAGED")
	user.CollectionSource = "Linux procfs"

	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 3, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+kthreadd.ID, kthreadd, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.item."+worker.ID, worker, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.item."+user.ID, user, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+kthreadd.ID, processes.LocationContext{ProcessID: kthreadd.ID, PID: kthreadd.PID, Platform: "linux", State: "UNKNOWN", Source: "test", Confidence: evidence.ConfidenceLow}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+worker.ID, processes.LocationContext{ProcessID: worker.ID, PID: worker.PID, Platform: "linux", State: "UNKNOWN", Source: "test", Confidence: evidence.ConfidenceLow}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.location."+user.ID, processes.LocationContext{ProcessID: user.ID, PID: user.PID, Platform: "linux", Path: user.ExecutablePath, State: "CONTROLLED", Source: "test", Confidence: evidence.ConfidenceHigh}, "test", now, evidence.ConfidenceHigh),
	}
	for _, id := range []string{"CHM-PRC-003", "CHM-PRC-006"} {
		r := mustRule(t, ProcessRules(), id)
		findings, err := EvaluateRules([]Rule{r}, obs, now)
		if err != nil {
			t.Fatal(err)
		}
		if findings[0].Status != StatusPass {
			t.Fatalf("%s should assess the userspace executable set without kernel-thread UNKNOWN inflation: %#v", id, findings[0])
		}
	}
}

func TestFix65LifecycleExitedProcessIsNotUnknownVoteForModuleOrEnvironmentRules(t *testing.T) {
	now := time.Now().UTC()
	live := testProcess(910, true, "PACKAGE_MANAGED")
	live.CollectionSource = "Linux procfs"
	gone := testProcess(911, true, "PACKAGE_MANAGED")
	gone.CollectionSource = "Linux procfs"
	modsLive := processes.LoadedModuleContext{ProcessID: live.ID, PID: live.PID, Platform: "linux", State: "OBSERVED", Source: "/proc/<pid>/maps", Confidence: evidence.ConfidenceHigh}
	modsGone := processes.LoadedModuleContext{ProcessID: gone.ID, PID: gone.PID, Platform: "linux", State: "UNKNOWN", Source: "Linux procfs lifecycle-aware loaded-module metadata", Confidence: evidence.ConfidenceExact, Reason: "process exited before loaded-module enrichment completed"}
	envLive := processes.RuntimeEnvironmentContext{ProcessID: live.ID, PID: live.PID, Platform: "linux", State: "OBSERVED", Posture: "NONE", ValuesRedacted: true, Source: "/proc/<pid>/environ redacted metadata", Confidence: evidence.ConfidenceHigh}
	envGone := processes.RuntimeEnvironmentContext{ProcessID: gone.ID, PID: gone.PID, Platform: "linux", State: "UNKNOWN", Posture: "UNKNOWN", ValuesRedacted: true, Source: "Linux procfs lifecycle-aware environment metadata", Confidence: evidence.ConfidenceExact, Reason: "process exited before environment enrichment completed"}
	obs := []evidence.Observation{
		evidence.NewObserved("process.platform", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", 2, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.item."+live.ID, live, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.item."+gone.ID, gone, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.modules."+live.ID, modsLive, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.modules."+gone.ID, modsGone, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("process.environment."+live.ID, envLive, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("process.environment."+gone.ID, envGone, "test", now, evidence.ConfidenceExact),
	}
	for _, id := range []string{"CHM-PRC-017", "CHM-PRC-019"} {
		r := mustRule(t, ProcessRules(), id)
		findings, err := EvaluateRules([]Rule{r}, obs, now)
		if err != nil {
			t.Fatal(err)
		}
		if findings[0].Status != StatusPass {
			t.Fatalf("%s should ignore a normalized exited-PID lifecycle record while retaining it in raw evidence: %#v", id, findings[0])
		}
	}
}

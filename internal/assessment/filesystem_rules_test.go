package assessment

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestPhase075FilesystemRulesDetectUntrustedWritableExecutable(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.ExecutableRecord{ID: "x", Path: "/tmp/x", Directory: "/tmp", State: evidence.StateObserved, Exists: true, Regular: true, Executable: true, PermissionModel: "POSIX_MODE", OtherWritable: true, BroadlyWritable: true, UntrustedWrite: true, WritePrincipals: []string{"other"}, DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.executable-permissions", fsinv.SourceStatus{ID: "executable-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.executable.x", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range findings {
		if f.RuleID == "CHM-FS-001" {
			found = true
			if f.Status != StatusFail || f.Severity != SeverityHigh {
				t.Fatalf("unexpected CHM-FS-001 finding: %#v", f)
			}
		}
	}
	if !found {
		t.Fatal("CHM-FS-001 missing")
	}
}

func TestPhase075FilesystemRulesWarnOnNonSystemGroupWritableExecutable(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.ExecutableRecord{ID: "g", Path: "/usr/local/bin/g", Directory: "/usr/local/bin", State: evidence.StateObserved, Exists: true, Regular: true, Executable: true, PermissionModel: "POSIX_MODE", GroupID: "1000", GroupWritable: true, BroadlyWritable: true, WritePrincipals: []string{"group:1000"}, DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("filesystem.source.executable-permissions", fsinv.SourceStatus{ID: "executable-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.executable.g", rec, "test", now, evidence.ConfidenceHigh),
	})
	rules := FilesystemRules()
	ev := rules[1].Evaluate(idx)
	if ev.Status != StatusWarn || ev.Applicability != Applicable {
		t.Fatalf("unexpected group-write evaluation: %#v", ev)
	}
}

func TestImplementedRulesIncludesFilesystemRulesExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		if strings.HasPrefix(r.ID, "CHM-FS-") {
			counts[r.ID]++
		}
	}
	for _, id := range []string{"CHM-FS-001", "CHM-FS-002", "CHM-FS-003", "CHM-FS-004", "CHM-FS-005", "CHM-FS-006", "CHM-FS-007", "CHM-FS-008", "CHM-FS-009", "CHM-FS-010", "CHM-FS-011", "CHM-FS-012", "CHM-FS-013", "CHM-FS-014", "CHM-FS-015", "CHM-FS-016", "CHM-FS-017", "CHM-FS-018", "CHM-FS-019", "CHM-FS-020"} {
		if counts[id] != 1 {
			t.Fatalf("filesystem rule counts: %#v", counts)
		}
	}
}

func TestPhase076FilesystemRulesDetectWeakPrivilegedSearchPath(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.SearchPathRecord{ID: "sp1", Path: "/usr/local/bin", State: evidence.StateObserved, Exists: true, Directory: true, PermissionModel: "POSIX_MODE", UntrustedWrite: true, WritePrincipals: []string{"other"}, Contexts: []string{"PRIVILEGED_USER", "SERVICE"}, DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.privileged-search-paths", fsinv.SourceStatus{ID: "privileged-search-paths", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.search_path.sp1", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-003"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-003 finding: %#v", f)
	}
}

func TestPhase076FilesystemRulesDetectWeakLoaderSearchPath(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.SearchPathRecord{ID: "sp2", Path: "/usr/lib", State: evidence.StateObserved, Exists: true, Directory: true, PermissionModel: "POSIX_MODE", UntrustedWrite: true, Contexts: []string{"LOADER", "SYSTEM_COMPONENT"}, DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.privileged-search-paths", fsinv.SourceStatus{ID: "privileged-search-paths", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.search_path.sp2", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-004"]; f.Status != StatusFail || f.Severity != SeverityCritical {
		t.Fatalf("unexpected CHM-FS-004 finding: %#v", f)
	}
}

func TestPhase077FilesystemRulesDetectUnexpectedSetIDExecutable(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.PrivilegedFileRecord{
		ID: "pf1", Path: "/usr/local/bin/admin-helper", State: evidence.StateObserved,
		Exists: true, Regular: true, Executable: true, SetUID: true, OwnerID: "0", GroupID: "0",
		PackageOwnership: "UNKNOWN", Classification: "CUSTOM_OR_UNEXPECTED", ReviewRequired: true,
		ReviewReasons: []string{"custom path"}, DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.linux-privileged-files", fsinv.SourceStatus{ID: "linux-privileged-files", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.privileged_executable.pf1", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-005"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-005 finding: %#v", f)
	}
}

func TestPhase077FilesystemRulesDetectUnexpectedFileCapabilityExecutable(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.PrivilegedFileRecord{
		ID: "pf2", Path: "/opt/custom/net-helper", State: evidence.StateObserved,
		Exists: true, Regular: true, Executable: true, Capabilities: []string{"CAP_NET_ADMIN"},
		PackageOwnership: "UNMANAGED", Classification: "CUSTOM_OR_UNEXPECTED", ReviewRequired: true,
		ReviewReasons: []string{"native package database reports no owning package"}, DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.linux-privileged-files", fsinv.SourceStatus{ID: "linux-privileged-files", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.privileged_executable.pf2", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-006"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-006 finding: %#v", f)
	}
}

func TestPhase077FilesystemRulesNotApplicableOutsideLinux(t *testing.T) {
	now := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewState("filesystem.source.linux-privileged-files", evidence.StateNotApplicable, "test", now, evidence.ConfidenceHigh, "not Linux"),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-FS-005" || f.RuleID == "CHM-FS-006" {
			if f.Status != StatusPass || f.Applicability != NotApplicable {
				t.Fatalf("expected not-applicable rule, got %#v", f)
			}
		}
	}
}

func TestPhase078FilesystemRulesDetectSensitiveWorldWrite(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.SensitiveFileRecord{
		ID: "sf1", Kind: "SSH_CONFIG", Scope: "SYSTEM", Path: "/etc/ssh/sshd_config", AccessPolicy: fsinv.SensitivePolicyWriteRestricted,
		State: evidence.StateObserved, Exists: true, OwnerID: "0", ExpectedOwnerID: "0", OwnerState: fsinv.SensitiveOwnerExpected,
		PermissionModel: "POSIX_MODE", OtherWritable: true, BroadlyWritable: true, UntrustedWrite: true, WritePrincipals: []string{"other"},
		DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.sensitive-file-permissions", fsinv.SourceStatus{ID: "sensitive-file-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.sensitive_file.sf1", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-007"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-007 finding: %#v", f)
	}
}

func TestPhase078FilesystemRulesDetectPrivateKeyBroadRead(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.SensitiveFileRecord{
		ID: "sf2", Kind: "PRIVATE_KEY", Scope: "USER", Path: "/home/alice/.ssh/id_ed25519", AccessPolicy: fsinv.SensitivePolicyOwnerOnly,
		State: evidence.StateObserved, Exists: true, OwnerID: "1000", ExpectedOwnerID: "1000", OwnerState: fsinv.SensitiveOwnerExpected,
		PermissionModel: "POSIX_MODE", OtherAccessible: true, BroadlyAccessible: true, UntrustedAccess: true, ReadPrincipals: []string{"other"},
		DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.sensitive-file-permissions", fsinv.SourceStatus{ID: "sensitive-file-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.sensitive_file.sf2", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-008"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-008 finding: %#v", f)
	}
}

func TestPhase078FilesystemRulesDetectSensitiveOwnerMismatch(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.SensitiveFileRecord{
		ID: "sf3", Kind: "SUDO_CONFIG", Scope: "SYSTEM", Path: "/etc/sudoers", AccessPolicy: fsinv.SensitivePolicyWriteRestricted,
		State: evidence.StateObserved, Exists: true, OwnerID: "1000", ExpectedOwnerID: "0", OwnerState: fsinv.SensitiveOwnerUnexpected,
		PermissionModel: "POSIX_MODE", DiscoverySource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.sensitive-file-permissions", fsinv.SourceStatus{ID: "sensitive-file-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.sensitive_file.sf3", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-009"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-009 finding: %#v", f)
	}
}

func TestPhase079FilesystemRulesDetectBroadACLWrite(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.ACLBoundaryRecord{
		ID: "acl1", Path: "/etc/ssh/sshd_config", Contexts: []string{"SENSITIVE_CONFIG"}, State: evidence.StateObserved,
		Exists: true, ACLModel: "POSIX_ACL", HasExtendedACL: true, DangerousBroadWrite: true,
		DangerousPrincipals: []string{"other"}, DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
		Grants: []fsinv.ACLGrant{{Principal: "other", PrincipalClass: "OTHER", Access: fsinv.ACLGrantAllow, Rights: []string{"WRITE"}, Effective: true, Broad: true, WriteLike: true}},
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.acl-boundaries", fsinv.SourceStatus{ID: "acl-boundaries", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.acl_boundary.acl1", rec, "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-010"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-010 finding: %#v", f)
	}
}

func TestPhase079FilesystemRulesWarnOnNamedACLWriter(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.ACLBoundaryRecord{
		ID: "acl2", Path: "/usr/local/bin", Contexts: []string{"PRIVILEGED_SEARCH_PATH"}, State: evidence.StateObserved,
		Exists: true, Directory: true, ACLModel: "POSIX_ACL", HasExtendedACL: true, ReviewWriteGrant: true,
		ReviewPrincipals: []string{"user:1001"}, DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
		Grants: []fsinv.ACLGrant{{Principal: "user:1001", PrincipalID: "1001", PrincipalClass: "NAMED_USER", Access: fsinv.ACLGrantAllow, Rights: []string{"WRITE"}, Effective: true, WriteLike: true}},
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.acl-boundaries", fsinv.SourceStatus{ID: "acl-boundaries", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.acl_boundary.acl2", rec, "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-011"]; f.Status != StatusWarn || f.Severity != SeverityMedium {
		t.Fatalf("unexpected CHM-FS-011 finding: %#v", f)
	}
}

func TestPhase079FilesystemRulesRemainUnknownWhenACLProviderDegrades(t *testing.T) {
	now := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewState("filesystem.source.acl-boundaries", evidence.StateDegraded, "test", now, evidence.ConfidenceMedium, "partial ACL visibility"),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-FS-010" || f.RuleID == "CHM-FS-011" {
			if f.Status != StatusUnknown {
				t.Fatalf("expected UNKNOWN for degraded ACL provider, got %#v", f)
			}
		}
	}
}

func TestPhase080FilesystemRulesDetectUnsafeSharedTemp(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.TempDirectoryRecord{
		ID: "tmp1", Path: "/tmp", Scope: fsinv.TempScopeSharedSystem, State: evidence.StateObserved,
		Exists: true, Directory: true, PermissionModel: "POSIX_MODE", Shared: true, OtherWritable: true,
		BroadCreate: true, BroadlyWritable: true, TrustedOwner: true, TrustedOwnerKnown: true, UnsafePermissions: true,
		DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.temporary-directory-security", fsinv.SourceStatus{ID: "temporary-directory-security", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.temp_directory.tmp1", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-012"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-012 finding: %#v", f)
	}
}

func TestPhase080FilesystemRulesAcceptStickySharedTemp(t *testing.T) {
	now := time.Now().UTC()
	rec := fsinv.TempDirectoryRecord{
		ID: "tmp2", Path: "/tmp", Scope: fsinv.TempScopeSharedSystem, State: evidence.StateObserved,
		Exists: true, Directory: true, PermissionModel: "POSIX_MODE", Shared: true, OtherWritable: true,
		StickyBit: true, BroadCreate: true, BroadlyWritable: true, TrustedOwner: true, TrustedOwnerKnown: true,
		ParentPath: "/", ParentState: evidence.StateObserved, ParentTrustedOwner: true, ParentTrustKnown: true,
		DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.temporary-directory-security", fsinv.SourceStatus{ID: "temporary-directory-security", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.temp_directory.tmp2", rec, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-FS-012" && f.Status != StatusPass {
			t.Fatalf("expected PASS, got %#v", f)
		}
	}
}

func TestPhase080FilesystemRulesDetectPrivilegedServiceArtifactInTemp(t *testing.T) {
	now := time.Now().UTC()
	tmp := fsinv.TempDirectoryRecord{ID: "tmp3", Path: "/tmp", Scope: fsinv.TempScopeSharedSystem, State: evidence.StateObserved, Exists: true, Directory: true, PermissionModel: "POSIX_MODE", Shared: true, StickyBit: true, TrustedOwner: true, TrustedOwnerKnown: true, DiscoverySources: []string{"test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	svc := services.Service{ID: "svc1", Name: "root-helper", Manager: "systemd", ExecutablePath: "/tmp/root-helper", Account: "root", StartMode: "ENABLED", RuntimeState: "RUNNING", PrivilegeContext: "ROOT", ConfigurationSource: "test", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.source.temporary-directory-security", fsinv.SourceStatus{ID: "temporary-directory-security", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.temp_directory.tmp3", tmp, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("service.item.svc1", svc, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(FilesystemRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if f := byID["CHM-FS-013"]; f.Status != StatusFail || f.Severity != SeverityHigh {
		t.Fatalf("unexpected CHM-FS-013 finding: %#v", f)
	}
}

func phase082POSIXMountEvidence(now time.Time, mounts ...fsinv.MountBoundary) []evidence.Observation {
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.permission_capability", fsinv.PermissionCapability{State: evidence.StateObserved, Model: "POSIX_MODE", Source: "test"}, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("filesystem.source.mount-boundaries", fsinv.SourceStatus{ID: "mount-boundaries", State: evidence.StateObserved, Source: "test", ItemCount: len(mounts)}, "test", now, evidence.ConfidenceHigh),
	}
	for i, m := range mounts {
		if m.ID == "" {
			m.ID = fmt.Sprintf("m%d", i)
		}
		if m.State == "" {
			m.State = evidence.StateObserved
		}
		if m.Confidence == "" {
			m.Confidence = evidence.ConfidenceExact
		}
		if m.CollectionSource == "" {
			m.CollectionSource = "test"
		}
		obs = append(obs, evidence.NewObserved("filesystem.mount."+m.ID, m, "test", now, m.Confidence))
	}
	return obs
}

func phase082Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range FilesystemRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestPhase082NosuidDetectsRemovableMount(t *testing.T) {
	now := time.Now().UTC()
	m := fsinv.MountBoundary{ID: "usb", Path: "/media/usb", BackingSource: "/dev/sdb1", Filesystem: "ext4", Options: []string{"rw", "nodev", "noexec"}, AccessMode: fsinv.MountAccessReadWrite, Classification: fsinv.MountClassRemovable, Removable: true, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	idx := NewIndex(phase082POSIXMountEvidence(now, m))
	r := phase082Rule(t, "CHM-FS-014")
	got := r.EvaluateProfile("workstation", idx)
	if got.Status != StatusFail || got.Applicability != Applicable || !strings.Contains(got.ObservedState, "nosuid") {
		t.Fatalf("unexpected nosuid evaluation: %#v", got)
	}
}

func TestPhase082NodevPassesWhenPresent(t *testing.T) {
	now := time.Now().UTC()
	m := fsinv.MountBoundary{ID: "share", Path: "/mnt/share", BackingSource: "server:/data", Filesystem: "nfs4", Options: []string{"rw", "nosuid", "nodev"}, AccessMode: fsinv.MountAccessReadWrite, Classification: fsinv.MountClassNetwork, Network: true, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	idx := NewIndex(phase082POSIXMountEvidence(now, m))
	r := phase082Rule(t, "CHM-FS-015")
	got := r.EvaluateProfile("server", idx)
	if got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("unexpected nodev evaluation: %#v", got)
	}
}

func TestPhase082NoexecIsProfileAwareForTemporaryMount(t *testing.T) {
	now := time.Now().UTC()
	m := fsinv.MountBoundary{ID: "tmp", Path: "/tmp", BackingSource: "tmpfs", Filesystem: "tmpfs", Options: []string{"rw", "nosuid", "nodev"}, AccessMode: fsinv.MountAccessReadWrite, Classification: fsinv.MountClassVirtual, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	idx := NewIndex(phase082POSIXMountEvidence(now, m))
	r := phase082Rule(t, "CHM-FS-016")
	if got := r.EvaluateProfile("developer", idx); got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("developer profile should not require noexec on temporary mount: %#v", got)
	}
	if got := r.EvaluateProfile("high-security", idx); got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("high-security profile should require noexec on temporary mount: %#v", got)
	}
}

func TestPhase082MountHardeningNotApplicableToWindowsVolumeSemantics(t *testing.T) {
	now := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.permission_capability", fsinv.PermissionCapability{State: evidence.StateObserved, Model: "NTFS_DACL", Source: "test"}, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("filesystem.source.mount-boundaries", fsinv.SourceStatus{ID: "mount-boundaries", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.mount.c", fsinv.MountBoundary{ID: "c", Path: `C:\\`, BackingSource: "C:", Filesystem: "NTFS", Options: []string{"drive_type:3"}, AccessMode: fsinv.MountAccessUnknown, Classification: fsinv.MountClassLocal, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}, "test", now, evidence.ConfidenceExact),
	}
	idx := NewIndex(obs)
	for _, id := range []string{"CHM-FS-014", "CHM-FS-015", "CHM-FS-016"} {
		got := phase082Rule(t, id).EvaluateProfile("high-security", idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable {
			t.Fatalf("%s should be not applicable to NTFS/DACL volume semantics: %#v", id, got)
		}
	}
}

func TestPhase082HighSecurityExtendsNosuidToDedicatedUserDataMount(t *testing.T) {
	now := time.Now().UTC()
	m := fsinv.MountBoundary{ID: "home", Path: "/home", BackingSource: "/dev/mapper/home", Filesystem: "ext4", Options: []string{"rw", "nodev"}, AccessMode: fsinv.MountAccessReadWrite, Classification: fsinv.MountClassLocal, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	idx := NewIndex(phase082POSIXMountEvidence(now, m))
	r := phase082Rule(t, "CHM-FS-014")
	if got := r.EvaluateProfile("default", idx); got.Status != StatusPass {
		t.Fatalf("default profile should not blanket-require nosuid on /home: %#v", got)
	}
	if got := r.EvaluateProfile("high-security", idx); got.Status != StatusFail {
		t.Fatalf("high-security profile should require nosuid on dedicated user-data mount: %#v", got)
	}
}

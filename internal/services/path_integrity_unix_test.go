//go:build linux || darwin

package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestPhase047UnixPrivilegedServicePathIntegrityDetectsWritableBoundary(t *testing.T) {
	root := t.TempDir()
	execDir := filepath.Join(root, "exec")
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(execDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// umask can mask Mkdir permissions; set the intended test posture explicitly.
	if err := os.Chmod(execDir, 0o777); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(execDir, "demo")
	cfg := filepath.Join(configDir, "demo.service")
	if err := os.WriteFile(exe, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	pi := unixServicePathIntegrity(Service{
		Name: "demo.service", Manager: "systemd", ExecutablePath: exe, DefinitionPath: cfg,
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if !pi.Privileged || pi.PrivilegeBasis != "ROOT" {
		t.Fatalf("expected privileged root correlation, got %#v", pi)
	}
	if !pi.ExecutableDirectory.LowerPrivilegeWritable || !pi.SearchPathWritable {
		t.Fatalf("expected writable executable/search boundary, got %#v", pi)
	}
	// Test files inherit the UID of the user running `go test`. For a root
	// service, a non-root-owned configuration is correctly a weak boundary
	// even when its mode is 0644/0755 because that owner can still modify it
	// (or its containing directory when applicable). A root-run test fixture
	// is expected to remain trusted.
	expectConfigWeak := os.Getuid() != 0
	if pi.Configuration.LowerPrivilegeWritable != expectConfigWeak || pi.ConfigurationDirectory.LowerPrivilegeWritable != expectConfigWeak {
		t.Fatalf("configuration ownership/write posture did not match fixture privilege: uid=%d posture=%#v", os.Getuid(), pi)
	}
	if err := pi.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPhase047UnixDoesNotPromoteNonPrivilegedService(t *testing.T) {
	pi := unixServicePathIntegrity(Service{
		Name: "demo.service", Manager: "systemd", ExecutablePath: "/tmp/demo", DefinitionPath: "/tmp/demo.service",
		Account: "svc", PrivilegeContext: "SERVICE_ACCOUNT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.Privileged {
		t.Fatalf("ordinary service account must not be promoted to root-equivalent: %#v", pi)
	}
}

func TestFix62MaskedSystemdUnitDoesNotDegradeMissingExecutable(t *testing.T) {
	pi := unixServicePathIntegrity(Service{
		Name: "masked.service", Manager: "systemd", StartMode: "masked",
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.State != "COMPLETE" || pi.Executable.State != "NOT_APPLICABLE" || pi.ExecutableDirectory.State != "NOT_APPLICABLE" || pi.SearchPathState != "NOT_APPLICABLE" {
		t.Fatalf("masked systemd unit should have no executable path boundary: %#v", pi)
	}
}

func TestFix62GeneratedSystemdUnitWithoutFragmentDoesNotDegradeConfiguration(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "demo")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	pi := unixServicePathIntegrity(Service{
		Name: "generated.service", Manager: "systemd", StartMode: "generated", ExecutablePath: exe,
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.Configuration.State != "NOT_APPLICABLE" || pi.ConfigurationDirectory.State != "NOT_APPLICABLE" {
		t.Fatalf("generated systemd service without a fragment should have no file-backed config boundary: %#v", pi)
	}
}

func TestFix62UnixPathPostureSpecialSymlinkDoesNotTreatDeviceIOAsReplacement(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "masked.service")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Skipf("cannot create /dev/null symlink fixture: %v", err)
	}
	p := unixPathPosture(link)
	if p.State != "OBSERVED" || p.LowerPrivilegeWritable {
		t.Fatalf("special symlink target I/O mode must not imply service-definition replacement: %#v", p)
	}
	if p.Reason == "" {
		t.Fatalf("expected explicit special-target explanation: %#v", p)
	}
}

func TestFix63EffectiveSystemdNoLifecycleExecutableIsNotApplicable(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "metadata-only.service")
	if err := os.WriteFile(cfg, []byte("[Service]\nType=oneshot\nRemainAfterExit=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pi := unixServicePathIntegrity(Service{
		Name: "metadata-only.service", Manager: "systemd", ServiceType: "oneshot",
		StartMode: "static", RuntimeState: "STOPPED", DefinitionState: "loaded", DefinitionPath: cfg,
		Account: "root", PrivilegeContext: "ROOT", CollectionSource: "systemctl show", Confidence: evidence.ConfidenceHigh,
	})
	if pi.State != "COMPLETE" || pi.Executable.State != "NOT_APPLICABLE" || pi.ExecutableDirectory.State != "NOT_APPLICABLE" || pi.SearchPathState != "NOT_APPLICABLE" {
		t.Fatalf("effective systemd unit with no lifecycle command should have no executable boundary: %#v", pi)
	}
	if pi.Configuration.State != "OBSERVED" {
		t.Fatalf("file-backed unit configuration should remain observed: %#v", pi)
	}
}

func TestFix63EffectiveSystemdLoadedUnitWithoutFragmentIsNotFileBacked(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "demo")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	pi := unixServicePathIntegrity(Service{
		Name: "transient-runtime.service", Manager: "systemd", StartMode: "static", RuntimeState: "RUNNING",
		DefinitionState: "loaded", ExecutablePath: exe, Account: "root", PrivilegeContext: "ROOT",
		CollectionSource: "systemctl show", Confidence: evidence.ConfidenceHigh,
	})
	if pi.State != "COMPLETE" || pi.Configuration.State != "NOT_APPLICABLE" || pi.ConfigurationDirectory.State != "NOT_APPLICABLE" {
		t.Fatalf("effective systemd unit without FragmentPath/SourcePath should be non-file-backed: %#v", pi)
	}
}

func TestFix64SystemdBasenameUsesBoundedManagerSearchPath(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := os.MkdirAll(first, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(second, "demo-command")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := systemdManagerSearchDirs
	systemdManagerSearchDirs = []string{first, second}
	t.Cleanup(func() { systemdManagerSearchDirs = old })

	pi := unixServicePathIntegrity(Service{
		Name: "demo.service", Manager: "systemd", ExecutablePath: "demo-command",
		DefinitionState: "loaded", CollectionSource: "systemctl show",
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.SearchResolution != "RELATIVE" || pi.SearchPathState != "OBSERVED" {
		t.Fatalf("expected observed manager-search resolution: %#v", pi)
	}
	if pi.Executable.Path != exe || pi.Executable.State != "OBSERVED" {
		t.Fatalf("expected resolved executable posture for %q: %#v", exe, pi)
	}
	if pi.State != "COMPLETE" {
		t.Fatalf("resolved manager search must not degrade provider health: %#v", pi)
	}
}

func TestFix64AbsentSystemdBasenameKeepsSearchBoundaryObserved(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := systemdManagerSearchDirs
	systemdManagerSearchDirs = []string{dir}
	t.Cleanup(func() { systemdManagerSearchDirs = old })

	pi := unixServicePathIntegrity(Service{
		Name: "stale.service", Manager: "systemd", ExecutablePath: "definitely-not-present",
		DefinitionState: "loaded", CollectionSource: "systemctl show",
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.SearchResolution != "RELATIVE" || pi.SearchPathState != "OBSERVED" {
		t.Fatalf("expected manager search directories to remain observed: %#v", pi)
	}
	if pi.Executable.State != "NOT_APPLICABLE" || pi.ExecutableDirectory.State != "NOT_APPLICABLE" {
		t.Fatalf("absent manager-search command should have no current file boundary: %#v", pi)
	}
	if pi.State != "COMPLETE" {
		t.Fatalf("observed command absence must not be mislabeled as collector degradation: %#v", pi)
	}
}

func TestFix64AbsentAbsoluteServiceExecutableUsesParentBoundary(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing-service-binary")
	pi := unixServicePathIntegrity(Service{
		Name: "stale-absolute.service", Manager: "systemd", ExecutablePath: missing,
		DefinitionState: "loaded", CollectionSource: "systemctl show",
		Account: "root", PrivilegeContext: "ROOT", Confidence: evidence.ConfidenceHigh,
	})
	if pi.Executable.State != "NOT_APPLICABLE" {
		t.Fatalf("absent absolute executable should be an observed applicability condition: %#v", pi)
	}
	if pi.ExecutableDirectory.State != "OBSERVED" || pi.SearchPathState != "OBSERVED" {
		t.Fatalf("containing-directory creation boundary should remain observed: %#v", pi)
	}
	if pi.State != "COMPLETE" {
		t.Fatalf("missing executable with observed parent boundary must not degrade provider health: %#v", pi)
	}
}

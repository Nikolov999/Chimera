//go:build linux || darwin

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestPhase097UnixPathIntegrityDetectsOtherWritableTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "startup.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	p := inspectUnixPersistencePath(path)
	if p.State != evidence.StateObserved || !p.Exists || !p.UntrustedWrite || !p.BroadlyWritable {
		t.Fatalf("unexpected posture: %#v", p)
	}
}

func TestPhase097NormalizePathIntegrityPreservesUnknown(t *testing.T) {
	na := pathNotApplicable("test")
	p := normalizePathIntegrity(PathIntegrity{Privileged: true, PrivilegeBasis: "ROOT", Executable: PathPosture{Path: "/root/demo", State: evidence.StateUnavailable, CollectionSource: "test", Confidence: evidence.ConfidenceMedium, Reason: "permission denied"}, ExecutableDirectory: na, ReferencedScript: na, ReferencedScriptDirectory: na, Definition: na, DefinitionDirectory: na})
	if p.State != evidence.StateDegraded || len(p.Degraded) == 0 {
		t.Fatalf("unexpected path integrity: %#v", p)
	}
}

func TestFix63XDGExecutableBasenameUsesBoundedSystemSearchPath(t *testing.T) {
	e := Entry{Mechanism: "XDG_AUTOSTART", Manager: "xdg-autostart", ExecutablePath: "sh"}
	p := fillUnixExecutablePosture(e, PathPosture{})
	if p.State != evidence.StateObserved || !filepath.IsAbs(p.Path) || !p.Exists {
		t.Fatalf("XDG command basename should resolve through bounded system search path: %#v", p)
	}
	if !strings.Contains(p.Reason, "XDG Exec command resolved") {
		t.Fatalf("expected explicit XDG resolution provenance: %#v", p)
	}
}

func TestFix63NonXDGRelativeExecutableRemainsUnresolved(t *testing.T) {
	e := Entry{Mechanism: "SYSTEMD_AUTOSTART", Manager: "systemd", ExecutablePath: "sh"}
	p := fillUnixExecutablePosture(e, PathPosture{})
	if p.State != evidence.StateUnavailable || !strings.Contains(p.Reason, "relative persistence executable") {
		t.Fatalf("non-XDG relative command must remain unresolved: %#v", p)
	}
}

func TestFix64PreservesUpstreamServiceExecutableApplicability(t *testing.T) {
	existing := PathPosture{
		Path: "/usr/bin/stale-demo", State: evidence.StateNotApplicable,
		CollectionSource: "service path-integrity metadata", Confidence: evidence.ConfidenceHigh,
		Reason: "configured service executable is not currently present; parent boundary assessed separately",
	}
	e := Entry{Mechanism: "SYSTEMD_SERVICE", Manager: "systemd", ExecutablePath: "/usr/bin/stale-demo"}
	p := fillUnixExecutablePosture(e, existing)
	if p.State != evidence.StateNotApplicable || p.CollectionSource != existing.CollectionSource || p.Reason != existing.Reason {
		t.Fatalf("stronger upstream applicability must survive persistence composition: %#v", p)
	}
}

func TestFix65MissingAbsoluteXDGTargetUsesParentCreationBoundary(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "stale-autostart-target")
	definition := filepath.Join(dir, "demo.desktop")
	if err := os.WriteFile(definition, []byte("[Desktop Entry]\nType=Application\n"), 0644); err != nil {
		t.Fatal(err)
	}
	e := Entry{
		Mechanism: "XDG_AUTOSTART", Manager: "xdg-autostart", Scope: "SYSTEM",
		ExecutablePath: missing, DefinitionPath: definition, PrivilegeContext: "USER",
	}
	fillUnixPathIntegrity(&e)
	if e.PathIntegrity.Executable.State != evidence.StateNotApplicable || !strings.Contains(e.PathIntegrity.Executable.Reason, "not currently present") {
		t.Fatalf("missing absolute XDG target should be applicability-aware: %#v", e.PathIntegrity.Executable)
	}
	if e.PathIntegrity.ExecutableDirectory.State != evidence.StateObserved || e.PathIntegrity.ExecutableDirectory.Path != dir {
		t.Fatalf("XDG parent creation/replacement boundary must remain assessed: %#v", e.PathIntegrity.ExecutableDirectory)
	}
	if e.PathIntegrity.Definition.State != evidence.StateObserved || e.PathIntegrity.State != evidence.StateObserved {
		t.Fatalf("observed XDG definition plus parent boundary should not degrade persistence: %#v", e.PathIntegrity)
	}
}

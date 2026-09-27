//go:build linux || darwin

package processes

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestUnixPermissionNodeDetectsWorldWritablePrivilegedExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	if err := os.WriteFile(path, []byte("x"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	p := Process{Principal: Principal{Elevated: true, UserID: "0", GroupID: "0"}}
	n := unixPermissionNode(path, "EXECUTABLE", p, false)
	if n.State != "OBSERVED" || !n.BroadWrite || !n.UntrustedWrite {
		t.Fatalf("expected world-writable privileged executable weakness: %#v", n)
	}
}

func TestUnixPermissionNodeStickyDirectorySuppressesPeerReplacementForOwner(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	p := Process{Principal: Principal{UserID: strconv.Itoa(os.Getuid()), GroupID: strconv.Itoa(os.Getgid())}}
	n := unixPermissionNode(shared, "DIRECTORY", p, true)
	if n.State != "OBSERVED" || !n.BroadWrite || n.UntrustedWrite {
		t.Fatalf("sticky shared directory should remain broad without proving peer replacement for its owner: %#v", n)
	}
}

func TestUnixPermissionNodeStickyDirectoryOwnedByLowerPrivilegePrincipalIsWeakForRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires a non-root owner to model a lower-privilege directory owner")
	}
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	p := Process{Principal: Principal{Elevated: true, UserID: "0", GroupID: "0"}}
	n := unixPermissionNode(shared, "DIRECTORY", p, true)
	if n.State != "OBSERVED" || !n.BroadWrite || !n.UntrustedWrite {
		t.Fatalf("a sticky directory owned by a lower-privilege principal remains controllable by that owner: %#v", n)
	}
}

func TestCollectPathPermissionsProducesOneContextPerProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := Process{ID: "proc-test", PID: 55, ExecutablePath: path, Principal: Principal{UserID: "0", GroupID: "0", Elevated: true}}
	out := collectPathPermissions(context.Background(), []Process{p}, "linux")
	if len(out) != 1 || out[0].ProcessID != p.ID || out[0].Executable.Path != path {
		t.Fatalf("unexpected permission contexts: %#v", out)
	}
}

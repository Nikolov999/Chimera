//go:build linux || darwin

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestInspectUnixExecutableDetectsWorldAndGroupWrite(t *testing.T) {
	dir := t.TempDir()
	world := filepath.Join(dir, "world-exec")
	group := filepath.Join(dir, "group-exec")
	plain := filepath.Join(dir, "not-exec")
	for _, p := range []string{world, group, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(world, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plain, 0o666); err != nil {
		t.Fatal(err)
	}

	cap := PermissionCapability{State: evidence.StateObserved, Model: "POSIX_MODE", Source: "test"}
	w, ok := inspectUnixExecutable(world, dir, cap)
	if !ok || !w.Executable || !w.OtherWritable || !w.BroadlyWritable || !w.UntrustedWrite {
		t.Fatalf("world-writable executable posture not detected: %#v", w)
	}
	g, ok := inspectUnixExecutable(group, dir, cap)
	if !ok || !g.Executable || !g.GroupWritable || !g.BroadlyWritable {
		t.Fatalf("group-writable executable posture not detected: %#v", g)
	}
	if _, ok := inspectUnixExecutable(plain, dir, cap); ok {
		t.Fatal("non-executable file should not enter executable inventory")
	}
}

func TestCanonicalExecutableDirectoriesCollapsesSymlinkAlias(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "bin")
	if err := os.Symlink(filepath.Join("usr", "bin"), alias); err != nil {
		t.Fatal(err)
	}
	got := canonicalExecutableDirectories([]string{alias, realDir})
	if len(got) != 1 {
		t.Fatalf("canonical dirs = %#v, want one merged-/usr directory", got)
	}
	if got[0] != realDir {
		t.Fatalf("canonical dir = %q, want %q", got[0], realDir)
	}
}

func TestFix62ExecutableDirectoryBoundMatchesGlobalRecordCeiling(t *testing.T) {
	if maxExecutableEntriesPerDirectory != maxExecutables {
		t.Fatalf("per-directory executable examination bound=%d want global record ceiling=%d", maxExecutableEntriesPerDirectory, maxExecutables)
	}
}

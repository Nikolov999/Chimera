//go:build linux || darwin

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestPhase076UnixPrivilegedSearchPathDetectsOtherWritableDirectory(t *testing.T) {
	root := t.TempDir()
	weak := filepath.Join(root, "weak-bin")
	if err := os.Mkdir(weak, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weak, 0o777); err != nil {
		t.Fatal(err)
	}
	rec := inspectUnixSearchPath(searchPathCandidate{Path: weak, Contexts: []string{"PRIVILEGED_USER"}, Source: "test"}, PermissionCapability{State: evidence.StateObserved, Model: "POSIX_MODE", Source: "test"})
	if rec.State != evidence.StateObserved || !rec.Exists || !rec.Directory || !rec.OtherWritable || !rec.UntrustedWrite {
		t.Fatalf("expected weak privileged search directory, got %#v", rec)
	}
}

func TestPhase076SearchPathCandidateNormalizationMergesContexts(t *testing.T) {
	root := t.TempDir()
	got := normalizeSearchPathCandidates([]searchPathCandidate{
		{Path: root, Contexts: []string{"service"}, Source: "a"},
		{Path: root, Contexts: []string{"loader", "service"}, Source: "b"},
	})
	if len(got) != 1 || len(got[0].Contexts) != 2 || got[0].Contexts[0] != "LOADER" || got[0].Contexts[1] != "SERVICE" {
		t.Fatalf("unexpected merged candidate: %#v", got)
	}
}

//go:build linux || darwin

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestInspectUnixSensitiveFileDetectsBroadAccessAndWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("not-read-by-collector"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := platformOwnership(info)
	rec := inspectUnixSensitiveFile(sensitiveCandidate{Kind: "CLOUD_CREDENTIAL", Scope: "USER", Path: path, AccessPolicy: SensitivePolicyOwnerOnly, ExpectedOwnerID: owner, Source: "test"}, platformPermissionCapability())
	if rec.State != evidence.StateObserved || !rec.Exists || !rec.OtherWritable || !rec.UntrustedWrite || !rec.OtherAccessible || !rec.UntrustedAccess {
		t.Fatalf("unexpected sensitive permission record: %#v", rec)
	}
	if rec.OwnerState != SensitiveOwnerExpected {
		t.Fatalf("expected owner match, got %#v", rec)
	}
}

func TestInspectUnixSensitiveFileWorksWithoutContentReadPermission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private-key")
	if err := os.WriteFile(path, []byte("secret-material-must-not-be-read"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	rec := inspectUnixSensitiveFile(sensitiveCandidate{Kind: "PRIVATE_KEY", Scope: "USER", Path: path, AccessPolicy: SensitivePolicyOwnerOnly, Source: "test"}, platformPermissionCapability())
	if rec.State != evidence.StateObserved || !rec.Exists || rec.BroadlyAccessible || rec.BroadlyWritable {
		t.Fatalf("metadata-only inspection failed: %#v", rec)
	}
}

func TestExpandSensitiveCandidatesSkipsPublicKeySibling(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"id_ed25519", "id_ed25519.pub"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, degraded := expandSensitiveCandidates([]sensitiveCandidate{{Kind: "PRIVATE_KEY", Scope: "USER", Path: filepath.Join(dir, "id_*"), AccessPolicy: SensitivePolicyOwnerOnly, Source: "test"}})
	if len(degraded) != 0 || len(got) != 1 || filepath.Base(got[0].Path) != "id_ed25519" {
		t.Fatalf("unexpected expanded private-key candidates: got=%#v degraded=%#v", got, degraded)
	}
}

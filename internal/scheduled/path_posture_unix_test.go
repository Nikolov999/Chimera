//go:build linux || darwin

package scheduled

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFix15UnixPathPostureRetainsLowerTrustWriteSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	got := normalizePathPosture(inspectPath(path))
	if got.State != "OBSERVED" || !got.UntrustedWritable || !got.BroadlyWritable {
		t.Fatalf("Unix lower-trust write semantics regressed: %#v", got)
	}
	if got.DACLState != "NOT_APPLICABLE" {
		t.Fatalf("Unix path must not claim a Windows DACL state: %#v", got)
	}
}

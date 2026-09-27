//go:build linux

package processes

import (
	"os"
	"syscall"
	"testing"
)

func TestFix64LinuxProcessLifecycleGoneRecognizesENOENTAndESRCH(t *testing.T) {
	for _, err := range []error{
		&os.PathError{Op: "open", Path: "/proc/999/maps", Err: syscall.ENOENT},
		&os.PathError{Op: "open", Path: "/proc/999/environ", Err: syscall.ESRCH},
	} {
		if !linuxProcessLifecycleGone(err) {
			t.Fatalf("expected procfs lifecycle error to be recognized: %v", err)
		}
	}
	if linuxProcessLifecycleGone(syscall.EACCES) {
		t.Fatal("permission denial must not be classified as a process-exit race")
	}
}

//go:build linux || darwin

package filesystem

import (
	"os"
	"strconv"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func platformOwnership(info os.FileInfo) (string, string) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10), strconv.FormatUint(uint64(st.Gid), 10)
	}
	return "", ""
}

func platformPermissionCapability() PermissionCapability {
	model := "POSIX_MODE"
	source := "POSIX ownership/mode metadata"
	if isDarwin() {
		model = "POSIX_MODE+NATIVE_ACL"
		source = "POSIX ownership/mode metadata with macOS native ACL capability"
	}
	return PermissionCapability{State: evidence.StateObserved, Model: model, Source: source}
}

//go:build !windows

package containers

import (
	"os"
	"strconv"
	"syscall"
)

func endpointOwnerMetadata(info os.FileInfo) (uid, gid string, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return "", "", false
	}
	return strconv.FormatUint(uint64(st.Uid), 10), strconv.FormatUint(uint64(st.Gid), 10), true
}

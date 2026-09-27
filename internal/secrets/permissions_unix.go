//go:build linux || darwin

package secrets

import (
	"context"
	"os"
	"strconv"
	"syscall"
)

func platformPermissionModel() string { return "POSIX_MODE" }

func applyBasicPermissionMetadata(r *Record, info os.FileInfo) {
	if r == nil || info == nil {
		return
	}
	r.PermissionState = "OBSERVED"
	r.Mode = info.Mode().String()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		r.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		r.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	}
	p := info.Mode().Perm()
	r.WorldReadable = boolTri(p&0004 != 0)
	r.WorldWritable = boolTri(p&0002 != 0)
	r.GroupReadable = boolTri(p&0040 != 0)
	r.GroupWritable = boolTri(p&0020 != 0)
	r.BroadlyAccessible = boolTri(p&(0040|0004) != 0)
	r.BroadlyWritable = boolTri(p&(0020|0002) != 0)
}

func enrichPlatformPermissions(_ context.Context, _ []Record) []string { return nil }
func boolTri(v bool) string {
	if v {
		return "TRUE"
	}
	return "FALSE"
}

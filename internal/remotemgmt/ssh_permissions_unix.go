//go:build linux || darwin

package remotemgmt

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func sshFilePosture(ctx context.Context, path string) SSHFilePosture {
	_ = ctx
	p := SSHFilePosture{ID: sshFileID(path), Path: path, State: evidence.StateUnavailable, Source: "POSIX ownership and mode metadata", PermissionBasis: "POSIX mode/uid/gid", Confidence: evidence.ConfidenceHigh}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsPermission(err) {
			p.State = evidence.StateDenied
		}
		p.Reason = err.Error()
		p.Confidence = evidence.ConfidenceLow
		return p
	}
	p.State = evidence.StateObserved
	p.Exists = true
	p.Mode = info.Mode().String()
	perm := info.Mode().Perm()
	p.BroadlyWritable = perm&0022 != 0
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		p.Owner = fmt.Sprint(st.Uid)
		p.Group = fmt.Sprint(st.Gid)
		p.TrustedOwner = st.Uid == 0
	} else {
		p.TrustedOwner = false
		p.Confidence = evidence.ConfidenceMedium
		p.Reason = "numeric owner metadata unavailable"
	}
	return p
}

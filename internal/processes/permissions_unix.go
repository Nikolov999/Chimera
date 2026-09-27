//go:build linux || darwin

package processes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformPathPermissions(ctx context.Context, items []Process, platform string) []PathPermissionContext {
	out := make([]PathPermissionContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			out = append(out, unknownPermissionContext(p, platform, ctx.Err().Error()))
			continue
		}
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" {
			out = append(out, unknownPermissionContext(p, platform, "executable path unavailable"))
			continue
		}
		c := PathPermissionContext{
			ProcessID: p.ID, Platform: platform, PID: p.PID, Path: path,
			Source: "POSIX ownership and mode metadata", Confidence: evidence.ConfidenceHigh,
		}
		c.Executable = unixPermissionNode(path, "EXECUTABLE", p, false)
		c.Parents = unixParentPermissionNodes(path, p)
		if c.Executable.State != "OBSERVED" {
			c.Reasons = append(c.Reasons, "executable permission metadata unavailable: "+fallback(c.Executable.Reason, c.Executable.State))
			c.Confidence = evidence.ConfidenceMedium
		}
		if c.Executable.UntrustedWrite {
			c.Reasons = append(c.Reasons, "executable is writable by a principal outside the trusted privileged boundary")
		}
		for _, n := range c.Parents {
			if n.UntrustedWrite {
				c.Reasons = append(c.Reasons, "parent directory permits untrusted replacement/write access: "+n.Path)
			}
			if n.State != "OBSERVED" {
				c.Confidence = evidence.ConfidenceMedium
			}
		}
		c = finalizePermissionContext(c)
		out = append(out, c)
	}
	return out
}

func unixParentPermissionNodes(path string, p Process) []PermissionNode {
	dir := filepath.Dir(path)
	out := make([]PermissionNode, 0, 8)
	seen := map[string]struct{}{}
	for i := 0; i < maxPermissionAncestors && dir != ""; i++ {
		clean := filepath.Clean(dir)
		if _, ok := seen[clean]; ok {
			break
		}
		seen[clean] = struct{}{}
		out = append(out, unixPermissionNode(clean, "DIRECTORY", p, true))
		parent := filepath.Dir(clean)
		if parent == clean {
			break
		}
		dir = parent
	}
	return out
}

func unixPermissionNode(path, kind string, p Process, directory bool) PermissionNode {
	n := PermissionNode{Path: path, Kind: kind, State: "UNKNOWN", ACLSource: "POSIX ownership and mode bits"}
	info, err := os.Lstat(path)
	if err != nil {
		n.Reason = err.Error()
		return n
	}
	n.State = "OBSERVED"
	n.Mode = info.Mode().String()
	n.Symlink = info.Mode()&os.ModeSymlink != 0
	n.Sticky = info.Mode()&os.ModeSticky != 0
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		n.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		n.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	}

	perm := info.Mode().Perm()
	ownerWrite := perm&0200 != 0
	groupWrite := perm&0020 != 0
	otherWrite := perm&0002 != 0
	if ownerWrite {
		n.WritePrincipals = append(n.WritePrincipals, "owner:"+fallback(n.OwnerID, "unknown"))
	}
	if groupWrite {
		n.WritePrincipals = append(n.WritePrincipals, "group:"+fallback(n.GroupID, "unknown"))
	}
	if otherWrite {
		n.WritePrincipals = append(n.WritePrincipals, "other")
	}
	n.BroadWrite = groupWrite || otherWrite

	elevated := p.Principal.Elevated
	processUID := strings.TrimSpace(p.Principal.UserID)
	processGID := strings.TrimSpace(p.Principal.GroupID)

	if directory && n.Sticky {
		// A sticky shared directory such as /tmp remains broadly writable, but
		// does not by itself prove that another principal can replace an
		// existing child owned by root/the process owner.
		if groupWrite || otherWrite {
			n.Reason = "shared writable directory is protected by the sticky bit; child replacement is not inferred from broad write bits alone"
		}
	} else {
		if otherWrite {
			n.UntrustedWrite = true
		}
		if groupWrite {
			// Group-write permits modification by peers in that group. Root
			// group is treated as part of the privileged boundary for an
			// elevated process; all other group-write grants are material.
			if !elevated || n.GroupID != "0" {
				n.UntrustedWrite = true
			}
		}
	}

	if elevated {
		// A non-root owner with owner-write on a privileged executable or its
		// parent directory can modify or replace the privileged path.
		if ownerWrite && n.OwnerID != "" && n.OwnerID != "0" {
			n.UntrustedWrite = true
		}
	} else if ownerWrite && n.OwnerID != "" && processUID != "" && n.OwnerID != processUID {
		// For non-privileged processes, ownership by a different principal is
		// not automatically weak; only record an explanatory mismatch.
		n.Reason = appendReason(n.Reason, fmt.Sprintf("owner uid %s differs from process uid %s", n.OwnerID, processUID))
	}
	if groupWrite && processGID != "" && n.GroupID != "" && n.GroupID != processGID {
		n.Reason = appendReason(n.Reason, fmt.Sprintf("writable group gid %s differs from process gid %s", n.GroupID, processGID))
	}
	if n.Symlink {
		n.Reason = appendReason(n.Reason, "path component is a symbolic link; target-chain ACL analysis is not inferred")
	}
	return n
}

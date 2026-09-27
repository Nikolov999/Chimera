//go:build linux || darwin

package filesystem

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformTempDirectories(ctx context.Context, candidates []tempDirectoryCandidate, capability PermissionCapability) ([]TempDirectoryRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStageTemp)
	defer stageCancel()
	ctx = stageCtx
	out := make([]TempDirectoryRecord, 0, len(candidates))
	degraded := []string{}
	unresolved := 0
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "temporary-directory security inventory stopped: "+ctx.Err().Error())
			break
		}
		r := inspectUnixTempDirectory(c, capability)
		out = append(out, r)
		if r.State != evidence.StateObserved || (r.ParentState != "" && r.ParentState != evidence.StateObserved) {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if len(out) == 0 {
		state = evidence.StateUnavailable
		reason = "no normalized temporary-directory candidates were available"
	} else if unresolved > 0 || len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("security metadata unresolved for %d of %d temporary-directory boundary record(s)", unresolved, len(out))
	}
	return out, SourceStatus{ID: "temporary-directory-security", State: state, Source: "bounded POSIX temporary-directory ownership/mode/sticky-bit and parent-boundary metadata", ItemCount: len(out), Reason: reason}, degraded
}

func inspectUnixTempDirectory(c tempDirectoryCandidate, capability PermissionCapability) TempDirectoryRecord {
	r := TempDirectoryRecord{
		ID: stableTempDirectoryID(c.Path), Path: c.Path, Scope: c.Scope, Shared: c.Shared,
		State: evidence.StateObserved, PermissionModel: capability.Model,
		DiscoverySources: append([]string(nil), c.Sources...), CollectionSource: "POSIX temporary-directory ownership/mode/sticky-bit metadata",
		Confidence: evidence.ConfidenceHigh,
	}
	linfo, err := os.Lstat(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			r.Exists = false
			r.Reason = "temporary directory does not exist on this host"
			return r
		}
		if os.IsPermission(err) {
			r.State = evidence.StateDenied
		} else {
			r.State = evidence.StateUnavailable
		}
		r.Reason = err.Error()
		return r
	}
	r.Exists = true
	r.Symlink = linfo.Mode()&os.ModeSymlink != 0
	info := linfo
	if r.Symlink {
		target, err := filepath.EvalSymlinks(c.Path)
		if err != nil {
			r.State = evidence.StateUnavailable
			r.Reason = "temporary-directory symbolic-link target resolution failed: " + err.Error()
			return r
		}
		r.ResolvedPath = target
		info, err = os.Stat(c.Path)
		if err != nil {
			if os.IsPermission(err) {
				r.State = evidence.StateDenied
			} else {
				r.State = evidence.StateUnavailable
			}
			r.Reason = "temporary-directory symbolic-link target metadata unavailable: " + err.Error()
			return r
		}
		r.CollectionSource = "POSIX ownership/mode/sticky-bit metadata on resolved temporary-directory target"
	}
	r.Directory = info.IsDir()
	r.Mode = info.Mode().String()
	if !r.Directory {
		r.UnsafePermissions = true
		r.Reason = appendTempReason(r.Reason, "temporary-area candidate is not a directory")
		return r
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		r.State = evidence.StateUnavailable
		r.Confidence = evidence.ConfidenceLow
		r.Reason = appendTempReason(r.Reason, "POSIX ownership metadata unavailable")
		return r
	}
	applyUnixTempMetadata(&r, st, info.Mode())
	inspectUnixTempParent(&r)
	return r
}

func applyUnixTempMetadata(r *TempDirectoryRecord, st *syscall.Stat_t, mode os.FileMode) {
	r.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
	r.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	perm := mode.Perm()
	r.StickyBit = mode&os.ModeSticky != 0
	r.GroupWritable = perm&0020 != 0
	r.OtherWritable = perm&0002 != 0
	r.BroadCreate = r.GroupWritable || r.OtherWritable
	r.BroadlyWritable = r.BroadCreate
	r.TrustedOwnerKnown = true
	r.TrustedOwner = !r.Shared || st.Uid == 0
	r.UnsafeOwnership = r.Shared && st.Uid != 0
	if perm&0200 != 0 {
		r.WritePrincipals = append(r.WritePrincipals, "owner:"+r.OwnerID)
	}
	if r.GroupWritable {
		r.WritePrincipals = append(r.WritePrincipals, "group:"+r.GroupID)
	}
	if r.OtherWritable {
		r.WritePrincipals = append(r.WritePrincipals, "other")
	}
	if r.Shared {
		// Shared POSIX temp areas are expected to be writable by many users; the
		// sticky bit is the critical anti-replacement/deletion boundary.
		r.UnsafePermissions = r.OtherWritable && !r.StickyBit
	} else {
		// A process/user-specific temp directory should not be writable by all users.
		r.UnsafePermissions = r.OtherWritable
	}
}

func inspectUnixTempParent(r *TempDirectoryRecord) {
	target := r.Path
	if r.ResolvedPath != "" {
		target = r.ResolvedPath
	}
	parent := filepath.Dir(target)
	if parent == target || parent == "." || parent == "" {
		return
	}
	r.ParentPath = parent
	info, err := os.Stat(parent)
	if err != nil {
		if os.IsPermission(err) {
			r.ParentState = evidence.StateDenied
		} else if os.IsNotExist(err) {
			r.ParentState = evidence.StateUnavailable
		} else {
			r.ParentState = evidence.StateUnavailable
		}
		r.Reason = appendTempReason(r.Reason, "parent boundary metadata unavailable: "+err.Error())
		return
	}
	r.ParentState = evidence.StateObserved
	r.ParentMode = info.Mode().String()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		r.ParentState = evidence.StateUnavailable
		r.Reason = appendTempReason(r.Reason, "parent POSIX ownership metadata unavailable")
		return
	}
	r.ParentOwnerID = strconv.FormatUint(uint64(st.Uid), 10)
	r.ParentTrustKnown = true
	r.ParentTrustedOwner = !r.Shared || st.Uid == 0
	r.ParentGroupID = strconv.FormatUint(uint64(st.Gid), 10)
	perm := info.Mode().Perm()
	r.ParentStickyBit = info.Mode()&os.ModeSticky != 0
	r.ParentBroadlyWritable = perm&0002 != 0
	r.ParentUnsafe = (r.ParentBroadlyWritable && !r.ParentStickyBit) || (r.Shared && st.Uid != 0)
}

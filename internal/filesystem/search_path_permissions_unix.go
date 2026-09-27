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

func collectPlatformSearchPaths(ctx context.Context, candidates []searchPathCandidate, capability PermissionCapability) ([]SearchPathRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStageSearchPath)
	defer stageCancel()
	ctx = stageCtx
	out := make([]SearchPathRecord, 0, len(candidates))
	degraded := []string{}
	unresolved := 0
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "privileged search-path inventory stopped: "+ctx.Err().Error())
			break
		}
		rec := inspectUnixSearchPath(c, capability)
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if len(out) == 0 {
		state = evidence.StateUnavailable
		reason = "no privileged search-path candidates were available"
	} else if unresolved > 0 || len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("permission metadata unresolved for %d of %d privileged search-path record(s)", unresolved, len(out))
	}
	return out, SourceStatus{ID: "privileged-search-paths", State: state, Source: "bounded privileged command/loader search-path metadata with POSIX ownership/mode evidence", ItemCount: len(out), Reason: reason}, degraded
}

func inspectUnixSearchPath(c searchPathCandidate, capability PermissionCapability) SearchPathRecord {
	rec := SearchPathRecord{
		ID: stableSearchPathID(c.Path), Path: c.Path, State: evidence.StateObserved,
		PermissionModel: capability.Model, Contexts: append([]string(nil), c.Contexts...),
		DiscoverySources: []string{c.Source}, CollectionSource: "POSIX directory ownership and mode metadata",
		Confidence: evidence.ConfidenceHigh,
	}
	linfo, err := os.Lstat(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			rec.Exists = false
			rec.Reason = "search directory does not exist on this host"
			return rec
		}
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec
	}
	rec.Exists = true
	rec.Symlink = linfo.Mode()&os.ModeSymlink != 0
	info := linfo
	inspectedPath := c.Path
	if rec.Symlink {
		target, err := filepath.EvalSymlinks(c.Path)
		if err != nil {
			if os.IsNotExist(err) {
				rec.Exists = false
				rec.Reason = "search-directory symbolic-link target does not exist"
				return rec
			}
			rec.State = evidence.StateUnavailable
			rec.Reason = "symbolic-link target resolution failed: " + err.Error()
			return rec
		}
		rec.ResolvedPath = target
		inspectedPath = target
		info, err = os.Stat(c.Path)
		if err != nil {
			if os.IsPermission(err) {
				rec.State = evidence.StateDenied
			} else {
				rec.State = evidence.StateUnavailable
			}
			rec.Reason = "symbolic-link target metadata unavailable: " + err.Error()
			return rec
		}
	}
	rec.Directory = info.IsDir()
	rec.Mode = info.Mode().String()
	if !rec.Directory {
		rec.Reason = appendFilesystemReason(rec.Reason, "search-path candidate is not a directory")
		return rec
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		rec.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
		perm := info.Mode().Perm()
		rec.GroupWritable = perm&0020 != 0
		rec.OtherWritable = perm&0002 != 0
		rec.BroadlyWritable = rec.GroupWritable || rec.OtherWritable
		if perm&0200 != 0 {
			rec.WritePrincipals = append(rec.WritePrincipals, "owner:"+rec.OwnerID)
		}
		if rec.GroupWritable {
			rec.WritePrincipals = append(rec.WritePrincipals, "group:"+rec.GroupID)
		}
		if rec.OtherWritable {
			rec.WritePrincipals = append(rec.WritePrincipals, "other")
		}
		// A privileged command/loader search directory is weak if it is owned by
		// a non-root principal, group-writable by a non-root group, or writable by others.
		rec.UntrustedWrite = st.Uid != 0 || (rec.GroupWritable && st.Gid != 0) || rec.OtherWritable
	} else {
		rec.State = evidence.StateUnavailable
		rec.Confidence = evidence.ConfidenceLow
		rec.Reason = appendFilesystemReason(rec.Reason, "POSIX ownership metadata unavailable")
	}
	if rec.Symlink {
		rec.CollectionSource = "POSIX directory ownership and mode metadata on resolved search-directory target"
		rec.Reason = appendFilesystemReason(rec.Reason, "permissions assessed on resolved target "+inspectedPath)
	}
	return rec
}

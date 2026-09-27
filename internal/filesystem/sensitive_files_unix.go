//go:build linux || darwin

package filesystem

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

func collectPlatformSensitiveFiles(ctx context.Context, capability PermissionCapability) ([]SensitiveFileRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStageSensitive)
	defer stageCancel()
	ctx = stageCtx
	candidates, degraded := expandSensitiveCandidates(platformSensitiveCandidates())
	out := make([]SensitiveFileRecord, 0, len(candidates))
	unresolved := 0
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "sensitive-file permission inventory interrupted: "+ctx.Err().Error())
			break
		}
		if c.ExpectedOwnerID == "" && c.Scope == "USER" {
			c.ExpectedOwnerID = inferUnixExpectedOwnerID(c.Path)
		}
		rec := inspectUnixSensitiveFile(c, capability)
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 || unresolved > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("sensitive-file permission inventory completed with %d unresolved record(s) and bounded/provider limitations", unresolved)
	}
	if ctx != nil && ctx.Err() != nil && len(out) == 0 {
		state = evidence.StateUnavailable
		reason = ctx.Err().Error()
	}
	return out, SourceStatus{ID: "sensitive-file-permissions", State: state, Source: "bounded sensitive-path inventory using POSIX ownership/mode metadata only", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func inspectUnixSensitiveFile(c sensitiveCandidate, capability PermissionCapability) SensitiveFileRecord {
	rec := SensitiveFileRecord{
		ID: stableSensitiveFileID(c.Kind, c.Path), Kind: c.Kind, Scope: c.Scope, Path: c.Path,
		AccessPolicy: c.AccessPolicy, ExpectedOwnerID: c.ExpectedOwnerID, OwnerState: SensitiveOwnerUnknown,
		State: evidence.StateObserved, PermissionModel: capability.Model, DiscoverySource: c.Source,
		CollectionSource: "POSIX ownership and mode metadata", Confidence: evidence.ConfidenceHigh,
	}
	linfo, err := os.Lstat(c.Path)
	if err != nil {
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else if os.IsNotExist(err) {
			rec.Exists = false
			rec.Reason = "path does not exist on this host"
			return rec
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec
	}
	rec.Exists = true
	rec.Symlink = linfo.Mode()&os.ModeSymlink != 0
	info := linfo
	if rec.Symlink {
		resolved, err := filepath.EvalSymlinks(c.Path)
		if err != nil {
			rec.State = evidence.StateUnavailable
			rec.Reason = "symbolic-link target resolution failed: " + err.Error()
			return rec
		}
		rec.ResolvedPath = resolved
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
		rec.CollectionSource = "POSIX ownership and mode metadata on resolved sensitive-path target"
	}
	rec.Directory = info.IsDir()
	rec.Mode = info.Mode().String()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		rec.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	}
	perm := info.Mode().Perm()
	rec.GroupWritable = perm&0020 != 0
	rec.OtherWritable = perm&0002 != 0
	rec.BroadlyWritable = rec.GroupWritable || rec.OtherWritable
	rec.UntrustedWrite = rec.OtherWritable
	if rec.GroupWritable {
		rec.WritePrincipals = append(rec.WritePrincipals, "group:"+fallback(rec.GroupID, "unknown"))
	}
	if rec.OtherWritable {
		rec.WritePrincipals = append(rec.WritePrincipals, "other")
	}

	if rec.Directory {
		rec.GroupAccessible = perm&(0040|0010) != 0
		rec.OtherAccessible = perm&(0004|0001) != 0
	} else {
		rec.GroupAccessible = perm&0040 != 0
		rec.OtherAccessible = perm&0004 != 0
	}
	rec.BroadlyAccessible = rec.GroupAccessible || rec.OtherAccessible
	rec.UntrustedAccess = rec.OtherAccessible
	if rec.GroupAccessible {
		rec.ReadPrincipals = append(rec.ReadPrincipals, "group:"+fallback(rec.GroupID, "unknown"))
	}
	if rec.OtherAccessible {
		rec.ReadPrincipals = append(rec.ReadPrincipals, "other")
	}

	if rec.ExpectedOwnerID != "" && rec.OwnerID != "" {
		if rec.ExpectedOwnerID == rec.OwnerID {
			rec.OwnerState = SensitiveOwnerExpected
		} else {
			rec.OwnerState = SensitiveOwnerUnexpected
		}
	} else if rec.Scope == "APPLICATION" {
		rec.OwnerState = SensitiveOwnerNotApplicable
	}
	return rec
}

func inferUnixExpectedOwnerID(path string) string {
	clean := filepath.Clean(path)
	home := ""
	if clean == "/root" || strings.HasPrefix(clean, "/root/") {
		home = "/root"
	} else {
		for _, base := range []string{"/home/", "/Users/"} {
			if strings.HasPrefix(clean, base) {
				rest := strings.TrimPrefix(clean, base)
				name := strings.SplitN(rest, "/", 2)[0]
				if name != "" {
					home = filepath.Join(strings.TrimSuffix(base, "/"), name)
				}
				break
			}
		}
	}
	if home == "" {
		return ""
	}
	info, err := os.Stat(home)
	if err != nil {
		return ""
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10)
	}
	return ""
}

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

const maxExecutableEntriesPerDirectory = maxExecutables

func collectPlatformExecutables(ctx context.Context, dirs []string, capability PermissionCapability) ([]ExecutableRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStageExecutable)
	defer stageCancel()
	ctx = stageCtx
	dirs = canonicalExecutableDirectories(dirs)
	out := make([]ExecutableRecord, 0, 1024)
	degraded := []string{}
	scanned := 0
	limited := 0
	unresolved := 0
	for _, dir := range dirs {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "executable inventory stopped: "+ctx.Err().Error())
			break
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) && limited < 16 {
				degraded = append(degraded, fmt.Sprintf("executable directory %s: %v", dir, err))
				limited++
			}
			continue
		}
		scanned++
		for i, entry := range entries {
			if i >= maxExecutableEntriesPerDirectory || len(out) >= maxExecutables {
				if limited < 16 {
					degraded = append(degraded, fmt.Sprintf("executable directory %s reached bounded enumeration limit", dir))
					limited++
				}
				break
			}
			if ctx != nil && ctx.Err() != nil {
				break
			}
			path := filepath.Join(dir, entry.Name())
			rec, include := inspectUnixExecutable(path, dir, capability)
			if include {
				out = append(out, rec)
				if rec.State != evidence.StateObserved {
					unresolved++
				}
			}
		}
		if len(out) >= maxExecutables {
			degraded = append(degraded, fmt.Sprintf("executable inventory reached global limit of %d records", maxExecutables))
			break
		}
	}
	state := evidence.StateObserved
	reason := ""
	if scanned == 0 {
		state = evidence.StateUnavailable
		reason = "no executable search directory could be enumerated"
	} else if len(degraded) > 0 || unresolved > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("enumerated %d of %d candidate executable directories with %d unresolved executable permission record(s) and partial limitations", scanned, len(dirs), unresolved)
	}
	source := SourceStatus{ID: "executable-permissions", State: state, Source: "bounded executable search-path enumeration with POSIX ownership/mode metadata", ItemCount: len(out), Reason: reason}
	return out, source, degraded
}

func inspectUnixExecutable(path, dir string, capability PermissionCapability) (ExecutableRecord, bool) {
	rec := ExecutableRecord{
		ID: stableExecutableID(path), Path: path, Directory: dir,
		State: evidence.StateObserved, PermissionModel: capability.Model,
		DiscoverySource:  "bounded executable search directory enumeration",
		CollectionSource: "POSIX ownership and mode metadata",
		Confidence:       evidence.ConfidenceHigh,
	}
	linfo, err := os.Lstat(path)
	if err != nil {
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec, true
	}
	rec.Exists = true
	rec.Symlink = linfo.Mode()&os.ModeSymlink != 0
	info := linfo
	inspectedPath := path
	if rec.Symlink {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			if os.IsNotExist(err) {
				return ExecutableRecord{}, false
			}
			rec.State = evidence.StateUnavailable
			rec.Reason = "symbolic-link target resolution failed: " + err.Error()
			return rec, true
		}
		rec.ResolvedPath = target
		inspectedPath = target
		info, err = os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return ExecutableRecord{}, false
			}
			if os.IsPermission(err) {
				rec.State = evidence.StateDenied
			} else {
				rec.State = evidence.StateUnavailable
			}
			rec.Reason = "symbolic-link target metadata unavailable: " + err.Error()
			return rec, true
		}
	}
	rec.Regular = info.Mode().IsRegular()
	rec.Executable = rec.Regular && info.Mode().Perm()&0111 != 0
	if !rec.Executable {
		return ExecutableRecord{}, false
	}
	rec.Mode = info.Mode().String()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		rec.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	}
	perm := info.Mode().Perm()
	rec.GroupWritable = perm&0020 != 0
	rec.OtherWritable = perm&0002 != 0
	rec.BroadlyWritable = rec.GroupWritable || rec.OtherWritable
	if perm&0200 != 0 {
		rec.WritePrincipals = append(rec.WritePrincipals, "owner:"+fallback(rec.OwnerID, "unknown"))
	}
	if rec.GroupWritable {
		rec.WritePrincipals = append(rec.WritePrincipals, "group:"+fallback(rec.GroupID, "unknown"))
	}
	if rec.OtherWritable {
		rec.WritePrincipals = append(rec.WritePrincipals, "other")
	}
	// World/other write is directly an untrusted-principal boundary. Group write
	// is retained separately as broad write because POSIX mode alone cannot prove
	// that every member of the owning group is untrusted.
	rec.UntrustedWrite = rec.OtherWritable
	if rec.Symlink {
		rec.CollectionSource = "POSIX ownership and mode metadata on resolved executable target"
		rec.Reason = appendFilesystemReason(rec.Reason, "permissions assessed on resolved target "+inspectedPath)
	}
	return rec, true
}

func appendFilesystemReason(existing, next string) string {
	existing = strings.TrimSpace(existing)
	next = strings.TrimSpace(next)
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}
	return existing + "; " + next
}

// canonicalExecutableDirectories collapses merged-/usr aliases before the
// expensive executable inventory. On modern Debian/Kali systems /bin and
// /sbin commonly resolve into /usr; scanning both names otherwise enumerates
// the same executable tree twice and can consume the global 8192-record bound.
func canonicalExecutableDirectories(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, dir := range in {
		dir = filepath.Clean(strings.TrimSpace(dir))
		if dir == "" || dir == "." {
			continue
		}
		canonical := dir
		if resolved, err := filepath.EvalSymlinks(dir); err == nil && strings.TrimSpace(resolved) != "" {
			canonical = filepath.Clean(resolved)
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out
}

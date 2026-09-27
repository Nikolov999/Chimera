//go:build linux

package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformNFSExports(ctx context.Context) ([]NetworkShareRecord, SourceStatus, []string) {
	paths := []string{}
	degraded := []string{}

	if _, err := os.Stat("/etc/exports"); err == nil {
		paths = append(paths, "/etc/exports")
	} else if !os.IsNotExist(err) {
		degraded = append(degraded, "NFS export configuration metadata unavailable at /etc/exports: "+err.Error())
	}

	entries, err := os.ReadDir("/etc/exports.d")
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".exports") {
				continue
			}
			paths = append(paths, filepath.Join("/etc/exports.d", entry.Name()))
		}
	} else if !os.IsNotExist(err) {
		degraded = append(degraded, "NFS export include directory unavailable at /etc/exports.d: "+err.Error())
	}

	paths = uniqueSorted(paths)
	if len(paths) == 0 {
		state := evidence.StateObserved
		reason := "no standard local NFS export configuration files are present"
		if len(degraded) > 0 {
			state = evidence.StateDegraded
			reason = strings.Join(uniqueSorted(degraded), "; ")
		}
		return nil, SourceStatus{ID: "nfs-exports", State: state, Source: "/etc/exports + /etc/exports.d/*.exports", ItemCount: 0, Reason: reason}, uniqueSorted(degraded)
	}

	out := []NetworkShareRecord{}
	for _, path := range paths {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "NFS export collection interrupted: "+ctx.Err().Error())
			break
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			degraded = append(degraded, "NFS export configuration unavailable at "+path+": "+err.Error())
			continue
		}
		out = append(out, parseLinuxNFSExports(string(raw), path)...)
		if len(out) >= maxNetworkShares {
			out = out[:maxNetworkShares]
			break
		}
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	sort.Slice(out, func(i, j int) bool { return networkShareSortKey(out[i]) < networkShareSortKey(out[j]) })
	return out, SourceStatus{ID: "nfs-exports", State: state, Source: strings.Join(paths, ", "), ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

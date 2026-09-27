//go:build darwin

package filesystem

import (
	"context"
	"os"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformNFSExports(ctx context.Context) ([]NetworkShareRecord, SourceStatus, []string) {
	const path = "/etc/exports"
	if ctx != nil && ctx.Err() != nil {
		reason := "NFS export collection interrupted: " + ctx.Err().Error()
		return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateDegraded, Source: path, Reason: reason}, []string{reason}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateObserved, Source: path, ItemCount: 0, Reason: "local NFS export configuration is not present"}, nil
		}
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		reason := "NFS export configuration unavailable: " + err.Error()
		return nil, SourceStatus{ID: "nfs-exports", State: state, Source: path, Reason: reason}, []string{reason}
	}
	out := parseDarwinNFSExports(string(raw), path)
	if len(out) > maxNetworkShares {
		out = out[:maxNetworkShares]
	}
	return out, SourceStatus{ID: "nfs-exports", State: evidence.StateObserved, Source: path, ItemCount: len(out), Reason: strings.TrimSpace("")}, nil
}

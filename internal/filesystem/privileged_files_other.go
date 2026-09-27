//go:build !linux

package filesystem

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformPrivilegedFiles(_ context.Context, _ []MountBoundary) ([]PrivilegedFileRecord, SourceStatus, []string) {
	return nil, SourceStatus{
		ID: "linux-privileged-files", State: evidence.StateNotApplicable,
		Source: "Linux SUID/SGID/file-capability inventory",
		Reason: "SUID/SGID and Linux file capabilities are not applicable on this platform",
	}, nil
}

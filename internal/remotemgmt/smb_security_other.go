//go:build !linux && !windows && !darwin

package remotemgmt

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformSMBSecurity(ctx context.Context) smbPlatformResult {
	_ = ctx
	return smbPlatformResult{
		ShareInventoryState:  evidence.StateUnsupported,
		ShareInventorySource: "unsupported platform",
		ShareInventoryReason: "SMB/file-sharing assessment is unsupported on this platform",
	}
}

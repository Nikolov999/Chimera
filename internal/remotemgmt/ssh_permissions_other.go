//go:build !linux && !darwin && !windows

package remotemgmt

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func sshFilePosture(ctx context.Context, path string) SSHFilePosture {
	_ = ctx
	return SSHFilePosture{ID: sshFileID(path), Path: path, State: evidence.StateUnsupported, Source: "platform filesystem permission provider", PermissionBasis: "unsupported platform", Confidence: evidence.ConfidenceLow, Reason: "SSH configuration permission assessment is unsupported on this platform"}
}

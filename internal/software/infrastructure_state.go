package software

import (
	"context"
	"errors"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func infrastructureStateForError(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return evidence.StateDegraded
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access is denied") || strings.Contains(msg, "unauthorized") {
		return evidence.StateDenied
	}
	return evidence.StateDegraded
}

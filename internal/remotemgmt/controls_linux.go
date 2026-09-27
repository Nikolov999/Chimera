//go:build linux

package remotemgmt

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
	"os"
	"strings"
)

func collectPlatformControls(ctx context.Context) []Control {
	_ = ctx
	out := []Control{}
	// coarse enablement hint retained for surface correlation. // performs the detailed SSH authentication/forwarding/algorithm assessment.
	if b, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		text := strings.ToLower(string(b))
		state := "PRESENT"
		_ = text
		out = append(out, Control{Family: "SSH", Name: "sshd configuration present", State: evidence.StateObserved, Value: state, Source: "/etc/ssh/sshd_config", Confidence: evidence.ConfidenceMedium})
	} else if os.IsPermission(err) {
		out = append(out, Control{Family: "SSH", Name: "sshd configuration visibility", State: evidence.StateDenied, Source: "/etc/ssh/sshd_config", Confidence: evidence.ConfidenceLow, Reason: "permission denied reading sshd configuration"})
	}
	return out
}

//go:build darwin

package remotemgmt

import (
	"context"
	"fmt"
	"github.com/Nikolov999/chimera/internal/evidence"
	"os/exec"
	"strings"
)

func collectPlatformControls(ctx context.Context) []Control {
	out := []Control{}
	if path, err := exec.LookPath("systemsetup"); err == nil {
		b, err := exec.CommandContext(ctx, path, "-getremotelogin").CombinedOutput()
		if err == nil {
			text := strings.ToLower(string(b))
			state := "UNKNOWN"
			if strings.Contains(text, "on") {
				state = "ENABLED"
			}
			if strings.Contains(text, "off") {
				state = "DISABLED"
			}
			out = append(out, Control{Family: "SSH", Name: "Remote Login", State: evidence.StateObserved, Value: state, Source: "systemsetup -getremotelogin", Confidence: evidence.ConfidenceHigh, AffectsEnablement: true})
		} else {
			out = append(out, Control{Family: "SSH", Name: "Remote Login", State: evidence.StateUnavailable, Source: "systemsetup -getremotelogin", Confidence: evidence.ConfidenceLow, Reason: "Remote Login setting unavailable without additional privilege or provider access"})
		}
	}
	if path, err := exec.LookPath("launchctl"); err == nil {
		b, err := exec.CommandContext(ctx, path, "print-disabled", "system").CombinedOutput()
		if err == nil {
			text := strings.ToLower(string(b))
			for _, x := range []struct{ family, name, label string }{{"VNC", "Screen Sharing", "com.apple.screensharing"}, {"VNC", "Remote Management", "com.apple.remotedesktop.agent"}} {
				value := "UNKNOWN"
				if strings.Contains(text, strings.ToLower(x.label)+" => true") {
					value = "DISABLED"
				}
				if strings.Contains(text, strings.ToLower(x.label)+" => false") {
					value = "ENABLED"
				}
				out = append(out, Control{Family: x.family, Name: x.name, State: evidence.StateObserved, Value: value, Source: "launchctl print-disabled system", Confidence: evidence.ConfidenceMedium, AffectsEnablement: true})
			}
		} else {
			out = append(out, Control{Family: "VNC", Name: "Screen Sharing launchd state", State: evidence.StateUnavailable, Source: "launchctl print-disabled system", Confidence: evidence.ConfidenceLow, Reason: fmt.Sprintf("launchd state unavailable: %v", err)})
		}
	}
	return out
}

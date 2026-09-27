//go:build darwin

package processes

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxDarwinIsolationExecutables = 256

type darwinSandboxEntitlement struct {
	state      string
	basis      string
	reason     string
	confidence evidence.Confidence
}

func collectIsolationPlatform(ctx context.Context, items []Process) ([]IsolationContext, isolationProviderStats) {
	stats := isolationProviderStats{ID: "darwin-process-isolation", State: evidence.StateObserved, Source: "codesign app-sandbox entitlement metadata"}
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		out := make([]IsolationContext, 0, len(items))
		for _, p := range items {
			out = append(out, IsolationContext{PID: p.PID, Platform: "darwin", State: "UNSUPPORTED", IsolationState: "UNKNOWN", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "macOS process sandbox metadata", Confidence: evidence.ConfidenceExact, Reason: "codesign executable not found; runtime sandbox membership is not exposed by ps"})
		}
		stats.State = evidence.StateUnsupported
		stats.Reason = "codesign executable not found; runtime sandbox membership is not exposed by ps"
		return out, stats
	}

	cache := map[string]darwinSandboxEntitlement{}
	unique := 0
	out := make([]IsolationContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c := IsolationContext{PID: p.PID, Platform: "darwin", State: "OBSERVED", IsolationState: "UNKNOWN", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "codesign app-sandbox entitlement metadata", Confidence: evidence.ConfidenceMedium}
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" {
			c.State = "UNKNOWN"
			c.Confidence = evidence.ConfidenceLow
			c.Reason = "executable path unavailable; runtime sandbox membership is not exposed by ps"
			stats.Missing++
			out = append(out, c)
			continue
		}
		ent, ok := cache[path]
		if !ok {
			if unique >= maxDarwinIsolationExecutables {
				ent = darwinSandboxEntitlement{state: "UNKNOWN", reason: "static sandbox-entitlement inspection skipped at safety bound", confidence: evidence.ConfidenceLow}
			} else {
				unique++
				ent = inspectDarwinSandboxEntitlement(ctx, codesign, path)
			}
			cache[path] = ent
		}
		c.Sandbox = ent.state
		c.SandboxBasis = ent.basis
		c.Reason = ent.reason
		c.Confidence = ent.confidence
		if ent.state == "ENTITLED" {
			c.IsolationState = "PARTIAL"
			c.Signals = []string{"app-sandbox-entitlement"}
			stats.Count++
		} else if ent.state == "NOT_ENTITLED" {
			c.IsolationState = "UNKNOWN"
			stats.Count++
		} else {
			c.State = "UNKNOWN"
			stats.Missing++
		}
		out = append(out, c)
	}
	if stats.Count == 0 && stats.Missing > 0 {
		stats.State = evidence.StateUnavailable
	} else if stats.Missing > 0 {
		stats.State = evidence.StateDegraded
	}
	return out, stats
}

func inspectDarwinSandboxEntitlement(ctx context.Context, codesign, path string) darwinSandboxEntitlement {
	b, err := exec.CommandContext(ctx, codesign, "-d", "--entitlements", ":-", "--", path).CombinedOutput()
	text := string(b)
	marker := "<key>com.apple.security.app-sandbox</key>"
	i := strings.Index(text, marker)
	if i >= 0 {
		tail := text[i+len(marker):]
		if len(tail) > 256 {
			tail = tail[:256]
		}
		if strings.Contains(tail, "<true") {
			return darwinSandboxEntitlement{state: "ENTITLED", basis: "code signature includes com.apple.security.app-sandbox=true", confidence: evidence.ConfidenceHigh}
		}
		if strings.Contains(tail, "<false") {
			return darwinSandboxEntitlement{state: "NOT_ENTITLED", basis: "code signature includes com.apple.security.app-sandbox=false", confidence: evidence.ConfidenceHigh}
		}
	}
	if err != nil {
		return darwinSandboxEntitlement{state: "UNKNOWN", reason: "sandbox entitlement unavailable: " + err.Error(), confidence: evidence.ConfidenceLow}
	}
	return darwinSandboxEntitlement{state: "NOT_ENTITLED", basis: "no com.apple.security.app-sandbox entitlement observed; runtime sandbox membership remains unresolved", confidence: evidence.ConfidenceMedium}
}

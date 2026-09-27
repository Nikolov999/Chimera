//go:build windows

package processes

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func windowsIsolationSummary(r winProc) IsolationSummary {
	app := "UNKNOWN"
	if r.AppContainerKnown {
		if r.AppContainer {
			app = "TRUE"
		} else {
			app = "FALSE"
		}
	}
	job := "UNKNOWN"
	if r.JobKnown {
		if r.InJob {
			job = "TRUE"
		} else {
			job = "FALSE"
		}
	}
	state := "UNKNOWN"
	reason := "AppContainer/job membership unavailable"
	switch {
	case r.AppContainerKnown && r.AppContainer:
		state = "ISOLATED"
		reason = "Windows token reports AppContainer membership"
	case r.JobKnown && r.InJob:
		state = "PARTIAL"
		reason = "process is assigned to a Windows job object; job limits are not inferred from membership alone"
	case r.AppContainerKnown && r.JobKnown:
		state = "HOST"
		reason = "no AppContainer or job-object membership observed"
	case r.AppContainerKnown:
		state = "HOST"
		reason = "token reports no AppContainer membership; job-object membership unavailable"
	case r.JobKnown:
		state = "PARTIAL"
		if !r.InJob {
			state = "UNKNOWN"
			reason = "job-object query reports no membership; AppContainer token metadata unavailable"
		}
	}
	return IsolationSummary{State: state, AppContainer: app, JobObject: job, Sandbox: "UNKNOWN", Reason: reason}
}

func collectIsolationPlatform(ctx context.Context, items []Process) ([]IsolationContext, isolationProviderStats) {
	stats := isolationProviderStats{ID: "windows-process-isolation", State: evidence.StateObserved, Source: "OpenProcessToken TokenIsAppContainer and IsProcessInJob metadata"}
	out := make([]IsolationContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		app := strings.ToUpper(strings.TrimSpace(p.Isolation.AppContainer))
		job := strings.ToUpper(strings.TrimSpace(p.Isolation.JobObject))
		c := IsolationContext{
			PID: p.PID, Platform: "windows", State: "OBSERVED", IsolationState: strings.ToUpper(fallback(p.Isolation.State, "UNKNOWN")),
			AppContainer: fallback(app, "UNKNOWN"), JobObject: fallback(job, "UNKNOWN"), Sandbox: "UNKNOWN",
			Source: "OpenProcessToken TokenIsAppContainer and IsProcessInJob metadata", Confidence: evidence.ConfidenceHigh,
			Reason: strings.TrimSpace(p.Isolation.Reason),
		}
		if c.AppContainer == "TRUE" {
			c.Signals = append(c.Signals, "appcontainer")
		}
		if c.JobObject == "TRUE" {
			c.Signals = append(c.Signals, "job-object-member")
		}
		if c.AppContainer == "UNKNOWN" && c.JobObject == "UNKNOWN" {
			c.State = "UNKNOWN"
			c.Confidence = evidence.ConfidenceLow
			stats.Missing++
		} else {
			stats.Count++
		}
		c.Signals = normalizedList(c.Signals)
		out = append(out, c)
	}
	if stats.Count == 0 && stats.Missing > 0 {
		stats.State = evidence.StateUnavailable
	} else if stats.Missing > 0 {
		stats.State = evidence.StateDegraded
	}
	return out, stats
}

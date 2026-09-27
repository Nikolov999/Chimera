//go:build linux

package processes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectRuntimeEnvironmentPlatform(ctx context.Context, items []Process) ([]RuntimeEnvironmentContext, environmentProviderStats) {
	stats := environmentProviderStats{ID: "linux-process-environment", State: evidence.StateObserved, Source: "/proc/<pid>/environ names and redacted classification metadata"}
	out := make([]RuntimeEnvironmentContext, 0, len(items))
	kernelThreads := linuxKernelThreadPIDs(items)
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		if _, ok := kernelThreads[p.PID]; ok {
			// Linux kernel threads have no userspace mm/environment. procfs commonly
			// returns ENOENT for /proc/<pid>/environ even though /proc/<pid>/status
			// remains observable. That is an expected kernel-thread property, not a
			// missing live-process environment record. Record an observed empty
			// environment posture so hundreds of kthreadd descendants cannot poison
			// the provider health state on an otherwise fully observable root scan.
			out = append(out, RuntimeEnvironmentContext{
				PID: p.PID, Platform: "linux", State: "OBSERVED", Posture: "NONE",
				ValuesRedacted: true, Source: "Linux kernel-thread classification from /proc process metadata",
				Confidence: evidence.ConfidenceExact, Reason: "kernel thread has no userspace process environment",
			})
			stats.Count++
			continue
		}
		entries, truncated, err := readLinuxEnvironment(filepath.Join("/proc", strconv.Itoa(p.PID), "environ"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || linuxProcessLifecycleGone(err) {
				// Userspace processes can legitimately disappear after the base /proc
				// snapshot and before secondary enrichment reaches /proc/<pid>/environ.
				// Once kernel threads have been classified above, ENOENT or ESRCH here
				// is a lifecycle race, not a provider-health failure. Keep the individual
				// process environment unknown and explicit, but count the race as a
				// handled record so one short-lived process cannot degrade the whole
				// Linux environment provider.
				out = append(out, RuntimeEnvironmentContext{
					PID: p.PID, Platform: "linux", State: "UNKNOWN", Posture: "UNKNOWN",
					ValuesRedacted: true, Source: "Linux procfs lifecycle-aware environment metadata",
					Confidence: evidence.ConfidenceExact, Reason: "process exited before environment enrichment completed",
				})
				stats.Count++
				continue
			}
			state := "UNKNOWN"
			if errors.Is(err, os.ErrPermission) {
				state = "DENIED"
				stats.Denied++
			} else {
				stats.Missing++
			}
			out = append(out, RuntimeEnvironmentContext{PID: p.PID, Platform: "linux", State: state, Posture: "UNKNOWN", ValuesRedacted: true, Source: "/proc/<pid>/environ redacted metadata", Confidence: evidence.ConfidenceLow, Reason: err.Error()})
			continue
		}
		c := inspectEnvironmentEntries(entries, "linux", "/proc/<pid>/environ redacted metadata")
		c.PID = p.PID
		if truncated {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = fmt.Sprintf("environment exceeded %d-byte safety bound; trailing partial metadata was discarded", maxEnvironmentBytes)
		}
		out = append(out, c)
		stats.Count++
	}
	if stats.Count == 0 && stats.Denied > 0 {
		stats.State = evidence.StateDenied
	} else if stats.Count == 0 && stats.Missing > 0 {
		stats.State = evidence.StateUnavailable
	} else if stats.Denied > 0 || stats.Missing > 0 {
		stats.State = evidence.StateDegraded
	}
	return out, stats
}

// linuxKernelThreadPIDs identifies the kthreadd process tree using only the
// already-normalized process snapshot. A kernel thread has no executable link or
// userspace command line, and descendants of PID 2 inherit that kernel-thread
// property. Requiring ancestry from PID 2 avoids classifying an ordinary process
// with temporarily unavailable executable metadata as a kernel thread.
func linuxKernelThreadPIDs(items []Process) map[int]struct{} {
	byPID := make(map[int]Process, len(items))
	for _, p := range items {
		if p.PID > 0 {
			byPID[p.PID] = p
		}
	}
	out := map[int]struct{}{}
	if p, ok := byPID[2]; ok && linuxKernelThreadShape(p) {
		out[2] = struct{}{}
	}
	for changed := true; changed; {
		changed = false
		for _, p := range items {
			if p.PID <= 0 || p.PID == 2 || !linuxKernelThreadShape(p) {
				continue
			}
			if _, known := out[p.PID]; known {
				continue
			}
			if _, parentKernel := out[p.PPID]; parentKernel {
				out[p.PID] = struct{}{}
				changed = true
			}
		}
	}
	return out
}

func linuxKernelThreadShape(p Process) bool {
	return strings.TrimSpace(p.ExecutablePath) == "" &&
		p.CommandLine.Available && p.CommandLine.ArgumentCount == 0 && p.CommandLine.ByteCount == 0
}

func readLinuxEnvironment(path string) ([]string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEnvironmentBytes+1))
	if err != nil {
		return nil, false, err
	}
	truncated := len(b) > maxEnvironmentBytes
	if truncated {
		b = b[:maxEnvironmentBytes]
		if i := bytes.LastIndexByte(b, 0); i >= 0 {
			b = b[:i+1]
		} else {
			b = nil
		}
	}
	parts := strings.Split(string(b), "\x00")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if strings.Contains(s, "=") {
			out = append(out, s)
		}
	}
	return out, truncated, nil
}

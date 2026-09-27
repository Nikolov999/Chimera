//go:build linux

package processes

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectExecutionMemoryPlatform(ctx context.Context, items []Process) ([]ExecutionMemoryContext, memoryProviderStats) {
	stats := memoryProviderStats{ID: "linux-proc-maps", State: evidence.StateObserved, Source: "/proc/<pid>/maps protection/backing metadata"}
	out := make([]ExecutionMemoryContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c, err := readLinuxMemoryMap(ctx, p.PID)
		if err != nil {
			c = ExecutionMemoryContext{PID: p.PID, Platform: "linux", State: "UNKNOWN", Source: "/proc/<pid>/maps", Confidence: evidence.ConfidenceLow, Reason: err.Error()}
			if linuxProcessLifecycleGone(err) {
				// A PID can disappear after the normalized base snapshot but before
				// executable-memory enrichment reaches /proc/<pid>/maps. Preserve the
				// per-process UNKNOWN record, but account for the lifecycle race as a
				// handled snapshot item so one normal process exit does not degrade the
				// whole Linux process provider.
				c.Source = "Linux procfs lifecycle-aware executable-memory metadata"
				c.Confidence = evidence.ConfidenceExact
				c.Reason = "process exited before executable-memory enrichment completed"
				stats.Count++
			} else if errors.Is(err, os.ErrPermission) {
				c.State = "DENIED"
				stats.Denied++
			} else {
				stats.Missing++
			}
		} else {
			stats.Count++
		}
		out = append(out, c)
	}
	return out, stats
}

func readLinuxMemoryMap(ctx context.Context, pid int) (ExecutionMemoryContext, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	f, err := os.Open(path)
	if err != nil {
		return ExecutionMemoryContext{}, err
	}
	defer f.Close()

	c := ExecutionMemoryContext{PID: pid, Platform: "linux", State: "OBSERVED", Source: "/proc/<pid>/maps", Confidence: evidence.ConfidenceHigh}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	regions := 0
	for s.Scan() {
		if ctx.Err() != nil {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = ctx.Err().Error()
			return c, nil
		}
		if regions >= maxMemoryRegionsPerProcess {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = "memory region inventory truncated at safety bound"
			c.Signals = append(c.Signals, "memory-region-inventory-truncated")
			break
		}
		regions++
		fields := strings.Fields(s.Text())
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		if len(perms) < 3 || perms[2] != 'x' {
			continue
		}
		c.ExecutableRegions++
		if len(perms) >= 2 && perms[1] == 'w' {
			c.WritableExecutableRegions++
		}
		backing := ""
		if len(fields) > 5 {
			backing = strings.Join(fields[5:], " ")
		}
		class := linuxExecutableBackingClass(backing)
		switch class {
		case "anonymous":
			c.AnonymousExecutableRegions++
		case "special":
			c.SpecialExecutableRegions++
		case "file":
			c.FileBackedExecutableRegions++
		}
		if strings.Contains(backing, " (deleted)") {
			c.DeletedExecutableRegions++
		}
		lower := strings.ToLower(backing)
		if strings.Contains(lower, "jit") || strings.Contains(lower, "v8") || strings.Contains(lower, "code-cache") {
			c.JITLikeContext = true
			c.JITBasis = append(c.JITBasis, "mapping-metadata-indicates-jit-or-code-cache")
		}
	}
	if err := s.Err(); err != nil {
		return ExecutionMemoryContext{}, err
	}
	c.RegionsObserved = regions
	return c, nil
}

func linuxExecutableBackingClass(backing string) string {
	b := strings.TrimSpace(backing)
	if b == "" {
		return "anonymous"
	}
	low := strings.ToLower(b)
	if strings.HasPrefix(low, "memfd:") || strings.HasPrefix(low, "/memfd:") || strings.HasPrefix(low, "anon_inode:") {
		return "anonymous"
	}
	if strings.HasPrefix(b, "[") {
		switch low {
		case "[vdso]", "[vsyscall]", "[vectors]":
			return "special"
		default:
			return "anonymous"
		}
	}
	return "file"
}

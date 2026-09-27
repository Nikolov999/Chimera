package processes

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxMemoryRegionsPerProcess = 131072

// ExecutionMemoryContext is additive metadata for executable virtual
// memory. It records page/region protections and backing class only. It never
// contains memory bytes, addresses, strings extracted from memory, or secrets.
type ExecutionMemoryContext struct {
	ProcessID                   string              `json:"process_id"`
	PID                         int                 `json:"pid"`
	Platform                    string              `json:"platform"`
	State                       string              `json:"state"`
	RegionsObserved             int                 `json:"regions_observed"`
	ExecutableRegions           int                 `json:"executable_regions"`
	WritableExecutableRegions   int                 `json:"writable_executable_regions"`
	AnonymousExecutableRegions  int                 `json:"anonymous_executable_regions"`
	FileBackedExecutableRegions int                 `json:"file_backed_executable_regions"`
	DeletedExecutableRegions    int                 `json:"deleted_executable_regions"`
	SpecialExecutableRegions    int                 `json:"special_executable_regions"`
	JITLikeContext              bool                `json:"jit_like_context"`
	JITBasis                    []string            `json:"jit_basis,omitempty"`
	Signals                     []string            `json:"signals,omitempty"`
	Source                      string              `json:"source"`
	Confidence                  evidence.Confidence `json:"confidence"`
	Reason                      string              `json:"reason,omitempty"`
}

type memoryProviderStats struct {
	ID      string
	State   evidence.State
	Source  string
	Count   int
	Denied  int
	Missing int
	Reason  string
}

func collectExecutionMemory(ctx context.Context, items []Process, platform string) ([]ExecutionMemoryContext, SourceStatus) {
	raw, stats := collectExecutionMemoryPlatform(ctx, items)
	out := normalizeExecutionMemory(items, raw, platform)
	state := stats.State
	if state == "" {
		state = evidence.StateObserved
	}
	reason := strings.TrimSpace(stats.Reason)
	if reason == "" && (stats.Denied > 0 || stats.Missing > 0) {
		parts := []string{}
		if stats.Denied > 0 {
			parts = append(parts, itoa(stats.Denied)+" process mapping record(s) permission-restricted")
		}
		if stats.Missing > 0 {
			parts = append(parts, itoa(stats.Missing)+" process mapping record(s) unavailable or exited during collection")
		}
		reason = strings.Join(parts, "; ")
		if stats.Count > 0 {
			state = evidence.StateDegraded
		} else if stats.Denied > 0 {
			state = evidence.StateDenied
		} else {
			state = evidence.StateUnavailable
		}
	}
	return out, SourceStatus{ID: stats.ID, State: state, Source: stats.Source, ItemCount: stats.Count, Reason: reason}
}

func normalizeExecutionMemory(items []Process, in []ExecutionMemoryContext, platform string) []ExecutionMemoryContext {
	byPID := make(map[int]ExecutionMemoryContext, len(in))
	for _, c := range in {
		if c.PID <= 0 {
			continue
		}
		c.Platform = fallback(strings.ToLower(strings.TrimSpace(c.Platform)), strings.ToLower(strings.TrimSpace(platform)))
		c.State = fallback(strings.ToUpper(strings.TrimSpace(c.State)), "UNKNOWN")
		c.Source = fallback(strings.TrimSpace(c.Source), "platform executable-memory metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceMedium
		}
		c.JITBasis = normalizedList(c.JITBasis)
		c.Signals = normalizedList(c.Signals)
		if c.WritableExecutableRegions > 0 {
			c.Signals = normalizedList(append(c.Signals, "writable-executable-memory"))
		}
		if c.AnonymousExecutableRegions > 0 {
			c.Signals = normalizedList(append(c.Signals, "anonymous-executable-memory"))
		}
		if c.DeletedExecutableRegions > 0 {
			c.Signals = normalizedList(append(c.Signals, "deleted-backing-executable-memory"))
		}
		if old, ok := byPID[c.PID]; !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) {
			byPID[c.PID] = c
		}
	}

	out := make([]ExecutionMemoryContext, 0, len(items))
	for _, p := range items {
		c, ok := byPID[p.PID]
		if !ok {
			c = ExecutionMemoryContext{
				PID:        p.PID,
				Platform:   strings.ToLower(strings.TrimSpace(platform)),
				State:      "UNKNOWN",
				Source:     "platform executable-memory metadata",
				Confidence: evidence.ConfidenceLow,
				Reason:     "executable-memory metadata unavailable for observed process",
			}
		}
		c.ProcessID = p.ID
		if !c.JITLikeContext {
			c.JITLikeContext, c.JITBasis = inferJITLikeProcess(p)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ProcessID < out[j].ProcessID
	})
	return out
}

func inferJITLikeProcess(p Process) (bool, []string) {
	name := strings.ToLower(strings.TrimSpace(p.Name + " " + p.Executable + " " + p.ExecutablePath))
	markers := []struct{ needle, label string }{
		{"java", "java-runtime"}, {"node", "node-v8-runtime"}, {"chrome", "chromium-v8-runtime"},
		{"chromium", "chromium-v8-runtime"}, {"electron", "electron-v8-runtime"}, {"firefox", "firefox-js-runtime"},
		{"dotnet", "dotnet-runtime"}, {"mono", "mono-runtime"}, {"julia", "julia-jit-runtime"},
		{"qemu", "dynamic-code-translation-runtime"}, {"php", "php-runtime"}, {"ruby", "ruby-runtime"},
	}
	basis := []string{}
	for _, m := range markers {
		if strings.Contains(name, m.needle) {
			basis = append(basis, m.label)
		}
	}
	basis = normalizedList(basis)
	return len(basis) > 0, basis
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [32]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

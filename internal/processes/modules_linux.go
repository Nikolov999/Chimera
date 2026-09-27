//go:build linux

package processes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxLinuxModuleProvenancePaths = 2048

func collectLoadedModulesPlatform(ctx context.Context, items []Process) ([]LoadedModuleContext, moduleProviderStats) {
	stats := moduleProviderStats{ID: "linux-proc-loaded-modules", State: evidence.StateObserved, Source: "/proc/<pid>/maps file-backed executable mappings plus batched native package ownership and POSIX directory metadata"}
	out := make([]LoadedModuleContext, 0, len(items))
	provider := detectLinuxPackageProvider()
	lookupSet := map[string]struct{}{}
	lookupPaths := make([]string, 0, 1024)
	totalModules := 0

	// First collect all /proc mapping metadata without invoking a package
	// manager. Package ownership is joined in a single bounded batch below.
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c, err := readLinuxLoadedModules(ctx, p)
		if err != nil {
			state := "UNKNOWN"
			source := "/proc/<pid>/maps"
			confidence := evidence.ConfidenceLow
			reason := err.Error()
			if linuxProcessLifecycleGone(err) {
				// The base /proc snapshot and module enrichment are intentionally
				// point-in-time views. A short-lived PID can disappear before its
				// maps file is opened. Preserve the per-process UNKNOWN context, but
				// classify the race explicitly so rule applicability can exclude it
				// without treating an ordinary process exit as missing evidence.
				source = "Linux procfs lifecycle-aware loaded-module metadata"
				confidence = evidence.ConfidenceExact
				reason = "process exited before loaded-module enrichment completed"
				stats.Count++
			} else if errors.Is(err, os.ErrPermission) {
				state = "DENIED"
				stats.Denied++
			} else {
				stats.Missing++
			}
			out = append(out, LoadedModuleContext{PID: p.PID, Platform: "linux", State: state, Source: source, Confidence: confidence, Reason: reason})
			continue
		}

		for i := range c.Modules {
			m := &c.Modules[i]
			dir := filepath.Dir(m.Path)
			node := unixPermissionNode(dir, "DIRECTORY", p, true)
			m.DirectoryState = node.State
			m.DirectoryWritable = node.UntrustedWrite || (p.Principal.Elevated && node.BroadWrite)
			m.BroadDirectoryWrite = node.BroadWrite
			if node.State != "OBSERVED" {
				m.Confidence = evidence.ConfidenceMedium
				m.Reason = appendReason(m.Reason, "module directory permission metadata unavailable: "+fallback(node.Reason, node.State))
			}
			if m.DeletedBacking {
				continue
			}
			lookup := linuxPackageLookupPath(m.Path)
			if _, ok := lookupSet[lookup]; !ok && len(lookupPaths) < maxLinuxModuleProvenancePaths {
				lookupSet[lookup] = struct{}{}
				lookupPaths = append(lookupPaths, lookup)
			}
		}
		c.Modules = normalizeLoadedModules(c.Modules, "linux")
		c.ModuleCount = len(c.Modules)
		totalModules += len(c.Modules)
		stats.Count += len(c.Modules)
		out = append(out, c)
		if totalModules >= maxLoadedModulesTotal {
			out[len(out)-1].State = "DEGRADED"
			out[len(out)-1].Confidence = evidence.ConfidenceMedium
			out[len(out)-1].Reason = appendReason(out[len(out)-1].Reason, fmt.Sprintf("loaded-module inventory bounded at %d total module records", maxLoadedModulesTotal))
			stats.State = evidence.StateDegraded
			stats.Reason = fmt.Sprintf("loaded-module inventory bounded at %d total module records", maxLoadedModulesTotal)
			break
		}
	}

	owners := map[string]linuxOwnership{}
	if provider.Name != "" && len(lookupPaths) > 0 && ctx.Err() == nil {
		owners = queryLinuxPackageOwnershipBatch(ctx, provider, lookupPaths)
	}

	processByPID := make(map[int]Process, len(items))
	for _, p := range items {
		processByPID[p.PID] = p
	}
	boundedProvenance := 0
	for ci := range out {
		c := &out[ci]
		process := processByPID[c.PID]
		for mi := range c.Modules {
			m := &c.Modules[mi]
			if m.DeletedBacking {
				m.TrustMismatch = moduleTrustMismatch(process.Trust.State, m.TrustState, true)
				continue
			}
			lookup := linuxPackageLookupPath(m.Path)
			owner, ok := owners[lookup]
			if !ok {
				switch {
				case provider.Name == "":
					owner = linuxOwnership{State: "UNKNOWN", Basis: "native Linux package provenance unavailable", Reason: "no supported package-ownership provider found", Confidence: evidence.ConfidenceLow}
				case ctx.Err() != nil:
					owner = linuxOwnership{State: "UNKNOWN", Basis: "native Linux package provenance bounded", Reason: ctx.Err().Error(), Confidence: evidence.ConfidenceLow}
				default:
					boundedProvenance++
					owner = linuxOwnership{State: "UNKNOWN", Basis: "native Linux package provenance bounded", Reason: fmt.Sprintf("module provenance lookup bounded at %d unique paths", maxLinuxModuleProvenancePaths), Confidence: evidence.ConfidenceLow}
				}
			}
			m.TrustState = owner.State
			m.TrustBasis = owner.Basis
			m.Provenance = owner.Package
			if owner.Confidence != "" && confidenceRank(owner.Confidence) < confidenceRank(m.Confidence) {
				m.Confidence = owner.Confidence
			}
			if owner.Reason != "" {
				m.Reason = appendReason(m.Reason, owner.Reason)
			}
			m.TrustMismatch = moduleTrustMismatch(process.Trust.State, m.TrustState, m.DeletedBacking)
		}
		c.Modules = normalizeLoadedModules(c.Modules, "linux")
		c.ModuleCount = len(c.Modules)
		summarizeLoadedModules(c)
	}

	if provider.Name == "" && stats.State == evidence.StateObserved {
		stats.State = evidence.StateDegraded
		stats.Reason = "loaded-module paths were collected, but no supported native Linux package-ownership provider was available"
	}
	if boundedProvenance > 0 {
		stats.State = evidence.StateDegraded
		stats.Reason = appendReason(stats.Reason, fmt.Sprintf("%d module path(s) exceeded the %d-path package provenance bound", boundedProvenance, maxLinuxModuleProvenancePaths))
	}
	return out, stats
}

func readLinuxLoadedModules(ctx context.Context, p Process) (LoadedModuleContext, error) {
	path := filepath.Join("/proc", strconv.Itoa(p.PID), "maps")
	f, err := os.Open(path)
	if err != nil {
		return LoadedModuleContext{}, err
	}
	defer f.Close()

	c := LoadedModuleContext{PID: p.PID, Platform: "linux", State: "OBSERVED", Source: "/proc/<pid>/maps", Confidence: evidence.ConfidenceHigh}
	mainExe := filepath.Clean(strings.TrimSpace(p.ExecutablePath))
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	seen := map[string]struct{}{}
	for s.Scan() {
		if ctx.Err() != nil {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = ctx.Err().Error()
			break
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || len(fields[1]) < 3 || fields[1][2] != 'x' {
			continue
		}
		raw := strings.Join(fields[5:], " ")
		deleted := strings.HasSuffix(raw, " (deleted)")
		clean := strings.TrimSuffix(raw, " (deleted)")
		if !strings.HasPrefix(clean, "/") || !linuxLoadedLibraryCandidate(clean) {
			continue
		}
		clean = filepath.Clean(clean)
		if mainExe != "" && clean == mainExe {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		state := "UNKNOWN"
		basis := "native package ownership pending"
		reason := ""
		if deleted {
			state = "DELETED_BACKING"
			basis = "procfs mapping path is marked deleted"
			reason = "loaded executable mapping references a deleted backing file"
		}
		c.Modules = append(c.Modules, LoadedModule{
			Path: clean, Name: filepath.Base(clean), DeletedBacking: deleted,
			TrustState: state, TrustBasis: basis, DirectoryState: "UNKNOWN",
			Source: "/proc/<pid>/maps", Confidence: evidence.ConfidenceHigh, Reason: reason,
		})
		if len(c.Modules) >= maxLoadedModulesPerProcess {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = appendReason(c.Reason, fmt.Sprintf("loaded-module inventory truncated at %d records for process", maxLoadedModulesPerProcess))
			break
		}
	}
	if err := s.Err(); err != nil {
		return LoadedModuleContext{}, err
	}
	return c, nil
}

func linuxLoadedLibraryCandidate(path string) bool {
	p := strings.ToLower(filepath.Clean(path))
	base := strings.ToLower(filepath.Base(p))
	if strings.Contains(base, ".so") || strings.HasSuffix(base, ".node") || strings.HasSuffix(base, ".dll") || strings.HasSuffix(base, ".dylib") {
		return true
	}
	for _, prefix := range []string{"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib/", "/opt/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

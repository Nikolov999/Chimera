//go:build darwin

package processes

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxDarwinModuleProcesses  = 256
	maxDarwinModuleTrustPaths = 1024
)

func collectLoadedModulesPlatform(ctx context.Context, items []Process) ([]LoadedModuleContext, moduleProviderStats) {
	vmmap, vmErr := exec.LookPath("vmmap")
	if vmErr != nil {
		out := make([]LoadedModuleContext, 0, len(items))
		for _, p := range items {
			out = append(out, LoadedModuleContext{PID: p.PID, Platform: "darwin", State: "UNAVAILABLE", Source: "macOS vmmap loaded-image metadata", Confidence: evidence.ConfidenceLow, Reason: "vmmap executable was not found"})
		}
		return out, moduleProviderStats{ID: "macos-loaded-modules", State: evidence.StateUnavailable, Source: "macOS vmmap loaded-image metadata", Reason: "vmmap executable was not found"}
	}
	codesign, codesignErr := exec.LookPath("codesign")
	pkgutil, pkgutilErr := exec.LookPath("pkgutil")
	trustCache := map[string]LoadedModule{}
	trustProbes := 0
	out := make([]LoadedModuleContext, 0, len(items))
	stats := moduleProviderStats{ID: "macos-loaded-modules", State: evidence.StateObserved, Source: "macOS vmmap loaded-image metadata plus codesign/pkgutil and POSIX directory metadata"}
	total := 0

	for index, p := range items {
		if index >= maxDarwinModuleProcesses || total >= maxLoadedModulesTotal {
			stats.State = evidence.StateDegraded
			stats.Reason = fmt.Sprintf("macOS loaded-module collection bounded at %d processes and %d total module records", maxDarwinModuleProcesses, maxLoadedModulesTotal)
			break
		}
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c, err := readDarwinLoadedModules(ctx, vmmap, p)
		if err != nil {
			stats.Denied++
			out = append(out, LoadedModuleContext{PID: p.PID, Platform: "darwin", State: "DENIED", Source: "macOS vmmap loaded-image metadata", Confidence: evidence.ConfidenceLow, Reason: err.Error()})
			continue
		}
		for i := range c.Modules {
			m := &c.Modules[i]
			key := filepath.Clean(m.Path)
			if cached, ok := trustCache[key]; ok {
				m.TrustState = cached.TrustState
				m.TrustBasis = cached.TrustBasis
				m.Provenance = cached.Provenance
				m.Signature = cached.Signature
				m.Reason = appendReason(m.Reason, cached.Reason)
				if confidenceRank(cached.Confidence) < confidenceRank(m.Confidence) {
					m.Confidence = cached.Confidence
				}
			} else {
				if trustProbes < maxDarwinModuleTrustPaths && codesignErr == nil {
					state, sig, basis, reason := verifyDarwinCodeSignature(ctx, codesign, key)
					m.TrustState, m.Signature, m.TrustBasis, m.Reason = state, sig, basis, appendReason(m.Reason, reason)
					trustProbes++
				} else if trustProbes < maxDarwinModuleTrustPaths && pkgutilErr == nil {
					if pkg := darwinPackageOwner(ctx, pkgutil, key); pkg != "" {
						m.TrustState = "PACKAGE_MANAGED"
						m.Provenance = pkg
						m.TrustBasis = "macOS package receipt provenance via pkgutil"
					} else {
						m.TrustState = "UNKNOWN"
						m.TrustBasis = "macOS package receipt provenance via pkgutil"
						m.Reason = appendReason(m.Reason, "no package receipt owner was established")
					}
					trustProbes++
				} else {
					m.TrustState = "UNKNOWN"
					m.TrustBasis = "macOS module trust verification unavailable or bounded"
					if codesignErr != nil && pkgutilErr != nil {
						m.Reason = appendReason(m.Reason, "codesign and pkgutil are unavailable")
					} else {
						m.Reason = appendReason(m.Reason, fmt.Sprintf("module trust verification bounded at %d unique paths", maxDarwinModuleTrustPaths))
					}
				}
				trustCache[key] = LoadedModule{TrustState: m.TrustState, TrustBasis: m.TrustBasis, Provenance: m.Provenance, Signature: m.Signature, Confidence: m.Confidence, Reason: m.Reason}
			}
			dirNode := unixPermissionNode(filepath.Dir(m.Path), "DIRECTORY", p, true)
			m.DirectoryState = dirNode.State
			m.DirectoryWritable = dirNode.UntrustedWrite || (p.Principal.Elevated && dirNode.BroadWrite)
			m.BroadDirectoryWrite = dirNode.BroadWrite
			if dirNode.State != "OBSERVED" {
				m.Confidence = evidence.ConfidenceMedium
				m.Reason = appendReason(m.Reason, "module directory permission metadata unavailable: "+fallback(dirNode.Reason, dirNode.State))
			}
			m.TrustMismatch = moduleTrustMismatch(p.Trust.State, m.TrustState, m.DeletedBacking)
		}
		c.Modules = normalizeLoadedModules(c.Modules, "darwin")
		c.ModuleCount = len(c.Modules)
		summarizeLoadedModules(&c)
		stats.Count += len(c.Modules)
		total += len(c.Modules)
		out = append(out, c)
	}
	if codesignErr != nil && pkgutilErr != nil && stats.State == evidence.StateObserved {
		stats.State = evidence.StateDegraded
		stats.Reason = "loaded-image paths were collected, but codesign/pkgutil provenance providers were unavailable"
	}
	if stats.Denied > 0 && stats.State == evidence.StateObserved {
		stats.State = evidence.StateDegraded
		stats.Reason = fmt.Sprintf("%d process loaded-image table(s) were inaccessible", stats.Denied)
	}
	return out, stats
}

func readDarwinLoadedModules(ctx context.Context, vmmap string, p Process) (LoadedModuleContext, error) {
	cmd := exec.CommandContext(ctx, vmmap, "-w", fmt.Sprintf("%d", p.PID))
	raw, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return LoadedModuleContext{}, ctx.Err()
		}
		text := strings.TrimSpace(string(raw))
		if text == "" {
			text = err.Error()
		}
		return LoadedModuleContext{}, fmt.Errorf("vmmap pid %d: %s", p.PID, text)
	}
	c := LoadedModuleContext{PID: p.PID, Platform: "darwin", State: "OBSERVED", Source: "macOS vmmap loaded-image metadata", Confidence: evidence.ConfidenceHigh}
	mainExe := filepath.Clean(strings.TrimSpace(p.ExecutablePath))
	seen := map[string]struct{}{}
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		if ctx.Err() != nil {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = ctx.Err().Error()
			break
		}
		line := strings.TrimSpace(s.Text())
		idx := strings.Index(line, "/")
		if idx < 0 {
			continue
		}
		candidate := strings.TrimSpace(line[idx:])
		candidate = trimDarwinVMMapPath(candidate)
		if candidate == "" || !darwinLoadedLibraryCandidate(candidate) {
			continue
		}
		candidate = filepath.Clean(candidate)
		if mainExe != "" && candidate == mainExe {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		c.Modules = append(c.Modules, LoadedModule{Path: candidate, Name: filepath.Base(candidate), TrustState: "UNKNOWN", TrustBasis: "macOS loaded-image provenance pending", DirectoryState: "UNKNOWN", Source: "macOS vmmap", Confidence: evidence.ConfidenceHigh})
		if len(c.Modules) >= maxLoadedModulesPerProcess {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = appendReason(c.Reason, fmt.Sprintf("loaded-module inventory truncated at %d records for process", maxLoadedModulesPerProcess))
			break
		}
	}
	return c, nil
}

func trimDarwinVMMapPath(v string) string {
	v = strings.TrimSpace(v)
	// vmmap normally places the mapped path at the end of a line. Keep spaces
	// that can legitimately occur in application bundle paths, but remove
	// common trailing region annotations.
	for _, marker := range []string{" [", " (", "\t"} {
		if i := strings.Index(v, marker); i > 0 {
			tail := strings.ToLower(v[i:])
			if strings.Contains(tail, "reserved") || strings.Contains(tail, "cow") || strings.Contains(tail, "shared") {
				v = strings.TrimSpace(v[:i])
			}
		}
	}
	return v
}

func darwinLoadedLibraryCandidate(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, ".dylib") || strings.Contains(p, ".framework/") || strings.Contains(p, ".bundle/") || strings.HasPrefix(p, "/usr/lib/") || strings.HasPrefix(p, "/system/library/")
}

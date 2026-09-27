//go:build linux

package processes

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

const (
	maxTrustEnrichmentPaths = 1024
	linuxTrustStageBudget   = 6 * time.Second
	linuxDpkgBatchSize      = 128
)

type linuxPackageProvider struct {
	Name string
	Path string
}

type linuxOwnership struct {
	State      string
	Package    string
	Basis      string
	Reason     string
	Confidence evidence.Confidence
}

// enrichTrust deliberately gives package provenance its own Linux stage budget.
// The base /proc inventory remains usable even when a package database is slow,
// and later process enrichments retain time inside the provider's 20s ceiling.
func enrichTrust(ctx context.Context, inv *Inventory) {
	provider := detectLinuxPackageProvider()
	stageCtx, cancel, _ := reliability.StageContext(ctx, linuxTrustStageBudget, 750*time.Millisecond, reliability.ProviderBudgetDefault)
	defer cancel()

	cache := map[string]TrustContext{}
	lookupByProcessPath := map[string]string{}
	uniqueLookup := map[string]struct{}{}
	orderedLookup := []string{}
	probed := 0

	for i := range inv.Processes {
		p := &inv.Processes[i]
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" || p.Trust.DeletedBacking {
			continue
		}
		key := filepath.Clean(path)
		if _, ok := lookupByProcessPath[key]; ok {
			continue
		}
		if probed >= maxTrustEnrichmentPaths {
			continue
		}
		lookup := linuxPackageLookupPath(key)
		lookupByProcessPath[key] = lookup
		probed++
		if _, ok := uniqueLookup[lookup]; !ok {
			uniqueLookup[lookup] = struct{}{}
			orderedLookup = append(orderedLookup, lookup)
		}
	}

	owners := map[string]linuxOwnership{}
	if provider.Name != "" && len(orderedLookup) > 0 {
		owners = queryLinuxPackageOwnershipBatch(stageCtx, provider, orderedLookup)
	}

	degraded := 0
	bounded := 0
	for i := range inv.Processes {
		p := &inv.Processes[i]
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" || p.Trust.DeletedBacking {
			continue
		}
		key := filepath.Clean(path)
		if cached, ok := cache[key]; ok {
			p.Trust = cached
			continue
		}
		t := p.Trust
		lookup, selected := lookupByProcessPath[key]
		if !selected {
			bounded++
			if t.Reason == "" {
				t.Reason = fmt.Sprintf("trust enrichment bounded at %d unique executable paths", maxTrustEnrichmentPaths)
			}
			cache[key] = t
			p.Trust = t
			continue
		}
		if provider.Name == "" {
			if t.Reason == "" {
				t.Reason = "no supported native Linux package-ownership provider is available"
			}
			cache[key] = t
			p.Trust = t
			continue
		}
		owner, ok := owners[lookup]
		if !ok {
			owner = linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via " + provider.Name, Reason: "package ownership batch returned no result", Confidence: evidence.ConfidenceLow}
		}
		switch owner.State {
		case "PACKAGE_MANAGED":
			t.State = "PACKAGE_MANAGED"
			t.Basis = owner.Basis
			t.Reason = ""
		case "UNMANAGED":
			t.State = "UNMANAGED"
			t.Basis = owner.Basis
			t.Reason = owner.Reason
		case "UNKNOWN":
			degraded++
			if owner.Reason != "" {
				t.Reason = owner.Reason
			}
			if strings.TrimSpace(t.Basis) == "" || strings.Contains(strings.ToLower(t.Basis), "deferred") {
				t.Basis = owner.Basis
			} else if owner.Basis != "" && !strings.Contains(t.Basis, owner.Basis) {
				t.Basis += "; " + owner.Basis
			}
		}
		cache[key] = t
		p.Trust = t
	}

	state := evidence.StateObserved
	reasons := []string{}
	if provider.Name == "" {
		state = evidence.StateUnavailable
		reasons = append(reasons, "no supported native Linux package-ownership provider found (dpkg-query, rpm, apk, or pacman)")
	} else if degraded > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("%d executable ownership lookup(s) could not be resolved cleanly", degraded))
	}
	if stageCtx.Err() != nil {
		state = evidence.StateDegraded
		reasons = append(reasons, "bounded package provenance stage: "+stageCtx.Err().Error())
	}
	if bounded > 0 {
		reasons = append(reasons, fmt.Sprintf("%d process executable path(s) were outside the %d-path provenance bound", bounded, maxTrustEnrichmentPaths))
	}
	addSource(inv, "linux-executable-provenance", state, linuxProviderSource(provider), probed, strings.Join(uniqueStrings(reasons), "; "))
}

func detectLinuxPackageProvider() linuxPackageProvider {
	for _, name := range []string{"dpkg-query", "rpm", "apk", "pacman"} {
		if path, err := exec.LookPath(name); err == nil {
			return linuxPackageProvider{Name: name, Path: path}
		}
	}
	return linuxPackageProvider{}
}

func linuxProviderSource(p linuxPackageProvider) string {
	if p.Name == "" {
		return "Linux native package ownership"
	}
	if p.Name == "dpkg-query" {
		return "Linux native package ownership via batched dpkg-query"
	}
	return "Linux native package ownership via " + p.Name
}

func linuxPackageLookupPath(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && strings.TrimSpace(resolved) != "" {
		return filepath.Clean(resolved)
	}
	return path
}

// queryLinuxPackageOwnershipBatch avoids spawning one package-manager process
// for every executable/library. Debian-family systems are the critical case:
// dpkg-query accepts many exact path patterns in one invocation, so 100s of
// per-path subprocesses collapse into a handful of bounded database queries.
func queryLinuxPackageOwnershipBatch(ctx context.Context, provider linuxPackageProvider, paths []string) map[string]linuxOwnership {
	out := make(map[string]linuxOwnership, len(paths))
	ordered := uniqueCleanLinuxPaths(paths)
	if provider.Name == "" {
		for _, path := range ordered {
			out[path] = linuxOwnership{State: "UNKNOWN", Basis: "native Linux package provenance unavailable", Reason: "no supported package-ownership provider found", Confidence: evidence.ConfidenceLow}
		}
		return out
	}
	if provider.Name != "dpkg-query" {
		for _, path := range ordered {
			if ctx.Err() != nil {
				out[path] = linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via " + provider.Name, Reason: ctx.Err().Error(), Confidence: evidence.ConfidenceLow}
				continue
			}
			out[path] = queryLinuxPackageOwnership(ctx, provider, path)
		}
		return out
	}

	for start := 0; start < len(ordered); start += linuxDpkgBatchSize {
		end := start + linuxDpkgBatchSize
		if end > len(ordered) {
			end = len(ordered)
		}
		chunk := ordered[start:end]
		if ctx.Err() != nil {
			for _, path := range chunk {
				out[path] = linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via dpkg-query", Reason: ctx.Err().Error(), Confidence: evidence.ConfidenceLow}
			}
			continue
		}
		args := append([]string{"-S"}, chunk...)
		cmd := exec.CommandContext(ctx, provider.Path, args...)
		stdout, err := cmd.Output()
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		matched := parseDpkgSearchOutput(string(stdout))
		for path, pkg := range matched {
			out[path] = linuxOwnership{State: "PACKAGE_MANAGED", Package: pkg, Basis: "native package ownership via dpkg-query: " + pkg, Confidence: evidence.ConfidenceExact}
		}
		for _, path := range chunk {
			if _, ok := out[path]; ok {
				continue
			}
			switch {
			case ctx.Err() != nil:
				out[path] = linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via dpkg-query", Reason: ctx.Err().Error(), Confidence: evidence.ConfidenceLow}
			case err == nil:
				out[path] = linuxOwnership{State: "UNMANAGED", Basis: "native package ownership via dpkg-query", Reason: "native package database reports no owner for executable path", Confidence: evidence.ConfidenceHigh}
			case dpkgSearchOnlyMissing(stderr):
				out[path] = linuxOwnership{State: "UNMANAGED", Basis: "native package ownership via dpkg-query", Reason: "native package database reports no owner for executable path", Confidence: evidence.ConfidenceHigh}
			default:
				reason := strings.TrimSpace(stderr)
				if reason == "" {
					reason = err.Error()
				}
				out[path] = linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via dpkg-query", Reason: reason, Confidence: evidence.ConfidenceLow}
			}
		}
	}
	return out
}

func uniqueCleanLinuxPaths(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func parseDpkgSearchOutput(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		owner := strings.TrimSpace(line[:idx])
		path := filepath.Clean(strings.TrimSpace(line[idx+2:]))
		if owner == "" || path == "" || path == "." || strings.Contains(strings.ToLower(owner), "diversion") {
			continue
		}
		out[path] = owner
	}
	return out
}

func dpkgSearchOnlyMissing(stderr string) bool {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return false
	}
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if !strings.Contains(line, "no path found matching pattern") {
			return false
		}
	}
	return true
}

func queryLinuxPackageOwnership(ctx context.Context, provider linuxPackageProvider, path string) linuxOwnership {
	if provider.Name == "" || strings.TrimSpace(path) == "" {
		return linuxOwnership{State: "UNKNOWN", Basis: "native Linux package provenance unavailable", Reason: "package ownership provider or executable path unavailable", Confidence: evidence.ConfidenceLow}
	}
	var cmd *exec.Cmd
	switch provider.Name {
	case "dpkg-query":
		cmd = exec.CommandContext(ctx, provider.Path, "-S", path)
	case "rpm":
		cmd = exec.CommandContext(ctx, provider.Path, "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\n", path)
	case "apk":
		cmd = exec.CommandContext(ctx, provider.Path, "info", "--who-owns", path)
	case "pacman":
		cmd = exec.CommandContext(ctx, provider.Path, "-Qo", path)
	default:
		return linuxOwnership{State: "UNKNOWN", Basis: "unsupported Linux package provenance provider", Reason: provider.Name, Confidence: evidence.ConfidenceLow}
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		pkg := parseLinuxPackageOwner(provider.Name, text)
		if pkg == "" {
			return linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via " + provider.Name, Reason: "package provider returned success without a parseable owner", Confidence: evidence.ConfidenceLow}
		}
		return linuxOwnership{State: "PACKAGE_MANAGED", Package: pkg, Basis: fmt.Sprintf("native package ownership via %s: %s", provider.Name, pkg), Confidence: evidence.ConfidenceExact}
	}
	if ctx.Err() != nil {
		return linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via " + provider.Name, Reason: ctx.Err().Error(), Confidence: evidence.ConfidenceLow}
	}
	if linuxOwnershipNotFound(provider.Name, text) {
		return linuxOwnership{State: "UNMANAGED", Basis: "native package ownership via " + provider.Name, Reason: "native package database reports no owner for executable path", Confidence: evidence.ConfidenceHigh}
	}
	if text == "" {
		text = err.Error()
	}
	return linuxOwnership{State: "UNKNOWN", Basis: "native package ownership via " + provider.Name, Reason: strings.TrimSpace(text), Confidence: evidence.ConfidenceLow}
}

func parseLinuxPackageOwner(provider, text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	switch provider {
	case "dpkg-query":
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			idx := strings.Index(line, ": ")
			if idx <= 0 {
				continue
			}
			owner := strings.TrimSpace(line[:idx])
			if owner != "" && !strings.Contains(strings.ToLower(owner), "diversion") {
				return owner
			}
		}
	case "rpm":
		return strings.Fields(text)[0]
	case "apk":
		if idx := strings.LastIndex(strings.ToLower(text), " is owned by "); idx >= 0 {
			return strings.TrimSpace(text[idx+len(" is owned by "):])
		}
		return strings.Fields(text)[0]
	case "pacman":
		if idx := strings.Index(strings.ToLower(text), " is owned by "); idx >= 0 {
			fields := strings.Fields(text[idx+len(" is owned by "):])
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func linuxOwnershipNotFound(provider, text string) bool {
	s := strings.ToLower(strings.TrimSpace(text))
	needles := []string{
		"no path found matching pattern",
		"is not owned by any package",
		"no package owns",
		"could not find owner",
		"could not find owner package",
		"not owned by any package",
	}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	if provider == "apk" && strings.Contains(s, "does not exist") {
		return true
	}
	return false
}

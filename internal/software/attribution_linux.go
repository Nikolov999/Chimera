//go:build linux

package software

import (
	"context"
	"fmt"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func resolvePlatformOwnership(ctx context.Context, path string, items []Item) ownershipResult {
	available := 0
	negative := 0
	degraded := make([]string, 0)

	if commandAvailable("dpkg-query") {
		available++
		text, err := runAttributionProbe(ctx, "dpkg-query", "-S", path)
		if err == nil {
			if id := parseDpkgOwner(text); id != "" {
				if item := findItemByPackageID(items, id); item != nil {
					return resultFromItem(item, "dpkg-query", "native file ownership", "dpkg-query identifies the executable as package-owned", evidence.ConfidenceExact)
				}
				return ownershipResult{Ownership: OwnershipPackage, PackageID: id, Product: "UNKNOWN", Version: "UNKNOWN", PackageSource: "dpkg", InstallPath: "UNKNOWN", Provider: "dpkg-query", ProviderState: evidence.StateObserved, Method: "native file ownership", Reason: "dpkg-query identifies the executable as package-owned; normalized installed-package metadata was not available for the owner", Confidence: evidence.ConfidenceHigh}
			}
			negative++
		} else if isNotOwnedError(err.Error()) {
			negative++
		} else {
			degraded = append(degraded, "dpkg-query: "+err.Error())
		}
	}

	if commandAvailable("rpm") {
		available++
		text, err := runAttributionProbe(ctx, "rpm", "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", path)
		if err == nil {
			f := strings.Split(strings.TrimSpace(text), "\t")
			if len(f) > 0 && strings.TrimSpace(f[0]) != "" {
				id := strings.TrimSpace(f[0])
				if item := findItemByPackageID(items, id); item != nil {
					return resultFromItem(item, "rpm", "native file ownership", "RPM database identifies the executable as package-owned", evidence.ConfidenceExact)
				}
				version := "UNKNOWN"
				if len(f) > 1 {
					version = normalizedOr(f[1], "UNKNOWN")
				}
				return ownershipResult{Ownership: OwnershipPackage, PackageID: id, Product: id, Version: version, PackageSource: "rpm", InstallPath: "UNKNOWN", Provider: "rpm", ProviderState: evidence.StateObserved, Method: "native file ownership", Reason: "RPM database identifies the executable as package-owned", Confidence: evidence.ConfidenceExact}
			}
			negative++
		} else if isNotOwnedError(err.Error()) {
			negative++
		} else {
			degraded = append(degraded, "rpm: "+err.Error())
		}
	}

	if commandAvailable("apk") {
		available++
		text, err := runAttributionProbe(ctx, "apk", "info", "--who-owns", path)
		if err == nil {
			if item := parseAPKOwner(text, items); item != nil {
				return resultFromItem(item, "apk", "native file ownership", "APK database identifies the executable as package-owned", evidence.ConfidenceExact)
			}
			negative++
		} else if isNotOwnedError(err.Error()) {
			negative++
		} else {
			degraded = append(degraded, "apk: "+err.Error())
		}
	}

	if commandAvailable("pacman") {
		available++
		text, err := runAttributionProbe(ctx, "pacman", "-Qo", path)
		if err == nil {
			if id := parsePacmanOwner(text); id != "" {
				if item := findItemByPackageID(items, id); item != nil {
					return resultFromItem(item, "pacman", "native file ownership", "pacman database identifies the executable as package-owned", evidence.ConfidenceExact)
				}
				return ownershipResult{Ownership: OwnershipPackage, PackageID: id, Product: id, Version: "UNKNOWN", PackageSource: "pacman", InstallPath: "UNKNOWN", Provider: "pacman", ProviderState: evidence.StateObserved, Method: "native file ownership", Reason: "pacman database identifies the executable as package-owned", Confidence: evidence.ConfidenceHigh}
			}
			negative++
		} else if isNotOwnedError(err.Error()) {
			negative++
		} else {
			degraded = append(degraded, "pacman: "+err.Error())
		}
	}

	if item := matchInstalledPath(path, items); item != nil {
		return resultFromItem(item, "installed-software-prefix", "installation-root attribution", "executable path is contained by the locally observed application/package installation root", evidence.ConfidenceHigh)
	}

	if available == 0 {
		return ownershipResult{Ownership: OwnershipUnknown, Provider: "linux package ownership", ProviderState: evidence.StateUnavailable, Method: "unresolved", Reason: "no supported native Linux file-ownership provider is available", Confidence: evidence.ConfidenceLow}
	}
	if negative > 0 && negative+len(degraded) == available {
		if len(degraded) == 0 {
			return ownershipResult{Ownership: OwnershipUnmanaged, Provider: "linux package ownership", ProviderState: evidence.StateObserved, Method: "native negative ownership", Reason: "available native package databases report no owner for the executable path", Confidence: evidence.ConfidenceHigh}
		}
		return ownershipResult{Ownership: OwnershipUnknown, Provider: "linux package ownership", ProviderState: evidence.StateDegraded, Method: "partial native ownership", Reason: fmt.Sprintf("ownership could not be resolved consistently; %s", strings.Join(degraded, "; ")), Confidence: evidence.ConfidenceLow}
	}
	return ownershipResult{Ownership: OwnershipUnknown, Provider: "linux package ownership", ProviderState: evidence.StateDegraded, Method: "native ownership", Reason: strings.Join(degraded, "; "), Confidence: evidence.ConfidenceLow}
}

func parseDpkgOwner(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		owner := strings.TrimSpace(line[:idx])
		if strings.Contains(strings.ToLower(owner), "diversion") || strings.Contains(owner, ",") {
			continue
		}
		return owner
	}
	return ""
}

func parsePacmanOwner(text string) string {
	const marker = " is owned by "
	for _, line := range strings.Split(text, "\n") {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[idx+len(marker):])
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func parseAPKOwner(text string, items []Item) *Item {
	lower := strings.ToLower(text)
	var best *Item
	bestLen := -1
	for i := range items {
		source := strings.ToLower(strings.TrimSpace(items[i].PackageSource))
		if source != "apk" && !strings.HasPrefix(source, "apk:") {
			continue
		}
		token := strings.ToLower(strings.TrimSpace(items[i].PackageID) + "-" + strings.TrimSpace(items[i].Version))
		if token == "-" || !strings.Contains(lower, token) {
			continue
		}
		if len(token) > bestLen {
			cp := items[i]
			best = &cp
			bestLen = len(token)
		}
	}
	return best
}

func isNotOwnedError(msg string) bool {
	s := strings.ToLower(msg)
	needles := []string{"no path found matching pattern", "is not owned by any package", "no package owns", "could not find owner", "no such package", "not owned"}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

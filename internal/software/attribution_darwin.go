//go:build darwin

package software

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func resolvePlatformOwnership(ctx context.Context, path string, items []Item) ownershipResult {
	if item := matchInstalledPath(path, items); item != nil {
		return resultFromItem(item, "macOS application metadata", "application-bundle attribution", "executable path is contained by a locally observed macOS application bundle", evidence.ConfidenceHigh)
	}
	if commandAvailable("pkgutil") {
		text, err := runAttributionProbe(ctx, "pkgutil", "--file-info", path)
		if err == nil {
			id, version := parsePkgutilFileInfo(text)
			if id != "" {
				return ownershipResult{Ownership: OwnershipPackage, PackageID: id, Product: "UNKNOWN", Version: normalizedOr(version, "UNKNOWN"), PackageSource: "macos-pkg-receipt", InstallPath: "UNKNOWN", Provider: "pkgutil", ProviderState: evidence.StateObserved, Method: "package-receipt file ownership", Reason: "macOS package receipt metadata attributes the executable path to an installed package receipt", Confidence: evidence.ConfidenceExact}
			}
		}
	}
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.HasPrefix(p, "/system/") || strings.HasPrefix(p, "/usr/bin/") || strings.HasPrefix(p, "/usr/sbin/") || strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/sbin/") {
		return ownershipResult{Ownership: OwnershipUnknown, Provider: "macOS package/application metadata", ProviderState: evidence.StateObserved, Method: "sealed-system boundary", Reason: "path lies in an operating-system managed location, but package-receipt ownership was not established; Chimera does not classify it as unmanaged", Confidence: evidence.ConfidenceMedium}
	}
	if portableCandidatePath(path) {
		return ownershipResult{Ownership: OwnershipUnmanaged, Provider: "macOS package/application metadata", ProviderState: evidence.StateObserved, Method: "portable-path candidate", Reason: "no application bundle or package receipt owns the executable and the path is in a per-user or temporary location", Confidence: evidence.ConfidenceMedium}
	}
	return ownershipResult{Ownership: OwnershipUnknown, Provider: "macOS package/application metadata", ProviderState: evidence.StateObserved, Method: "unresolved", Reason: "no application bundle or package receipt ownership could be established from local metadata", Confidence: evidence.ConfidenceLow}
}

func parsePkgutilFileInfo(text string) (string, string) {
	id, version := "", ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "pkgid:") {
			id = strings.TrimSpace(line[len("pkgid:"):])
		}
		if strings.HasPrefix(strings.ToLower(line), "pkg-version:") {
			version = strings.TrimSpace(line[len("pkg-version:"):])
		}
	}
	return id, version
}

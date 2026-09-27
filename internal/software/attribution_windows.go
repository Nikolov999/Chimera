//go:build windows

package software

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func resolvePlatformOwnership(ctx context.Context, path string, items []Item) ownershipResult {
	_ = ctx
	if item := matchInstalledPath(path, items); item != nil {
		return resultFromItem(item, "windows installed-application metadata", "installation-root attribution", "executable path is contained by a locally observed uninstall-registry or AppX/MSIX installation root", evidence.ConfidenceHigh)
	}

	// Windows does not expose a universal read-only file-to-package ownership
	// database for classic Win32 applications. Do not mislabel an MSI/portable
	// binary as unmanaged simply because InstallLocation metadata is absent.
	if root := strings.TrimSpace(os.Getenv("SystemRoot")); root != "" {
		p := strings.ToLower(filepath.Clean(path))
		r := strings.ToLower(filepath.Clean(root))
		if pathWithin(p, r) {
			return ownershipResult{Ownership: OwnershipUnknown, Provider: "windows installation metadata", ProviderState: evidence.StateObserved, Method: "system-root boundary", Reason: "path is under the Windows system root, but has no exact classic-Windows file-to-package ownership provider; ownership is therefore not guessed", Confidence: evidence.ConfidenceMedium}
		}
	}
	if portableCandidatePath(path) {
		return ownershipResult{Ownership: OwnershipUnmanaged, Provider: "windows installation metadata", ProviderState: evidence.StateObserved, Method: "portable-path candidate", Reason: "no observed application installation root owns the executable and the path is in a per-user or temporary location; preserved as an unmanaged portable candidate", Confidence: evidence.ConfidenceMedium}
	}
	return ownershipResult{Ownership: OwnershipUnknown, Provider: "windows installation metadata", ProviderState: evidence.StateObserved, Method: "unresolved", Reason: "no exact classic-Windows file ownership mapping is available and no observed application installation root contains the executable", Confidence: evidence.ConfidenceLow}
}

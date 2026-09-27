//go:build windows

package filesystem

import (
	"github.com/Nikolov999/chimera/internal/evidence"
	"os"
)

func platformOwnership(os.FileInfo) (string, string) { return "", "" }
func platformPermissionCapability() PermissionCapability {
	return PermissionCapability{State: evidence.StateObserved, Model: "NTFS_DACL", Source: "Windows filesystem security descriptor capability"}
}

//go:build !linux && !darwin && !windows

package secrets

import (
	"context"
	"os"
)

func platformPermissionModel() string { return "UNSUPPORTED" }
func applyBasicPermissionMetadata(r *Record, info os.FileInfo) {
	if r != nil && info != nil {
		r.Mode = info.Mode().String()
		r.PermissionState = "UNKNOWN"
	}
}
func enrichPlatformPermissions(_ context.Context, _ []Record) []string { return nil }

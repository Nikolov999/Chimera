//go:build !linux && !darwin && !windows

package processes

import "context"

func collectPlatformPathPermissions(_ context.Context, items []Process, platform string) []PathPermissionContext {
	out := make([]PathPermissionContext, 0, len(items))
	for _, p := range items {
		out = append(out, unknownPermissionContext(p, platform, "platform executable permission analysis is unsupported"))
	}
	return out
}

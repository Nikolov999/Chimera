//go:build darwin

package filesystem

import "context"

// macOS keeps its Fix59 behavior. Fix60's filesystem staging is Linux-only.
func unixFilesystemStageContext(parent context.Context, _ string) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return parent, func() {}
}

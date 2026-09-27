//go:build !linux && !darwin && !windows

package software

import "context"

func collectPlatformRuntimes(context.Context, *Inventory) {}

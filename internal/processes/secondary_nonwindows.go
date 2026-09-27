//go:build !windows && !linux

package processes

import "context"

func collectConcurrentSecondary(_ context.Context, _ *Inventory) bool { return false }

//go:build !linux && !windows && !darwin

package processes

import "context"

func enrichTrust(ctx context.Context, inv *Inventory) {
	_ = ctx
	_ = inv
}

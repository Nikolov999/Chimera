//go:build !linux && !windows && !darwin

package kernel

import "context"

func collectPlatform(ctx context.Context, k *Inventory) {
	_ = ctx
	k.KernelRelease = "unsupported"
	k.BootMode = "unsupported"
	k.Update = UpdateStatus{State: "UNSUPPORTED", Source: "platform", Detail: "kernel collector supports Windows, Linux, and macOS"}
}

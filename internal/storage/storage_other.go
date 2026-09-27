//go:build !linux && !windows && !darwin

package storage

import (
	"context"
	"runtime"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(context.Context) ([]Volume, []SourceStatus, []string) {
	reason := "storage encryption posture is unsupported on " + runtime.GOOS
	return nil, []SourceStatus{{ID: "platform-storage", State: evidence.StateUnsupported, Source: "platform storage provider", Reason: reason}}, []string{reason}
}

func collectMemoryProtection(context.Context, []Volume) ([]SwapArea, HibernationPosture, []SourceStatus, []string) {
	reason := "swap/hibernation posture is unsupported on " + runtime.GOOS
	h := HibernationPosture{
		SupportState: SupportUnknown, ConfigurationState: HibernationNotApplicable,
		ExposureState: ExposureNotApplicable, EncryptionState: EncryptionNotApplicable,
		State: evidence.StateUnsupported, CollectionSource: "platform memory-state provider",
		Confidence: evidence.ConfidenceExact, Reason: reason,
	}
	return nil, h, []SourceStatus{{ID: "platform-memory-state", State: evidence.StateUnsupported, Source: "platform memory-state provider", Reason: reason}}, []string{reason}
}

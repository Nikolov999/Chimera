//go:build !linux && !darwin && !windows

package processes

import "github.com/Nikolov999/chimera/internal/evidence"

func platformLocationHints(string) locationHints {
	return locationHints{Confidence: evidence.ConfidenceLow}
}

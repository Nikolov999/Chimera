//go:build !windows && !linux && !darwin

package kernel

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectInstalledVulnerableDriverCandidatesPlatform(context.Context, []driverIntelEntry) ([]driverCandidate, evidence.State, string, string) {
	return nil, evidence.StateNotApplicable, "pinned installed-driver seed has no entries for this platform", "embedded driver intelligence"
}

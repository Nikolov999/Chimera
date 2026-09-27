//go:build darwin

package kernel

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectInstalledVulnerableDriverCandidatesPlatform(context.Context, []driverIntelEntry) ([]driverCandidate, evidence.State, string, string) {
	// 's pinned seed currently contains no macOS kernel-extension
	// identities. Loaded kexts remain available for future exact correlation.
	return nil, evidence.StateNotApplicable, "pinned installed-driver seed has no entries for this platform", "embedded driver intelligence"
}

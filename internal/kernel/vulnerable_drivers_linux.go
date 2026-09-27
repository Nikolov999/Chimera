//go:build linux

package kernel

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectInstalledVulnerableDriverCandidatesPlatform(context.Context, []driverIntelEntry) ([]driverCandidate, evidence.State, string, string) {
	// 's pinned seed currently contains Windows vulnerable-driver
	// identities only. Loaded Linux modules are still correlated generically;
	// no synthetic Linux match is invented when the local seed has no entry.
	return nil, evidence.StateNotApplicable, "pinned installed-driver seed has no entries for this platform", "embedded driver intelligence"
}

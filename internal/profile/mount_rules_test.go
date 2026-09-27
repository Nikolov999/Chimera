package profile

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
)

func TestPhase082ProfileApplyUsesMountRuleProfileEvaluator(t *testing.T) {
	now := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("filesystem.permission_capability", fsinv.PermissionCapability{State: evidence.StateObserved, Model: "POSIX_MODE", Source: "test"}, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("filesystem.source.mount-boundaries", fsinv.SourceStatus{ID: "mount-boundaries", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.mount.tmp", fsinv.MountBoundary{ID: "tmp", Path: "/tmp", BackingSource: "tmpfs", Filesystem: "tmpfs", Options: []string{"rw", "nosuid", "nodev"}, AccessMode: fsinv.MountAccessReadWrite, Classification: fsinv.MountClassVirtual, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}, "test", now, evidence.ConfidenceExact),
	}

	developer, err := Resolve("developer")
	if err != nil {
		t.Fatal(err)
	}
	devApplied, err := Apply(developer, assessment.FilesystemRules())
	if err != nil {
		t.Fatal(err)
	}
	devFindings, err := assessment.EvaluateRules(devApplied.Rules, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingStatus(devFindings, "CHM-FS-016"); got != assessment.StatusPass {
		t.Fatalf("developer profile should not require noexec on /tmp, got %s", got)
	}

	strict, err := Resolve("high-security")
	if err != nil {
		t.Fatal(err)
	}
	strictApplied, err := Apply(strict, assessment.FilesystemRules())
	if err != nil {
		t.Fatal(err)
	}
	strictFindings, err := assessment.EvaluateRules(strictApplied.Rules, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingStatus(strictFindings, "CHM-FS-016"); got != assessment.StatusFail {
		t.Fatalf("high-security profile should require noexec on /tmp, got %s", got)
	}
}

func findingStatus(findings []assessment.Finding, id string) assessment.Status {
	for _, f := range findings {
		if f.RuleID == id {
			return f.Status
		}
	}
	return ""
}

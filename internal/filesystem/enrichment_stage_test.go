package filesystem

import (
	"context"
	"testing"
	"time"
)

func TestWindowsFilesystemStageBudgetsAreBounded(t *testing.T) {
	for _, stage := range []string{filesystemStageExecutable, filesystemStageSearchPath, filesystemStageSensitive, filesystemStageTemp, filesystemStageACL} {
		budget := windowsFilesystemStageBudgets[stage]
		max := 10 * time.Second
		if budget <= 0 || budget > max {
			t.Fatalf("unexpected %s budget %s", stage, budget)
		}
	}
}

func TestFilesystemEnrichmentStageContextPortableContract(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	child, done, _ := filesystemEnrichmentStageContext(parent, filesystemStageSensitive)
	defer done()
	if child == nil {
		t.Fatal("nil stage context")
	}
}

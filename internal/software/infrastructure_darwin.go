//go:build darwin

package software

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformInfrastructureActivity(ctx context.Context) ([]infrastructureActivity, []SourceStatus) {
	out := make([]infrastructureActivity, 0)
	sources := make([]SourceStatus, 0, 2)
	if text, err := run(ctx, "ps", "-axo", "comm="); err == nil {
		for _, line := range strings.Split(text, "\n") {
			if name := strings.TrimSpace(line); name != "" {
				out = append(out, infrastructureActivity{Kind: "process", Name: name, Path: name})
			}
		}
		sources = append(sources, SourceStatus{ID: "darwin-ps-processes", State: evidence.StateObserved, Source: "ps process metadata", ItemCount: len(out)})
	} else {
		sources = append(sources, SourceStatus{ID: "darwin-ps-processes", State: infrastructureStateForError(ctx, err), Source: "ps process metadata", Reason: err.Error()})
	}
	if text, err := run(ctx, "launchctl", "list"); err == nil {
		before := len(out)
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] != "Label" {
				out = append(out, infrastructureActivity{Kind: "service", Name: fields[2]})
			}
		}
		sources = append(sources, SourceStatus{ID: "darwin-launchctl-services", State: evidence.StateObserved, Source: "launchctl service metadata", ItemCount: len(out) - before})
	}
	return out, sources
}

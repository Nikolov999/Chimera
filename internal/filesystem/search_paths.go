package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type searchPathCandidate struct {
	Path     string
	Contexts []string
	Source   string
}

func privilegedSearchPathCandidates() []searchPathCandidate {
	items := append([]searchPathCandidate(nil), platformPrivilegedSearchPathCandidates()...)
	for _, part := range filepath.SplitList(os.Getenv("PATH")) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if abs, err := filepath.Abs(part); err == nil {
			part = abs
		}
		contexts := []string{"CURRENT_PROCESS_PATH"}
		if currentProcessPrivileged() {
			contexts = append(contexts, "PRIVILEGED_USER")
		}
		items = append(items, searchPathCandidate{Path: part, Contexts: contexts, Source: "current process PATH environment metadata"})
	}
	return normalizeSearchPathCandidates(items)
}

func normalizeSearchPathCandidates(in []searchPathCandidate) []searchPathCandidate {
	out := make([]searchPathCandidate, 0, len(in))
	byKey := map[string]int{}
	for _, c := range in {
		c.Path = strings.TrimSpace(c.Path)
		if c.Path == "" {
			continue
		}
		if abs, err := filepath.Abs(c.Path); err == nil {
			c.Path = abs
		}
		c.Path = filepath.Clean(c.Path)
		c.Contexts = uniqueSortedUpper(c.Contexts)
		c.Source = strings.TrimSpace(c.Source)
		if len(c.Contexts) == 0 {
			continue
		}
		if c.Source == "" {
			c.Source = "platform privileged search-path inventory"
		}
		key := platformPathKey(c.Path)
		if pos, ok := byKey[key]; ok {
			out[pos].Contexts = uniqueSortedUpper(append(out[pos].Contexts, c.Contexts...))
			if !strings.Contains(out[pos].Source, c.Source) {
				out[pos].Source += "; " + c.Source
			}
			continue
		}
		byKey[key] = len(out)
		out = append(out, c)
		if len(out) >= maxSearchPaths {
			break
		}
	}
	return out
}

// repairSearchPathRecords protects the inventory contract from a single partial
// provider row. Records with a usable path are retained and explicitly degraded;
// rows without any path identity are quarantined because they cannot be bound to
// a deterministic search-path record safely.
func repairSearchPathRecords(in []SearchPathRecord, capability PermissionCapability) ([]SearchPathRecord, []string) {
	out := make([]SearchPathRecord, 0, len(in))
	limitations := []string{}
	for i, sp := range in {
		sp.Path = strings.TrimSpace(sp.Path)
		if sp.Path == "" || sp.Path == "." {
			limitations = append(limitations, fmt.Sprintf("quarantined filesystem search-path record %d: missing path identity", i))
			continue
		}
		missing := []string{}
		if strings.TrimSpace(sp.ID) == "" {
			sp.ID = stableSearchPathID(sp.Path)
			missing = append(missing, "id")
		}
		if sp.State == "" {
			sp.State = evidence.StateDegraded
			missing = append(missing, "state")
		}
		if strings.TrimSpace(sp.PermissionModel) == "" {
			sp.PermissionModel = strings.TrimSpace(capability.Model)
			if sp.PermissionModel == "" {
				sp.PermissionModel = "UNKNOWN"
			}
			missing = append(missing, "permission_model")
		}
		if strings.TrimSpace(sp.CollectionSource) == "" {
			sp.CollectionSource = "filesystem search-path provider"
			missing = append(missing, "collection_source")
		}
		if sp.Confidence == "" {
			sp.Confidence = evidence.ConfidenceLow
			missing = append(missing, "confidence")
		}
		if len(sp.Contexts) == 0 {
			sp.Contexts = []string{"UNKNOWN_CONTEXT"}
			missing = append(missing, "contexts")
		}
		if len(sp.DiscoverySources) == 0 {
			sp.DiscoverySources = []string{"unknown search-path discovery source"}
			missing = append(missing, "discovery_sources")
		}
		if len(missing) > 0 {
			if sp.State == evidence.StateObserved {
				sp.State = evidence.StateDegraded
			}
			detail := "provider record was incomplete; repaired missing fields: " + strings.Join(missing, ",")
			if strings.TrimSpace(sp.Reason) == "" {
				sp.Reason = detail
			} else {
				sp.Reason = strings.TrimSpace(sp.Reason) + "; " + detail
			}
			limitations = append(limitations, fmt.Sprintf("filesystem search-path record %q degraded: %s", sp.Path, detail))
		}
		out = append(out, sp)
	}
	return out, uniqueSorted(limitations)
}

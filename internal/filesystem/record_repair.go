package filesystem

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// repairExecutableRecords retains a Windows provider row when it has enough
// identity to remain auditable. Missing non-identity contract fields are filled
// conservatively and the row is marked DEGRADED. A pathless row is quarantined.
func repairExecutableRecords(in []ExecutableRecord, capability PermissionCapability) ([]ExecutableRecord, []string) {
	out := make([]ExecutableRecord, 0, len(in))
	limitations := []string{}
	for i, r := range in {
		r.Path = strings.TrimSpace(r.Path)
		if r.Path == "" || r.Path == "." {
			limitations = append(limitations, fmt.Sprintf("quarantined filesystem executable record %d: missing path identity", i))
			continue
		}
		r.Path = filepath.Clean(r.Path)
		missing := []string{}
		if strings.TrimSpace(r.ID) == "" {
			r.ID = stableExecutableID(r.Path)
			missing = append(missing, "id")
		}
		if strings.TrimSpace(r.Directory) == "" || r.Directory == "." {
			r.Directory = filepath.Dir(r.Path)
			missing = append(missing, "directory")
		}
		if r.State == "" {
			r.State = evidence.StateDegraded
			missing = append(missing, "state")
		}
		if strings.TrimSpace(r.PermissionModel) == "" {
			r.PermissionModel = strings.TrimSpace(capability.Model)
			if r.PermissionModel == "" {
				r.PermissionModel = "UNKNOWN"
			}
			missing = append(missing, "permission_model")
		}
		if strings.TrimSpace(r.DiscoverySource) == "" {
			r.DiscoverySource = "filesystem executable inventory provider"
			missing = append(missing, "discovery_source")
		}
		if strings.TrimSpace(r.CollectionSource) == "" {
			r.CollectionSource = "filesystem executable metadata provider"
			missing = append(missing, "collection_source")
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceLow
			missing = append(missing, "confidence")
		}
		if len(missing) > 0 {
			if r.State == evidence.StateObserved {
				r.State = evidence.StateDegraded
			}
			detail := "provider record was incomplete; repaired missing fields: " + strings.Join(missing, ",")
			r.Reason = appendReasonText(r.Reason, detail)
			limitations = append(limitations, fmt.Sprintf("filesystem executable record %q degraded: %s", r.Path, detail))
		}
		out = append(out, r)
	}
	return out, uniqueSorted(limitations)
}

// repairTempDirectoryRecords applies the same record-level failure policy to
// temporary-directory security rows. Path identity is never invented; other
// missing contract fields are filled conservatively and provenance is retained.
func repairTempDirectoryRecords(in []TempDirectoryRecord, capability PermissionCapability) ([]TempDirectoryRecord, []string) {
	out := make([]TempDirectoryRecord, 0, len(in))
	limitations := []string{}
	for i, r := range in {
		r.Path = strings.TrimSpace(r.Path)
		if r.Path == "" || r.Path == "." {
			limitations = append(limitations, fmt.Sprintf("quarantined filesystem temporary-directory record %d: missing path identity", i))
			continue
		}
		r.Path = filepath.Clean(r.Path)
		missing := []string{}
		if strings.TrimSpace(r.ID) == "" {
			r.ID = stableTempDirectoryID(r.Path)
			missing = append(missing, "id")
		}
		if strings.TrimSpace(r.Scope) == "" {
			r.Scope = TempScopeProcess
			missing = append(missing, "scope")
		}
		if r.State == "" {
			r.State = evidence.StateDegraded
			missing = append(missing, "state")
		}
		if strings.TrimSpace(r.PermissionModel) == "" {
			r.PermissionModel = strings.TrimSpace(capability.Model)
			if r.PermissionModel == "" {
				r.PermissionModel = "UNKNOWN"
			}
			missing = append(missing, "permission_model")
		}
		if len(r.DiscoverySources) == 0 {
			r.DiscoverySources = []string{"filesystem temporary-directory discovery provider"}
			missing = append(missing, "discovery_sources")
		}
		if strings.TrimSpace(r.CollectionSource) == "" {
			r.CollectionSource = "filesystem temporary-directory metadata provider"
			missing = append(missing, "collection_source")
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceLow
			missing = append(missing, "confidence")
		}
		if len(missing) > 0 {
			if r.State == evidence.StateObserved {
				r.State = evidence.StateDegraded
			}
			detail := "provider record was incomplete; repaired missing fields: " + strings.Join(missing, ",")
			r.Reason = appendReasonText(r.Reason, detail)
			limitations = append(limitations, fmt.Sprintf("filesystem temporary-directory record %q degraded: %s", r.Path, detail))
		}
		out = append(out, r)
	}
	return out, uniqueSorted(limitations)
}

func appendReasonText(reason, addition string) string {
	reason = strings.TrimSpace(reason)
	addition = strings.TrimSpace(addition)
	if reason == "" {
		return addition
	}
	if addition == "" {
		return reason
	}
	return reason + "; " + addition
}

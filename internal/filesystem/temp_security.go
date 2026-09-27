package filesystem

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	TempScopeSharedSystem = "SHARED_SYSTEM"
	TempScopeSharedMemory = "SHARED_MEMORY"
	TempScopeProcess      = "PROCESS_ENVIRONMENT"
)

type TempDirectoryRecord struct {
	ID                    string              `json:"id"`
	Path                  string              `json:"path"`
	ResolvedPath          string              `json:"resolved_path,omitempty"`
	Scope                 string              `json:"scope"`
	State                 evidence.State      `json:"state"`
	Exists                bool                `json:"exists"`
	Directory             bool                `json:"directory"`
	Symlink               bool                `json:"symlink"`
	Mode                  string              `json:"mode,omitempty"`
	OwnerID               string              `json:"owner_id,omitempty"`
	GroupID               string              `json:"group_id,omitempty"`
	PermissionModel       string              `json:"permission_model"`
	Shared                bool                `json:"shared"`
	StickyBit             bool                `json:"sticky_bit"`
	GroupWritable         bool                `json:"group_writable"`
	OtherWritable         bool                `json:"other_writable"`
	BroadCreate           bool                `json:"broad_create"`
	BroadControl          bool                `json:"broad_control"`
	BroadlyWritable       bool                `json:"broadly_writable"`
	TrustedOwner          bool                `json:"trusted_owner"`
	TrustedOwnerKnown     bool                `json:"trusted_owner_known"`
	UnsafeOwnership       bool                `json:"unsafe_ownership"`
	UnsafePermissions     bool                `json:"unsafe_permissions"`
	ParentPath            string              `json:"parent_path,omitempty"`
	ParentState           evidence.State      `json:"parent_state,omitempty"`
	ParentMode            string              `json:"parent_mode,omitempty"`
	ParentOwnerID         string              `json:"parent_owner_id,omitempty"`
	ParentGroupID         string              `json:"parent_group_id,omitempty"`
	ParentStickyBit       bool                `json:"parent_sticky_bit"`
	ParentBroadlyWritable bool                `json:"parent_broadly_writable"`
	ParentTrustedOwner    bool                `json:"parent_trusted_owner"`
	ParentTrustKnown      bool                `json:"parent_trust_known"`
	ParentUnsafe          bool                `json:"parent_unsafe"`
	WritePrincipals       []string            `json:"write_principals,omitempty"`
	DiscoverySources      []string            `json:"discovery_sources"`
	CollectionSource      string              `json:"collection_source"`
	Confidence            evidence.Confidence `json:"confidence"`
	Reason                string              `json:"reason,omitempty"`
}

type tempDirectoryCandidate struct {
	Path    string
	Scope   string
	Shared  bool
	Sources []string
}

func tempDirectoryCandidates(inv Inventory) []tempDirectoryCandidate {
	byPath := map[string]*tempDirectoryCandidate{}
	add := func(path, scope string, shared bool, source string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if path == "." || path == "" {
			return
		}
		key := platformPathKey(path)
		c, ok := byPath[key]
		if !ok {
			c = &tempDirectoryCandidate{Path: path, Scope: strings.ToUpper(strings.TrimSpace(scope)), Shared: shared}
			byPath[key] = c
		}
		c.Shared = c.Shared || shared
		if c.Scope == "" || (c.Scope == TempScopeProcess && scope != TempScopeProcess) {
			c.Scope = strings.ToUpper(strings.TrimSpace(scope))
		}
		c.Sources = uniqueSorted(append(c.Sources, source))
	}
	for _, p := range inv.Paths {
		if !strings.EqualFold(p.Kind, "TEMP") {
			continue
		}
		scope, shared := classifyTempCandidate(p.Path, p.CollectionSource)
		add(p.Path, scope, shared, "temporary-area inventory: "+p.CollectionSource)
	}
	out := make([]tempDirectoryCandidate, 0, len(byPath))
	for _, c := range byPath {
		if c.Scope == "" {
			c.Scope = TempScopeProcess
		}
		if len(c.Sources) == 0 {
			c.Sources = []string{"normalized temporary-area inventory"}
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return platformPathKey(out[i].Path) < platformPathKey(out[j].Path) })
	if len(out) > maxTempDirectories {
		out = out[:maxTempDirectories]
	}
	return out
}

func classifyTempCandidate(path, source string) (string, bool) {
	p := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), `\`, "/"))
	s := strings.ToLower(source)
	switch {
	case p == "/tmp" || p == "/var/tmp" || p == "/private/tmp" || p == "/private/var/tmp":
		return TempScopeSharedSystem, true
	case p == "/dev/shm":
		return TempScopeSharedMemory, true
	case strings.Contains(s, "system temporary area") || strings.Contains(s, "shared temporary area") || strings.Contains(s, "persistent temporary area"):
		return TempScopeSharedSystem, true
	default:
		return TempScopeProcess, false
	}
}

func normalizeTempDirectories(in []TempDirectoryRecord) []TempDirectoryRecord {
	out := make([]TempDirectoryRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r.Path = filepath.Clean(strings.TrimSpace(r.Path))
		if r.Path == "." || r.Path == "" {
			continue
		}
		r.ResolvedPath = strings.TrimSpace(r.ResolvedPath)
		if r.ResolvedPath != "" {
			r.ResolvedPath = filepath.Clean(r.ResolvedPath)
		}
		r.Scope = strings.ToUpper(strings.TrimSpace(r.Scope))
		if r.Scope == "" {
			r.Scope = TempScopeProcess
		}
		r.PermissionModel = strings.TrimSpace(r.PermissionModel)
		r.ParentPath = strings.TrimSpace(r.ParentPath)
		if r.ParentPath != "" {
			r.ParentPath = filepath.Clean(r.ParentPath)
		}
		r.WritePrincipals = uniqueSorted(r.WritePrincipals)
		r.DiscoverySources = uniqueSorted(r.DiscoverySources)
		r.CollectionSource = strings.TrimSpace(r.CollectionSource)
		if r.ID == "" {
			r.ID = stableTempDirectoryID(r.Path)
		}
		if r.State == "" {
			r.State = evidence.StateUnavailable
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceLow
		}
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
		if len(out) >= maxTempDirectories {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return tempDirectorySortKey(out[i]) < tempDirectorySortKey(out[j]) })
	return out
}

func tempDirectorySortKey(r TempDirectoryRecord) string {
	return platformPathKey(r.Path) + "|" + r.ID
}

func stableTempDirectoryID(path string) string {
	sum := sha256.Sum256([]byte("TEMP_DIRECTORY|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}

func appendTempReason(existing, next string) string {
	existing = strings.TrimSpace(existing)
	next = strings.TrimSpace(next)
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}
	return existing + "; " + next
}

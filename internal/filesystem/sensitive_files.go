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
	SensitivePolicyWriteRestricted = "WRITE_RESTRICTED"
	SensitivePolicyNoWorldRead     = "NO_WORLD_READ"
	SensitivePolicyOwnerOnly       = "OWNER_ONLY"

	SensitiveOwnerExpected      = "EXPECTED"
	SensitiveOwnerUnexpected    = "UNEXPECTED"
	SensitiveOwnerUnknown       = "UNKNOWN"
	SensitiveOwnerNotApplicable = "NOT_APPLICABLE"
)

type sensitiveCandidate struct {
	Kind            string
	Scope           string
	Path            string
	AccessPolicy    string
	ExpectedOwnerID string
	Source          string
}

func expandSensitiveCandidates(in []sensitiveCandidate) ([]sensitiveCandidate, []string) {
	out := make([]sensitiveCandidate, 0, len(in))
	degraded := []string{}
	seen := map[string]struct{}{}
	for _, c := range in {
		c.Kind = strings.ToUpper(strings.TrimSpace(c.Kind))
		c.Scope = strings.ToUpper(strings.TrimSpace(c.Scope))
		c.Path = strings.TrimSpace(c.Path)
		c.AccessPolicy = strings.ToUpper(strings.TrimSpace(c.AccessPolicy))
		c.ExpectedOwnerID = strings.TrimSpace(c.ExpectedOwnerID)
		c.Source = strings.TrimSpace(c.Source)
		if c.Kind == "" || c.Scope == "" || c.Path == "" || c.AccessPolicy == "" {
			continue
		}
		if c.Source == "" {
			c.Source = "sensitive filesystem permission candidate"
		}
		add := func(item sensitiveCandidate) {
			item.Path = filepath.Clean(strings.TrimSpace(item.Path))
			if item.Path == "." || item.Path == "" {
				return
			}
			if item.Kind == "PRIVATE_KEY" && strings.HasSuffix(strings.ToLower(item.Path), ".pub") {
				return
			}
			key := item.Kind + "|" + item.Scope + "|" + platformPathKey(item.Path)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
		if strings.ContainsAny(c.Path, "*?[") {
			matches, err := filepath.Glob(c.Path)
			if err != nil {
				degraded = append(degraded, "invalid sensitive-path pattern "+c.Path+": "+err.Error())
				continue
			}
			sort.Slice(matches, func(i, j int) bool { return platformPathKey(matches[i]) < platformPathKey(matches[j]) })
			for _, match := range matches {
				item := c
				item.Path = match
				add(item)
				if len(out) >= maxSensitiveFiles {
					break
				}
			}
		} else {
			add(c)
		}
		if len(out) >= maxSensitiveFiles {
			degraded = append(degraded, "sensitive-file candidate inventory reached bounded limit")
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return platformPathKey(out[i].Path) < platformPathKey(out[j].Path)
	})
	return out, uniqueSorted(degraded)
}

func normalizeSensitiveFiles(in []SensitiveFileRecord) []SensitiveFileRecord {
	out := make([]SensitiveFileRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r.Kind = strings.ToUpper(strings.TrimSpace(r.Kind))
		r.Scope = strings.ToUpper(strings.TrimSpace(r.Scope))
		r.Path = filepath.Clean(strings.TrimSpace(r.Path))
		if r.Path == "." || r.Path == "" {
			continue
		}
		r.ResolvedPath = strings.TrimSpace(r.ResolvedPath)
		if r.ResolvedPath != "" {
			r.ResolvedPath = filepath.Clean(r.ResolvedPath)
		}
		r.AccessPolicy = strings.ToUpper(strings.TrimSpace(r.AccessPolicy))
		r.PermissionModel = strings.TrimSpace(r.PermissionModel)
		r.OwnerID = strings.TrimSpace(r.OwnerID)
		r.GroupID = strings.TrimSpace(r.GroupID)
		r.ExpectedOwnerID = strings.TrimSpace(r.ExpectedOwnerID)
		r.OwnerState = strings.ToUpper(strings.TrimSpace(r.OwnerState))
		if r.OwnerState == "" {
			r.OwnerState = SensitiveOwnerUnknown
		}
		r.ReadPrincipals = uniqueSorted(r.ReadPrincipals)
		r.WritePrincipals = uniqueSorted(r.WritePrincipals)
		r.DiscoverySource = strings.TrimSpace(r.DiscoverySource)
		r.CollectionSource = strings.TrimSpace(r.CollectionSource)
		if r.ID == "" {
			r.ID = stableSensitiveFileID(r.Kind, r.Path)
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceLow
		}
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
		if len(out) >= maxSensitiveFiles {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return sensitiveFileSortKey(out[i]) < sensitiveFileSortKey(out[j]) })
	return out
}

func sensitiveFileSortKey(r SensitiveFileRecord) string {
	return r.Scope + "|" + r.Kind + "|" + platformPathKey(r.Path) + "|" + r.ID
}

func stableSensitiveFileID(kind, path string) string {
	sum := sha256.Sum256([]byte("SENSITIVE_FILE|" + strings.ToUpper(strings.TrimSpace(kind)) + "|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}

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
	ACLGrantAllow = "ALLOW"
	ACLGrantDeny  = "DENY"
)

type ACLGrant struct {
	Principal      string   `json:"principal"`
	PrincipalID    string   `json:"principal_id,omitempty"`
	PrincipalClass string   `json:"principal_class"`
	Access         string   `json:"access"`
	Rights         []string `json:"rights"`
	Inherited      bool     `json:"inherited"`
	Effective      bool     `json:"effective"`
	Broad          bool     `json:"broad"`
	Trusted        bool     `json:"trusted"`
	WriteLike      bool     `json:"write_like"`
	ControlLike    bool     `json:"control_like"`
}

type ACLBoundaryRecord struct {
	ID                    string              `json:"id"`
	Path                  string              `json:"path"`
	Contexts              []string            `json:"contexts"`
	State                 evidence.State      `json:"state"`
	Exists                bool                `json:"exists"`
	Directory             bool                `json:"directory"`
	OwnerID               string              `json:"owner_id,omitempty"`
	ACLModel              string              `json:"acl_model"`
	HasExtendedACL        bool                `json:"has_extended_acl"`
	Grants                []ACLGrant          `json:"grants,omitempty"`
	DangerousBroadWrite   bool                `json:"dangerous_broad_write"`
	DangerousBroadControl bool                `json:"dangerous_broad_control"`
	ReviewWriteGrant      bool                `json:"review_write_grant"`
	DangerousPrincipals   []string            `json:"dangerous_principals,omitempty"`
	ReviewPrincipals      []string            `json:"review_principals,omitempty"`
	DiscoverySources      []string            `json:"discovery_sources"`
	CollectionSource      string              `json:"collection_source"`
	Confidence            evidence.Confidence `json:"confidence"`
	Reason                string              `json:"reason,omitempty"`
}

type aclBoundaryCandidate struct {
	Path     string
	Contexts []string
	Sources  []string
}

func aclBoundaryCandidates(inv Inventory) []aclBoundaryCandidate {
	byPath := map[string]*aclBoundaryCandidate{}
	add := func(path string, contexts []string, sources ...string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if path == "." || path == "" {
			return
		}
		key := platformPathKey(path)
		item, ok := byPath[key]
		if !ok {
			item = &aclBoundaryCandidate{Path: path}
			byPath[key] = item
		}
		item.Contexts = uniqueSortedUpper(append(item.Contexts, contexts...))
		item.Sources = uniqueSorted(append(item.Sources, sources...))
	}

	// Highest-value boundaries first: sensitive files and privileged resolution paths.
	for _, sf := range inv.SensitiveFiles {
		if sf.State == evidence.StateObserved && !sf.Exists {
			continue
		}
		ctx := []string{"SENSITIVE_FILE", sf.Scope, sf.Kind}
		add(sf.Path, ctx, "sensitive-file boundary: "+sf.DiscoverySource)
		if sf.ResolvedPath != "" && platformPathKey(sf.ResolvedPath) != platformPathKey(sf.Path) {
			add(sf.ResolvedPath, append(ctx, "SYMLINK_TARGET"), "resolved target of "+sf.Path)
		}
	}
	for _, sp := range inv.SearchPaths {
		if sp.State == evidence.StateObserved && !sp.Exists {
			continue
		}
		contexts := append([]string{"PRIVILEGED_SEARCH_PATH"}, sp.Contexts...)
		add(sp.Path, contexts, append([]string{"privileged search-path boundary"}, sp.DiscoverySources...)...)
		if sp.ResolvedPath != "" && platformPathKey(sp.ResolvedPath) != platformPathKey(sp.Path) {
			add(sp.ResolvedPath, append(contexts, "SYMLINK_TARGET"), "resolved target of "+sp.Path)
		}
	}

	// Selected filesystem roots/configuration paths are included, but ordinary temp/user roots are not.
	for _, p := range inv.Paths {
		if p.State == evidence.StateObserved && !p.Exists {
			continue
		}
		switch p.Kind {
		case "SENSITIVE_CONFIG":
			add(p.Path, []string{"SENSITIVE_CONFIG"}, "security-sensitive path: "+p.CollectionSource)
		case "ROOT":
			if isHighImpactRoot(p.Path) {
				add(p.Path, []string{"SYSTEM_ROOT"}, "selected system root: "+p.CollectionSource)
			}
		}
	}

	// Only a bounded, high-value subset of review targets is promoted into the ACL set.
	// Setuid/capability/unmanaged targets take precedence; setgid-only review targets are capped so
	// a noisy host cannot crowd authentication/search/system boundaries out of the selected inventory.
	privilegedAdded := 0
	setgidOnlyAdded := 0
	for _, pf := range inv.PrivilegedFiles {
		if !pf.ReviewRequired || (pf.State == evidence.StateObserved && !pf.Exists) {
			continue
		}
		highValue := pf.SetUID || len(pf.Capabilities) > 0 || len(pf.InheritableCaps) > 0 || pf.PackageOwnership == "UNMANAGED"
		if !highValue {
			if !pf.SetGID || setgidOnlyAdded >= 64 {
				continue
			}
			setgidOnlyAdded++
		}
		add(pf.Path, []string{"PRIVILEGED_EXECUTABLE", pf.Classification}, "privileged executable requiring review")
		privilegedAdded++
		if privilegedAdded >= 128 {
			break
		}
	}

	out := make([]aclBoundaryCandidate, 0, len(byPath))
	for _, item := range byPath {
		if len(item.Contexts) == 0 {
			item.Contexts = []string{"HIGH_IMPACT"}
		}
		if len(item.Sources) == 0 {
			item.Sources = []string{"selected high-impact filesystem boundary"}
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := aclCandidatePriority(out[i]), aclCandidatePriority(out[j])
		if pi != pj {
			return pi < pj
		}
		return platformPathKey(out[i].Path) < platformPathKey(out[j].Path)
	})
	if len(out) > maxACLBoundaries {
		out = out[:maxACLBoundaries]
	}
	// Stable public ordering is path-based; priority only controls bounded admission.
	sort.Slice(out, func(i, j int) bool { return platformPathKey(out[i].Path) < platformPathKey(out[j].Path) })
	return out
}

func aclCandidatePriority(c aclBoundaryCandidate) int {
	if containsString(c.Contexts, "SENSITIVE_FILE") {
		return 0
	}
	if containsString(c.Contexts, "PRIVILEGED_SEARCH_PATH") {
		return 1
	}
	if containsString(c.Contexts, "PRIVILEGED_EXECUTABLE") {
		return 2
	}
	if containsString(c.Contexts, "SENSITIVE_CONFIG") {
		return 3
	}
	return 4
}

func isHighImpactRoot(path string) bool {
	p := strings.ToLower(platformPathKey(path))
	if p == "/" || p == "/etc" || p == "/usr" || p == "/system" || p == "/library" || p == "/usr/local" {
		return true
	}
	if strings.Contains(p, `\windows`) || strings.Contains(p, `\program files`) || strings.HasSuffix(p, `:\`) {
		return true
	}
	return false
}

func normalizeACLBoundaries(in []ACLBoundaryRecord) []ACLBoundaryRecord {
	out := make([]ACLBoundaryRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r.Path = filepath.Clean(strings.TrimSpace(r.Path))
		if r.Path == "." || r.Path == "" {
			continue
		}
		r.Contexts = uniqueSortedUpper(r.Contexts)
		r.ACLModel = strings.TrimSpace(r.ACLModel)
		r.OwnerID = strings.TrimSpace(r.OwnerID)
		r.DiscoverySources = uniqueSorted(r.DiscoverySources)
		r.CollectionSource = strings.TrimSpace(r.CollectionSource)
		r.DangerousPrincipals = uniqueSorted(r.DangerousPrincipals)
		r.ReviewPrincipals = uniqueSorted(r.ReviewPrincipals)
		for i := range r.Grants {
			g := &r.Grants[i]
			g.Principal = strings.TrimSpace(g.Principal)
			g.PrincipalID = strings.TrimSpace(g.PrincipalID)
			g.PrincipalClass = strings.ToUpper(strings.TrimSpace(g.PrincipalClass))
			g.Access = strings.ToUpper(strings.TrimSpace(g.Access))
			g.Rights = uniqueSortedUpper(g.Rights)
		}
		sort.Slice(r.Grants, func(i, j int) bool {
			a, b := r.Grants[i], r.Grants[j]
			ka := a.PrincipalClass + "|" + a.PrincipalID + "|" + a.Principal + "|" + a.Access + "|" + strings.Join(a.Rights, ",")
			kb := b.PrincipalClass + "|" + b.PrincipalID + "|" + b.Principal + "|" + b.Access + "|" + strings.Join(b.Rights, ",")
			return ka < kb
		})
		if r.ID == "" {
			r.ID = stableACLBoundaryID(r.Path)
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
		if len(out) >= maxACLBoundaries {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return aclBoundarySortKey(out[i]) < aclBoundarySortKey(out[j]) })
	return out
}

func aclBoundarySortKey(r ACLBoundaryRecord) string {
	return platformPathKey(r.Path) + "|" + r.ID
}

func stableACLBoundaryID(path string) string {
	sum := sha256.Sum256([]byte("ACL_BOUNDARY|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}

func classifyACLBoundary(rec *ACLBoundaryRecord) {
	dangerous := []string{}
	review := []string{}
	for _, grant := range rec.Grants {
		if !grant.Effective || strings.ToUpper(grant.Access) != ACLGrantAllow {
			continue
		}
		if grant.Broad && grant.WriteLike {
			rec.DangerousBroadWrite = true
			dangerous = append(dangerous, grant.Principal)
		}
		if grant.Broad && grant.ControlLike {
			rec.DangerousBroadControl = true
			dangerous = append(dangerous, grant.Principal)
		}
		if grant.WriteLike && !grant.Broad && !grant.Trusted && grant.PrincipalClass != "OWNER" && grant.PrincipalClass != "DEFAULT_OWNER" {
			rec.ReviewWriteGrant = true
			review = append(review, grant.Principal)
		}
	}
	rec.DangerousPrincipals = uniqueSorted(dangerous)
	rec.ReviewPrincipals = uniqueSorted(review)
}

package processes

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxPermissionAncestors = 16

// PermissionNode is the normalized access-control view of an
// executable or one of its parent directories. It records only metadata needed
// to reason about replacement/write boundaries; no file content is read.
type PermissionNode struct {
	Path            string   `json:"path"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	OwnerID         string   `json:"owner_id,omitempty"`
	Owner           string   `json:"owner,omitempty"`
	GroupID         string   `json:"group_id,omitempty"`
	Group           string   `json:"group,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	ACLSource       string   `json:"acl_source"`
	WritePrincipals []string `json:"write_principals,omitempty"`
	BroadWrite      bool     `json:"broad_write"`
	UntrustedWrite  bool     `json:"untrusted_write"`
	Sticky          bool     `json:"sticky,omitempty"`
	Symlink         bool     `json:"symlink,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// PathPermissionContext is additive evidence for a live process.
// It deliberately remains separate from the chimera.processes/v1
// Process record so the original process contract remains stable.
type PathPermissionContext struct {
	ProcessID                string              `json:"process_id"`
	Platform                 string              `json:"platform"`
	PID                      int                 `json:"pid"`
	Path                     string              `json:"path"`
	State                    string              `json:"state"`
	Executable               PermissionNode      `json:"executable"`
	Parents                  []PermissionNode    `json:"parents,omitempty"`
	UntrustedExecutableWrite bool                `json:"untrusted_executable_write"`
	UntrustedParentWrite     bool                `json:"untrusted_parent_write"`
	BroadExecutableWrite     bool                `json:"broad_executable_write"`
	BroadParentWrite         bool                `json:"broad_parent_write"`
	Reasons                  []string            `json:"reasons,omitempty"`
	Source                   string              `json:"source"`
	Confidence               evidence.Confidence `json:"confidence"`
}

func collectPathPermissions(ctx context.Context, items []Process, platform string) []PathPermissionContext {
	out := collectPlatformPathPermissions(ctx, items, platform)
	byID := make(map[string]PathPermissionContext, len(out))
	for _, c := range out {
		c.ProcessID = strings.TrimSpace(c.ProcessID)
		c.Platform = fallback(strings.TrimSpace(c.Platform), platform)
		c.Path = strings.TrimSpace(c.Path)
		c.State = strings.ToUpper(fallback(strings.TrimSpace(c.State), "UNKNOWN"))
		c.Source = fallback(strings.TrimSpace(c.Source), "local executable path permission metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceLow
		}
		c.Reasons = uniqueStrings(c.Reasons)
		c.Parents = normalizePermissionNodes(c.Parents)
		c.Executable = normalizePermissionNode(c.Executable)
		if c.ProcessID != "" {
			byID[c.ProcessID] = c
		}
	}

	normalized := make([]PathPermissionContext, 0, len(items))
	for _, p := range items {
		c, ok := byID[p.ID]
		if !ok {
			c = unknownPermissionContext(p, platform, "permission collector did not return a record")
		}
		normalized = append(normalized, c)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].PID != normalized[j].PID {
			return normalized[i].PID < normalized[j].PID
		}
		return normalized[i].ProcessID < normalized[j].ProcessID
	})
	return normalized
}

func unknownPermissionContext(p Process, platform, reason string) PathPermissionContext {
	reason = fallback(strings.TrimSpace(reason), "permission metadata unavailable")
	return PathPermissionContext{
		ProcessID:  p.ID,
		Platform:   platform,
		PID:        p.PID,
		Path:       strings.TrimSpace(p.ExecutablePath),
		State:      "UNKNOWN",
		Executable: PermissionNode{Path: strings.TrimSpace(p.ExecutablePath), Kind: "EXECUTABLE", State: "UNKNOWN", ACLSource: "local filesystem permission metadata", Reason: reason},
		Reasons:    []string{reason},
		Source:     "local executable path permission metadata",
		Confidence: evidence.ConfidenceLow,
	}
}

func finalizePermissionContext(c PathPermissionContext) PathPermissionContext {
	c.UntrustedExecutableWrite = c.Executable.UntrustedWrite
	c.BroadExecutableWrite = c.Executable.BroadWrite
	unresolved := c.Executable.State != "OBSERVED"
	for _, n := range c.Parents {
		c.UntrustedParentWrite = c.UntrustedParentWrite || n.UntrustedWrite
		c.BroadParentWrite = c.BroadParentWrite || n.BroadWrite
		unresolved = unresolved || n.State != "OBSERVED"
	}
	switch {
	case c.UntrustedExecutableWrite || c.UntrustedParentWrite:
		c.State = "WEAK"
	case unresolved:
		c.State = "UNKNOWN"
	default:
		c.State = "CONTROLLED"
	}
	return c
}

func normalizePermissionNode(n PermissionNode) PermissionNode {
	n.Path = strings.TrimSpace(n.Path)
	n.Kind = strings.ToUpper(fallback(strings.TrimSpace(n.Kind), "UNKNOWN"))
	n.State = strings.ToUpper(fallback(strings.TrimSpace(n.State), "UNKNOWN"))
	n.ACLSource = fallback(strings.TrimSpace(n.ACLSource), "local filesystem permission metadata")
	n.WritePrincipals = uniqueStrings(n.WritePrincipals)
	n.Reason = strings.TrimSpace(n.Reason)
	return n
}

func normalizePermissionNodes(in []PermissionNode) []PermissionNode {
	out := make([]PermissionNode, 0, len(in))
	seen := map[string]struct{}{}
	for _, n := range in {
		n = normalizePermissionNode(n)
		if n.Path == "" {
			continue
		}
		key := strings.ToLower(n.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
		if len(out) >= maxPermissionAncestors {
			break
		}
	}
	return out
}

func appendReason(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	extra = strings.TrimSpace(extra)
	if existing == "" {
		return extra
	}
	if extra == "" {
		return existing
	}
	return existing + "; " + extra
}

package processes

import (
	"encoding/json"
	"sort"
	"strings"
)

type windowsTrustCandidate struct {
	Path     string `json:"path"`
	Priority int    `json:"priority"`
}

type windowsTrustEnvelope struct {
	SchemaVersion int                     `json:"schema_version"`
	Items         []windowsTrustCandidate `json:"items"`
}

type windowsTrustRow struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

const windowsTrustSchemaVersion = 1

func makeWindowsTrustCandidates(items []Process) []windowsTrustCandidate {
	// Privileged executable paths are evaluated first because CHM-PRC-003/004
	// require the strongest provenance coverage. Remaining unique paths are then
	// sorted deterministically. No process is removed from inventory if its trust
	// enrichment is not reached.
	type candidateState struct {
		path       string
		privileged bool
	}
	byPath := map[string]candidateState{}
	for _, p := range items {
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" {
			continue
		}
		key := strings.ToLower(path)
		v := byPath[key]
		if v.path == "" {
			v.path = path
		}
		v.privileged = v.privileged || p.Principal.Elevated
		byPath[key] = v
	}
	ordered := make([]candidateState, 0, len(byPath))
	for _, v := range byPath {
		ordered = append(ordered, v)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].privileged != ordered[j].privileged {
			return ordered[i].privileged
		}
		return strings.ToLower(ordered[i].path) < strings.ToLower(ordered[j].path)
	})
	out := make([]windowsTrustCandidate, 0, len(ordered))
	for _, v := range ordered {
		priority := 1
		if v.privileged {
			priority = 0
		}
		out = append(out, windowsTrustCandidate{Path: v.path, Priority: priority})
	}
	return out
}

func decodeWindowsTrustNDJSON(raw []byte) ([]windowsTrustRow, int) {
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	rows := make([]windowsTrustRow, 0, len(lines))
	malformed := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row windowsTrustRow
		if err := json.Unmarshal([]byte(line), &row); err != nil || strings.TrimSpace(row.Path) == "" {
			malformed++
			continue
		}
		rows = append(rows, row)
	}
	return rows, malformed
}

func applyWindowsTrustRow(p *Process, row windowsTrustRow) {
	if p == nil {
		return
	}
	p.Trust.Signature = fallback(strings.TrimSpace(row.Status), "UNKNOWN")
	p.Trust.Reason = strings.TrimSpace(row.Reason)
	switch strings.ToLower(strings.TrimSpace(row.Status)) {
	case "valid":
		p.Trust.State = "SIGNED_VALID"
	case "notsigned":
		p.Trust.State = "UNSIGNED"
	case "hashmismatch":
		p.Trust.State = "HASH_MISMATCH"
	case "nottrusted":
		p.Trust.State = "SIGNATURE_UNTRUSTED"
	default:
		p.Trust.State = "UNKNOWN"
	}
}

func markWindowsTrustUnresolved(inv *Inventory, completed map[string]windowsTrustRow, reason string) {
	if inv == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	for i := range inv.Processes {
		path := strings.TrimSpace(inv.Processes[i].ExecutablePath)
		if path == "" {
			continue
		}
		if completed != nil {
			if _, ok := completed[strings.ToLower(path)]; ok {
				continue
			}
		}
		inv.Processes[i].Trust.State = "UNKNOWN"
		inv.Processes[i].Trust.Signature = fallback(strings.TrimSpace(inv.Processes[i].Trust.Signature), "UNKNOWN")
		inv.Processes[i].Trust.Reason = reason
	}
}

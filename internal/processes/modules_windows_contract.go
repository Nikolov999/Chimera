package processes

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	windowsModuleCandidateSchemaVersion  = 1
	windowsModuleEnrichmentSchemaVersion = 1
	defaultWindowsModuleBatchSize        = 24
	defaultWindowsModuleEnrichmentBatch  = 48
	windowsLoadedModuleEnrichmentLimit   = 256
)

type windowsModuleCandidate struct {
	CandidateID    string `json:"candidate_id"`
	PID            int    `json:"pid"`
	Name           string `json:"name,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	StartTime      string `json:"start_time,omitempty"`
}

type windowsModuleCandidateEnvelope struct {
	SchemaVersion int                      `json:"schema_version"`
	Items         []windowsModuleCandidate `json:"items"`
}

type windowsModuleRow struct {
	CandidateID string `json:"candidate_id"`
	PID         int    `json:"pid"`
	Path        string `json:"path"`
	Name        string `json:"name"`
	BaseAddress string `json:"base_address"`
}

type windowsModuleProcessRow struct {
	CandidateID string `json:"candidate_id"`
	PID         int    `json:"pid"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	ModuleCount int    `json:"module_count"`
}

type windowsModuleEnumerationPayload struct {
	Rows      []windowsModuleRow        `json:"rows"`
	Processes []windowsModuleProcessRow `json:"processes"`
	Visited   int                       `json:"visited"`
	Truncated bool                      `json:"truncated"`
}

type windowsModuleEnrichmentCandidate struct {
	CandidateID string `json:"candidate_id"`
	Path        string `json:"path"`
}

type windowsModuleEnrichmentEnvelope struct {
	SchemaVersion int                                `json:"schema_version"`
	Items         []windowsModuleEnrichmentCandidate `json:"items"`
}

type windowsModuleEnrichmentRow struct {
	CandidateID    string `json:"candidate_id"`
	Path           string `json:"path"`
	Signature      string `json:"signature"`
	SignatureState string `json:"signature_state"`
	DirectoryState string `json:"directory_state"`
	DirectoryWeak  bool   `json:"directory_weak"`
	DirectoryBroad bool   `json:"directory_broad"`
	Deleted        bool   `json:"deleted"`
	Reason         string `json:"reason"`
}

type windowsModuleEnrichmentPayload struct {
	Rows      []windowsModuleEnrichmentRow `json:"rows"`
	Visited   int                          `json:"visited"`
	Degraded  int                          `json:"degraded"`
	Truncated bool                         `json:"truncated"`
}

type windowsModuleBatchTelemetry struct {
	Stage      string
	Index      int
	Candidates int
	Completed  int
	Denied     int
	Exited     int
	Failed     int
	Elapsed    time.Duration
	TimedOut   bool
	Reason     string
}

type windowsModuleEnumerationAccumulator struct {
	Rows   []windowsModuleRow
	Status map[string]windowsModuleProcessRow
}

func newWindowsModuleEnumerationAccumulator(capacity int) *windowsModuleEnumerationAccumulator {
	if capacity < 0 {
		capacity = 0
	}
	return &windowsModuleEnumerationAccumulator{
		Rows:   make([]windowsModuleRow, 0, capacity*8),
		Status: make(map[string]windowsModuleProcessRow, capacity),
	}
}

func (a *windowsModuleEnumerationAccumulator) Apply(payload windowsModuleEnumerationPayload, batch []windowsModuleCandidate) error {
	if a == nil {
		return fmt.Errorf("Windows module enumeration accumulator is nil")
	}
	if err := validateWindowsModuleEnumerationPayload(payload, batch); err != nil {
		return err
	}
	a.Rows = append(a.Rows, payload.Rows...)
	for _, p := range payload.Processes {
		p.State = normalizeWindowsModuleProcessState(p.State)
		p.Reason = strings.TrimSpace(p.Reason)
		a.Status[p.CandidateID] = p
	}
	return nil
}

func (a *windowsModuleEnumerationAccumulator) MarkUnavailable(batch []windowsModuleCandidate, reason string) {
	if a == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	for _, c := range batch {
		a.Status[c.CandidateID] = windowsModuleProcessRow{
			CandidateID: c.CandidateID,
			PID:         c.PID,
			State:       "PROVIDER_UNAVAILABLE",
			Reason:      reason,
		}
	}
}

func makeWindowsModuleCandidates(items []Process) ([]windowsModuleCandidate, error) {
	out := make([]windowsModuleCandidate, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for i, p := range items {
		if p.PID <= 0 {
			continue
		}
		id := strings.TrimSpace(p.ID)
		if id == "" {
			id = fmt.Sprintf("pid:%d:%s:%s", p.PID, strings.ToLower(strings.TrimSpace(p.ExecutablePath)), strings.TrimSpace(p.StartTime))
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("Windows module candidate %d has duplicate candidate_id %q", i, id)
		}
		seen[id] = struct{}{}
		out = append(out, windowsModuleCandidate{
			CandidateID:    id,
			PID:            p.PID,
			Name:           strings.TrimSpace(p.Name),
			ExecutablePath: strings.TrimSpace(p.ExecutablePath),
			StartTime:      strings.TrimSpace(p.StartTime),
		})
	}
	return out, nil
}

func marshalWindowsModuleCandidates(items []windowsModuleCandidate) ([]byte, error) {
	if err := validateWindowsModuleCandidates(items); err != nil {
		return nil, err
	}
	return json.Marshal(windowsModuleCandidateEnvelope{SchemaVersion: windowsModuleCandidateSchemaVersion, Items: append([]windowsModuleCandidate(nil), items...)})
}

func validateWindowsModuleCandidates(items []windowsModuleCandidate) error {
	seen := make(map[string]struct{}, len(items))
	for i, item := range items {
		id := strings.TrimSpace(item.CandidateID)
		if id == "" {
			return fmt.Errorf("Windows module candidate %d missing candidate_id", i)
		}
		if item.PID <= 0 {
			return fmt.Errorf("Windows module candidate %d (%s) has invalid pid %d", i, id, item.PID)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("Windows module candidate envelope contains duplicate candidate_id %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func chunkWindowsModuleCandidates(items []windowsModuleCandidate, size int) [][]windowsModuleCandidate {
	if size <= 0 {
		size = defaultWindowsModuleBatchSize
	}
	out := make([][]windowsModuleCandidate, 0, (len(items)+size-1)/size)
	for start := 0; start < len(items); start += size {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		out = append(out, append([]windowsModuleCandidate(nil), items[start:end]...))
	}
	return out
}

func makeWindowsModuleEnrichmentCandidates(paths []string, limit int) []windowsModuleEnrichmentCandidate {
	type pathCount struct {
		Path  string
		Count int
	}
	counts := make(map[string]pathCount, len(paths))
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		key := strings.ToLower(path)
		entry := counts[key]
		if entry.Path == "" {
			entry.Path = path
		}
		entry.Count++
		counts[key] = entry
	}
	unique := make([]pathCount, 0, len(counts))
	for _, entry := range counts {
		unique = append(unique, entry)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Count != unique[j].Count {
			return unique[i].Count > unique[j].Count
		}
		return strings.ToLower(unique[i].Path) < strings.ToLower(unique[j].Path)
	})
	if limit <= 0 || limit > len(unique) {
		limit = len(unique)
	}
	unique = unique[:limit]
	out := make([]windowsModuleEnrichmentCandidate, 0, len(unique))
	for i, entry := range unique {
		out = append(out, windowsModuleEnrichmentCandidate{CandidateID: fmt.Sprintf("module-path-%06d", i+1), Path: entry.Path})
	}
	return out
}

func marshalWindowsModuleEnrichmentCandidates(items []windowsModuleEnrichmentCandidate) ([]byte, error) {
	seenID := make(map[string]struct{}, len(items))
	seenPath := make(map[string]struct{}, len(items))
	for i, item := range items {
		id := strings.TrimSpace(item.CandidateID)
		path := strings.TrimSpace(item.Path)
		if id == "" || path == "" {
			return nil, fmt.Errorf("Windows module enrichment candidate %d is incomplete", i)
		}
		if _, ok := seenID[id]; ok {
			return nil, fmt.Errorf("Windows module enrichment candidate duplicate candidate_id %q", id)
		}
		seenID[id] = struct{}{}
		pathKey := strings.ToLower(path)
		if _, ok := seenPath[pathKey]; ok {
			return nil, fmt.Errorf("Windows module enrichment candidate duplicate path %q", path)
		}
		seenPath[pathKey] = struct{}{}
	}
	return json.Marshal(windowsModuleEnrichmentEnvelope{SchemaVersion: windowsModuleEnrichmentSchemaVersion, Items: append([]windowsModuleEnrichmentCandidate(nil), items...)})
}

func chunkWindowsModuleEnrichmentCandidates(items []windowsModuleEnrichmentCandidate, size int) [][]windowsModuleEnrichmentCandidate {
	if size <= 0 {
		size = defaultWindowsModuleEnrichmentBatch
	}
	out := make([][]windowsModuleEnrichmentCandidate, 0, (len(items)+size-1)/size)
	for start := 0; start < len(items); start += size {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		out = append(out, append([]windowsModuleEnrichmentCandidate(nil), items[start:end]...))
	}
	return out
}

func validateWindowsModuleEnumerationPayload(payload windowsModuleEnumerationPayload, batch []windowsModuleCandidate) error {
	byID := make(map[string]windowsModuleCandidate, len(batch))
	for _, c := range batch {
		byID[c.CandidateID] = c
	}
	seenProcess := make(map[string]struct{}, len(payload.Processes))
	for i, p := range payload.Processes {
		c, ok := byID[strings.TrimSpace(p.CandidateID)]
		if !ok {
			return fmt.Errorf("enumeration process row %d references unknown candidate_id %q", i, p.CandidateID)
		}
		if p.PID != c.PID {
			return fmt.Errorf("enumeration process row %d candidate %q pid=%d want %d", i, p.CandidateID, p.PID, c.PID)
		}
		if _, dup := seenProcess[p.CandidateID]; dup {
			return fmt.Errorf("enumeration payload contains duplicate process status for candidate_id %q", p.CandidateID)
		}
		seenProcess[p.CandidateID] = struct{}{}
		if strings.TrimSpace(p.State) == "" {
			return fmt.Errorf("enumeration process row %d candidate %q has empty state", i, p.CandidateID)
		}
		if p.ModuleCount < 0 {
			return fmt.Errorf("enumeration process row %d candidate %q has negative module_count", i, p.CandidateID)
		}
	}
	if len(seenProcess) != len(batch) {
		return fmt.Errorf("enumeration payload returned %d process status row(s) for %d candidate(s)", len(seenProcess), len(batch))
	}
	for i, r := range payload.Rows {
		c, ok := byID[strings.TrimSpace(r.CandidateID)]
		if !ok {
			return fmt.Errorf("enumeration module row %d references unknown candidate_id %q", i, r.CandidateID)
		}
		if r.PID != c.PID {
			return fmt.Errorf("enumeration module row %d candidate %q pid=%d want %d", i, r.CandidateID, r.PID, c.PID)
		}
		if strings.TrimSpace(r.Path) == "" {
			return fmt.Errorf("enumeration module row %d candidate %q has empty path", i, r.CandidateID)
		}
	}
	return nil
}

func validateWindowsModuleEnrichmentPayload(payload windowsModuleEnrichmentPayload, batch []windowsModuleEnrichmentCandidate) error {
	byID := make(map[string]windowsModuleEnrichmentCandidate, len(batch))
	for _, c := range batch {
		byID[c.CandidateID] = c
	}
	seen := make(map[string]struct{}, len(payload.Rows))
	for i, r := range payload.Rows {
		c, ok := byID[strings.TrimSpace(r.CandidateID)]
		if !ok {
			return fmt.Errorf("enrichment row %d references unknown candidate_id %q", i, r.CandidateID)
		}
		if !strings.EqualFold(strings.TrimSpace(r.Path), strings.TrimSpace(c.Path)) {
			return fmt.Errorf("enrichment row %d candidate %q path mismatch", i, r.CandidateID)
		}
		if _, dup := seen[r.CandidateID]; dup {
			return fmt.Errorf("enrichment payload contains duplicate row for candidate_id %q", r.CandidateID)
		}
		seen[r.CandidateID] = struct{}{}
	}
	if len(seen) != len(batch) {
		return fmt.Errorf("enrichment payload returned %d row(s) for %d candidate(s)", len(seen), len(batch))
	}
	return nil
}

func normalizeWindowsModuleProcessState(state string) string {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "OBSERVED":
		return "OBSERVED"
	case "DEGRADED":
		return "DEGRADED"
	case "PROCESS_EXITED", "MISSING":
		return "PROCESS_EXITED"
	case "ACCESS_DENIED", "DENIED":
		return "ACCESS_DENIED"
	case "PROTECTED_PROCESS":
		return "PROTECTED_PROCESS"
	case "WOW64_ARCH_MISMATCH":
		return "WOW64_ARCH_MISMATCH"
	case "ENUMERATION_FAILED":
		return "ENUMERATION_FAILED"
	case "PROVIDER_UNAVAILABLE", "UNAVAILABLE":
		return "PROVIDER_UNAVAILABLE"
	default:
		return "ENUMERATION_FAILED"
	}
}

func formatWindowsModuleBatchTelemetry(items []windowsModuleBatchTelemetry) string {
	if len(items) == 0 {
		return ""
	}
	completed, candidates, denied, exited, failed, timedOut := 0, 0, 0, 0, 0, 0
	var elapsed time.Duration
	for _, t := range items {
		candidates += t.Candidates
		completed += t.Completed
		denied += t.Denied
		exited += t.Exited
		failed += t.Failed
		elapsed += t.Elapsed
		if t.TimedOut {
			timedOut++
		}
	}
	return fmt.Sprintf("batches=%d candidates=%d completed=%d denied=%d exited=%d failed=%d timed_out=%d elapsed=%s", len(items), candidates, completed, denied, exited, failed, timedOut, elapsed.Round(time.Millisecond))
}

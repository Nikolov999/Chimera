package suppression

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
)

const SchemaVersion = "chimera.suppression/v1"

type State string

const (
	StateApplied   State = "APPLIED"
	StateExpired   State = "EXPIRED"
	StateUnmatched State = "UNMATCHED"
)

// Definition is a user-authored, read-only finding suppression. At least one
// of RuleID or AffectedObject must be present. Expiration is mandatory so a
// policy exception cannot silently become permanent.
type Definition struct {
	ID             string            `json:"id,omitempty"`
	RuleID         string            `json:"rule_id,omitempty"`
	AffectedObject string            `json:"affected_object,omitempty"`
	Reason         string            `json:"reason"`
	Owner          string            `json:"owner"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Source         string            `json:"-"`
}

type Entry struct {
	ID                string            `json:"id"`
	RuleID            string            `json:"rule_id,omitempty"`
	AffectedObject    string            `json:"affected_object,omitempty"`
	MatchScope        string            `json:"match_scope"`
	Reason            string            `json:"reason"`
	Owner             string            `json:"owner"`
	CreatedAt         time.Time         `json:"created_at"`
	ExpiresAt         time.Time         `json:"expires_at"`
	AssessedAt        time.Time         `json:"assessed_at"`
	Source            string            `json:"source,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	State             State             `json:"state"`
	MatchedFindingIDs []string          `json:"matched_finding_ids,omitempty"`
}

type Summary struct {
	Total              int `json:"total"`
	Applied            int `json:"applied"`
	Expired            int `json:"expired"`
	Unmatched          int `json:"unmatched"`
	FindingsSuppressed int `json:"findings_suppressed"`
}

type Report struct {
	Schema     string    `json:"suppression_schema"`
	AssessedAt time.Time `json:"assessed_at"`
	Summary    Summary   `json:"summary"`
	Entries    []Entry   `json:"entries"`
}

func NormalizeAndValidate(defs []Definition, rules []assessment.Rule) ([]Definition, error) {
	knownRules := make(map[string]struct{}, len(rules)+2)
	// custom profiles can generate these stable enterprise-policy
	// findings at runtime; config validation must allow them even before a
	// specific custom profile is resolved.
	knownRules["CHM-ENT-001"] = struct{}{}
	knownRules["CHM-ENT-002"] = struct{}{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("suppression rule catalog: %w", err)
		}
		knownRules[strings.ToUpper(strings.TrimSpace(r.ID))] = struct{}{}
	}

	out := make([]Definition, 0, len(defs))
	seenIDs := make(map[string]struct{}, len(defs))
	for i, raw := range defs {
		d := cloneDefinition(raw)
		d.ID = strings.TrimSpace(d.ID)
		d.RuleID = strings.ToUpper(strings.TrimSpace(d.RuleID))
		d.AffectedObject = strings.TrimSpace(d.AffectedObject)
		d.Reason = strings.TrimSpace(d.Reason)
		d.Owner = strings.TrimSpace(d.Owner)
		d.Source = strings.TrimSpace(d.Source)

		if d.RuleID == "" && d.AffectedObject == "" {
			return nil, fmt.Errorf("suppression %d: rule_id or affected_object is required", i)
		}
		if d.RuleID != "" {
			if _, ok := knownRules[d.RuleID]; !ok {
				return nil, fmt.Errorf("suppression %d: unknown rule_id %q", i, d.RuleID)
			}
		}
		if d.Reason == "" {
			return nil, fmt.Errorf("suppression %d: reason is required", i)
		}
		if d.Owner == "" {
			return nil, fmt.Errorf("suppression %d: owner is required", i)
		}
		if d.CreatedAt.IsZero() {
			return nil, fmt.Errorf("suppression %d: created_at is required", i)
		}
		if d.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("suppression %d: expires_at is required", i)
		}
		d.CreatedAt = d.CreatedAt.UTC()
		d.ExpiresAt = d.ExpiresAt.UTC()
		if !d.ExpiresAt.After(d.CreatedAt) {
			return nil, fmt.Errorf("suppression %d: expires_at must be after created_at", i)
		}
		if d.ID == "" {
			d.ID = stableID(d)
		}
		if !validID(d.ID) {
			return nil, fmt.Errorf("suppression %d: id %q may contain only letters, numbers, dot, underscore, colon, and hyphen", i, d.ID)
		}
		key := strings.ToLower(d.ID)
		if _, exists := seenIDs[key]; exists {
			return nil, fmt.Errorf("duplicate suppression id %q", d.ID)
		}
		seenIDs[key] = struct{}{}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].ID) < strings.ToLower(out[j].ID) })
	return out, nil
}

// Apply returns a new finding slice and an immutable audit report. No finding,
// status, evidence record, observed state, or remediation text is removed.
func Apply(findings []assessment.Finding, defs []Definition, rules []assessment.Rule, assessedAt time.Time) ([]assessment.Finding, Report, error) {
	if assessedAt.IsZero() {
		return nil, Report{}, fmt.Errorf("suppression assessment timestamp is required")
	}
	assessedAt = assessedAt.UTC()
	normalized, err := NormalizeAndValidate(defs, rules)
	if err != nil {
		return nil, Report{}, err
	}
	out := cloneFindings(findings)
	if err := assessment.ValidateAll(out); err != nil {
		return nil, Report{}, fmt.Errorf("suppression input findings: %w", err)
	}

	entries := make([]Entry, 0, len(normalized))
	suppressed := make(map[string]struct{})
	for _, d := range normalized {
		entry := Entry{
			ID: d.ID, RuleID: d.RuleID, AffectedObject: d.AffectedObject,
			MatchScope: matchScope(d), Reason: d.Reason, Owner: d.Owner,
			CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, AssessedAt: assessedAt,
			Source: d.Source, Metadata: cloneMetadata(d.Metadata),
		}
		if !assessedAt.Before(d.ExpiresAt) {
			entry.State = StateExpired
			entries = append(entries, entry)
			continue
		}

		for i := range out {
			if !matches(d, out[i]) {
				continue
			}
			entry.MatchedFindingIDs = append(entry.MatchedFindingIDs, out[i].ID)
			out[i].Suppression = assessment.SuppressionSuppressed
			out[i].Suppressions = append(out[i].Suppressions, assessment.SuppressionRecord{
				ID: d.ID, MatchScope: entry.MatchScope, Reason: d.Reason, Owner: d.Owner,
				CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, AppliedAt: assessedAt,
				Source: d.Source, Metadata: cloneMetadata(d.Metadata),
			})
			suppressed[out[i].ID] = struct{}{}
		}
		sort.Strings(entry.MatchedFindingIDs)
		if len(entry.MatchedFindingIDs) == 0 {
			entry.State = StateUnmatched
		} else {
			entry.State = StateApplied
		}
		entries = append(entries, entry)
	}

	for i := range out {
		sort.Slice(out[i].Suppressions, func(a, b int) bool {
			return strings.ToLower(out[i].Suppressions[a].ID) < strings.ToLower(out[i].Suppressions[b].ID)
		})
	}
	assessment.SortFindings(out)
	if err := assessment.ValidateAll(out); err != nil {
		return nil, Report{}, fmt.Errorf("suppression output findings: %w", err)
	}

	report := Report{Schema: SchemaVersion, AssessedAt: assessedAt, Entries: entries}
	report.Summary.Total = len(entries)
	report.Summary.FindingsSuppressed = len(suppressed)
	for _, e := range entries {
		switch e.State {
		case StateApplied:
			report.Summary.Applied++
		case StateExpired:
			report.Summary.Expired++
		case StateUnmatched:
			report.Summary.Unmatched++
		}
	}
	return out, report, nil
}

func matches(d Definition, f assessment.Finding) bool {
	if d.RuleID != "" && !strings.EqualFold(d.RuleID, strings.TrimSpace(f.RuleID)) {
		return false
	}
	if d.AffectedObject != "" && d.AffectedObject != strings.TrimSpace(f.AffectedObject) {
		return false
	}
	return true
}

func matchScope(d Definition) string {
	switch {
	case d.RuleID != "" && d.AffectedObject != "":
		return "RULE_AND_OBJECT"
	case d.RuleID != "":
		return "RULE"
	default:
		return "OBJECT"
	}
}

func stableID(d Definition) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(d.RuleID)), strings.TrimSpace(d.AffectedObject),
		strings.TrimSpace(d.Owner), d.CreatedAt.UTC().Format(time.RFC3339Nano), d.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return "CHM-SUP-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

func validID(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func cloneDefinition(in Definition) Definition {
	out := in
	out.Metadata = cloneMetadata(in.Metadata)
	return out
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func cloneFindings(in []assessment.Finding) []assessment.Finding {
	out := make([]assessment.Finding, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Evidence = append([]assessment.EvidenceRef(nil), in[i].Evidence...)
		out[i].References = append([]assessment.Reference(nil), in[i].References...)
		out[i].Suppressions = append([]assessment.SuppressionRecord(nil), in[i].Suppressions...)
	}
	return out
}

// ValidateEngineContract exercises the lifecycle invariants over one
// implemented rule without collecting host evidence.
func ValidateEngineContract(rules []assessment.Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("suppression engine requires at least one implemented rule")
	}
	at := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	r := rules[0]
	findings, err := assessment.EvaluateRules([]assessment.Rule{r}, nil, at)
	if err != nil {
		return fmt.Errorf("evaluate suppression contract fixture: %w", err)
	}
	defs := []Definition{{
		ID: "phase111-contract", RuleID: r.ID, Reason: "contract validation", Owner: "chimera",
		CreatedAt: at.Add(-time.Hour), ExpiresAt: at.Add(time.Hour),
	}}
	out, report, err := Apply(findings, defs, rules, at)
	if err != nil {
		return err
	}
	if len(out) != 1 || out[0].Suppression != assessment.SuppressionSuppressed || len(out[0].Suppressions) != 1 {
		return fmt.Errorf("active suppression was not attached to the finding")
	}
	if report.Schema != SchemaVersion || report.Summary.Applied != 1 || report.Summary.FindingsSuppressed != 1 {
		return fmt.Errorf("suppression audit report did not preserve applied state")
	}
	if out[0].Status != findings[0].Status || out[0].ObservedState != findings[0].ObservedState || len(out[0].Evidence) != len(findings[0].Evidence) {
		return fmt.Errorf("suppression mutated raw finding state or evidence")
	}
	return nil
}

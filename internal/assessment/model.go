package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const SchemaVersion = "chimera.finding/v1"

type Status string

const (
	StatusPass    Status = "PASS"
	StatusWarn    Status = "WARN"
	StatusFail    Status = "FAIL"
	StatusUnknown Status = "UNKNOWN"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Applicability string

const (
	Applicable    Applicability = "APPLICABLE"
	NotApplicable Applicability = "NOT_APPLICABLE"
	Undetermined  Applicability = "UNDETERMINED"
)

type SuppressionState string

const (
	SuppressionActive     SuppressionState = "ACTIVE"
	SuppressionSuppressed SuppressionState = "SUPPRESSED"
)

type SuppressionRecord struct {
	ID         string            `json:"id"`
	MatchScope string            `json:"match_scope"`
	Reason     string            `json:"reason"`
	Owner      string            `json:"owner"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	AppliedAt  time.Time         `json:"applied_at"`
	Source     string            `json:"source,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url,omitempty"`
}

type EvidenceRef struct {
	Key         string              `json:"key"`
	State       evidence.State      `json:"state"`
	Value       any                 `json:"value,omitempty"`
	Source      string              `json:"source"`
	CollectedAt time.Time           `json:"collected_at"`
	Confidence  evidence.Confidence `json:"confidence"`
	Reason      string              `json:"reason,omitempty"`
}

type Finding struct {
	ID                  string              `json:"id"`
	RuleID              string              `json:"rule_id"`
	Title               string              `json:"title"`
	Status              Status              `json:"status"`
	Severity            Severity            `json:"severity"`
	Confidence          evidence.Confidence `json:"confidence"`
	Category            string              `json:"category"`
	Platform            string              `json:"platform"`
	AffectedObject      string              `json:"affected_object"`
	ObservedState       string              `json:"observed_state"`
	ExpectedState       string              `json:"expected_state"`
	Evidence            []EvidenceRef       `json:"evidence"`
	Risk                string              `json:"risk"`
	Remediation         string              `json:"remediation"`
	References          []Reference         `json:"references,omitempty"`
	CollectionSource    string              `json:"collection_source"`
	FirstObserved       time.Time           `json:"first_observed"`
	AssessmentTimestamp time.Time           `json:"assessment_timestamp"`
	Applicability       Applicability       `json:"applicability"`
	Suppression         SuppressionState    `json:"suppression_state"`
	Suppressions        []SuppressionRecord `json:"suppressions,omitempty"`
}

func (f Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" {
		return fmt.Errorf("finding id is required")
	}
	if strings.TrimSpace(f.RuleID) == "" {
		return fmt.Errorf("finding %q rule id is required", f.ID)
	}
	if strings.TrimSpace(f.Title) == "" {
		return fmt.Errorf("finding %q title is required", f.ID)
	}
	if !validStatus(f.Status) {
		return fmt.Errorf("finding %q has invalid status %q", f.ID, f.Status)
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("finding %q has invalid severity %q", f.ID, f.Severity)
	}
	if !validConfidence(f.Confidence) {
		return fmt.Errorf("finding %q has invalid confidence %q", f.ID, f.Confidence)
	}
	if strings.TrimSpace(f.Category) == "" || strings.TrimSpace(f.Platform) == "" || strings.TrimSpace(f.AffectedObject) == "" {
		return fmt.Errorf("finding %q category, platform, and affected object are required", f.ID)
	}
	if strings.TrimSpace(f.ObservedState) == "" || strings.TrimSpace(f.ExpectedState) == "" {
		return fmt.Errorf("finding %q observed and expected state are required", f.ID)
	}
	if strings.TrimSpace(f.Risk) == "" || strings.TrimSpace(f.Remediation) == "" || strings.TrimSpace(f.CollectionSource) == "" {
		return fmt.Errorf("finding %q risk, remediation, and collection source are required", f.ID)
	}
	if f.FirstObserved.IsZero() || f.AssessmentTimestamp.IsZero() {
		return fmt.Errorf("finding %q timestamps are required", f.ID)
	}
	if !validApplicability(f.Applicability) {
		return fmt.Errorf("finding %q has invalid applicability %q", f.ID, f.Applicability)
	}
	if f.Suppression != SuppressionActive && f.Suppression != SuppressionSuppressed {
		return fmt.Errorf("finding %q has invalid suppression state %q", f.ID, f.Suppression)
	}
	if f.Suppression == SuppressionActive && len(f.Suppressions) != 0 {
		return fmt.Errorf("finding %q is active but carries suppression records", f.ID)
	}
	if f.Suppression == SuppressionSuppressed && len(f.Suppressions) == 0 {
		return fmt.Errorf("finding %q is suppressed without suppression audit records", f.ID)
	}
	seenSuppressions := map[string]struct{}{}
	for i, s := range f.Suppressions {
		if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.MatchScope) == "" || strings.TrimSpace(s.Reason) == "" || strings.TrimSpace(s.Owner) == "" {
			return fmt.Errorf("finding %q suppression %d is missing id, match scope, reason, or owner", f.ID, i)
		}
		if s.CreatedAt.IsZero() || s.ExpiresAt.IsZero() || s.AppliedAt.IsZero() {
			return fmt.Errorf("finding %q suppression %d timestamps are required", f.ID, i)
		}
		if !s.ExpiresAt.After(s.CreatedAt) || !s.ExpiresAt.After(s.AppliedAt) {
			return fmt.Errorf("finding %q suppression %d has invalid expiration", f.ID, i)
		}
		key := strings.ToLower(strings.TrimSpace(s.ID))
		if _, ok := seenSuppressions[key]; ok {
			return fmt.Errorf("finding %q has duplicate suppression id %q", f.ID, s.ID)
		}
		seenSuppressions[key] = struct{}{}
	}
	for i, e := range f.Evidence {
		obs := evidence.Observation{Key: e.Key, State: e.State, Value: e.Value, Source: e.Source, CollectedAt: e.CollectedAt, Confidence: e.Confidence, Reason: e.Reason}
		if err := obs.Validate(); err != nil {
			return fmt.Errorf("finding %q evidence %d: %w", f.ID, i, err)
		}
	}
	return nil
}

func ValidateAll(findings []Finding) error {
	seen := make(map[string]struct{}, len(findings))
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("finding %d: %w", i, err)
		}
		if _, ok := seen[f.ID]; ok {
			return fmt.Errorf("duplicate finding id %q", f.ID)
		}
		seen[f.ID] = struct{}{}
	}
	return nil
}

func StableFindingID(ruleID, affectedObject string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(ruleID) + "\x00" + strings.TrimSpace(affectedObject)))
	return "CHM-F-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

func SortFindings(findings []Finding) {
	order := map[Status]int{StatusFail: 0, StatusWarn: 1, StatusUnknown: 2, StatusPass: 3}
	sev := map[Severity]int{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3, SeverityInfo: 4}
	sort.SliceStable(findings, func(i, j int) bool {
		if order[findings[i].Status] != order[findings[j].Status] {
			return order[findings[i].Status] < order[findings[j].Status]
		}
		if sev[findings[i].Severity] != sev[findings[j].Severity] {
			return sev[findings[i].Severity] < sev[findings[j].Severity]
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].AffectedObject < findings[j].AffectedObject
	})
}

func validStatus(v Status) bool {
	switch v {
	case StatusPass, StatusWarn, StatusFail, StatusUnknown:
		return true
	default:
		return false
	}
}

func validSeverity(v Severity) bool {
	switch v {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validApplicability(v Applicability) bool {
	switch v {
	case Applicable, NotApplicable, Undetermined:
		return true
	default:
		return false
	}
}

func validConfidence(v evidence.Confidence) bool {
	switch v {
	case evidence.ConfidenceLow, evidence.ConfidenceMedium, evidence.ConfidenceHigh, evidence.ConfidenceExact:
		return true
	default:
		return false
	}
}

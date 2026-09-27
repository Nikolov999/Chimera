package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidencequality"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/snapshot"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/version"
)

const (
	SchemaVersion = "chimera.enterprise-report/v1"
	EngineVersion = "report/phase115-v1"
)

type Host struct {
	Hostname       string `json:"hostname"`
	CurrentUser    string `json:"current_user"`
	Platform       string `json:"platform"`
	OSVersion      string `json:"os_version,omitempty"`
	OSBuild        string `json:"os_build,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Architecture   string `json:"architecture"`
	CollectionTier string `json:"collection_tier"`
	Fingerprint    string `json:"fingerprint"`
}

type Assessment struct {
	ID              string                  `json:"id"`
	State           scan.State              `json:"state"`
	StartedAt       time.Time               `json:"started_at"`
	CompletedAt     time.Time               `json:"completed_at"`
	DurationMS      float64                 `json:"duration_ms"`
	TimedOut        bool                    `json:"timed_out"`
	Profile         string                  `json:"profile"`
	Selection       selection.Report        `json:"selection"`
	CategorySummary scan.CategoryCounts     `json:"category_summary"`
	Evaluation      scan.EvaluationCoverage `json:"evaluation"`
}

type ReleaseReadiness struct {
	RawLimitationOccurrences   int      `json:"raw_limitation_occurrences"`
	UniqueLimitations          int      `json:"unique_limitations"`
	UniqueReleaseBlockers      int      `json:"unique_release_blockers"`
	ProductDefectLimitations   int      `json:"product_defect_limitations"`
	DeadlineBudgetLimitations  int      `json:"deadline_budget_limitations"`
	ProductDefectUnknown       int      `json:"product_defect_unknown"`
	ReleaseBlockerRootCauseIDs []string `json:"release_blocker_root_cause_ids"`
}

type EvidenceQuality struct {
	State              scan.State                     `json:"state"`
	Counts             scan.EvidenceCounts            `json:"counts"`
	DegradationReasons []string                       `json:"degradation_reasons,omitempty"`
	RawLimitations     []string                       `json:"raw_limitations,omitempty"`
	Limitations        []evidencequality.Limitation   `json:"limitations,omitempty"`
	LimitationSummary  evidencequality.Summary        `json:"limitation_summary"`
	UnknownCauses      []evidencequality.UnknownCause `json:"unknown_causes,omitempty"`
	UnknownSummary     evidencequality.UnknownSummary `json:"unknown_summary"`
	UnknownAudit       evidencequality.UnknownAudit   `json:"unknown_audit"`
	ReleaseReadiness   ReleaseReadiness               `json:"release_readiness"`
}

type Findings struct {
	Summary scan.FindingCounts   `json:"summary"`
	Items   []assessment.Finding `json:"items"`
}

// AssessmentSnapshotRef identifies the immutable Fix52 normalized assessment
// consumed by this report. Digest equality is the machine-verifiable guarantee
// that scan and report describe the same provider/evidence/finding snapshot.
type AssessmentSnapshotRef struct {
	Schema       string    `json:"schema"`
	AssessmentID string    `json:"assessment_id"`
	Digest       string    `json:"digest"`
	CapturedAt   time.Time `json:"captured_at"`
	Source       string    `json:"source"`
}

type Result struct {
	Schema             string                          `json:"report_schema"`
	EngineVersion      string                          `json:"engine_version"`
	GeneratedAt        time.Time                       `json:"generated_at"`
	Tool               version.Info                    `json:"tool"`
	Host               Host                            `json:"host"`
	Assessment         Assessment                      `json:"assessment"`
	EvidenceQuality    EvidenceQuality                 `json:"evidence_quality"`
	AssessmentSnapshot AssessmentSnapshotRef           `json:"assessment_snapshot"`
	Snapshot           snapshot.Snapshot               `json:"snapshot"`
	RuleSet            snapshot.RuleSetProvenance      `json:"rule_set"`
	Intelligence       snapshot.IntelligenceProvenance `json:"intelligence"`
	Suppressions       suppression.Report              `json:"suppressions"`
	Prioritization     prioritization.Result           `json:"prioritization"`
	Remediation        remediation.Result              `json:"remediation"`
	Findings           Findings                        `json:"findings"`
	Limitations        []string                        `json:"limitations"`
	Safety             string                          `json:"safety"`
}

func Build(s scan.Result) (Result, error) {
	return build(s, AssessmentSnapshotRef{
		Schema: scan.AssessmentSnapshotSchemaVersion, AssessmentID: s.Snapshot.AssessmentID,
		CapturedAt: s.Timing.CompletedAt, Source: "live-assessment",
	})
}

// BuildFromAssessmentSnapshot renders a report from an already frozen scan. It
// performs no host collection and is the Fix52 path used by the Windows release
// gate to compare report semantics with the exact scan that produced them.
func BuildFromAssessmentSnapshot(frozen scan.AssessmentSnapshot, source string) (Result, error) {
	if err := frozen.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate immutable assessment snapshot: %w", err)
	}
	s, err := frozen.ResultCopy()
	if err != nil {
		return Result{}, fmt.Errorf("copy immutable assessment snapshot: %w", err)
	}
	return build(s, AssessmentSnapshotRef{
		Schema: frozen.Schema, AssessmentID: frozen.AssessmentID, Digest: frozen.Digest,
		CapturedAt: frozen.CapturedAt, Source: stableSnapshotSource(source),
	})
}

func build(s scan.Result, snapshotRef AssessmentSnapshotRef) (Result, error) {
	if s.Snapshot.AssessmentID == "" {
		return Result{}, fmt.Errorf("assessment snapshot is missing")
	}
	if s.Prioritization == nil {
		return Result{}, fmt.Errorf("risk prioritization is missing")
	}
	if s.Remediation == nil {
		return Result{}, fmt.Errorf("remediation view is missing")
	}
	if err := s.Prioritization.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate prioritization: %w", err)
	}
	if err := s.Remediation.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate remediation: %w", err)
	}
	if err := assessment.ValidateAll(s.Findings); err != nil {
		return Result{}, fmt.Errorf("validate findings: %w", err)
	}

	findings := append([]assessment.Finding(nil), s.Findings...)
	assessment.SortFindings(findings)
	rawLimitations := collectLimitations(s)
	classifiedLimitations, limitationSummary := evidencequality.ClassifyAll(rawLimitations)
	unknownCauses, unknownSummary := evidencequality.ClassifyUnknownFindings(findings)
	unknownAudit := evidencequality.AuditUnknownFindings(findings)
	releaseReadiness := buildReleaseReadiness(classifiedLimitations, limitationSummary, unknownAudit)
	limitations := canonicalLimitationStrings(classifiedLimitations)
	out := Result{
		Schema:        SchemaVersion,
		EngineVersion: EngineVersion,
		GeneratedAt:   s.Timing.CompletedAt,
		Tool:          version.Current(),
		Host: Host{
			Hostname: stable(s.Overview.Hostname), CurrentUser: stable(s.Overview.CurrentUser),
			Platform: stable(s.Overview.OS), OSVersion: s.Overview.OSVersion, OSBuild: s.Overview.OSBuild,
			Kernel: s.Overview.Kernel, Architecture: stable(s.Overview.Architecture),
			CollectionTier: stable(s.Overview.Privilege.CollectionTier), Fingerprint: s.Snapshot.HostFingerprint.Value,
		},
		Assessment: Assessment{
			ID: s.Snapshot.AssessmentID, State: s.State, StartedAt: s.Timing.StartedAt,
			CompletedAt: s.Timing.CompletedAt, DurationMS: s.Timing.DurationMS, TimedOut: s.TimedOut,
			Profile: s.Profile.Descriptor.Name, Selection: s.Selection, CategorySummary: s.Summary.Categories, Evaluation: s.Summary.Evaluation,
		},
		EvidenceQuality: EvidenceQuality{
			State: s.Collection.State, Counts: s.Collection.Evidence,
			DegradationReasons: append([]string(nil), s.Collection.DegradationReasons...),
			RawLimitations:     append([]string(nil), rawLimitations...),
			Limitations:        classifiedLimitations, LimitationSummary: limitationSummary,
			UnknownCauses: unknownCauses, UnknownSummary: unknownSummary, UnknownAudit: unknownAudit,
			ReleaseReadiness: releaseReadiness,
		},
		AssessmentSnapshot: snapshotRef,
		Snapshot:           s.Snapshot,
		RuleSet:            s.Snapshot.Rules,
		Intelligence:       s.Snapshot.Intelligence,
		Suppressions:       s.Suppressions,
		Prioritization:     *s.Prioritization,
		Remediation:        *s.Remediation,
		Findings:           Findings{Summary: s.Summary.Findings, Items: findings},
		Limitations:        limitations,
		Safety:             "read-only report generated from the same normalized evidence, rule evaluation, suppression, prioritization, and remediation contracts used by the live assessment; no export format mutates host state or performs network activity",
	}
	if err := out.Validate(); err != nil {
		return Result{}, err
	}
	return out, nil
}

func buildReleaseReadiness(limitations []evidencequality.Limitation, summary evidencequality.Summary, audit evidencequality.UnknownAudit) ReleaseReadiness {
	rootIDs := make([]string, 0, summary.UniqueReleaseBlockers)
	for _, limitation := range limitations {
		if !limitation.ReleaseBlocker || strings.TrimSpace(limitation.RootCauseID) == "" {
			continue
		}
		rootIDs = append(rootIDs, limitation.RootCauseID)
	}
	sort.Strings(rootIDs)
	return ReleaseReadiness{
		RawLimitationOccurrences:   summary.TotalOccurrences,
		UniqueLimitations:          summary.UniqueLimitations,
		UniqueReleaseBlockers:      summary.UniqueReleaseBlockers,
		ProductDefectLimitations:   summary.ProductDefect,
		DeadlineBudgetLimitations:  summary.DeadlineBudget,
		ProductDefectUnknown:       audit.Summary.ProductDefect,
		ReleaseBlockerRootCauseIDs: rootIDs,
	}
}

func collectLimitations(s scan.Result) []string {
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
	}
	if s.TimedOut {
		add("assessment reached its configured timeout; some evidence or categories may be incomplete")
	}
	if s.Summary.Evaluation.SelectedRules > 0 && !s.Summary.Evaluation.Complete {
		add(fmt.Sprintf("assessment incomplete: %d of %d selected rules evaluated; %d NOT_EVALUATED", s.Summary.Evaluation.EvaluatedRules, s.Summary.Evaluation.SelectedRules, s.Summary.Evaluation.NotEvaluatedRules))
	}
	for _, v := range s.Collection.DegradationReasons {
		add(v)
	}
	for _, c := range s.Categories {
		if c.Reason != "" {
			add(c.Name + ": " + c.Reason)
		}
		for _, v := range c.DegradationReasons {
			add(c.Name + ": " + v)
		}
	}
	if s.Snapshot.Intelligence.Reason != "" {
		add("intelligence: " + s.Snapshot.Intelligence.Reason)
	}
	if s.Overview.Privilege.ElevationNote != "" {
		add("privilege: " + s.Overview.Privilege.ElevationNote)
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func canonicalLimitationStrings(items []evidencequality.Limitation) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		reason := strings.TrimSpace(item.Reason)
		if reason == "" {
			continue
		}
		switch {
		case item.AffectedRecords > 0 && item.Occurrences > 1:
			reason = fmt.Sprintf("%s (affected records=%d, occurrences=%d)", reason, item.AffectedRecords, item.Occurrences)
		case item.AffectedRecords > 0:
			reason = fmt.Sprintf("%s (affected records=%d)", reason, item.AffectedRecords)
		case item.Occurrences > 1:
			reason = fmt.Sprintf("%s (occurrences=%d)", reason, item.Occurrences)
		}
		out = append(out, reason)
	}
	return out
}

func stableSnapshotSource(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "assessment-snapshot"
	}
	return v
}

func stable(v string) string {
	if strings.TrimSpace(v) == "" {
		return "UNAVAILABLE"
	}
	return v
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion || r.EngineVersion != EngineVersion {
		return fmt.Errorf("unexpected report contract %q / %q", r.Schema, r.EngineVersion)
	}
	if r.GeneratedAt.IsZero() || r.Assessment.ID == "" || r.Host.Fingerprint == "" {
		return fmt.Errorf("report assessment identity and timestamps are required")
	}
	if r.Tool.Product == "" || r.Tool.Version == "" || r.Host.Platform == "" || r.Host.Architecture == "" {
		return fmt.Errorf("report tool and host metadata are incomplete")
	}
	if r.AssessmentSnapshot.Schema != "" {
		if r.AssessmentSnapshot.Schema != scan.AssessmentSnapshotSchemaVersion || strings.TrimSpace(r.AssessmentSnapshot.AssessmentID) == "" || r.AssessmentSnapshot.AssessmentID != r.Assessment.ID || r.AssessmentSnapshot.CapturedAt.IsZero() {
			return fmt.Errorf("report immutable assessment snapshot provenance is invalid")
		}
		if r.AssessmentSnapshot.Source != "live-assessment" && len(strings.TrimSpace(r.AssessmentSnapshot.Digest)) != 64 {
			return fmt.Errorf("report immutable assessment snapshot digest is invalid")
		}
	}
	if r.RuleSet.Schema == "" || r.RuleSet.Version == "" || r.RuleSet.Digest.Value == "" {
		return fmt.Errorf("report rule-set provenance is incomplete")
	}
	if r.Intelligence.Version == "" || r.Intelligence.State == "" {
		return fmt.Errorf("report intelligence provenance is incomplete")
	}
	if r.Assessment.Evaluation.SelectedRules > 0 && r.Assessment.Evaluation.EvaluatedRules+r.Assessment.Evaluation.NotEvaluatedRules != r.Assessment.Evaluation.SelectedRules {
		return fmt.Errorf("report evaluation coverage does not account for selected rules")
	}
	if err := assessment.ValidateAll(r.Findings.Items); err != nil {
		return err
	}
	if r.Findings.Summary.Total != len(r.Findings.Items) {
		return fmt.Errorf("report finding summary does not match finding items")
	}
	if err := r.Prioritization.Validate(); err != nil {
		return err
	}
	if err := r.Remediation.Validate(); err != nil {
		return err
	}
	if r.Limitations == nil {
		return fmt.Errorf("report limitations collection must be non-nil")
	}
	if r.EvidenceQuality.LimitationSummary.UniqueLimitations != len(r.EvidenceQuality.Limitations) {
		return fmt.Errorf("report limitation summary does not match canonical limitations")
	}
	rootIDs := map[string]struct{}{}
	releaseBlockerIDs := map[string]struct{}{}
	for _, limitation := range r.EvidenceQuality.Limitations {
		rootID := strings.TrimSpace(limitation.RootCauseID)
		if rootID == "" {
			return fmt.Errorf("canonical limitation is missing root_cause_id")
		}
		if _, exists := rootIDs[rootID]; exists {
			return fmt.Errorf("duplicate canonical limitation root_cause_id %q", rootID)
		}
		rootIDs[rootID] = struct{}{}
		if limitation.ReleaseBlocker {
			releaseBlockerIDs[rootID] = struct{}{}
			if strings.TrimSpace(limitation.Provider) == "" || strings.TrimSpace(limitation.Message) == "" {
				return fmt.Errorf("release blocker %q is missing provider/message root-cause metadata", rootID)
			}
		}
	}
	if r.EvidenceQuality.LimitationSummary.ReleaseBlockers != len(releaseBlockerIDs) {
		return fmt.Errorf("report release-blocker summary=%d does not match unique root causes=%d", r.EvidenceQuality.LimitationSummary.ReleaseBlockers, len(releaseBlockerIDs))
	}
	if r.EvidenceQuality.LimitationSummary.UniqueReleaseBlockers != len(releaseBlockerIDs) {
		return fmt.Errorf("report unique release-blocker summary=%d does not match unique root causes=%d", r.EvidenceQuality.LimitationSummary.UniqueReleaseBlockers, len(releaseBlockerIDs))
	}
	if r.EvidenceQuality.UnknownSummary.Total != r.Findings.Summary.Unknown {
		return fmt.Errorf("report UNKNOWN-cause summary=%d does not match UNKNOWN findings=%d", r.EvidenceQuality.UnknownSummary.Total, r.Findings.Summary.Unknown)
	}
	if err := r.EvidenceQuality.UnknownAudit.Validate(r.Findings.Summary.Unknown); err != nil {
		return fmt.Errorf("validate UNKNOWN audit: %w", err)
	}
	ready := r.EvidenceQuality.ReleaseReadiness
	if ready.RawLimitationOccurrences != r.EvidenceQuality.LimitationSummary.TotalOccurrences ||
		ready.UniqueLimitations != r.EvidenceQuality.LimitationSummary.UniqueLimitations ||
		ready.UniqueReleaseBlockers != r.EvidenceQuality.LimitationSummary.UniqueReleaseBlockers ||
		ready.ProductDefectLimitations != r.EvidenceQuality.LimitationSummary.ProductDefect ||
		ready.DeadlineBudgetLimitations != r.EvidenceQuality.LimitationSummary.DeadlineBudget ||
		ready.ProductDefectUnknown != r.EvidenceQuality.UnknownAudit.Summary.ProductDefect {
		return fmt.Errorf("report release-readiness summary does not agree with evidence-quality accounting")
	}
	wantRoots := make([]string, 0, len(releaseBlockerIDs))
	for rootID := range releaseBlockerIDs {
		wantRoots = append(wantRoots, rootID)
	}
	sort.Strings(wantRoots)
	if len(ready.ReleaseBlockerRootCauseIDs) != len(wantRoots) {
		return fmt.Errorf("report release-readiness root count=%d does not match canonical blockers=%d", len(ready.ReleaseBlockerRootCauseIDs), len(wantRoots))
	}
	for i := range wantRoots {
		if ready.ReleaseBlockerRootCauseIDs[i] != wantRoots[i] {
			return fmt.Errorf("report release-readiness root[%d]=%q want %q", i, ready.ReleaseBlockerRootCauseIDs[i], wantRoots[i])
		}
	}
	return nil
}

func ValidateEngineContract() error {
	if SchemaVersion != "chimera.enterprise-report/v1" || EngineVersion != "report/phase115-v1" {
		return fmt.Errorf("unexpected report engine identifiers")
	}
	return nil
}

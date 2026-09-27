package assessmentdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
)

const (
	SchemaVersion            = "chimera.assessment-diff/v1"
	maxAssessmentBytes int64 = 256 << 20
)

type Classification string

const (
	ClassNew              Classification = "NEW"
	ClassResolved         Classification = "RESOLVED"
	ClassRegressed        Classification = "REGRESSED"
	ClassImproved         Classification = "IMPROVED"
	ClassUnchanged        Classification = "UNCHANGED"
	ClassAddedToScope     Classification = "ADDED_TO_SCOPE"
	ClassRemovedFromScope Classification = "REMOVED_FROM_SCOPE"
	ClassRemoved          Classification = "REMOVED"
	ClassNotEvaluated     Classification = "NOT_EVALUATED"
	ClassNewlyEvaluated   Classification = "NEWLY_EVALUATED"
)

type AssessmentRef struct {
	Path                string `json:"path"`
	AssessmentID        string `json:"assessment_id"`
	HostFingerprint     string `json:"host_fingerprint"`
	AssessedAt          string `json:"assessed_at"`
	ToolVersion         string `json:"tool_version"`
	Profile             string `json:"profile"`
	ProfileDigest       string `json:"profile_digest"`
	RuleSetVersion      string `json:"rule_set_version"`
	RuleSetDigest       string `json:"rule_set_digest"`
	ConfigDigest        string `json:"config_digest"`
	IntelligenceVersion string `json:"intelligence_version"`
	IntelligenceDigest  string `json:"intelligence_digest,omitempty"`
	SuppressionDigest   string `json:"suppression_digest"`
}

type ProvenanceChanges struct {
	ConfigPolicy      bool `json:"config_policy_changed"`
	Profile           bool `json:"profile_changed"`
	RuleSet           bool `json:"rule_set_changed"`
	Selection         bool `json:"selection_changed"`
	Intelligence      bool `json:"intelligence_changed"`
	SuppressionPolicy bool `json:"suppression_policy_changed"`
}

type FindingState struct {
	Status         assessment.Status           `json:"status"`
	Severity       assessment.Severity         `json:"severity"`
	Confidence     evidence.Confidence         `json:"confidence"`
	Applicability  assessment.Applicability    `json:"applicability"`
	Suppression    assessment.SuppressionState `json:"suppression_state"`
	ObservedState  string                      `json:"observed_state"`
	ExpectedState  string                      `json:"expected_state"`
	EvidenceDigest string                      `json:"evidence_digest"`
}

type FindingChange struct {
	FindingID            string         `json:"finding_id"`
	RuleID               string         `json:"rule_id"`
	Category             string         `json:"category"`
	AffectedObject       string         `json:"affected_object"`
	Classification       Classification `json:"classification"`
	Before               *FindingState  `json:"before,omitempty"`
	After                *FindingState  `json:"after,omitempty"`
	StatusChanged        bool           `json:"status_changed"`
	SeverityChanged      bool           `json:"severity_changed"`
	ConfidenceChanged    bool           `json:"confidence_changed"`
	ApplicabilityChanged bool           `json:"applicability_changed"`
	EvidenceChanged      bool           `json:"evidence_changed"`
	SuppressionChanged   bool           `json:"suppression_changed"`
	NewlySuppressed      bool           `json:"newly_suppressed"`
	Unsuppressed         bool           `json:"unsuppressed"`
	Reasons              []string       `json:"reasons,omitempty"`
}

type Summary struct {
	BeforeFindings   int `json:"before_findings"`
	AfterFindings    int `json:"after_findings"`
	Matched          int `json:"matched"`
	New              int `json:"new"`
	Resolved         int `json:"resolved"`
	Regressed        int `json:"regressed"`
	Improved         int `json:"improved"`
	Unchanged        int `json:"unchanged"`
	AddedToScope     int `json:"added_to_scope"`
	RemovedFromScope int `json:"removed_from_scope"`
	Removed          int `json:"removed"`
	Suppressed       int `json:"suppressed"`
	NewlySuppressed  int `json:"newly_suppressed"`
	Unsuppressed     int `json:"unsuppressed"`
	EvidenceChanged  int `json:"evidence_changed"`
	NotEvaluated     int `json:"not_evaluated"`
	NewlyEvaluated   int `json:"newly_evaluated"`
}

type Result struct {
	Schema            string            `json:"assessment_diff_schema"`
	Before            AssessmentRef     `json:"before"`
	After             AssessmentRef     `json:"after"`
	SameHost          bool              `json:"same_host"`
	ComparableScope   bool              `json:"comparable_scope"`
	ProvenanceChanges ProvenanceChanges `json:"provenance_changes"`
	Summary           Summary           `json:"summary"`
	Changes           []FindingChange   `json:"changes"`
}

type loadedAssessment struct {
	path string
	scan scan.Result
}

type envelope struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data"`
}

func CompareFiles(beforePath, afterPath string) (Result, error) {
	before, err := load(beforePath)
	if err != nil {
		return Result{}, fmt.Errorf("load before assessment: %w", err)
	}
	after, err := load(afterPath)
	if err != nil {
		return Result{}, fmt.Errorf("load after assessment: %w", err)
	}
	return Compare(before, after)
}

func CompareResults(beforePath string, before scan.Result, afterPath string, after scan.Result) (Result, error) {
	return Compare(loadedAssessment{path: beforePath, scan: before}, loadedAssessment{path: afterPath, scan: after})
}

func Compare(before, after loadedAssessment) (Result, error) {
	if err := validateLoaded(before); err != nil {
		return Result{}, fmt.Errorf("before assessment: %w", err)
	}
	if err := validateLoaded(after); err != nil {
		return Result{}, fmt.Errorf("after assessment: %w", err)
	}
	if before.scan.Snapshot.HostFingerprint.Value != after.scan.Snapshot.HostFingerprint.Value {
		return Result{}, fmt.Errorf("assessment host fingerprints differ (%s != %s); refusing cross-host diff", short(before.scan.Snapshot.HostFingerprint.Value), short(after.scan.Snapshot.HostFingerprint.Value))
	}

	pc := provenanceChanges(before.scan, after.scan)
	out := Result{
		Schema:            SchemaVersion,
		Before:            ref(before),
		After:             ref(after),
		SameHost:          true,
		ComparableScope:   !pc.Profile && !pc.RuleSet && !pc.Selection,
		ProvenanceChanges: pc,
		Summary:           Summary{BeforeFindings: len(before.scan.Findings), AfterFindings: len(after.scan.Findings)},
	}

	beforeByID := indexFindings(before.scan.Findings)
	afterByID := indexFindings(after.scan.Findings)
	beforeSelected := selectedRules(before.scan.Selection)
	afterSelected := selectedRules(after.scan.Selection)
	beforeEvaluated := evaluatedRules(before.scan)
	afterEvaluated := evaluatedRules(after.scan)

	ids := make([]string, 0, len(beforeByID)+len(afterByID))
	seen := map[string]struct{}{}
	for id := range beforeByID {
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for id := range afterByID {
		if _, ok := seen[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		bf, bok := beforeByID[id]
		af, aok := afterByID[id]
		change, err := compareFinding(bf, bok, af, aok, beforeSelected, afterSelected, beforeEvaluated, afterEvaluated)
		if err != nil {
			return Result{}, err
		}
		out.Changes = append(out.Changes, change)
		addSummary(&out.Summary, change, bok && aok)
	}
	sort.SliceStable(out.Changes, func(i, j int) bool {
		ai, aj := classificationRank(out.Changes[i].Classification), classificationRank(out.Changes[j].Classification)
		if ai != aj {
			return ai < aj
		}
		if out.Changes[i].RuleID != out.Changes[j].RuleID {
			return out.Changes[i].RuleID < out.Changes[j].RuleID
		}
		if out.Changes[i].AffectedObject != out.Changes[j].AffectedObject {
			return out.Changes[i].AffectedObject < out.Changes[j].AffectedObject
		}
		return out.Changes[i].FindingID < out.Changes[j].FindingID
	})
	return out, nil
}

func load(path string) (loadedAssessment, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return loadedAssessment{}, fmt.Errorf("assessment path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return loadedAssessment{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return loadedAssessment{}, err
	}
	if !st.Mode().IsRegular() {
		return loadedAssessment{}, fmt.Errorf("%q is not a regular file", path)
	}
	if st.Size() > maxAssessmentBytes {
		return loadedAssessment{}, fmt.Errorf("%q exceeds %d-byte assessment input limit", path, maxAssessmentBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAssessmentBytes+1))
	if err != nil {
		return loadedAssessment{}, err
	}
	if int64(len(b)) > maxAssessmentBytes {
		return loadedAssessment{}, fmt.Errorf("%q exceeds %d-byte assessment input limit", path, maxAssessmentBytes)
	}

	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return loadedAssessment{}, fmt.Errorf("decode JSON: %w", err)
	}
	var s scan.Result
	if len(env.Data) > 0 {
		if env.Command != "scan" {
			return loadedAssessment{}, fmt.Errorf("JSON envelope command is %q, expected scan", env.Command)
		}
		if err := json.Unmarshal(env.Data, &s); err != nil {
			return loadedAssessment{}, fmt.Errorf("decode scan envelope data: %w", err)
		}
	} else if err := json.Unmarshal(b, &s); err != nil {
		return loadedAssessment{}, fmt.Errorf("decode scan result: %w", err)
	}
	return loadedAssessment{path: path, scan: s}, nil
}

func validateLoaded(in loadedAssessment) error {
	if in.scan.Schema != scan.SchemaVersion {
		return fmt.Errorf("unsupported scan schema %q", in.scan.Schema)
	}
	if in.scan.FindingSchema != assessment.SchemaVersion {
		return fmt.Errorf("unsupported finding schema %q", in.scan.FindingSchema)
	}
	if in.scan.Selection.Schema != selection.SchemaVersion {
		return fmt.Errorf("unsupported selection schema %q", in.scan.Selection.Schema)
	}
	if err := assessment.ValidateAll(in.scan.Findings); err != nil {
		return fmt.Errorf("validate findings: %w", err)
	}
	if err := in.scan.Snapshot.Validate(); err != nil {
		return fmt.Errorf("validate deterministic snapshot: %w", err)
	}
	return nil
}

func ref(in loadedAssessment) AssessmentRef {
	s := in.scan.Snapshot
	return AssessmentRef{
		Path:                in.path,
		AssessmentID:        s.AssessmentID,
		HostFingerprint:     s.HostFingerprint.Value,
		AssessedAt:          s.AssessedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		ToolVersion:         s.Tool.Version,
		Profile:             s.Profile.Name,
		ProfileDigest:       s.Profile.Digest.Value,
		RuleSetVersion:      s.Rules.Version,
		RuleSetDigest:       s.Rules.Digest.Value,
		ConfigDigest:        s.Config.Digest.Value,
		IntelligenceVersion: s.Intelligence.Version,
		IntelligenceDigest:  s.Intelligence.Digest,
		SuppressionDigest:   s.Suppressions.Digest.Value,
	}
}

func provenanceChanges(a, b scan.Result) ProvenanceChanges {
	return ProvenanceChanges{
		ConfigPolicy:      a.Snapshot.Config.Digest.Value != b.Snapshot.Config.Digest.Value,
		Profile:           a.Snapshot.Profile.Digest.Value != b.Snapshot.Profile.Digest.Value,
		RuleSet:           a.Snapshot.Rules.Digest.Value != b.Snapshot.Rules.Digest.Value || a.Snapshot.Rules.Version != b.Snapshot.Rules.Version,
		Selection:         selectionDigest(a.Selection) != selectionDigest(b.Selection),
		Intelligence:      a.Snapshot.Intelligence.Digest != b.Snapshot.Intelligence.Digest || a.Snapshot.Intelligence.Version != b.Snapshot.Intelligence.Version,
		SuppressionPolicy: a.Snapshot.Suppressions.Digest.Value != b.Snapshot.Suppressions.Digest.Value,
	}
}

func compareFinding(before assessment.Finding, bok bool, after assessment.Finding, aok bool, beforeSelected, afterSelected map[string]bool, evaluated ...map[string]bool) (FindingChange, error) {
	beforeEvaluated, afterEvaluated := beforeSelected, afterSelected
	if len(evaluated) >= 2 {
		beforeEvaluated, afterEvaluated = evaluated[0], evaluated[1]
	}
	switch {
	case !bok && !aok:
		return FindingChange{}, fmt.Errorf("internal diff error: finding absent from both assessments")
	case !bok:
		st, err := state(after)
		if err != nil {
			return FindingChange{}, err
		}
		class := ClassNew
		reason := "finding is present only in the after assessment"
		ruleID := strings.ToUpper(strings.TrimSpace(after.RuleID))
		if beforeSelected[ruleID] && !beforeEvaluated[ruleID] {
			class, reason = ClassNewlyEvaluated, "rule was selected before but NOT_EVALUATED; this assessment produced its first comparable result"
		} else if !beforeSelected[ruleID] && afterSelected[ruleID] {
			class, reason = ClassAddedToScope, "rule was not selected before and is selected after"
		}
		return FindingChange{
			FindingID: after.ID, RuleID: after.RuleID, Category: after.Category, AffectedObject: after.AffectedObject,
			Classification: class, After: &st, EvidenceChanged: true,
			NewlySuppressed:    after.Suppression == assessment.SuppressionSuppressed,
			SuppressionChanged: after.Suppression == assessment.SuppressionSuppressed,
			Reasons:            []string{reason},
		}, nil
	case !aok:
		st, err := state(before)
		if err != nil {
			return FindingChange{}, err
		}
		class := ClassRemoved
		reason := "finding is absent from the after assessment"
		ruleID := strings.ToUpper(strings.TrimSpace(before.RuleID))
		if afterSelected[ruleID] && !afterEvaluated[ruleID] {
			class, reason = ClassNotEvaluated, "rule remains selected but was NOT_EVALUATED in the after assessment; no resolution conclusion is possible"
		} else if beforeSelected[ruleID] && !afterSelected[ruleID] {
			class, reason = ClassRemovedFromScope, "rule was selected before but is not selected after"
		} else if postureRank(before) > 0 {
			class, reason = ClassResolved, "adverse finding is absent while its rule remains in assessment scope and was evaluated"
		}
		return FindingChange{
			FindingID: before.ID, RuleID: before.RuleID, Category: before.Category, AffectedObject: before.AffectedObject,
			Classification: class, Before: &st, EvidenceChanged: true,
			Unsuppressed:       before.Suppression == assessment.SuppressionSuppressed,
			SuppressionChanged: before.Suppression == assessment.SuppressionSuppressed,
			Reasons:            []string{reason},
		}, nil
	}

	bs, err := state(before)
	if err != nil {
		return FindingChange{}, err
	}
	as, err := state(after)
	if err != nil {
		return FindingChange{}, err
	}
	br, ar := postureRank(before), postureRank(after)
	class := ClassUnchanged
	reasons := []string{"finding posture is unchanged"}
	if ar > br {
		class = ClassRegressed
		reasons = []string{fmt.Sprintf("posture worsened from %s/%s to %s/%s", before.Applicability, before.Status, after.Applicability, after.Status)}
	} else if ar < br {
		if ar == 0 {
			class = ClassResolved
			reasons = []string{fmt.Sprintf("posture resolved from %s/%s to %s/%s", before.Applicability, before.Status, after.Applicability, after.Status)}
		} else {
			class = ClassImproved
			reasons = []string{fmt.Sprintf("posture improved from %s/%s to %s/%s but remains adverse", before.Applicability, before.Status, after.Applicability, after.Status)}
		}
	}
	evChanged := bs.EvidenceDigest != as.EvidenceDigest
	supChanged := suppressionDigest(before) != suppressionDigest(after) || before.Suppression != after.Suppression
	statusChanged := before.Status != after.Status
	sevChanged := before.Severity != after.Severity
	confChanged := before.Confidence != after.Confidence
	appChanged := before.Applicability != after.Applicability
	if evChanged {
		reasons = append(reasons, "normalized evidence content changed")
	}
	if supChanged {
		reasons = append(reasons, "suppression state or attached suppression policy changed")
	}
	if sevChanged {
		reasons = append(reasons, fmt.Sprintf("severity changed from %s to %s", before.Severity, after.Severity))
	}
	if confChanged {
		reasons = append(reasons, fmt.Sprintf("confidence changed from %s to %s", before.Confidence, after.Confidence))
	}
	if before.ObservedState != after.ObservedState {
		reasons = append(reasons, "observed state text changed")
	}
	if before.ExpectedState != after.ExpectedState {
		reasons = append(reasons, "expected state text changed")
	}
	return FindingChange{
		FindingID: after.ID, RuleID: after.RuleID, Category: after.Category, AffectedObject: after.AffectedObject,
		Classification: class, Before: &bs, After: &as,
		StatusChanged: statusChanged, SeverityChanged: sevChanged, ConfidenceChanged: confChanged, ApplicabilityChanged: appChanged,
		EvidenceChanged: evChanged, SuppressionChanged: supChanged,
		NewlySuppressed: before.Suppression != assessment.SuppressionSuppressed && after.Suppression == assessment.SuppressionSuppressed,
		Unsuppressed:    before.Suppression == assessment.SuppressionSuppressed && after.Suppression != assessment.SuppressionSuppressed,
		Reasons:         reasons,
	}, nil
}

func state(f assessment.Finding) (FindingState, error) {
	d, err := evidenceDigest(f.Evidence)
	if err != nil {
		return FindingState{}, fmt.Errorf("finding %s evidence digest: %w", f.ID, err)
	}
	return FindingState{
		Status: f.Status, Severity: f.Severity, Confidence: f.Confidence, Applicability: f.Applicability,
		Suppression: f.Suppression, ObservedState: f.ObservedState, ExpectedState: f.ExpectedState, EvidenceDigest: d,
	}, nil
}

func postureRank(f assessment.Finding) int {
	if f.Applicability == assessment.NotApplicable {
		return 0
	}
	switch f.Status {
	case assessment.StatusPass:
		return 0
	case assessment.StatusUnknown:
		return 1
	case assessment.StatusWarn:
		return 2
	case assessment.StatusFail:
		return 3
	default:
		return 0
	}
}

type normalizedEvidence struct {
	Key        string              `json:"key"`
	State      evidence.State      `json:"state"`
	Value      any                 `json:"value,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Reason     string              `json:"reason,omitempty"`
}

func evidenceDigest(items []assessment.EvidenceRef) (string, error) {
	rows := make([]normalizedEvidence, 0, len(items))
	for _, e := range items {
		rows = append(rows, normalizedEvidence{Key: e.Key, State: e.State, Value: e.Value, Source: e.Source, Confidence: e.Confidence, Reason: e.Reason})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Key != rows[j].Key {
			return rows[i].Key < rows[j].Key
		}
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		bi, _ := json.Marshal(rows[i].Value)
		bj, _ := json.Marshal(rows[j].Value)
		return string(bi) < string(bj)
	})
	return digest(rows)
}

func suppressionDigest(f assessment.Finding) string {
	type row struct {
		ID, MatchScope, Reason, Owner, CreatedAt, ExpiresAt, Source string
		Metadata                                                    map[string]string
	}
	rows := make([]row, 0, len(f.Suppressions))
	for _, s := range f.Suppressions {
		rows = append(rows, row{
			ID: s.ID, MatchScope: s.MatchScope, Reason: s.Reason, Owner: s.Owner,
			CreatedAt: s.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			ExpiresAt: s.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			Source:    s.Source, Metadata: s.Metadata,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	d, _ := digest(rows)
	return d
}

func selectionDigest(r selection.Report) string {
	type row struct {
		RuleID   string
		Outcome  selection.Outcome
		Severity assessment.Severity
	}
	rows := make([]row, 0, len(r.Decisions))
	for _, d := range r.Decisions {
		rows = append(rows, row{RuleID: strings.ToUpper(strings.TrimSpace(d.RuleID)), Outcome: d.Outcome, Severity: d.Severity})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RuleID < rows[j].RuleID })
	d, _ := digest(struct {
		Request   selection.Request
		Decisions []row
	}{r.Request, rows})
	return d
}

func digest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func selectedRules(r selection.Report) map[string]bool {
	out := map[string]bool{}
	for _, d := range r.Decisions {
		if d.Outcome == selection.OutcomeSelected {
			out[strings.ToUpper(strings.TrimSpace(d.RuleID))] = true
		}
	}
	return out
}

func evaluatedRules(s scan.Result) map[string]bool {
	if s.Summary.Evaluation.Complete {
		return selectedRules(s.Selection)
	}
	out := map[string]bool{}
	for _, category := range s.Categories {
		if category.EvaluatedRules == 0 {
			continue
		}
		for _, ruleID := range category.RuleIDs {
			out[strings.ToUpper(strings.TrimSpace(ruleID))] = true
		}
	}
	return out
}

func indexFindings(findings []assessment.Finding) map[string]assessment.Finding {
	out := make(map[string]assessment.Finding, len(findings))
	for _, f := range findings {
		out[f.ID] = f
	}
	return out
}

func addSummary(s *Summary, c FindingChange, matched bool) {
	if matched {
		s.Matched++
	}
	switch c.Classification {
	case ClassNew:
		s.New++
	case ClassResolved:
		s.Resolved++
	case ClassRegressed:
		s.Regressed++
	case ClassImproved:
		s.Improved++
	case ClassUnchanged:
		s.Unchanged++
	case ClassAddedToScope:
		s.AddedToScope++
	case ClassRemovedFromScope:
		s.RemovedFromScope++
	case ClassRemoved:
		s.Removed++
	case ClassNotEvaluated:
		s.NotEvaluated++
	case ClassNewlyEvaluated:
		s.NewlyEvaluated++
	}
	if c.After != nil && c.After.Suppression == assessment.SuppressionSuppressed {
		s.Suppressed++
	}
	if c.NewlySuppressed {
		s.NewlySuppressed++
	}
	if c.Unsuppressed {
		s.Unsuppressed++
	}
	if c.EvidenceChanged {
		s.EvidenceChanged++
	}
}

func classificationRank(c Classification) int {
	switch c {
	case ClassRegressed:
		return 0
	case ClassNew:
		return 1
	case ClassAddedToScope:
		return 2
	case ClassImproved:
		return 3
	case ClassResolved:
		return 4
	case ClassRemovedFromScope:
		return 5
	case ClassNotEvaluated:
		return 6
	case ClassNewlyEvaluated:
		return 7
	case ClassRemoved:
		return 8
	case ClassUnchanged:
		return 9
	default:
		return 8
	}
}

func short(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:12]
}

func ValidateContract() error {
	if SchemaVersion != "chimera.assessment-diff/v1" {
		return fmt.Errorf("unexpected assessment diff schema %q", SchemaVersion)
	}
	classes := []Classification{ClassNew, ClassResolved, ClassRegressed, ClassImproved, ClassUnchanged, ClassAddedToScope, ClassRemovedFromScope, ClassRemoved, ClassNotEvaluated, ClassNewlyEvaluated}
	seen := map[Classification]struct{}{}
	for _, c := range classes {
		if _, ok := seen[c]; ok {
			return fmt.Errorf("duplicate assessment diff classification %q", c)
		}
		seen[c] = struct{}{}
	}
	return nil
}

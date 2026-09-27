package exporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/report"
)

const EngineVersion = "export/phase115-v1"

type Format string

const (
	FormatJSON  Format = "json"
	FormatText  Format = "text"
	FormatCSV   Format = "csv"
	FormatSARIF Format = "sarif"
)

func ParseFormat(v string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(v))) {
	case FormatJSON:
		return FormatJSON, nil
	case FormatText, "txt":
		return FormatText, nil
	case FormatCSV:
		return FormatCSV, nil
	case FormatSARIF:
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("unsupported export format %q; expected json, text, csv, or sarif", v)
	}
}

func Write(w io.Writer, f Format, r report.Result) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("validate enterprise report: %w", err)
	}
	switch f {
	case FormatJSON:
		// Exported JSON is a machine format. Keep it compact so large evidence-rich
		// reports are not amplified by presentation-only indentation.
		enc := json.NewEncoder(w)
		return enc.Encode(r)
	case FormatText:
		return writeText(w, r)
	case FormatCSV:
		return writeCSV(w, r)
	case FormatSARIF:
		return writeSARIF(w, r)
	default:
		return fmt.Errorf("unsupported export format %q", f)
	}
}

func writeText(w io.Writer, r report.Result) error {
	p := func(format string, args ...any) error { _, err := fmt.Fprintf(w, format, args...); return err }
	if err := p("IRONCLAD CHIMERA ENTERPRISE REPORT\n"); err != nil {
		return err
	}
	if err := p("Schema: %s\nEngine: %s\nTool: %s\nAssessment ID: %s\nHost: %s\nPlatform: %s/%s\nFingerprint: %s\nProfile: %s\nState: %s\nRule evaluation: %d/%d (%.1f%%), NOT_EVALUATED=%d, complete=%t\n\n",
		r.Schema, r.EngineVersion, r.Tool.Version, r.Assessment.ID, r.Host.Hostname, r.Host.Platform, r.Host.Architecture, r.Host.Fingerprint, r.Assessment.Profile, r.Assessment.State,
		r.Assessment.Evaluation.EvaluatedRules, r.Assessment.Evaluation.SelectedRules, r.Assessment.Evaluation.Percent, r.Assessment.Evaluation.NotEvaluatedRules, r.Assessment.Evaluation.Complete); err != nil {
		return err
	}
	if err := p("EVIDENCE QUALITY\nTotal=%d Observed=%d Degraded=%d Denied=%d Unavailable=%d Unsupported=%d NotApplicable=%d\n\n",
		r.EvidenceQuality.Counts.Total, r.EvidenceQuality.Counts.Observed, r.EvidenceQuality.Counts.Degraded, r.EvidenceQuality.Counts.Denied,
		r.EvidenceQuality.Counts.Unavailable, r.EvidenceQuality.Counts.Unsupported, r.EvidenceQuality.Counts.NotApplicable); err != nil {
		return err
	}
	if err := p("PROVENANCE\nRuleSet=%s Digest=%s\nIntelligence=%s State=%s Source=%s\n\n",
		r.RuleSet.Version, r.RuleSet.Digest.Value, r.Intelligence.Version, r.Intelligence.State, r.Intelligence.Source); err != nil {
		return err
	}
	if err := p("FINDINGS\nTotal=%d FAIL=%d WARN=%d UNKNOWN=%d PASS=%d Suppressed=%d\n",
		r.Findings.Summary.Total, r.Findings.Summary.Fail, r.Findings.Summary.Warn, r.Findings.Summary.Unknown, r.Findings.Summary.Pass, r.Findings.Summary.Suppressed); err != nil {
		return err
	}
	priorities := priorityIndex(r.Prioritization.Findings)
	for _, f := range r.Findings.Items {
		pr := priorities[f.ID]
		if err := p("- [%s/%s] %s %s | %s | %s | priority=%s/%d rank=%d | suppression=%s\n  observed: %s\n  expected: %s\n  remediation: %s\n",
			f.Status, f.Severity, f.ID, f.RuleID, f.Title, f.AffectedObject, pr.Band, pr.Score, pr.Rank, f.Suppression, f.ObservedState, f.ExpectedState, f.Remediation); err != nil {
			return err
		}
	}
	if err := p("\nREMEDIATION\nActions=%d Critical=%d High=%d Medium=%d Low=%d NeedsEvidence=%d Suppressed=%d\n",
		r.Remediation.Summary.Actions, r.Remediation.Summary.CriticalActions, r.Remediation.Summary.HighActions,
		r.Remediation.Summary.MediumActions, r.Remediation.Summary.LowActions, r.Remediation.Summary.NeedsEvidence, r.Remediation.Summary.Suppressed); err != nil {
		return err
	}
	for _, a := range r.Remediation.Actions {
		if err := p("- #%d [%s/%d] %s %s | %s\n  guidance: %s\n  verify: %s\n", a.PriorityRank, a.PriorityBand, a.PriorityScore, a.FindingID, a.RuleID, a.AffectedObject, a.Guidance, a.Verification); err != nil {
			return err
		}
	}
	if err := p("\nLIMITATIONS\n"); err != nil {
		return err
	}
	if len(r.Limitations) == 0 {
		if err := p("- none recorded\n"); err != nil {
			return err
		}
	} else {
		for _, v := range r.Limitations {
			if err := p("- %s\n", v); err != nil {
				return err
			}
		}
	}
	return p("\nSAFETY\n%s\n", r.Safety)
}

func writeCSV(w io.Writer, r report.Result) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	header := []string{"assessment_id", "host_fingerprint", "host", "platform", "profile", "assessment_state", "evaluation_selected", "evaluation_evaluated", "evaluation_not_evaluated", "evaluation_percent", "evaluation_complete", "evidence_quality_state", "rule_set_version", "intelligence_version", "limitations", "finding_id", "rule_id", "title", "status", "severity", "confidence", "priority_score", "priority_band", "priority_rank", "category", "affected_object", "observed_state", "expected_state", "suppression_state", "risk", "remediation", "references", "evidence_keys"}
	if err := cw.Write(header); err != nil {
		return err
	}
	priorities := priorityIndex(r.Prioritization.Findings)
	for _, f := range r.Findings.Items {
		p := priorities[f.ID]
		refs := make([]string, 0, len(f.References))
		for _, ref := range f.References {
			v := strings.TrimSpace(ref.Title)
			if ref.URL != "" {
				v += " " + ref.URL
			}
			if v != "" {
				refs = append(refs, v)
			}
		}
		keys := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			if e.Key != "" {
				keys = append(keys, e.Key)
			}
		}
		sort.Strings(keys)
		row := []string{
			r.Assessment.ID, r.Host.Fingerprint, r.Host.Hostname, r.Host.Platform + "/" + r.Host.Architecture, r.Assessment.Profile, string(r.Assessment.State),
			strconv.Itoa(r.Assessment.Evaluation.SelectedRules), strconv.Itoa(r.Assessment.Evaluation.EvaluatedRules), strconv.Itoa(r.Assessment.Evaluation.NotEvaluatedRules), strconv.FormatFloat(r.Assessment.Evaluation.Percent, 'f', 1, 64), strconv.FormatBool(r.Assessment.Evaluation.Complete),
			string(r.EvidenceQuality.State), r.RuleSet.Version, r.Intelligence.Version, strings.Join(r.Limitations, " | "),
			f.ID, f.RuleID, f.Title, string(f.Status), string(f.Severity), string(f.Confidence), strconv.Itoa(p.Score), string(p.Band), strconv.Itoa(p.Rank), f.Category, f.AffectedObject,
			f.ObservedState, f.ExpectedState, string(f.Suppression), f.Risk, f.Remediation, strings.Join(refs, " | "), strings.Join(keys, " | "),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	if len(r.Findings.Items) == 0 && r.Assessment.Evaluation.SelectedRules > 0 && !r.Assessment.Evaluation.Complete {
		row := make([]string, len(header))
		row[0] = r.Assessment.ID
		row[1] = r.Host.Fingerprint
		row[2] = r.Host.Hostname
		row[3] = r.Host.Platform + "/" + r.Host.Architecture
		row[4] = r.Assessment.Profile
		row[5] = string(r.Assessment.State)
		row[6] = strconv.Itoa(r.Assessment.Evaluation.SelectedRules)
		row[7] = strconv.Itoa(r.Assessment.Evaluation.EvaluatedRules)
		row[8] = strconv.Itoa(r.Assessment.Evaluation.NotEvaluatedRules)
		row[9] = strconv.FormatFloat(r.Assessment.Evaluation.Percent, 'f', 1, 64)
		row[10] = strconv.FormatBool(r.Assessment.Evaluation.Complete)
		row[11] = string(r.EvidenceQuality.State)
		row[12] = r.RuleSet.Version
		row[13] = r.Intelligence.Version
		row[14] = strings.Join(r.Limitations, " | ")
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func priorityIndex(items []prioritization.FindingPriority) map[string]prioritization.FindingPriority {
	out := make(map[string]prioritization.FindingPriority, len(items))
	for _, p := range items {
		out[p.FindingID] = p
	}
	return out
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Help             sarifMessage   `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Properties   map[string]any     `json:"properties,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

func writeSARIF(w io.Writer, r report.Result) error {
	priorities := priorityIndex(r.Prioritization.Findings)
	ruleByID := map[string]sarifRule{}
	results := []sarifResult{}
	for _, f := range r.Findings.Items {
		if f.Status == assessment.StatusPass || f.Applicability == assessment.NotApplicable {
			continue
		}
		ruleByID[f.RuleID] = sarifRule{
			ID: f.RuleID, Name: f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			Help:             sarifMessage{Text: f.Remediation},
			Properties:       map[string]any{"category": f.Category, "raw_severity": f.Severity},
		}
		p := priorities[f.ID]
		sr := sarifResult{
			RuleID: f.RuleID, Level: sarifLevel(f), Message: sarifMessage{Text: f.ObservedState},
			Properties: map[string]any{
				"finding_id": f.ID, "status": f.Status, "severity": f.Severity, "confidence": f.Confidence,
				"category": f.Category, "platform": f.Platform, "affected_object": f.AffectedObject,
				"expected_state": f.ExpectedState, "priority_score": p.Score, "priority_band": p.Band, "priority_rank": p.Rank,
				"suppression_state": f.Suppression, "risk": f.Risk, "collection_source": f.CollectionSource,
			},
		}
		if f.Suppression == assessment.SuppressionSuppressed {
			for _, s := range f.Suppressions {
				sr.Suppressions = append(sr.Suppressions, sarifSuppression{Kind: "external", Status: "accepted", Justification: s.ID + ": " + s.Reason + " (owner: " + s.Owner + ")"})
			}
		}
		results = append(results, sr)
	}
	ids := make([]string, 0, len(ruleByID))
	for id := range ruleByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, ruleByID[id])
	}
	log := sarifLog{
		Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: r.Tool.Product, Version: r.Tool.Version, SemanticVersion: r.Tool.Version, Rules: rules}},
			Results: results,
			Properties: map[string]any{
				"chimera_report_schema": r.Schema, "chimera_export_engine": EngineVersion, "assessment_id": r.Assessment.ID,
				"host_fingerprint": r.Host.Fingerprint, "host": r.Host.Hostname, "platform": r.Host.Platform + "/" + r.Host.Architecture,
				"profile": r.Assessment.Profile, "assessment_state": r.Assessment.State,
				"evaluation_selected": r.Assessment.Evaluation.SelectedRules, "evaluation_evaluated": r.Assessment.Evaluation.EvaluatedRules,
				"evaluation_not_evaluated": r.Assessment.Evaluation.NotEvaluatedRules, "evaluation_percent": r.Assessment.Evaluation.Percent, "evaluation_complete": r.Assessment.Evaluation.Complete,
				"rule_set_version": r.RuleSet.Version, "rule_set_digest": r.RuleSet.Digest.Value, "intelligence_version": r.Intelligence.Version, "intelligence_state": r.Intelligence.State,
				"limitations": r.Limitations,
			},
		}},
	}
	// SARIF is machine-readable JSON and follows the same compact-output policy
	// as the native JSON exporter.
	enc := json.NewEncoder(w)
	return enc.Encode(log)
}

func sarifLevel(f assessment.Finding) string {
	if f.Status == assessment.StatusUnknown {
		return "note"
	}
	switch f.Severity {
	case assessment.SeverityCritical, assessment.SeverityHigh:
		return "error"
	case assessment.SeverityMedium, assessment.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

func ValidateEngineContract() error {
	for _, v := range []string{string(FormatJSON), string(FormatText), string(FormatCSV), string(FormatSARIF)} {
		if _, err := ParseFormat(v); err != nil {
			return err
		}
	}
	if EngineVersion != "export/phase115-v1" {
		return fmt.Errorf("unexpected exporter engine version")
	}
	return nil
}

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/report"
)

func ReportHuman(w io.Writer, r report.Result, verbose bool) {
	fmt.Fprintln(w, "ENTERPRISE REPORT")
	fmt.Fprintf(w, "  Schema              %s\n", r.Schema)
	fmt.Fprintf(w, "  Engine              %s\n", r.EngineVersion)
	fmt.Fprintf(w, "  Assessment ID       %s\n", r.Assessment.ID)
	fmt.Fprintf(w, "  Host                %s\n", r.Host.Hostname)
	fmt.Fprintf(w, "  Platform            %s/%s\n", r.Host.Platform, r.Host.Architecture)
	fmt.Fprintf(w, "  Profile             %s\n", r.Assessment.Profile)
	fmt.Fprintf(w, "  Assessment state    %s\n", r.Assessment.State)
	fmt.Fprintf(w, "  Rule evaluation     %d/%d (%.1f%%)\n", r.Assessment.Evaluation.EvaluatedRules, r.Assessment.Evaluation.SelectedRules, r.Assessment.Evaluation.Percent)
	if !r.Assessment.Evaluation.Complete {
		fmt.Fprintln(w, "  Assessment          INCOMPLETE")
		fmt.Fprintf(w, "  NOT_EVALUATED       %d\n", r.Assessment.Evaluation.NotEvaluatedRules)
	}
	fmt.Fprintf(w, "  Host fingerprint    %s\n", shortDigest(r.Host.Fingerprint))
	fmt.Fprintf(w, "  Rule set            %s (%s)\n", r.RuleSet.Version, shortDigest(r.RuleSet.Digest.Value))
	fmt.Fprintf(w, "  Intelligence        %s / %s\n", r.Intelligence.State, r.Intelligence.Version)

	fmt.Fprintln(w, "\nEVIDENCE QUALITY")
	fmt.Fprintf(w, "  State               %s\n", r.EvidenceQuality.State)
	fmt.Fprintf(w, "  Total / observed    %d / %d\n", r.EvidenceQuality.Counts.Total, r.EvidenceQuality.Counts.Observed)
	fmt.Fprintf(w, "  Degraded / denied   %d / %d\n", r.EvidenceQuality.Counts.Degraded, r.EvidenceQuality.Counts.Denied)
	fmt.Fprintf(w, "  Unavailable         %d\n", r.EvidenceQuality.Counts.Unavailable)
	fmt.Fprintf(w, "  Unsupported         %d\n", r.EvidenceQuality.Counts.Unsupported)
	fmt.Fprintf(w, "  Not applicable      %d\n", r.EvidenceQuality.Counts.NotApplicable)
	fmt.Fprintf(w, "  Release blockers    %d unique\n", r.EvidenceQuality.LimitationSummary.UniqueReleaseBlockers)
	fmt.Fprintf(w, "  Limitations         %d unique / %d raw\n", r.EvidenceQuality.LimitationSummary.UniqueLimitations, r.EvidenceQuality.LimitationSummary.TotalOccurrences)
	fmt.Fprintf(w, "  Defect UNKNOWN      %d\n", r.EvidenceQuality.UnknownAudit.Summary.ProductDefect)
	if r.EvidenceQuality.LimitationSummary.AffectedRecords > 0 {
		fmt.Fprintf(w, "  Affected records    %d\n", r.EvidenceQuality.LimitationSummary.AffectedRecords)
	}
	if verbose {
		fmt.Fprintf(w, "  Limit classes       deadline=%d defect=%d permission=%d optional=%d expected=%d n/a=%d other=%d\n",
			r.EvidenceQuality.LimitationSummary.DeadlineBudget, r.EvidenceQuality.LimitationSummary.ProductDefect,
			r.EvidenceQuality.LimitationSummary.Permission, r.EvidenceQuality.LimitationSummary.OptionalProvider,
			r.EvidenceQuality.LimitationSummary.ExpectedEnvironment, r.EvidenceQuality.LimitationSummary.NotApplicable,
			r.EvidenceQuality.LimitationSummary.Other)
		if r.EvidenceQuality.LimitationSummary.UniqueReleaseBlockers > 0 {
			fmt.Fprintln(w, "  Release blocker roots")
			for _, limitation := range r.EvidenceQuality.Limitations {
				if !limitation.ReleaseBlocker {
					continue
				}
				fmt.Fprintf(w, "    - %s provider=%s", limitation.RootCauseID, limitation.Provider)
				if limitation.Stage != "" {
					fmt.Fprintf(w, " stage=%s", limitation.Stage)
				}
				if limitation.AffectedRecords > 0 {
					fmt.Fprintf(w, " affected=%d", limitation.AffectedRecords)
				}
				fmt.Fprintln(w)
			}
		}
	}

	if !r.Assessment.Evaluation.Complete {
		fmt.Fprintln(w, "\nASSESSMENT INCOMPLETE")
		fmt.Fprintf(w, "  Findings below represent only %d of %d selected rules evaluated.\n", r.Assessment.Evaluation.EvaluatedRules, r.Assessment.Evaluation.SelectedRules)
	}

	fmt.Fprintln(w, "\nFINDINGS")
	fmt.Fprintf(w, "  Total               %d\n", r.Findings.Summary.Total)
	fmt.Fprintf(w, "  FAIL / WARN         %d / %d\n", r.Findings.Summary.Fail, r.Findings.Summary.Warn)
	fmt.Fprintf(w, "  UNKNOWN / PASS      %d / %d\n", r.Findings.Summary.Unknown, r.Findings.Summary.Pass)
	fmt.Fprintf(w, "  Suppressed          %d\n", r.Findings.Summary.Suppressed)
	fmt.Fprintf(w, "  Priority C/H/M/L    %d / %d / %d / %d\n",
		r.Prioritization.Summary.CriticalFindings, r.Prioritization.Summary.HighFindings,
		r.Prioritization.Summary.MediumFindings, r.Prioritization.Summary.LowFindings)

	if r.EvidenceQuality.UnknownSummary.Total > 0 {
		u := r.EvidenceQuality.UnknownSummary
		fmt.Fprintln(w, "\nUNKNOWN CAUSES")
		fmt.Fprintf(w, "  Total               %d\n", u.Total)
		fmt.Fprintf(w, "  Missing / degraded  %d / %d\n", u.MissingRequiredEvidence, u.DegradedEvidence)
		fmt.Fprintf(w, "  Defect / deadline   %d / %d\n", u.ProductDefect, u.DeadlineBudget)
		fmt.Fprintf(w, "  Permission          %d\n", u.PermissionRestriction)
		fmt.Fprintf(w, "  Expected / optional %d / %d\n", u.ExpectedEnvironment, u.OptionalProvider)
		fmt.Fprintf(w, "  Safe unsupported    %d\n", u.UnsupportedSafe)
		fmt.Fprintf(w, "  N/A / other         %d / %d\n", u.NotApplicable, u.Other)
	}

	if r.EvidenceQuality.UnknownAudit.Summary.Total > 0 {
		u := r.EvidenceQuality.UnknownAudit.Summary
		fmt.Fprintln(w, "\nUNKNOWN AUDIT")
		fmt.Fprintf(w, "  Total               %d\n", u.Total)
		fmt.Fprintf(w, "  Required evidence   %d\n", u.RequiredEvidenceMissing)
		fmt.Fprintf(w, "  Product defect      %d\n", u.ProductDefect)
		fmt.Fprintf(w, "  Permission          %d\n", u.PermissionRestriction)
		fmt.Fprintf(w, "  Optional provider   %d\n", u.OptionalProviderAbsent)
		fmt.Fprintf(w, "  Environmental       %d\n", u.EnvironmentalAbsence)
		fmt.Fprintf(w, "  Safe boundary       %d\n", u.SafeCollectionBoundary)
		fmt.Fprintf(w, "  Unsupported state   %d\n", u.UnsupportedState)
		fmt.Fprintf(w, "  N/A / temporal      %d / %d\n", u.NonApplicable, u.TemporalRace)
		fmt.Fprintf(w, "  Other explained     %d\n", u.OtherExplained)
		if verbose {
			for _, entry := range r.EvidenceQuality.UnknownAudit.Entries {
				fmt.Fprintf(w, "    - %s [%s] family=%s affected=%d root=%s\n", entry.RuleID, entry.Classification, entry.RuleFamily, entry.AffectedCount, entry.RootCauseID)
				fmt.Fprintf(w, "      dependency: %s\n", strings.Join(entry.EvidenceDependencies, ", "))
				fmt.Fprintf(w, "      reason: %s\n", entry.Reason)
			}
		}
	}

	fmt.Fprintln(w, "\nREMEDIATION")
	fmt.Fprintf(w, "  Actions             %d\n", r.Remediation.Summary.Actions)
	fmt.Fprintf(w, "  Critical / High     %d / %d\n", r.Remediation.Summary.CriticalActions, r.Remediation.Summary.HighActions)
	fmt.Fprintf(w, "  Medium / Low        %d / %d\n", r.Remediation.Summary.MediumActions, r.Remediation.Summary.LowActions)
	fmt.Fprintf(w, "  Needs evidence      %d\n", r.Remediation.Summary.NeedsEvidence)
	fmt.Fprintf(w, "  Suppressed          %d\n", r.Remediation.Summary.Suppressed)

	fmt.Fprintln(w, "\nLIMITATIONS")
	if len(r.Limitations) == 0 {
		fmt.Fprintln(w, "  None recorded")
	} else {
		for _, v := range r.Limitations {
			fmt.Fprintf(w, "  - %s\n", v)
		}
	}

	if verbose {
		fmt.Fprintln(w, "\nPRIORITIZED REMEDIATION")
		for _, a := range r.Remediation.Actions {
			fmt.Fprintf(w, "  #%d [%s/%d] %s %s\n", a.PriorityRank, a.PriorityBand, a.PriorityScore, a.FindingID, a.Title)
			fmt.Fprintf(w, "    Object      %s\n", a.AffectedObject)
			fmt.Fprintf(w, "    Guidance    %s\n", a.Guidance)
			fmt.Fprintf(w, "    Verify      %s\n", a.Verification)
		}
	}

	fmt.Fprintln(w, "\nEXPORT")
	fmt.Fprintln(w, "  JSON                chimera export json --output assessment.json")
	fmt.Fprintln(w, "  Structured text     chimera export text --output assessment.txt")
	fmt.Fprintln(w, "  CSV                 chimera export csv --output findings.csv")
	fmt.Fprintln(w, "  SARIF               chimera export sarif --output assessment.sarif")
}

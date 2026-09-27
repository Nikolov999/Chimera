package render

import (
	"fmt"
	"io"

	"github.com/Nikolov999/chimera/internal/remediation"
)

func RemediationHuman(w io.Writer, r remediation.Result, verbose bool) {
	fmt.Fprintln(w, "REMEDIATION")
	fmt.Fprintf(w, "  Engine              %s\n", r.EngineVersion)
	fmt.Fprintf(w, "  Rule evaluation     %d/%d (%.1f%%)\n", r.Evaluation.EvaluatedRules, r.Evaluation.SelectedRules, r.Evaluation.Percent)
	if !r.Evaluation.Complete {
		fmt.Fprintln(w, "  Assessment          INCOMPLETE")
		fmt.Fprintf(w, "  NOT_EVALUATED       %d\n", r.Evaluation.NotEvaluatedRules)
	}
	fmt.Fprintf(w, "  Actionable fixes    %d\n", r.Summary.Actions)
	fmt.Fprintf(w, "  Critical / High     %d / %d\n", r.Summary.CriticalActions, r.Summary.HighActions)
	fmt.Fprintf(w, "  Medium / Low        %d / %d\n", r.Summary.MediumActions, r.Summary.LowActions)
	fmt.Fprintf(w, "  Needs evidence      %d\n", r.Summary.NeedsEvidence)
	fmt.Fprintf(w, "  Suppressed          %d\n", r.Summary.Suppressed)
	fmt.Fprintf(w, "  Categories          %d\n", r.Summary.Categories)
	fmt.Fprintf(w, "  Affected components %d\n", r.Summary.AffectedComponents)
	fmt.Fprintf(w, "  Safety              %s\n", r.Safety)

	if len(r.Groups) == 0 {
		if !r.Evaluation.Complete {
			if r.Evaluation.EvaluatedRules == 0 {
				fmt.Fprintln(w, "\n  Assessment incomplete. No remediation conclusion can be made because none of the selected rules were evaluated.")
			} else {
				fmt.Fprintln(w, "\n  No active FAIL/WARN findings were produced by the evaluated subset; assessment coverage is incomplete.")
			}
		} else {
			fmt.Fprintln(w, "\n  No active FAIL/WARN findings require remediation under the current profile and selection.")
		}
		return
	}

	for _, pg := range r.Groups {
		fmt.Fprintf(w, "\n[%s PRIORITY]\n", pg.Band)
		for _, cg := range pg.Categories {
			fmt.Fprintf(w, "  %s\n", cg.Category)
			for _, og := range cg.Components {
				fmt.Fprintf(w, "    %s\n", og.AffectedObject)
				for _, a := range og.Actions {
					fmt.Fprintf(w, "      #%d score=%d severity=%s %s  %s\n", a.PriorityRank, a.PriorityScore, a.RawSeverity, a.FindingID, a.Title)
					if verbose {
						fmt.Fprintf(w, "        Rule        %s\n", a.RuleID)
						fmt.Fprintf(w, "        Status      %s\n", a.Status)
						fmt.Fprintf(w, "        Confidence  %s\n", a.Confidence)
						if a.Risk != "" {
							fmt.Fprintf(w, "        Risk        %s\n", a.Risk)
						}
					}
					fmt.Fprintf(w, "        Guidance    %s\n", a.Guidance)
					fmt.Fprintf(w, "        Verify      %s\n", a.Verification)
					if verbose && len(a.EvidenceKeys) > 0 {
						fmt.Fprintln(w, "        Evidence")
						for _, key := range a.EvidenceKeys {
							fmt.Fprintf(w, "          - %s\n", key)
						}
					}
				}
			}
		}
	}
}

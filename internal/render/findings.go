package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
)

func FindingsHuman(w io.Writer, findings []assessment.Finding, verbose bool) {
	counts := map[assessment.Status]int{}
	suppressed := 0
	for _, f := range findings {
		counts[f.Status]++
		if f.Suppression == assessment.SuppressionSuppressed {
			suppressed++
		}
	}
	fmt.Fprintln(w, "FINDINGS")
	fmt.Fprintf(w, "  Total    %d\n", len(findings))
	fmt.Fprintf(w, "  FAIL     %d\n", counts[assessment.StatusFail])
	fmt.Fprintf(w, "  WARN     %d\n", counts[assessment.StatusWarn])
	fmt.Fprintf(w, "  UNKNOWN  %d\n", counts[assessment.StatusUnknown])
	fmt.Fprintf(w, "  PASS     %d\n", counts[assessment.StatusPass])
	fmt.Fprintf(w, "  SUPPRESSED %d\n", suppressed)
	for _, f := range findings {
		fmt.Fprintf(w, "\n[%s] %s  %s\n", f.Status, f.ID, f.Title)
		fmt.Fprintf(w, "  Rule              %s\n", f.RuleID)
		fmt.Fprintf(w, "  Severity          %s\n", f.Severity)
		fmt.Fprintf(w, "  Confidence        %s\n", f.Confidence)
		fmt.Fprintf(w, "  Category          %s\n", f.Category)
		fmt.Fprintf(w, "  Affected object   %s\n", f.AffectedObject)
		fmt.Fprintf(w, "  Observed          %s\n", f.ObservedState)
		fmt.Fprintf(w, "  Expected          %s\n", f.ExpectedState)
		fmt.Fprintf(w, "  Applicability     %s\n", f.Applicability)
		fmt.Fprintf(w, "  Suppression       %s\n", f.Suppression)
		if f.Suppression == assessment.SuppressionSuppressed {
			for _, sr := range f.Suppressions {
				fmt.Fprintf(w, "    - %s owner=%s expires=%s reason=%s\n", sr.ID, sr.Owner, sr.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"), sr.Reason)
			}
		}
		if f.Status != assessment.StatusPass || verbose {
			fmt.Fprintf(w, "  Risk              %s\n", f.Risk)
			fmt.Fprintf(w, "  Remediation       %s\n", f.Remediation)
		}
		if verbose && len(f.Evidence) > 0 {
			fmt.Fprintln(w, "  Evidence")
			for _, e := range f.Evidence {
				line := fmt.Sprintf("    - %s [%s] source=%s", e.Key, e.State, e.Source)
				if strings.TrimSpace(e.Reason) != "" {
					line += " reason=" + e.Reason
				}
				fmt.Fprintln(w, line)
			}
		}
	}
}

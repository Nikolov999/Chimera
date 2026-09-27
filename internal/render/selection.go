package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/selection"
)

func SelectionHuman(w io.Writer, report selection.Report, verbose bool) {
	fmt.Fprintln(w, "RULE SELECTION")
	fmt.Fprintf(w, "  Severity threshold %s\n", report.Request.Severity)
	fmt.Fprintf(w, "  Category           %s\n", displaySelectionValue(report.Request.Category))
	fmt.Fprintf(w, "  Include            %s\n", displaySelectionList(report.Request.Include))
	fmt.Fprintf(w, "  Exclude            %s\n", displaySelectionList(report.Request.Exclude))
	fmt.Fprintf(w, "  Rules              %d selected / %d skipped / %d suppressed / %d total\n",
		report.Summary.Selected, report.Summary.Skipped, report.Summary.Suppressed, report.Summary.Total)
	if verbose {
		fmt.Fprintln(w, "  Decisions")
		for _, d := range report.Decisions {
			fmt.Fprintf(w, "    %-14s %-11s %-12s %s\n", d.RuleID, d.Outcome, d.Severity, d.Reason)
		}
	}
}

func SelectionDecisionHuman(w io.Writer, report selection.Report, decision selection.Decision) {
	fmt.Fprintln(w, "RULE SELECTION")
	fmt.Fprintf(w, "  Severity threshold %s\n", report.Request.Severity)
	fmt.Fprintf(w, "  Rule               %s\n", decision.RuleID)
	fmt.Fprintf(w, "  Category           %s\n", decision.Category)
	fmt.Fprintf(w, "  Effective severity %s\n", decision.Severity)
	fmt.Fprintf(w, "  Outcome            %s\n", decision.Outcome)
	fmt.Fprintf(w, "  Reason             %s\n", decision.Reason)
}

func displaySelectionValue(v string) string {
	if strings.TrimSpace(v) == "" {
		return "none"
	}
	return v
}

func displaySelectionList(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ", ")
}

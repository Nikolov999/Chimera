package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/baseline"
)

func BaselineHuman(w io.Writer, b baseline.Result, verbose bool) {
	fmt.Fprintln(w, "BASELINE")
	fmt.Fprintf(w, "  State              %s\n", b.State)
	fmt.Fprintf(w, "  Profile            %s\n", b.Profile.Name)
	fmt.Fprintf(w, "  Coverage           %s (%d/%d selected)\n", b.Coverage.State, b.Coverage.Selected, b.Coverage.Total)
	fmt.Fprintf(w, "  Rule evaluation    %d/%d (%.1f%%)\n", b.Coverage.Evaluated, b.Coverage.Selected, b.Coverage.EvaluationPercent)
	if b.Coverage.NotEvaluated > 0 {
		fmt.Fprintln(w, "  Assessment         INCOMPLETE")
	}
	fmt.Fprintf(w, "  Scan state         %s\n", b.ScanState)
	fmt.Fprintf(w, "  Assessment ID      %s\n", displayBaseline(b.AssessmentID))
	fmt.Fprintf(w, "  Rule set           %s\n", b.RuleSetVersion)
	fmt.Fprintf(w, "  Engine             %s\n", b.EngineVersion)
	fmt.Fprintf(w, "  Assessed at        %s\n", b.AssessedAt.Format("2006-01-02T15:04:05Z07:00"))

	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Rules              %d\n", b.Summary.Total)
	fmt.Fprintf(w, "  Applicable         %d\n", b.Summary.Applicable)
	fmt.Fprintf(w, "  FAIL               %d\n", b.Summary.Fail)
	fmt.Fprintf(w, "  WARN               %d\n", b.Summary.Warn)
	fmt.Fprintf(w, "  UNKNOWN            %d\n", b.Summary.Unknown)
	fmt.Fprintf(w, "  PASS               %d\n", b.Summary.Pass)
	fmt.Fprintf(w, "  Not applicable     %d\n", b.Summary.NotApplicable)
	fmt.Fprintf(w, "  NOT_EVALUATED      %d\n", b.Summary.NotEvaluated)
	fmt.Fprintf(w, "  Suppressed         %d\n", b.Summary.Suppressed)
	SuppressionsHuman(w, b.Suppressions, verbose)

	fmt.Fprintln(w, "\nCIS-INSPIRED ALIGNMENT")
	fmt.Fprintf(w, "  Catalog            %s\n", b.CISInspired.CatalogVersion)
	fmt.Fprintf(w, "  Scope              %s\n", b.CISInspired.Framework.Kind)
	fmt.Fprintf(w, "  Mapped rules       %d/%d (core observability rules intentionally unmapped=%d)\n", b.CISInspired.Summary.MappedRules, b.CISInspired.Summary.ImplementedRules, b.CISInspired.Summary.UnmappedRules)
	fmt.Fprintf(w, "  Concepts           %d full=%d partial=%d none=%d\n", b.CISInspired.Summary.Concepts, b.CISInspired.Summary.FullConcepts, b.CISInspired.Summary.PartialConcepts, b.CISInspired.Summary.Unevaluated)
	fmt.Fprintln(w, "  Certification      none; benchmark-neutral concept alignment only")
	if verbose {
		for _, c := range b.CISInspired.Concepts {
			fmt.Fprintf(w, "    %-19s %-14s coverage=%-7s evaluated=%d/%d %s\n", c.Concept.ID, c.State, c.Coverage, c.Counts.Evaluated, c.Counts.Mapped, c.Concept.Title)
		}
	}

	fmt.Fprintln(w, "\nCATEGORIES")
	for _, c := range b.Categories {
		fmt.Fprintf(w, "  %-18s %-14s rules=%d fail=%d warn=%d unknown=%d pass=%d n/a=%d not-evaluated=%d suppressed=%d\n",
			c.Name, c.State, c.Counts.Total, c.Counts.Fail, c.Counts.Warn, c.Counts.Unknown, c.Counts.Pass, c.Counts.NotApplicable, c.Counts.NotEvaluated, c.Counts.Suppressed)
		if verbose {
			for _, r := range c.Rules {
				fmt.Fprintf(w, "    %-16s %-14s %-8s suppression=%s %s\n", r.RuleID, r.State, r.Severity, r.Suppression, r.Title)
				fmt.Fprintf(w, "      observed: %s\n", r.ObservedState)
				fmt.Fprintf(w, "      expected: %s\n", r.ExpectedState)
				if r.Reason != "" {
					fmt.Fprintf(w, "      reason:   %s\n", r.Reason)
				}
			}
		}
	}

	if b.Coverage.State != "FULL" {
		fmt.Fprintln(w, "\nCOVERAGE NOTE")
		fmt.Fprintf(w, "  %s; skipped=%d suppressed=%d not-evaluated=%d\n", b.Coverage.Reason, b.Coverage.Skipped, b.Coverage.Suppressed, b.Coverage.NotEvaluated)
	}
}

func displayBaseline(v string) string {
	if strings.TrimSpace(v) == "" {
		return "UNAVAILABLE"
	}
	return v
}

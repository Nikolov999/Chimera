package render

import (
	"fmt"
	"io"

	"github.com/Nikolov999/chimera/internal/prioritization"
)

func PrioritizationHuman(w io.Writer, r prioritization.Result, verbose bool) {
	fmt.Fprintln(w, "\nRISK PRIORITIZATION")
	fmt.Fprintf(w, "  Engine              %s\n", r.EngineVersion)
	fmt.Fprintf(w, "  Actionable findings %d / %d\n", r.Summary.ActionableFindings, r.Summary.Findings)
	fmt.Fprintf(w, "  Critical / High     %d / %d\n", r.Summary.CriticalFindings, r.Summary.HighFindings)
	if r.Summary.Vulnerabilities > 0 {
		fmt.Fprintf(w, "  Vulnerabilities     %d (%d critical / %d high)\n", r.Summary.Vulnerabilities, r.Summary.CriticalVulnerabilities, r.Summary.HighVulnerabilities)
	}
	limit := len(r.Findings)
	if !verbose && limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		p := r.Findings[i]
		if p.Score == 0 {
			continue
		}
		rank := "-"
		if p.Rank > 0 {
			rank = fmt.Sprintf("%d", p.Rank)
		}
		fmt.Fprintf(w, "  #%s %-12s score=%3d band=%-8s severity=%-8s rule=%s\n", rank, p.FindingID, p.Score, p.Band, p.Severity, p.RuleID)
		if verbose {
			for _, f := range p.Factors {
				fmt.Fprintf(w, "      +%-2d %-22s %s\n", f.Points, f.Name, f.Reason)
			}
		}
	}
	if !verbose && len(r.Findings) > limit {
		fmt.Fprintf(w, "  ... %d additional finding priorities available in JSON or verbose output\n", len(r.Findings)-limit)
	}
}

func FindingPriorityHuman(w io.Writer, p prioritization.FindingPriority, verbose bool) {
	fmt.Fprintln(w, "\nPRIORITY")
	fmt.Fprintf(w, "  Score              %d\n", p.Score)
	fmt.Fprintf(w, "  Band               %s\n", p.Band)
	fmt.Fprintf(w, "  Rank               %d\n", p.Rank)
	fmt.Fprintf(w, "  Raw severity       %s\n", p.Severity)
	fmt.Fprintf(w, "  Actionable         %t\n", p.Actionable)
	fmt.Fprintf(w, "  Reason             %s\n", p.PriorityReason)
	if verbose {
		for _, f := range p.Factors {
			fmt.Fprintf(w, "    +%-2d %-22s %s\n", f.Points, f.Name, f.Reason)
		}
	}
}

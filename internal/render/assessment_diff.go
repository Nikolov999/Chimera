package render

import (
	"fmt"
	"io"

	"github.com/Nikolov999/chimera/internal/assessmentdiff"
)

func AssessmentDiffHuman(w io.Writer, d assessmentdiff.Result, verbose bool) {
	fmt.Fprintln(w, "ASSESSMENT DIFF")
	fmt.Fprintf(w, "  Before assessment  %s\n", d.Before.AssessmentID)
	fmt.Fprintf(w, "  After assessment   %s\n", d.After.AssessmentID)
	fmt.Fprintf(w, "  Host fingerprint   %s\n", shortDiffDigest(d.Before.HostFingerprint))
	fmt.Fprintf(w, "  Comparable scope   %t\n", d.ComparableScope)
	fmt.Fprintf(w, "  Before profile     %s\n", d.Before.Profile)
	fmt.Fprintf(w, "  After profile      %s\n", d.After.Profile)

	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Findings           %d -> %d\n", d.Summary.BeforeFindings, d.Summary.AfterFindings)
	fmt.Fprintf(w, "  New                %d\n", d.Summary.New)
	fmt.Fprintf(w, "  Regressed          %d\n", d.Summary.Regressed)
	fmt.Fprintf(w, "  Resolved           %d\n", d.Summary.Resolved)
	fmt.Fprintf(w, "  Improved           %d\n", d.Summary.Improved)
	fmt.Fprintf(w, "  Unchanged          %d\n", d.Summary.Unchanged)
	fmt.Fprintf(w, "  Added to scope     %d\n", d.Summary.AddedToScope)
	fmt.Fprintf(w, "  Removed from scope %d\n", d.Summary.RemovedFromScope)
	fmt.Fprintf(w, "  Removed            %d\n", d.Summary.Removed)
	fmt.Fprintf(w, "  Suppressed after   %d\n", d.Summary.Suppressed)
	fmt.Fprintf(w, "  Newly suppressed   %d\n", d.Summary.NewlySuppressed)
	fmt.Fprintf(w, "  Unsuppressed       %d\n", d.Summary.Unsuppressed)
	fmt.Fprintf(w, "  Evidence changed   %d\n", d.Summary.EvidenceChanged)

	fmt.Fprintln(w, "\nPROVENANCE CHANGES")
	fmt.Fprintf(w, "  Config policy      %t\n", d.ProvenanceChanges.ConfigPolicy)
	fmt.Fprintf(w, "  Profile            %t\n", d.ProvenanceChanges.Profile)
	fmt.Fprintf(w, "  Rule set           %t\n", d.ProvenanceChanges.RuleSet)
	fmt.Fprintf(w, "  Selection          %t\n", d.ProvenanceChanges.Selection)
	fmt.Fprintf(w, "  Intelligence       %t\n", d.ProvenanceChanges.Intelligence)
	fmt.Fprintf(w, "  Suppression policy %t\n", d.ProvenanceChanges.SuppressionPolicy)

	fmt.Fprintln(w, "\nCHANGES")
	for _, c := range d.Changes {
		if !verbose && c.Classification == assessmentdiff.ClassUnchanged && !c.EvidenceChanged && !c.SuppressionChanged {
			continue
		}
		before, after := "-", "-"
		if c.Before != nil {
			before = string(c.Before.Status)
		}
		if c.After != nil {
			after = string(c.After.Status)
		}
		fmt.Fprintf(w, "  %-18s %-16s %s -> %s  %s  %s\n", c.Classification, c.RuleID, before, after, c.AffectedObject, c.FindingID)
		if c.EvidenceChanged {
			fmt.Fprintln(w, "    evidence changed")
		}
		if c.SuppressionChanged {
			fmt.Fprintln(w, "    suppression changed")
		}
		if verbose {
			for _, reason := range c.Reasons {
				fmt.Fprintf(w, "    %s\n", reason)
			}
		}
	}
}

func shortDiffDigest(v string) string {
	if len(v) <= 16 {
		return v
	}
	return v[:16]
}

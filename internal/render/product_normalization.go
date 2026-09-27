package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/productnorm"
)

func ProductNormalizationHuman(w io.Writer, r productnorm.Result, verbose bool) {
	fmt.Fprintln(w, "\nPRODUCT NORMALIZATION")
	fmt.Fprintf(w, "  State          %s\n", r.State)
	fmt.Fprintf(w, "  Engine         %s\n", r.EngineVersion)
	fmt.Fprintf(w, "  Intelligence   %s\n", r.IntelligenceVersion)
	if r.State != "COMPLETE" {
		fmt.Fprintf(w, "  Reason         %s\n", value(r.Reason))
		return
	}
	fmt.Fprintf(w, "  Candidates     %d\n", r.Summary.Candidates)
	fmt.Fprintf(w, "  Matched        %d\n", r.Summary.Matched)
	fmt.Fprintf(w, "  Unmatched      %d\n", r.Summary.Unmatched)
	fmt.Fprintf(w, "  Ambiguous      %d\n", r.Summary.Ambiguous)
	fmt.Fprintf(w, "  Comparable     %d\n", r.Summary.Comparable)

	if !verbose {
		return
	}
	fmt.Fprintln(w, "\nNORMALIZED PRODUCT IDENTITIES")
	for _, m := range r.Matches {
		selected := "-"
		if m.ProductID != "" {
			selected = m.ProductID
		} else if len(m.Alternatives) > 0 {
			selected = strings.Join(m.Alternatives, ",")
		}
		fmt.Fprintf(w, "  %-10s %-34s -> %s\n", m.State, truncate(m.CandidateRef, 34), selected)
		fmt.Fprintf(w, "    ecosystem: %s -> %s\n", m.CandidateEcosystem, value(m.MappingEcosystem))
		fmt.Fprintf(w, "    version:   %s [%s comparable=%t]\n", m.Version, m.VersionScheme, m.VersionComparable)
		if m.MatchMethod != "" {
			fmt.Fprintf(w, "    method:    %s\n", m.MatchMethod)
		}
		if len(m.MatchSignals) > 0 {
			fmt.Fprintf(w, "    signals:   %s\n", strings.Join(m.MatchSignals, ", "))
		}
		fmt.Fprintf(w, "    reason:    %s\n", m.Reason)
	}
}

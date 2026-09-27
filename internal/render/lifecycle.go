package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/lifecycle"
)

func LifecycleHuman(w io.Writer, r lifecycle.Result, verbose bool) {
	fmt.Fprintln(w, "\nSOFTWARE LIFECYCLE / SUPPORT")
	fmt.Fprintf(w, "  State              %s\n", r.State)
	fmt.Fprintf(w, "  Engine             %s\n", r.EngineVersion)
	fmt.Fprintf(w, "  Intelligence       %s\n", r.IntelligenceVersion)
	if r.Reason != "" {
		fmt.Fprintf(w, "  Reason             %s\n", r.Reason)
	}
	fmt.Fprintf(w, "  Candidates         %d\n", r.Summary.Candidates)
	fmt.Fprintf(w, "  With intelligence  %d\n", r.Summary.WithIntelligence)
	fmt.Fprintf(w, "  Supported          %d\n", r.Summary.Supported)
	fmt.Fprintf(w, "  End-of-life        %d\n", r.Summary.EndOfLife)
	fmt.Fprintf(w, "  Unsupported        %d\n", r.Summary.Unsupported)
	fmt.Fprintf(w, "  Unknown            %d\n", r.Summary.Unknown)
	fmt.Fprintf(w, "  No intelligence    %d\n", r.Summary.NoIntelligence)

	if len(r.Evaluations) == 0 {
		return
	}
	fmt.Fprintln(w, "\nLIFECYCLE EVALUATIONS")
	for _, ev := range r.Evaluations {
		fmt.Fprintf(w, "  %-12s %-26s %-16s end=%s\n", ev.Status, truncate(ev.Product, 26), truncate(ev.Version, 16), ev.EndOfSupport.Format("2006-01-02"))
		fmt.Fprintf(w, "    target:     %s\n", ev.CandidateRef)
		fmt.Fprintf(w, "    reason:     %s\n", ev.Reason)
		if !verbose {
			continue
		}
		fmt.Fprintf(w, "    record:     %s\n", ev.RecordID)
		fmt.Fprintf(w, "    source:     %s\n", ev.SourceID)
		fmt.Fprintf(w, "    confidence: %s\n", ev.Confidence)
		if len(ev.MatchEvidence) > 0 {
			fmt.Fprintf(w, "    match:      %s\n", strings.Join(ev.MatchEvidence, ", "))
		}
		fmt.Fprintf(w, "    reference:  %s\n", ev.Reference)
	}
}

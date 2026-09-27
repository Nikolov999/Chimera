package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/suppression"
)

func SuppressionsHuman(w io.Writer, report suppression.Report, verbose bool) {
	if report.Schema == "" {
		return
	}
	fmt.Fprintln(w, "\nSUPPRESSIONS")
	fmt.Fprintf(w, "  Configured          %d\n", report.Summary.Total)
	fmt.Fprintf(w, "  Applied             %d\n", report.Summary.Applied)
	fmt.Fprintf(w, "  Expired             %d\n", report.Summary.Expired)
	fmt.Fprintf(w, "  Unmatched           %d\n", report.Summary.Unmatched)
	fmt.Fprintf(w, "  Findings suppressed %d\n", report.Summary.FindingsSuppressed)
	if !verbose || len(report.Entries) == 0 {
		return
	}
	entries := append([]suppression.Entry(nil), report.Entries...)
	sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].ID) < strings.ToLower(entries[j].ID) })
	for _, e := range entries {
		fmt.Fprintf(w, "  - %s [%s] scope=%s owner=%s expires=%s\n", e.ID, e.State, e.MatchScope, e.Owner, e.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"))
		if e.RuleID != "" {
			fmt.Fprintf(w, "    rule             %s\n", e.RuleID)
		}
		if e.AffectedObject != "" {
			fmt.Fprintf(w, "    affected object  %s\n", e.AffectedObject)
		}
		fmt.Fprintf(w, "    reason           %s\n", e.Reason)
		if e.Source != "" {
			fmt.Fprintf(w, "    source           %s\n", e.Source)
		}
		if len(e.MatchedFindingIDs) > 0 {
			fmt.Fprintf(w, "    findings         %s\n", strings.Join(e.MatchedFindingIDs, ", "))
		}
	}
}

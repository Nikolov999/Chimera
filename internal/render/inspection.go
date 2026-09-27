package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
)

func FindingInspectionHuman(w io.Writer, in assessment.FindingInspection, verbose bool) {
	f := in.Finding
	fmt.Fprintln(w, "FINDING")
	fmt.Fprintf(w, "  ID                %s\n", f.ID)
	fmt.Fprintf(w, "  Rule              %s\n", f.RuleID)
	fmt.Fprintf(w, "  Status            %s\n", f.Status)
	fmt.Fprintf(w, "  Severity          %s\n", f.Severity)
	fmt.Fprintf(w, "  Confidence        %s\n", f.Confidence)
	fmt.Fprintf(w, "  Category          %s\n", f.Category)
	fmt.Fprintf(w, "  Platform          %s\n", f.Platform)
	fmt.Fprintf(w, "  Affected object   %s\n", f.AffectedObject)
	fmt.Fprintf(w, "  Title             %s\n", f.Title)
	fmt.Fprintf(w, "  Observed          %s\n", f.ObservedState)
	fmt.Fprintf(w, "  Expected          %s\n", f.ExpectedState)
	fmt.Fprintf(w, "  Applicability     %s\n", f.Applicability)
	fmt.Fprintf(w, "  Suppression       %s\n", f.Suppression)
	for _, sr := range f.Suppressions {
		fmt.Fprintf(w, "    - %s owner=%s expires=%s reason=%s\n", sr.ID, sr.Owner, sr.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"), sr.Reason)
	}
	fmt.Fprintf(w, "  Risk              %s\n", f.Risk)
	fmt.Fprintf(w, "  Remediation       %s\n", f.Remediation)
	fmt.Fprintf(w, "  Suppression       %s\n", f.Suppression)
	fmt.Fprintf(w, "  First observed    %s\n", f.FirstObserved.UTC().Format("2006-01-02T15:04:05.000000000Z"))
	fmt.Fprintf(w, "  Assessed          %s\n", f.AssessmentTimestamp.UTC().Format("2006-01-02T15:04:05.000000000Z"))

	fmt.Fprintln(w, "\nRULE")
	fmt.Fprintf(w, "  ID                %s\n", in.Rule.ID)
	fmt.Fprintf(w, "  Expected          %s\n", in.Rule.ExpectedState)
	fmt.Fprintf(w, "  Affected object   %s\n", in.Rule.AffectedObject)

	printProvenance(w, in, verbose)
	printReproducibility(w, in)
}

func FindingExplanationHuman(w io.Writer, in assessment.FindingInspection, verbose bool) {
	f := in.Finding
	fmt.Fprintln(w, "EXPLANATION")
	fmt.Fprintf(w, "  Finding           %s\n", f.ID)
	fmt.Fprintf(w, "  Rule              %s — %s\n", f.RuleID, f.Title)
	fmt.Fprintf(w, "  Decision          %s\n", f.Status)
	fmt.Fprintf(w, "  Why               observed=%s; expected=%s; applicability=%s; confidence=%s\n", f.ObservedState, f.ExpectedState, f.Applicability, f.Confidence)
	fmt.Fprintf(w, "  Risk              %s\n", f.Risk)
	fmt.Fprintf(w, "  Remediation       %s\n", f.Remediation)
	fmt.Fprintf(w, "  Collection source %s\n", f.CollectionSource)
	printProvenance(w, in, verbose)
	printReproducibility(w, in)
}

func FindingEvidenceHuman(w io.Writer, in assessment.FindingInspection, verbose bool) {
	fmt.Fprintln(w, "EVIDENCE PROVENANCE")
	fmt.Fprintf(w, "  Finding           %s\n", in.Finding.ID)
	fmt.Fprintf(w, "  Rule              %s\n", in.Finding.RuleID)
	fmt.Fprintf(w, "  Evidence schema   %s\n", in.EvidenceSchema)
	printProvenanceRecords(w, in.Provenance, verbose)
	printReproducibility(w, in)
}

func printProvenance(w io.Writer, in assessment.FindingInspection, verbose bool) {
	fmt.Fprintln(w, "\nEVIDENCE PROVENANCE")
	printProvenanceRecords(w, in.Provenance, verbose)
}

func printProvenanceRecords(w io.Writer, refs []assessment.EvidenceRef, verbose bool) {
	if len(refs) == 0 {
		fmt.Fprintln(w, "  none — rule evaluated without a present evidence record")
		return
	}
	for _, e := range refs {
		fmt.Fprintf(w, "  %s\n", e.Key)
		fmt.Fprintf(w, "    state           %s\n", e.State)
		fmt.Fprintf(w, "    source          %s\n", e.Source)
		fmt.Fprintf(w, "    confidence      %s\n", e.Confidence)
		fmt.Fprintf(w, "    collected       %s\n", e.CollectedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))
		if strings.TrimSpace(e.Reason) != "" {
			fmt.Fprintf(w, "    reason          %s\n", e.Reason)
		}
		if verbose && e.Value != nil {
			fmt.Fprintf(w, "    value           %s\n", compactValue(e.Value))
		}
	}
}

func printReproducibility(w io.Writer, in assessment.FindingInspection) {
	r := in.Reproducible
	fmt.Fprintln(w, "\nREPRODUCIBILITY")
	fmt.Fprintf(w, "  Derived ID        %s\n", r.DerivedID)
	fmt.Fprintf(w, "  ID match          %t\n", r.MatchesID)
	fmt.Fprintf(w, "  Evidence digest   %s\n", r.EvidenceDigest)
	fmt.Fprintf(w, "  Evidence keys     %s\n", strings.Join(r.EvidenceKeys, ", "))
	fmt.Fprintf(w, "  Algorithm         %s\n", r.Algorithm)
}

func compactValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

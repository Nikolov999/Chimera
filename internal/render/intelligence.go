package render

import (
	"fmt"
	"io"

	"github.com/Nikolov999/chimera/internal/intelligence"
)

func IntelligenceHuman(w io.Writer, loaded intelligence.Loaded, verbose bool) {
	m := loaded.Metadata
	fmt.Fprintln(w, "VULNERABILITY INTELLIGENCE")
	fmt.Fprintf(w, "  State             %s\n", m.State)
	fmt.Fprintf(w, "  Schema            %s\n", m.Schema)
	fmt.Fprintf(w, "  Version           %s\n", m.Version)
	fmt.Fprintf(w, "  Retrieved         %s\n", m.RetrievedAt.Local().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(w, "  Digest            %s:%s\n", m.DigestAlgorithm, m.Digest)
	fmt.Fprintf(w, "  Records           %d sources / %d products / %d vulnerabilities / %d lifecycle records\n", m.SourceCount, m.ProductCount, m.VulnerabilityCount, m.LifecycleCount)
	fmt.Fprintf(w, "  Store             %s\n", m.Source)

	fmt.Fprintln(w, "\nPRODUCT MAPPINGS")
	for _, p := range loaded.Store.Products {
		fmt.Fprintf(w, "  %-24s %-16s %s\n", p.ID, p.Ecosystem, p.Product)
		if verbose {
			if p.Vendor != "" {
				fmt.Fprintf(w, "    vendor: %s\n", p.Vendor)
			}
			if len(p.Aliases) > 0 {
				fmt.Fprintf(w, "    aliases: %v\n", p.Aliases)
			}
			if len(p.CPEs) > 0 {
				fmt.Fprintf(w, "    cpe: %v\n", p.CPEs)
			}
			if len(p.PURLs) > 0 {
				fmt.Fprintf(w, "    purl: %v\n", p.PURLs)
			}
		}
	}

	fmt.Fprintln(w, "\nLIFECYCLE RECORDS")
	for _, r := range loaded.Store.Lifecycles {
		fmt.Fprintf(w, "  %-24s %-18s %-12s end=%s\n", r.ID, r.Product, r.VersionSeries, r.EndOfSupport.Format("2006-01-02"))
		if verbose {
			fmt.Fprintf(w, "    kinds: %v  source=%s  after=%s\n", r.TargetKinds, r.SourceID, r.StatusAfterEnd)
			fmt.Fprintf(w, "    reference: %s\n", r.Reference)
		}
	}

	fmt.Fprintln(w, "\nVULNERABILITY RECORDS")
	for _, v := range loaded.Store.Vulnerabilities {
		fmt.Fprintf(w, "  %-18s source=%s affected_products=%d\n", v.ID, v.SourceID, len(v.Affected))
		if verbose {
			fmt.Fprintf(w, "    summary: %s\n", v.Summary)
			for _, a := range v.Affected {
				fmt.Fprintf(w, "    product: %s\n", a.ProductID)
				for _, r := range a.Ranges {
					fmt.Fprintf(w, "      range: kind=%s introduced=%s last_affected=%s fixed=%s exact=%v constraint=%s\n", r.Kind, r.Introduced, r.LastAffected, r.Fixed, r.Exact, r.Constraint)
				}
				if len(a.FixedVersions) > 0 {
					fmt.Fprintf(w, "      fixed versions: %v\n", a.FixedVersions)
				}
			}
		}
	}
}

func IntelligenceRefreshHuman(w io.Writer, result intelligence.RefreshResult) {
	fmt.Fprintln(w, "INTELLIGENCE REFRESH")
	fmt.Fprintf(w, "  State             %s\n", result.State)
	fmt.Fprintf(w, "  Source            %s\n", result.SourceURL)
	fmt.Fprintf(w, "  Directory         %s\n", result.Directory)
	fmt.Fprintf(w, "  Trusted key       %s\n", result.KeyID)
	fmt.Fprintf(w, "  Signature         %s\n", result.SignatureAlgorithm)
	fmt.Fprintf(w, "  Verified          %s\n", result.VerifiedAt.Local().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(w, "  Atomic activation %t\n", result.AtomicActivation)
	fmt.Fprintf(w, "  Previous snapshot %t\n", result.PreviousAvailable)
	fmt.Fprintf(w, "  Active version    %s\n", result.Current.Version)
	fmt.Fprintf(w, "  Active digest     %s:%s\n\n", result.Current.DigestAlgorithm, result.Current.Digest)
}

func IntelligenceRollbackHuman(w io.Writer, result intelligence.RollbackResult) {
	fmt.Fprintln(w, "INTELLIGENCE ROLLBACK")
	fmt.Fprintf(w, "  State             %s\n", result.State)
	fmt.Fprintf(w, "  Directory         %s\n", result.Directory)
	fmt.Fprintf(w, "  Rolled back       %s\n", result.RolledBackAt.Local().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(w, "  Network access    %t\n", result.NetworkAccess)
	fmt.Fprintf(w, "  Atomic activation %t\n", result.AtomicActivation)
	fmt.Fprintf(w, "  From              %s (%s)\n", result.From.Version, result.From.Digest)
	fmt.Fprintf(w, "  To                %s (%s)\n", result.To.Version, result.To.Digest)
}

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/doctor"
)

func DoctorHuman(w io.Writer, r doctor.Result, verbose bool) {
	fmt.Fprintln(w, "CHIMERA DOCTOR")
	fmt.Fprintf(w, "  Overall state      %s\n", r.State)
	fmt.Fprintf(w, "  Platform           %s/%s\n", r.Platform, r.Architecture)
	fmt.Fprintf(w, "  Platform support   %s\n", yesNo(r.Supported))
	fmt.Fprintf(w, "  Collection tier    %s\n", value(r.Privilege.CollectionTier))
	fmt.Fprintf(w, "  Checks             %d total / %d pass / %d warn / %d fail / %d n/a\n", r.Summary.Total, r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.NotApplicable)

	printDoctorChecks(w, "PLATFORM", r.PlatformChecks, verbose)
	printDoctorChecks(w, "COLLECTORS", r.Collectors, verbose)
	printDoctorDependencies(w, r.Dependencies, verbose)
	printDoctorChecks(w, "RULE PACKS", r.RulePacks, verbose)
	printDoctorChecks(w, "PERMISSIONS", r.Permissions, verbose)

	fmt.Fprintln(w, "\nCONFIGURATION")
	fmt.Fprintf(w, "  %-18s %s\n", r.Config.State, r.Config.Detail)
	if verbose {
		for _, source := range r.Config.Sources {
			fmt.Fprintf(w, "    source: %s\n", source)
		}
	}

	fmt.Fprintln(w, "\nINTELLIGENCE")
	fmt.Fprintf(w, "  %-18s %s\n", r.Intelligence.State, r.Intelligence.Detail)
	if verbose {
		fmt.Fprintf(w, "    mode: %s\n", r.Intelligence.Mode)
		fmt.Fprintf(w, "    freshness: %s\n", r.Intelligence.Freshness)
		if r.Intelligence.Version != "" {
			fmt.Fprintf(w, "    version: %s\n", r.Intelligence.Version)
			fmt.Fprintf(w, "    schema: %s\n", r.Intelligence.Schema)
			fmt.Fprintf(w, "    digest: %s\n", r.Intelligence.Digest)
			fmt.Fprintf(w, "    records: %d sources / %d products / %d vulnerabilities / %d lifecycle\n", r.Intelligence.SourceCount, r.Intelligence.ProductCount, r.Intelligence.VulnerabilityCount, r.Intelligence.LifecycleCount)
		}
		if r.Intelligence.Path != "" {
			fmt.Fprintf(w, "    path: %s\n", r.Intelligence.Path)
		}
		if r.Intelligence.RetrievedAt != nil {
			fmt.Fprintf(w, "    retrieved: %s\n", r.Intelligence.RetrievedAt.Local().Format("2006-01-02T15:04:05Z07:00"))
			fmt.Fprintf(w, "    age: %s\n", r.Intelligence.Age)
		}
	}
}

func printDoctorChecks(w io.Writer, title string, checks []doctor.Check, verbose bool) {
	fmt.Fprintln(w, "\n"+title)
	if len(checks) == 0 {
		fmt.Fprintln(w, "  NOT_APPLICABLE     no checks registered")
		return
	}
	for _, c := range checks {
		req := "optional"
		if c.Required {
			req = "required"
		}
		fmt.Fprintf(w, "  %-18s %-31s %s\n", c.State, c.Title, c.Detail)
		if verbose {
			fmt.Fprintf(w, "    id: %s / %s\n", c.ID, req)
			if strings.TrimSpace(c.Source) != "" {
				fmt.Fprintf(w, "    source: %s\n", c.Source)
			}
			if strings.TrimSpace(c.Remedy) != "" {
				fmt.Fprintf(w, "    remedy: %s\n", c.Remedy)
			}
		}
	}
}

func printDoctorDependencies(w io.Writer, checks []doctor.DependencyCheck, verbose bool) {
	fmt.Fprintln(w, "\nDEPENDENCIES")
	if len(checks) == 0 {
		fmt.Fprintln(w, "  NOT_APPLICABLE     no external dependency groups registered for this platform")
		return
	}
	for _, c := range checks {
		fmt.Fprintf(w, "  %-18s %-31s %s\n", c.State, c.Purpose, c.Detail)
		if verbose {
			fmt.Fprintf(w, "    id: %s / %s\n", c.ID, c.Requirement)
			for _, provider := range c.Providers {
				state := "missing"
				if provider.Available {
					state = "available"
				}
				if provider.Path != "" {
					fmt.Fprintf(w, "    - %s: %s (%s)\n", provider.Name, state, provider.Path)
				} else {
					fmt.Fprintf(w, "    - %s: %s\n", provider.Name, state)
				}
			}
		}
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

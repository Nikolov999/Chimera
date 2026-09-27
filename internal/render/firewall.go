package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/firewall"
)

func FirewallHuman(w io.Writer, inv firewall.Inventory, verbose bool) {
	fmt.Fprintln(w, "FIREWALL POSTURE")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Providers          %d\n", inv.Summary.Providers)
	fmt.Fprintf(w, "  Observed           %d\n", inv.Summary.ObservedProviders)
	fmt.Fprintf(w, "  Enabled            %d\n", inv.Summary.EnabledProviders)
	fmt.Fprintf(w, "  Disabled           %d\n", inv.Summary.DisabledProviders)
	fmt.Fprintf(w, "  Mixed              %d\n", inv.Summary.MixedProviders)
	fmt.Fprintf(w, "  Denied             %d\n", inv.Summary.DeniedProviders)
	fmt.Fprintf(w, "  Unavailable        %d\n", inv.Summary.UnavailableProviders)
	fmt.Fprintf(w, "  Not applicable     %d\n", inv.Summary.NotApplicableProviders)
	fmt.Fprintf(w, "  Policies/scopes    %d\n", inv.Summary.Policies)
	fmt.Fprintf(w, "  Known rule count   %d\n", inv.Summary.KnownRules)
	fmt.Fprintf(w, "  Parsed restrictions %d\n", inv.Summary.RestrictionRules)
	fmt.Fprintf(w, "  Listener coverage  %d (present=%d absent=%d ambiguous=%d unavailable=%d)\n", inv.Summary.ListenerCoverage, inv.Summary.CoveragePresent, inv.Summary.CoverageAbsent, inv.Summary.CoverageAmbiguous, inv.Summary.CoverageUnavailable)

	fmt.Fprintln(w, "\nPROVIDERS")
	if len(inv.Providers) == 0 {
		fmt.Fprintln(w, "  No firewall provider status returned.")
	}
	for _, p := range inv.Providers {
		rules := "unknown"
		if p.RuleCountKnown {
			rules = fmt.Sprint(p.RuleCount)
		}
		fmt.Fprintf(w, "  %-28s %-14s enabled=%-14s policies=%d rules=%s\n", truncate(p.Name, 28), strings.ToUpper(string(p.State)), p.Enabled, p.PolicyCount, rules)
		if verbose {
			fmt.Fprintf(w, "    id:     %s\n", p.ID)
			fmt.Fprintf(w, "    source: %s\n", p.Source)
			if p.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", p.Reason)
			}
		}
	}
	fmt.Fprintln(w, "\nPOLICIES")
	if len(inv.Policies) == 0 {
		fmt.Fprintln(w, "  No firewall policy/profile details were observable.")
	}
	for _, p := range inv.Policies {
		fmt.Fprintf(w, "  %-27s %-20s enabled=%-9s in=%-14s out=%-14s fwd=%s\n", truncate(p.Provider, 27), truncate(p.Scope, 20), p.Enabled, fallbackRender(p.DefaultInbound, "UNKNOWN"), fallbackRender(p.DefaultOutbound, "UNKNOWN"), fallbackRender(p.DefaultForward, "UNKNOWN"))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", p.ID)
			if p.RuleCountKnown {
				fmt.Fprintf(w, "    rules:      %d\n", p.RuleCount)
			}
			if p.Logging != "" {
				fmt.Fprintf(w, "    logging:    %s\n", p.Logging)
			}
			for _, a := range p.Attributes {
				fmt.Fprintf(w, "    %-12s %s\n", a.Name+":", truncate(a.Value, 120))
			}
			fmt.Fprintf(w, "    source:     %s\n", p.Source)
			fmt.Fprintf(w, "    confidence: %s\n", p.Confidence)
		}
	}
	fmt.Fprintln(w, "\nLISTENER COVERAGE")
	if len(inv.ListenerCoverage) == 0 {
		fmt.Fprintln(w, "  No non-loopback listeners required firewall correlation.")
	}
	for _, c := range inv.ListenerCoverage {
		fmt.Fprintf(w, "  %-5s %-39s %-11s %-13s %s\n", c.Protocol, fmt.Sprintf("%s:%d", c.LocalAddress, c.LocalPort), c.State, c.BindingClass, truncate(c.ProcessName, 28))
		if verbose {
			fmt.Fprintf(w, "    endpoint:   %s\n", c.EndpointID)
			fmt.Fprintf(w, "    providers:  %s\n", strings.Join(c.ProviderIDs, ", "))
			fmt.Fprintf(w, "    policies:   %s\n", strings.Join(c.PolicyIDs, ", "))
			fmt.Fprintf(w, "    rules:      %s\n", strings.Join(c.RestrictionIDs, ", "))
			fmt.Fprintf(w, "    basis:      %s\n", c.Basis)
			fmt.Fprintf(w, "    confidence: %s\n", c.Confidence)
		}
	}

	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintln(w, "  - "+d)
		}
	}
}

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/software"
)

func SoftwareHuman(w io.Writer, inv software.Inventory, verbose bool) {
	fmt.Fprintln(w, "SOFTWARE INVENTORY")
	fmt.Fprintf(w, "  Platform       %s/%s\n", value(inv.Platform), value(inv.Architecture))
	fmt.Fprintf(w, "  Components     %d\n", len(inv.Items))
	fmt.Fprintf(w, "  Runtimes       %d\n", len(inv.Runtimes))
	fmt.Fprintf(w, "  Infrastructure %d\n", len(inv.Infrastructure))
	fmt.Fprintf(w, "  Browsers       %d\n", len(inv.Browsers))
	fmt.Fprintf(w, "  High-risk apps %d\n", len(inv.HighRiskClients))
	fmt.Fprintf(w, "  Attributions   %d\n", len(inv.BinaryAttributions))
	fmt.Fprintf(w, "  Providers      %d software / %d runtime / %d infrastructure / %d client / %d attribution\n", len(inv.Sources), len(inv.RuntimeSources), len(inv.InfrastructureSources), len(inv.ClientSources), len(inv.AttributionSources))

	fmt.Fprintln(w, "\nPROVIDERS")
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-24s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", src.Reason)
		}
	}

	fmt.Fprintln(w, "\nINSTALLED SOFTWARE")
	if len(inv.Items) == 0 {
		fmt.Fprintln(w, "  No software records were returned by the available native providers.")
	}
	for _, item := range inv.Items {
		fmt.Fprintf(w, "  %-34s %-18s %-12s %s\n", truncate(item.Product, 34), truncate(item.Version, 18), truncate(item.Architecture, 12), item.PackageSource)
		if verbose {
			fmt.Fprintf(w, "    id:       %s\n", item.ID)
			fmt.Fprintf(w, "    kind:     %s\n", item.Kind)
			fmt.Fprintf(w, "    package:  %s\n", item.PackageID)
			fmt.Fprintf(w, "    vendor:   %s\n", item.Vendor)
			fmt.Fprintf(w, "    path:     %s\n", item.InstallPath)
			fmt.Fprintf(w, "    support:  %s — %s\n", item.SupportState, item.SupportReason)
			fmt.Fprintf(w, "    source:   %s\n", item.CollectionSource)
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	fmt.Fprintln(w, "\nRUNTIMES / FRAMEWORKS / TOOLCHAINS")
	if len(inv.Runtimes) == 0 {
		fmt.Fprintln(w, "  No supported runtime/framework records were observed from local metadata.")
	}
	for _, item := range inv.Runtimes {
		fmt.Fprintf(w, "  %-18s %-32s %-18s %s\n", truncate(item.Family, 18), truncate(item.Product, 32), truncate(item.Version, 18), item.Kind)
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", item.ID)
			fmt.Fprintf(w, "    arch:       %s\n", item.Architecture)
			fmt.Fprintf(w, "    executable: %s\n", item.Executable)
			fmt.Fprintf(w, "    exec-path:  %s\n", item.ExecutablePath)
			fmt.Fprintf(w, "    install:    %s\n", item.InstallPath)
			fmt.Fprintf(w, "    distro:     %s\n", item.Distribution)
			fmt.Fprintf(w, "    source:     %s\n", item.CollectionSource)
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	fmt.Fprintln(w, "\nSERVER / INFRASTRUCTURE SOFTWARE")
	if len(inv.Infrastructure) == 0 {
		fmt.Fprintln(w, "  No supported server/infrastructure products were attributed from installed software or running activity.")
	}
	for _, item := range inv.Infrastructure {
		presence := "installed"
		if item.Running && item.Installed {
			presence = "installed+running"
		} else if item.Running {
			presence = "running-unattributed"
		}
		fmt.Fprintf(w, "  %-22s %-28s %-18s %s\n", truncate(item.Role, 22), truncate(item.Product, 28), truncate(item.Version, 18), presence)
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", item.ID)
			fmt.Fprintf(w, "    family:     %s\n", item.Family)
			fmt.Fprintf(w, "    package:    %s\n", item.PackageID)
			fmt.Fprintf(w, "    install:    %s\n", item.InstallPath)
			fmt.Fprintf(w, "    instances:  %s\n", strings.Join(item.RunningInstances, ", "))
			fmt.Fprintf(w, "    exec-paths: %s\n", strings.Join(item.ExecutablePaths, ", "))
			fmt.Fprintf(w, "    sources:    %s\n", strings.Join(item.DetectionSources, ", "))
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	fmt.Fprintln(w, "\nBROWSERS")
	if len(inv.Browsers) == 0 {
		fmt.Fprintln(w, "  No supported browser products were attributed from installed-software metadata.")
	}
	for _, item := range inv.Browsers {
		fmt.Fprintf(w, "  %-18s %-28s %-18s %s\n", truncate(item.Family, 18), truncate(item.Product, 28), truncate(item.Version, 18), item.Channel)
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", item.ID)
			fmt.Fprintf(w, "    arch:       %s\n", item.Architecture)
			fmt.Fprintf(w, "    package:    %s\n", item.PackageID)
			fmt.Fprintf(w, "    install:    %s\n", item.InstallPath)
			fmt.Fprintf(w, "    sources:    %s\n", strings.Join(item.DetectionSources, ", "))
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	fmt.Fprintln(w, "\nHIGH-RISK CLIENT SOFTWARE")
	if len(inv.HighRiskClients) == 0 {
		fmt.Fprintln(w, "  No supported high-risk client products were attributed from installed-software metadata.")
	}
	for _, item := range inv.HighRiskClients {
		fmt.Fprintf(w, "  %-18s %-30s %-18s %s\n", truncate(item.Category, 18), truncate(item.Product, 30), truncate(item.Version, 18), strings.Join(item.ContentSurfaces, ","))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", item.ID)
			fmt.Fprintf(w, "    family:     %s\n", item.Family)
			fmt.Fprintf(w, "    arch:       %s\n", item.Architecture)
			fmt.Fprintf(w, "    package:    %s\n", item.PackageID)
			fmt.Fprintf(w, "    install:    %s\n", item.InstallPath)
			fmt.Fprintf(w, "    sources:    %s\n", strings.Join(item.DetectionSources, ", "))
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	fmt.Fprintln(w, "\nPACKAGE / APPLICATION BINARY ATTRIBUTION")
	if len(inv.BinaryAttributions) == 0 {
		fmt.Fprintln(w, "  No runtime or recognized infrastructure executable paths were available for attribution.")
	}
	for _, item := range inv.BinaryAttributions {
		name := "UNKNOWN"
		if len(item.Targets) > 0 {
			name = item.Targets[0].Name
		}
		fmt.Fprintf(w, "  %-30s %-20s %-18s %s\n", truncate(name, 30), item.Ownership, item.Distribution, truncate(item.PackageID, 30))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", item.ID)
			fmt.Fprintf(w, "    path:       %s\n", item.Path)
			fmt.Fprintf(w, "    resolved:   %s (%s)\n", item.ResolvedPath, item.PathState)
			fmt.Fprintf(w, "    product:    %s %s\n", item.Product, item.Version)
			fmt.Fprintf(w, "    source:     %s\n", item.PackageSource)
			fmt.Fprintf(w, "    install:    %s\n", item.InstallPath)
			fmt.Fprintf(w, "    provider:   %s [%s]\n", item.Provider, strings.ToUpper(string(item.ProviderState)))
			fmt.Fprintf(w, "    method:     %s\n", item.Method)
			fmt.Fprintf(w, "    reason:     %s\n", item.Reason)
			fmt.Fprintf(w, "    confidence: %s\n", item.Confidence)
		}
	}

	if verbose {
		fmt.Fprintln(w, "\nATTRIBUTION PROVIDERS")
		for _, src := range inv.AttributionSources {
			fmt.Fprintf(w, "  %-32s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
			if src.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", src.Reason)
			}
		}
	}

	if verbose {
		fmt.Fprintln(w, "\nCLIENT CLASSIFICATION PROVIDERS")
		for _, src := range inv.ClientSources {
			fmt.Fprintf(w, "  %-32s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
			if src.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", src.Reason)
			}
		}
	}

	if verbose {
		fmt.Fprintln(w, "\nINFRASTRUCTURE PROVIDERS")
		for _, src := range inv.InfrastructureSources {
			fmt.Fprintf(w, "  %-32s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
			if src.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", src.Reason)
			}
		}
	}

	if verbose {
		fmt.Fprintln(w, "\nRUNTIME PROVIDERS")
		for _, src := range inv.RuntimeSources {
			fmt.Fprintf(w, "  %-24s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
			if src.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", src.Reason)
			}
		}
	}
	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintln(w, "  - "+d)
		}
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

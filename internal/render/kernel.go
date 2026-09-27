package render

import (
	"fmt"
	kinfo "github.com/Nikolov999/chimera/internal/kernel"
	"io"
	"strings"
	"time"
)

func KernelHuman(w io.Writer, k kinfo.Inventory, verbose bool) {
	fmt.Fprintln(w, "KERNEL / OS BASELINE")
	fmt.Fprintf(w, "  OS                 %s\n", value(k.OSName))
	fmt.Fprintf(w, "  OS version         %s\n", value(k.OSVersion))
	if k.OSBuild != "" {
		fmt.Fprintf(w, "  OS build           %s\n", k.OSBuild)
	}
	fmt.Fprintf(w, "  Support channel    %s\n", value(k.SupportChannel))
	fmt.Fprintf(w, "  Kernel release     %s\n", value(k.KernelRelease))
	if k.KernelVersion != "" {
		fmt.Fprintf(w, "  Kernel version     %s\n", k.KernelVersion)
	}
	fmt.Fprintf(w, "  Architecture       %s\n", value(k.Architecture))
	fmt.Fprintf(w, "  Boot mode          %s\n", value(k.BootMode))
	if k.BootTime != nil {
		fmt.Fprintf(w, "  Boot time          %s\n", k.BootTime.Local().Format(time.RFC3339))
	}
	if k.UptimeSeconds > 0 {
		fmt.Fprintf(w, "  Uptime             %s\n", duration(k.UptimeSeconds))
	}
	if k.BootID != "" && verbose {
		fmt.Fprintf(w, "  Boot ID            %s\n", k.BootID)
	}
	fmt.Fprintf(w, "  Update state       %s\n", strings.ToUpper(value(k.Update.State)))
	if verbose && k.Update.Detail != "" {
		fmt.Fprintf(w, "  Update detail      %s\n", k.Update.Detail)
	}
	fmt.Fprintln(w, "\nSECURE BOOT ASSESSMENT")
	fmt.Fprintf(w, "  State              %s\n", strings.ToUpper(value(k.SecureBoot.State)))
	if k.SecureBoot.Mode != "" {
		fmt.Fprintf(w, "  Mode               %s\n", k.SecureBoot.Mode)
	}
	fmt.Fprintf(w, "  Evidence state     %s\n", strings.ToUpper(string(k.SecureBoot.CollectionState)))
	if verbose {
		fmt.Fprintf(w, "  Provider           %s\n", value(k.SecureBoot.Provider))
		fmt.Fprintf(w, "  Source             %s\n", value(k.SecureBoot.Source))
		fmt.Fprintf(w, "  Confidence         %s\n", strings.ToUpper(string(k.SecureBoot.Confidence)))
		if k.SecureBoot.Reason != "" {
			fmt.Fprintf(w, "  Reason             %s\n", k.SecureBoot.Reason)
		}
	}
	fmt.Fprintln(w, "\nKERNEL / CODE-INTEGRITY CONTROLS")
	for _, c := range k.IntegrityControls {
		fmt.Fprintf(w, "  %-40s %s\n", c.Name, strings.ToUpper(value(c.State)))
		if c.Mode != "" {
			fmt.Fprintf(w, "    mode:       %s\n", c.Mode)
		}
		fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(c.CollectionState)))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", c.ID)
			fmt.Fprintf(w, "    provider:   %s\n", value(c.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(c.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(c.Confidence)))
			if c.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", c.Reason)
			}
		}
	}
	fmt.Fprintln(w, "\nASLR / MEMORY MITIGATIONS")
	for _, m := range k.MemoryMitigations {
		fmt.Fprintf(w, "  %-40s %s\n", m.Name, strings.ToUpper(value(m.State)))
		if m.Mode != "" {
			fmt.Fprintf(w, "    mode:       %s\n", m.Mode)
		}
		fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(m.CollectionState)))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", m.ID)
			fmt.Fprintf(w, "    provider:   %s\n", value(m.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(m.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(m.Confidence)))
			if m.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", m.Reason)
			}
		}
	}
	fmt.Fprintln(w, "\nKERNEL POINTER / DEBUG EXPOSURE")
	for _, d := range k.DebugExposure {
		fmt.Fprintf(w, "  %-40s %s\n", d.Name, strings.ToUpper(value(d.State)))
		if d.Mode != "" {
			fmt.Fprintf(w, "    mode:       %s\n", d.Mode)
		}
		fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(d.CollectionState)))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", d.ID)
			fmt.Fprintf(w, "    provider:   %s\n", value(d.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(d.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(d.Confidence)))
			if d.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", d.Reason)
			}
		}
	}
	fmt.Fprintln(w, "\nUNPRIVILEGED KERNEL FEATURE EXPOSURE")
	for _, u := range k.UnprivilegedFeatures {
		fmt.Fprintf(w, "  %-40s %s\n", u.Name, strings.ToUpper(value(u.State)))
		if u.Mode != "" {
			fmt.Fprintf(w, "    mode:       %s\n", u.Mode)
		}
		fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(u.CollectionState)))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", u.ID)
			fmt.Fprintf(w, "    provider:   %s\n", value(u.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(u.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(u.Confidence)))
			if u.Exposed != nil {
				fmt.Fprintf(w, "    exposed:    %t\n", *u.Exposed)
			}
			if u.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", u.Reason)
			}
		}
	}

	fmt.Fprintln(w, "\nLOADED KERNEL MODULES / DRIVERS")
	for _, m := range k.LoadedModules {
		flags := "NONE"
		if len(m.Flags) > 0 {
			flags = strings.Join(m.Flags, ",")
		}
		fmt.Fprintf(w, "  %-34s %-10s sig=%-16s trust=%-20s backing=%s\n", value(m.Name), strings.ToUpper(value(m.LoadState)), strings.ToUpper(value(m.SignatureState)), strings.ToUpper(value(m.TrustState)), strings.ToUpper(value(m.BackingState)))
		if len(m.Flags) > 0 || verbose {
			fmt.Fprintf(w, "    flags:      %s\n", flags)
		}
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", value(m.ID))
			fmt.Fprintf(w, "    kind:       %s\n", value(m.Kind))
			fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(m.CollectionState)))
			fmt.Fprintf(w, "    provider:   %s\n", value(m.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(m.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(m.Confidence)))
			if m.Version != "" {
				fmt.Fprintf(w, "    version:    %s\n", m.Version)
			}
			if m.Path != "" {
				fmt.Fprintf(w, "    path:       %s\n", m.Path)
			}
			if m.Signer != "" {
				fmt.Fprintf(w, "    signer:     %s\n", m.Signer)
			}
			if m.Provenance != "" {
				fmt.Fprintf(w, "    provenance: %s\n", m.Provenance)
			}
			if m.Taint != "" {
				fmt.Fprintf(w, "    taint:      %s\n", m.Taint)
			}
			if m.OutOfTree != nil {
				fmt.Fprintf(w, "    out-of-tree:%t\n", *m.OutOfTree)
			}
			if m.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", m.Reason)
			}
		}
	}

	fmt.Fprintln(w, "\nVULNERABLE DRIVER ASSESSMENT")
	fmt.Fprintf(w, "  Intelligence       %s (%s)\n", value(k.DriverIntelligence.Version), value(k.DriverIntelligence.Schema))
	fmt.Fprintf(w, "  Platform entries   %d\n", k.DriverIntelligence.PlatformEntries)
	fmt.Fprintf(w, "  Candidates         %d\n", k.DriverIntelligence.CandidateCount)
	fmt.Fprintf(w, "  Identity matches   %d\n", k.DriverIntelligence.MatchCount)
	fmt.Fprintf(w, "  Unresolved         %d\n", k.DriverIntelligence.UnresolvedCount)
	fmt.Fprintf(w, "  Installed source   %s (%s)\n", value(k.DriverIntelligence.InstalledCollectionSource), strings.ToUpper(string(k.DriverIntelligence.InstalledCollectionState)))
	if verbose && k.DriverIntelligence.InstalledCollectionReason != "" {
		fmt.Fprintf(w, "    collection:   %s\n", k.DriverIntelligence.InstalledCollectionReason)
	}
	if len(k.VulnerableDrivers) == 0 {
		fmt.Fprintln(w, "  No local driver identities matched the pinned vulnerable-driver seed.")
	}
	for _, v := range k.VulnerableDrivers {
		fmt.Fprintf(w, "  %-28s %-10s %-10s exposure=%-10s resolution=%s\n", value(v.DriverName), value(v.InstalledState), value(v.LoadState), value(v.ExposureState), value(v.ResolutionState))
		fmt.Fprintf(w, "    intelligence: %s  vulnerabilities=%s\n", value(v.IntelligenceID), strings.Join(v.Vulnerabilities, ","))
		if verbose {
			fmt.Fprintf(w, "    match:        %s\n", value(v.MatchBasis))
			fmt.Fprintf(w, "    confidence:   %s\n", strings.ToUpper(string(v.Confidence)))
			if v.DriverVersion != "" {
				fmt.Fprintf(w, "    version:      %s\n", v.DriverVersion)
			}
			if v.DriverPath != "" {
				fmt.Fprintf(w, "    path:         %s\n", v.DriverPath)
			}
			fmt.Fprintf(w, "    fingerprint:  %s\n", value(v.FingerprintState))
			if v.SHA256 != "" {
				fmt.Fprintf(w, "    sha256:       %s\n", v.SHA256)
			}
			if v.ExposureReason != "" {
				fmt.Fprintf(w, "    exposure:     %s\n", v.ExposureReason)
			}
			if v.Advisory != "" {
				fmt.Fprintf(w, "    advisory:     %s\n", v.Advisory)
			}
			if v.Reason != "" {
				fmt.Fprintf(w, "    reason:       %s\n", v.Reason)
			}
		}
	}

	fmt.Fprintln(w, "\nMANDATORY ACCESS / ISOLATION POSTURE")
	for _, m := range k.MandatoryAccess {
		fmt.Fprintf(w, "  %-34s %-22s framework=%s\n", value(m.Name), strings.ToUpper(value(m.State)), value(m.Framework))
		if m.Mode != "" {
			fmt.Fprintf(w, "    mode:       %s\n", m.Mode)
		}
		fmt.Fprintf(w, "    evidence:   %s\n", strings.ToUpper(string(m.CollectionState)))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", value(m.ID))
			fmt.Fprintf(w, "    provider:   %s\n", value(m.Provider))
			fmt.Fprintf(w, "    source:     %s\n", value(m.Source))
			fmt.Fprintf(w, "    confidence: %s\n", strings.ToUpper(string(m.Confidence)))
			if m.Enabled != nil {
				fmt.Fprintf(w, "    enabled:    %t\n", *m.Enabled)
			}
			if m.Reason != "" {
				fmt.Fprintf(w, "    reason:     %s\n", m.Reason)
			}
		}
	}

	fmt.Fprintln(w, "\nHARDENING CAPABILITIES")
	for _, c := range k.HardeningCapabilities {
		fmt.Fprintf(w, "  %-34s %-12s %s\n", c.Name, strings.ToUpper(c.State), c.Source)
		if verbose && c.Detail != "" {
			fmt.Fprintf(w, "    %s\n", c.Detail)
		}
	}
	if verbose {
		fmt.Fprintln(w, "\nNORMALIZED EVIDENCE")
		for _, e := range k.Evidence {
			fmt.Fprintf(w, "  %-48s %-14s %-6s %s\n", e.Key, e.State, e.Confidence, e.Source)
			if e.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", e.Reason)
			}
		}
	}
	if verbose && len(k.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range k.Degraded {
			fmt.Fprintln(w, "  -", d)
		}
	}
}

package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/cli"
	"github.com/Nikolov999/chimera/internal/overview"
)

const (
	cyan  = "\x1b[38;5;81m"
	blue  = "\x1b[38;5;75m"
	dim   = "\x1b[2m"
	reset = "\x1b[0m"
)

func Banner(w io.Writer, opts cli.Options) {
	if opts.JSON || opts.Quiet {
		return
	}
	useColor := !opts.NoColor && !opts.Plain
	lines := []string{
		"   ________  __  ________  __________  ___",
		"  / ____/ / / / /  _/  |/  / ____/ / / /",
		" / /   / /_/ /  / // /|_/ / __/ / /_/ / ",
		"/ /___/ __  / _/ // /  / / /___/ __  /  ",
		"\\____/_/ /_/ /___/_/  /_/_____/_/ /_/   ",
	}
	for i, line := range lines {
		if useColor {
			c := cyan
			if i%2 == 1 {
				c = blue
			}
			fmt.Fprintln(w, c+line+reset)
		} else {
			fmt.Fprintln(w, line)
		}
	}
	tagline := "IRONCLAD live-host vulnerability, exposure & misconfiguration assessment"
	if useColor {
		fmt.Fprintln(w, dim+tagline+reset)
	} else {
		fmt.Fprintln(w, tagline)
	}
	fmt.Fprintln(w)
}

func JSON(w io.Writer, v any) error {
	// Machine-readable JSON is intentionally compact. Pretty-print whitespace can
	// inflate large live-host assessments by tens of megabytes without adding
	// semantic value. The trailing newline retained by Encoder keeps CLI/file
	// streaming behavior conventional while preserving the frozen JSON schemas.
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}

func OverviewHuman(w io.Writer, o overview.Overview, verbose bool) {
	fmt.Fprintln(w, "OVERVIEW")
	fmt.Fprintf(w, "  Hostname           %s\n", value(o.Hostname))
	fmt.Fprintf(w, "  Current user       %s\n", value(o.CurrentUser))
	fmt.Fprintf(w, "  OS                 %s\n", value(o.OS))
	if o.OSVersion != "" {
		fmt.Fprintf(w, "  OS version         %s\n", o.OSVersion)
	}
	if o.OSBuild != "" {
		fmt.Fprintf(w, "  OS build           %s\n", o.OSBuild)
	}
	fmt.Fprintf(w, "  Kernel             %s\n", value(o.Kernel))
	fmt.Fprintf(w, "  Architecture       %s\n", o.Architecture)
	if o.BootTime != nil {
		fmt.Fprintf(w, "  Boot time          %s\n", o.BootTime.Local().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "  Uptime             %s\n", duration(o.UptimeSeconds))
	fmt.Fprintf(w, "  Privilege          %s", value(o.Privilege.Level))
	if o.Privilege.Principal != "" {
		fmt.Fprintf(w, " (%s)", o.Privilege.Principal)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Collection tier    %s\n", value(o.Privilege.CollectionTier))
	if o.Privilege.ElevationState != "" {
		fmt.Fprintf(w, "  Elevation state    %s\n", o.Privilege.ElevationState)
	}
	if o.Privilege.IntegrityLevel != "" {
		fmt.Fprintf(w, "  Integrity level    %s\n", o.Privilege.IntegrityLevel)
	}
	if o.Privilege.ElevationNote != "" {
		fmt.Fprintf(w, "  Privilege note     %s\n", o.Privilege.ElevationNote)
	}
	if verbose && len(o.Privilege.DeeperEvidence) > 0 {
		fmt.Fprintln(w, "  Deeper evidence")
		for _, opportunity := range o.Privilege.DeeperEvidence {
			fmt.Fprintf(w, "    - %s [%s]: %s\n", opportunity.Area, opportunity.Requirement, opportunity.Reason)
		}
	}
	if o.CPUModel != "" {
		fmt.Fprintf(w, "  CPU                %s\n", o.CPUModel)
	}
	fmt.Fprintf(w, "  Logical CPUs       %d\n", o.LogicalCPUs)
	fmt.Fprintf(w, "  Memory             %s\n", formatBytes(o.MemoryTotalBytes))
	fmt.Fprintf(w, "  Processes          %d\n", o.ProcessCount)
	fmt.Fprintf(w, "  TCP listeners      %d\n", o.ListenerCount)
	fmt.Fprintln(w, "\nSECURITY CONTROLS")
	for _, c := range o.SecurityControls {
		fmt.Fprintf(w, "  %-28s %-12s", c.Name, strings.ToUpper(c.State))
		if c.Detail != "" {
			fmt.Fprintf(w, " %s", c.Detail)
		}
		fmt.Fprintln(w)
	}
	if verbose {
		fmt.Fprintln(w, "\nNORMALIZED EVIDENCE")
		for _, e := range o.Evidence {
			fmt.Fprintf(w, "  %-42s %-14s %-6s %s\n", e.Key, e.State, e.Confidence, e.Source)
			if e.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", e.Reason)
			}
		}
	}
	if verbose && len(o.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range o.Degraded {
			fmt.Fprintln(w, "  -", d)
		}
	}
}

func value(s string) string {
	if strings.TrimSpace(s) == "" {
		return "UNAVAILABLE"
	}
	return s
}

func duration(sec int64) string {
	if sec <= 0 {
		return "UNAVAILABLE"
	}
	d := time.Duration(sec) * time.Second
	days := d / (24 * time.Hour)
	d %= 24 * time.Hour
	if days > 0 {
		return fmt.Sprintf("%dd %s", days, d.Truncate(time.Second))
	}
	return d.Truncate(time.Second).String()
}

func formatBytes(n uint64) string {
	if n == 0 {
		return "UNAVAILABLE"
	}
	const gib = 1024 * 1024 * 1024
	const mib = 1024 * 1024
	if n >= gib {
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(gib))
	}
	return fmt.Sprintf("%.2f MiB", float64(n)/float64(mib))
}

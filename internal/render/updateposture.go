package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/updateposture"
)

func UpdatePostureHuman(w io.Writer, r updateposture.Result, verbose bool) {
	fmt.Fprintln(w, "\nMISSING SECURITY UPDATE / PATCH POSTURE")
	fmt.Fprintf(w, "  State                  %s\n", r.State)
	fmt.Fprintf(w, "  Collector              %s\n", r.CollectorVersion)
	fmt.Fprintf(w, "  Pending updates        %d\n", r.Summary.Pending)
	fmt.Fprintf(w, "  Security               %d\n", r.Summary.Security)
	fmt.Fprintf(w, "  Other                  %d\n", r.Summary.Other)
	fmt.Fprintf(w, "  Unknown classification %d\n", r.Summary.UnknownClassification)
	fmt.Fprintf(w, "  Reboot required        %t\n", r.Summary.RebootRequired)
	fmt.Fprintf(w, "  Metadata freshness     fresh=%d stale=%d unknown=%d\n", r.Summary.FreshProviders, r.Summary.StaleProviders, r.Summary.UnknownFreshnessProviders)

	if len(r.Updates) > 0 {
		fmt.Fprintln(w, "\nPENDING UPDATE CANDIDATES")
		for _, u := range r.Updates {
			version := u.CandidateVersion
			if strings.TrimSpace(version) == "" {
				version = "UNKNOWN"
			}
			fmt.Fprintf(w, "  %-10s %-30s %s\n", u.Classification, truncate(u.Product, 30), truncate(version, 24))
			if verbose {
				fmt.Fprintf(w, "    id:         %s\n", u.ID)
				fmt.Fprintf(w, "    installed:  %s\n", value(u.InstalledVersion))
				fmt.Fprintf(w, "    package:    %s\n", u.PackageID)
				fmt.Fprintf(w, "    source:     %s\n", u.Source)
				fmt.Fprintf(w, "    confidence: %s\n", u.Confidence)
				fmt.Fprintf(w, "    reboot:     %t\n", u.RebootRequired)
				fmt.Fprintf(w, "    reason:     %s\n", u.Reason)
			}
		}
	}
	if verbose && len(r.Providers) > 0 {
		fmt.Fprintln(w, "\nUPDATE METADATA PROVIDERS")
		for _, p := range r.Providers {
			fmt.Fprintf(w, "  %-20s %-14s items=%d security=%d freshness=%s\n", p.ID, strings.ToUpper(string(p.State)), p.ItemCount, p.SecurityCount, p.Freshness)
			fmt.Fprintf(w, "    source: %s\n", p.Source)
			if !p.MetadataTime.IsZero() {
				fmt.Fprintf(w, "    metadata time: %s\n", p.MetadataTime.Format("2006-01-02T15:04:05Z07:00"))
			}
			if p.Partial {
				fmt.Fprintln(w, "    partial: true")
			}
			if p.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", p.Reason)
			}
			for _, st := range p.Stages {
				fmt.Fprintf(w, "    stage %-28s %-12s elapsed=%dms", st.ID, strings.ToUpper(string(st.State)), st.ElapsedMS)
				if st.ExitCode != nil {
					fmt.Fprintf(w, " exit=%d", *st.ExitCode)
				}
				fmt.Fprintln(w)
				if st.Command != "" {
					fmt.Fprintf(w, "      command: %s\n", st.Command)
				}
				if st.ExceptionType != "" || st.ExceptionMessage != "" {
					fmt.Fprintf(w, "      exception: %s %s\n", value(st.ExceptionType), value(st.ExceptionMessage))
				}
				if st.Reason != "" {
					fmt.Fprintf(w, "      reason: %s\n", st.Reason)
				}
			}
		}
	}
	if verbose && len(r.Limitations) > 0 {
		fmt.Fprintln(w, "\nUPDATE POSTURE LIMITATIONS")
		for _, v := range r.Limitations {
			fmt.Fprintln(w, "  - "+v)
		}
	}
}

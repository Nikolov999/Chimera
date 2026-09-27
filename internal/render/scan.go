package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/scan"
)

func ScanHuman(w io.Writer, s scan.Result, verbose bool) {
	fmt.Fprintln(w, "SCAN")
	if s.Profile.Descriptor.Name != "" {
		fmt.Fprintf(w, "  Profile            %s\n", s.Profile.Descriptor.Name)
	}
	fmt.Fprintf(w, "  State              %s\n", s.State)
	fmt.Fprintf(w, "  Duration           %s\n", formatScanDuration(s.Timing.DurationMS))
	fmt.Fprintf(w, "  Workers            %d used / %d configured\n", s.WorkersUsed, s.MaxWorkers)
	fmt.Fprintf(w, "  Timed out          %t\n", s.TimedOut)
	if !s.Summary.Evaluation.Complete {
		fmt.Fprintln(w, "  Assessment         INCOMPLETE")
		fmt.Fprintf(w, "  Rule evaluation    %d/%d (%.1f%%), NOT_EVALUATED=%d\n", s.Summary.Evaluation.EvaluatedRules, s.Summary.Evaluation.SelectedRules, s.Summary.Evaluation.Percent, s.Summary.Evaluation.NotEvaluatedRules)
	}
	if s.Snapshot.AssessmentID != "" {
		fmt.Fprintf(w, "  Assessment ID      %s\n", s.Snapshot.AssessmentID)
		fmt.Fprintf(w, "  Host fingerprint   %s\n", shortDigest(s.Snapshot.HostFingerprint.Value))
		fmt.Fprintf(w, "  Config digest      %s\n", shortDigest(s.Snapshot.Config.Digest.Value))
		fmt.Fprintf(w, "  Profile digest     %s\n", shortDigest(s.Snapshot.Profile.Digest.Value))
		fmt.Fprintf(w, "  Rule set           %s (%s)\n", s.Snapshot.Rules.Version, shortDigest(s.Snapshot.Rules.Digest.Value))
		fmt.Fprintf(w, "  Intelligence       %s / %s", s.Snapshot.Intelligence.State, s.Snapshot.Intelligence.Version)
		if s.Snapshot.Intelligence.Mode != "" || s.Snapshot.Intelligence.Freshness != "" {
			fmt.Fprintf(w, " (%s, %s)", s.Snapshot.Intelligence.Mode, s.Snapshot.Intelligence.Freshness)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  Host               %s\n", scanValue(s.Overview.Hostname))
	fmt.Fprintf(w, "  Platform           %s/%s\n", scanValue(s.Overview.OS), scanValue(s.Overview.Architecture))
	fmt.Fprintf(w, "  Collection tier    %s\n", scanValue(s.Overview.Privilege.CollectionTier))
	if s.Software != nil {
		fmt.Fprintf(w, "  Software records   %d\n", len(s.Software.Items))
	}
	if s.Processes != nil {
		fmt.Fprintf(w, "  Process records    %d\n", len(s.Processes.Processes))
	}
	if s.Services != nil {
		fmt.Fprintf(w, "  Service records    %d (%d running / %d privileged)\n", len(s.Services.Services), s.Services.Summary.Running, s.Services.Summary.Privileged)
	}
	if s.Scheduled != nil {
		fmt.Fprintf(w, "  Scheduled records  %d (%d enabled / %d privileged)\n", len(s.Scheduled.Entries), s.Scheduled.Summary.Enabled, s.Scheduled.Summary.Privileged)
	}
	if s.Persistence != nil {
		fmt.Fprintf(w, "  Persistence points %d (%d enabled / %d privileged)\n", len(s.Persistence.Entries), s.Persistence.Summary.Enabled, s.Persistence.Summary.Privileged)
	}
	if s.Accounts != nil {
		fmt.Fprintf(w, "  Account records    %d (%d privileged / %d service)\n", len(s.Accounts.Accounts), s.Accounts.Summary.Privileged, s.Accounts.Summary.ServiceAccounts)
	}
	if s.Filesystem != nil {
		fmt.Fprintf(w, "  Filesystem paths   %d (%d roots / %d search paths / %d mounts)\n", len(s.Filesystem.Paths), s.Filesystem.Summary.SecurityRoots, s.Filesystem.Summary.SearchPaths, len(s.Filesystem.MountBoundaries))
	}
	if s.ProductNormalization != nil {
		fmt.Fprintf(w, "  Product mapping    %s (%d/%d matched)\n", s.ProductNormalization.State, s.ProductNormalization.Summary.Matched, s.ProductNormalization.Summary.Candidates)
	}
	if s.VulnerabilityCorrelation != nil {
		fmt.Fprintf(w, "  CVE correlation    %s (%d affected / %d unresolved / %d evaluated)\n", s.VulnerabilityCorrelation.State, s.VulnerabilityCorrelation.Summary.Affected, s.VulnerabilityCorrelation.Summary.Unresolved, s.VulnerabilityCorrelation.Summary.Evaluations)
	}
	if s.VulnerabilityReachability != nil {
		fmt.Fprintf(w, "  CVE reachability   %s (%d listening / %d privileged / %d installed-only / %d contexts)\n", s.VulnerabilityReachability.State, s.VulnerabilityReachability.Summary.Listening, s.VulnerabilityReachability.Summary.Privileged, s.VulnerabilityReachability.Summary.InstalledOnly, s.VulnerabilityReachability.Summary.Evaluations)
	}
	if s.Lifecycle != nil {
		fmt.Fprintf(w, "  Lifecycle          %s (%d EOL / %d unsupported / %d supported / %d covered)\n", s.Lifecycle.State, s.Lifecycle.Summary.EndOfLife, s.Lifecycle.Summary.Unsupported, s.Lifecycle.Summary.Supported, s.Lifecycle.Summary.WithIntelligence)
	}
	if s.Overview.Privilege.ElevationNote != "" {
		fmt.Fprintf(w, "  Privilege note     %s\n", s.Overview.Privilege.ElevationNote)
	}
	if verbose && s.Profile.Descriptor.Name != "" {
		applicable, notApplicable, raised := decisionCounts(s.Profile.RuleDecisions)
		fmt.Fprintf(w, "  Profile rules      %d applicable / %d N/A / %d severity raised\n", applicable, notApplicable, raised)
	}

	fmt.Fprintln(w)
	SelectionHuman(w, s.Selection, verbose)
	SuppressionsHuman(w, s.Suppressions, verbose)

	fmt.Fprintln(w, "\nCOLLECTION")
	fmt.Fprintf(w, "  State              %s\n", s.Collection.State)
	fmt.Fprintf(w, "  Duration           %s\n", formatScanDuration(s.Collection.Timing.DurationMS))
	fmt.Fprintf(w, "  Evidence           %d total / %d observed\n", s.Collection.Evidence.Total, s.Collection.Evidence.Observed)
	fmt.Fprintf(w, "  Degraded           %d\n", s.Collection.Evidence.Degraded)
	fmt.Fprintf(w, "  Denied             %d\n", s.Collection.Evidence.Denied)
	fmt.Fprintf(w, "  Unavailable        %d\n", s.Collection.Evidence.Unavailable)
	fmt.Fprintf(w, "  Unsupported        %d\n", s.Collection.Evidence.Unsupported)
	fmt.Fprintf(w, "  Not applicable     %d\n", s.Collection.Evidence.NotApplicable)
	if verbose && len(s.Collection.Providers) > 0 {
		fmt.Fprintln(w, "  Provider timings")
		for _, provider := range s.Collection.Providers {
			fmt.Fprintf(w, "    %-20s %-14s %s\n", provider.Name, provider.State, formatScanDuration(provider.Timing.DurationMS))
		}
	}
	if verbose && len(s.Collection.DegradationReasons) > 0 {
		fmt.Fprintln(w, "  Degradation reasons")
		for _, reason := range s.Collection.DegradationReasons {
			fmt.Fprintln(w, "    - "+reason)
		}
	}

	fmt.Fprintln(w, "\nCATEGORIES")
	fmt.Fprintf(w, "  Total %d / Complete %d / Degraded %d / Skipped %d / Not applicable %d\n",
		s.Summary.Categories.Total, s.Summary.Categories.Complete, s.Summary.Categories.Degraded,
		s.Summary.Categories.Skipped, s.Summary.Categories.NotApplicable)
	for _, c := range s.Categories {
		fmt.Fprintf(w, "\n  %-16s %-14s rules=%d evaluated=%d not-evaluated=%d findings=%d duration=%s\n",
			c.Name, c.State, c.RuleCount, c.EvaluatedRules, c.NotEvaluatedRules, c.Findings.Total, formatScanDuration(c.Timing.DurationMS))
		fmt.Fprintf(w, "    PASS=%d WARN=%d FAIL=%d UNKNOWN=%d N/A=%d SUPPRESSED=%d\n",
			c.Findings.Pass, c.Findings.Warn, c.Findings.Fail, c.Findings.Unknown, c.Findings.NotApplicable, c.Findings.Suppressed)
		if c.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", c.Reason)
		}
		if verbose && len(c.DegradationReasons) > 0 {
			for _, reason := range c.DegradationReasons {
				fmt.Fprintln(w, "    degraded: "+reason)
			}
		}
	}

	fmt.Fprintln(w, "\nASSESSMENT SUMMARY")
	if !s.Summary.Evaluation.Complete {
		fmt.Fprintln(w, "  ASSESSMENT INCOMPLETE")
	}
	fmt.Fprintf(w, "  Rule evaluation    %d/%d (%.1f%%)\n", s.Summary.Evaluation.EvaluatedRules, s.Summary.Evaluation.SelectedRules, s.Summary.Evaluation.Percent)
	fmt.Fprintf(w, "  NOT_EVALUATED      %d\n", s.Summary.Evaluation.NotEvaluatedRules)
	fmt.Fprintf(w, "  Findings           %d\n", s.Summary.Findings.Total)
	fmt.Fprintf(w, "  FAIL               %d\n", s.Summary.Findings.Fail)
	fmt.Fprintf(w, "  WARN               %d\n", s.Summary.Findings.Warn)
	fmt.Fprintf(w, "  UNKNOWN            %d\n", s.Summary.Findings.Unknown)
	fmt.Fprintf(w, "  PASS               %d\n", s.Summary.Findings.Pass)
	fmt.Fprintf(w, "  Not applicable     %d\n", s.Summary.Findings.NotApplicable)
	fmt.Fprintf(w, "  Suppressed         %d\n", s.Summary.Findings.Suppressed)
	if s.Prioritization != nil {
		PrioritizationHuman(w, *s.Prioritization, verbose)
	}
	if s.Remediation != nil {
		fmt.Fprintln(w, "\nREMEDIATION SUMMARY")
		fmt.Fprintf(w, "  Actionable fixes    %d\n", s.Remediation.Summary.Actions)
		fmt.Fprintf(w, "  Critical / High     %d / %d\n", s.Remediation.Summary.CriticalActions, s.Remediation.Summary.HighActions)
		fmt.Fprintf(w, "  Needs evidence      %d\n", s.Remediation.Summary.NeedsEvidence)
		fmt.Fprintf(w, "  Suppressed          %d\n", s.Remediation.Summary.Suppressed)
		fmt.Fprintln(w, "  Full view           chimera remediation")
	}

	if len(s.Findings) > 0 {
		fmt.Fprintln(w)
		FindingsHuman(w, s.Findings, verbose)
	}
}

func formatScanDuration(ms float64) string {
	if ms < 0 {
		return "UNAVAILABLE"
	}
	return (time.Duration(ms * float64(time.Millisecond))).String()
}

func scanValue(v string) string {
	if strings.TrimSpace(v) == "" {
		return "UNAVAILABLE"
	}
	return v
}

func shortDigest(v string) string {
	if len(v) <= 16 {
		return v
	}
	return v[:16]
}

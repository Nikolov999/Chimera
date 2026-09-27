package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/scheduled"
)

func ScheduledHuman(w io.Writer, inv scheduled.Inventory, verbose bool) {
	fmt.Fprintln(w, "SCHEDULED EXECUTION")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Entries            %d\n", inv.Summary.Entries)
	fmt.Fprintf(w, "  Enabled            %d\n", inv.Summary.Enabled)
	fmt.Fprintf(w, "  Disabled           %d\n", inv.Summary.Disabled)
	fmt.Fprintf(w, "  Privileged         %d\n", inv.Summary.Privileged)
	fmt.Fprintf(w, "  With action        %d\n", inv.Summary.WithAction)
	fmt.Fprintf(w, "  With definition    %d\n", inv.Summary.WithDefinition)
	fmt.Fprintf(w, "  systemd timers     %d\n", inv.Summary.SystemdTimers)
	fmt.Fprintf(w, "  cron entries       %d\n", inv.Summary.CronEntries)
	fmt.Fprintf(w, "  Windows tasks      %d\n", inv.Summary.WindowsTasks)
	fmt.Fprintf(w, "  launchd schedules  %d\n", inv.Summary.LaunchdSchedules)
	fmt.Fprintf(w, "  Broad-write action %d\n", inv.Summary.BroadlyWritableAction)
	fmt.Fprintf(w, "  Broad-write config %d\n", inv.Summary.BroadlyWritableDefinition)
	fmt.Fprintf(w, "  Referenced scripts  %d\n", inv.Summary.WithReferencedScript)
	fmt.Fprintf(w, "  Assessed workdirs   %d\n", inv.Summary.WorkingDirectoryAssessed)
	fmt.Fprintf(w, "  Broad-write workdir %d\n", inv.Summary.BroadlyWritableWorkdir)
	fmt.Fprintf(w, "  Hidden              %d\n", inv.Summary.Hidden)
	fmt.Fprintf(w, "  Hidden privileged   %d\n", inv.Summary.HiddenPrivileged)
	fmt.Fprintf(w, "  Custom privileged   %d\n", inv.Summary.CustomPrivilegedAccounts)
	fmt.Fprintln(w, "\nPROVIDERS")
	if len(inv.Sources) == 0 {
		fmt.Fprintln(w, "  No scheduled-execution provider status returned.")
	}
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-28s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", src.Reason)
		}
	}
	fmt.Fprintln(w, "\nENTRIES")
	if len(inv.Entries) == 0 {
		fmt.Fprintln(w, "  No scheduled-execution records were returned by available local providers.")
	}
	for _, e := range inv.Entries {
		action := e.ActionExecutable
		if action == "" {
			action = "UNAVAILABLE"
		}
		fmt.Fprintf(w, "  %-34s %-22s %-11s %-18s %s\n", truncate(e.Name, 34), truncate(e.Manager, 22), truncate(e.EnabledState, 11), truncate(e.Account, 18), truncate(action, 60))
		if verbose {
			fmt.Fprintf(w, "    id:          %s\n", e.ID)
			fmt.Fprintf(w, "    kind:        %s\n", e.Kind)
			fmt.Fprintf(w, "    schedule:    %s\n", truncate(e.Schedule, 140))
			if e.TriggerTarget != "" {
				fmt.Fprintf(w, "    target:      %s\n", truncate(e.TriggerTarget, 100))
			}
			fmt.Fprintf(w, "    privilege:   %s\n", e.PrivilegeContext)
			fmt.Fprintf(w, "    run-level:   %s\n", e.RunLevel)
			fmt.Fprintf(w, "    logon-type:  %s\n", e.LogonType)
			fmt.Fprintf(w, "    hidden:      %s\n", e.HiddenState)
			fmt.Fprintf(w, "    args:        present=%t (values not retained)\n", e.ArgumentsPresent)
			if e.ReferencedScriptPath != "" {
				fmt.Fprintf(w, "    script:      %s\n", truncate(e.ReferencedScriptPath, 120))
			}
			if e.WorkingDirectory != "" {
				fmt.Fprintf(w, "    workdir:     %s\n", truncate(e.WorkingDirectory, 120))
			}
			if e.DefinitionPath != "" {
				fmt.Fprintf(w, "    definition:  %s\n", truncate(e.DefinitionPath, 120))
			}
			fmt.Fprintf(w, "    action-path: %s broad-write=%t group-write=%t\n", e.ActionPath.State, e.ActionPath.BroadlyWritable, e.ActionPath.GroupWritable)
			fmt.Fprintf(w, "    action-dir:  %s broad-write=%t group-write=%t\n", e.ActionDirectoryPosture.State, e.ActionDirectoryPosture.BroadlyWritable, e.ActionDirectoryPosture.GroupWritable)
			if e.ReferencedScriptPath != "" {
				fmt.Fprintf(w, "    script-path: %s broad-write=%t group-write=%t\n", e.ReferencedScriptPathPosture.State, e.ReferencedScriptPathPosture.BroadlyWritable, e.ReferencedScriptPathPosture.GroupWritable)
			}
			fmt.Fprintf(w, "    workdir:     %s broad-write=%t group-write=%t\n", e.WorkingDirectoryPosture.State, e.WorkingDirectoryPosture.BroadlyWritable, e.WorkingDirectoryPosture.GroupWritable)
			fmt.Fprintf(w, "    def-path:    %s broad-write=%t group-write=%t\n", e.DefinitionPathPosture.State, e.DefinitionPathPosture.BroadlyWritable, e.DefinitionPathPosture.GroupWritable)
			fmt.Fprintf(w, "    def-dir:     %s broad-write=%t group-write=%t\n", e.DefinitionDirectoryPosture.State, e.DefinitionDirectoryPosture.BroadlyWritable, e.DefinitionDirectoryPosture.GroupWritable)
			fmt.Fprintf(w, "    source:      %s\n", e.CollectionSource)
			fmt.Fprintf(w, "    confidence:  %s\n", e.Confidence)
		}
	}
	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintln(w, "  - "+d)
		}
	}
}

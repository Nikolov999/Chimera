package render

import (
	"fmt"
	"io"

	"github.com/Nikolov999/chimera/internal/persistence"
)

func PersistenceHuman(w io.Writer, inv persistence.Inventory, verbose bool) {
	fmt.Fprintln(w, "PERSISTENCE")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))

	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Entries            %d\n", inv.Summary.Entries)
	fmt.Fprintf(w, "  Services           %d\n", inv.Summary.Services)
	fmt.Fprintf(w, "  Scheduled          %d\n", inv.Summary.Scheduled)
	fmt.Fprintf(w, "  Run keys           %d\n", inv.Summary.RunKeys)
	fmt.Fprintf(w, "  Startup folders    %d\n", inv.Summary.StartupFolders)
	fmt.Fprintf(w, "  systemd autostart  %d\n", inv.Summary.SystemdAutostart)
	fmt.Fprintf(w, "  XDG autostart      %d\n", inv.Summary.XDGAutostart)
	fmt.Fprintf(w, "  launchd            %d\n", inv.Summary.Launchd)
	fmt.Fprintf(w, "  Login items        %d\n", inv.Summary.LoginItems)
	fmt.Fprintf(w, "  Cron               %d\n", inv.Summary.Cron)
	fmt.Fprintf(w, "  Enabled            %d\n", inv.Summary.Enabled)
	fmt.Fprintf(w, "  Disabled           %d\n", inv.Summary.Disabled)
	fmt.Fprintf(w, "  Enabled unknown    %d\n", inv.Summary.UnknownEnabled)
	fmt.Fprintf(w, "  Privileged         %d\n", inv.Summary.Privileged)
	fmt.Fprintf(w, "  With executable    %d\n", inv.Summary.WithExecutable)
	fmt.Fprintf(w, "  With definition    %d\n", inv.Summary.WithDefinition)
	fmt.Fprintf(w, "  Path assessed      %d\n", inv.Summary.PathIntegrityAssessed)
	fmt.Fprintf(w, "  Weak paths         %d\n", inv.Summary.WeakPathEntries)
	fmt.Fprintf(w, "  Privileged weak    %d\n", inv.Summary.PrivilegedWeakPathEntries)
	fmt.Fprintf(w, "  Path unresolved    %d\n", inv.Summary.PathIntegrityUnresolved)
	fmt.Fprintf(w, "  Privilege joined   %d\n", inv.Summary.PrivilegeCorrelated)
	fmt.Fprintf(w, "  High privilege     %d\n", inv.Summary.HighPrivilegeExecution)
	fmt.Fprintf(w, "  Weak + high priv   %d\n", inv.Summary.WeakHighPrivilegeEntries)
	fmt.Fprintf(w, "  Privilege unknown  %d\n", inv.Summary.PrivilegeUnresolved)

	fmt.Fprintln(w, "\nPRIVILEGE / IDENTITY STATES")
	fmt.Fprintf(w, "  Local privileged      %d\n", inv.Summary.PrivilegeLocalPrivileged)
	fmt.Fprintf(w, "  Local standard        %d\n", inv.Summary.PrivilegeLocalStandard)
	fmt.Fprintf(w, "  Built-in SYSTEM       %d\n", inv.Summary.PrivilegeBuiltinSystem)
	fmt.Fprintf(w, "  Built-in service      %d\n", inv.Summary.PrivilegeBuiltinService)
	fmt.Fprintf(w, "  Service virtual       %d\n", inv.Summary.PrivilegeServiceVirtualAccount)
	fmt.Fprintf(w, "  Domain / external     %d\n", inv.Summary.PrivilegeDomainOrExternal)
	fmt.Fprintf(w, "  Identity not found    %d\n", inv.Summary.PrivilegeIdentityNotFound)
	fmt.Fprintf(w, "  Provider unavailable  %d\n", inv.Summary.PrivilegeProviderUnavailable)
	fmt.Fprintf(w, "  Group membership gap  %d\n", inv.Summary.PrivilegeGroupMembershipUnavailable)
	fmt.Fprintf(w, "  Identity unknown      %d\n", inv.Summary.PrivilegeStateUnknown)

	if len(inv.Entries) > 0 {
		fmt.Fprintln(w, "\nPERSISTENCE POINTS")
		limit := len(inv.Entries)
		if !verbose && limit > 80 {
			limit = 80
		}
		for _, e := range inv.Entries[:limit] {
			fmt.Fprintf(w, "  %-18s %-22s %-9s %-10s %s\n", e.Mechanism, e.Name, e.Scope, e.EnabledState, value(e.ExecutablePath))
			if verbose {
				fmt.Fprintf(w, "    id=%s manager=%s account=%s privilege=%s runtime=%s args_present=%t path_state=%s privileged_path=%t\n", e.ID, e.Manager, e.Account, e.PrivilegeContext, e.RuntimeState, e.ArgumentsPresent, e.PathIntegrity.State, e.PathIntegrity.Privileged)
				fmt.Fprintf(w, "    privilege-correlation: state=%s privilege_state=%s level=%s account_match=%s high_privilege=%t risk=%s\n", e.PrivilegeCorrelation.State, e.PrivilegeCorrelation.PrivilegeState, e.PrivilegeCorrelation.ExecutionLevel, e.PrivilegeCorrelation.AccountMatchState, e.PrivilegeCorrelation.HighPrivilege, e.PrivilegeCorrelation.RiskContext)
				if e.PrivilegeCorrelation.PrincipalSID != "" {
					fmt.Fprintf(w, "    principal sid: %s\n", e.PrivilegeCorrelation.PrincipalSID)
				}
				if len(e.PrivilegeCorrelation.PrivilegeBasis) > 0 {
					fmt.Fprintf(w, "    privilege basis: %v\n", e.PrivilegeCorrelation.PrivilegeBasis)
				}
				if e.PrivilegeCorrelation.Reason != "" {
					fmt.Fprintf(w, "    privilege reason: %s\n", e.PrivilegeCorrelation.Reason)
				}
				if len(e.PathIntegrity.WeakRoles) > 0 {
					fmt.Fprintf(w, "    weak-path roles: %v\n", e.PathIntegrity.WeakRoles)
				}
				if e.DefinitionPath != "" {
					fmt.Fprintf(w, "    definition: %s\n", e.DefinitionPath)
				}
				fmt.Fprintf(w, "    source: %s\n", e.CollectionSource)
			}
		}
		if limit < len(inv.Entries) {
			fmt.Fprintf(w, "  ... %d additional persistence point(s); use --verbose or --json\n", len(inv.Entries)-limit)
		}
	}

	if verbose && len(inv.Sources) > 0 {
		fmt.Fprintln(w, "\nPROVIDERS")
		for _, s := range inv.Sources {
			fmt.Fprintf(w, "  %-28s %-14s items=%d %s\n", s.ID, s.State, s.ItemCount, s.Source)
			if s.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", s.Reason)
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

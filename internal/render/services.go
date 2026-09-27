package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/services"
)

func ServicesHuman(w io.Writer, inv services.Inventory, verbose bool) {
	fmt.Fprintln(w, "SERVICES")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))

	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Services           %d\n", inv.Summary.Services)
	fmt.Fprintf(w, "  Inventory ID       %s\n", inv.Summary.InventoryFingerprint)
	fmt.Fprintf(w, "  Running            %d\n", inv.Summary.Running)
	fmt.Fprintf(w, "  Stopped            %d\n", inv.Summary.Stopped)
	fmt.Fprintf(w, "  Runtime unknown    %d\n", inv.Summary.RuntimeUnknown)
	fmt.Fprintf(w, "  Enabled            %d\n", inv.Summary.Enabled)
	fmt.Fprintf(w, "  Disabled           %d\n", inv.Summary.Disabled)
	fmt.Fprintf(w, "  Start mode unknown %d\n", inv.Summary.StartModeUnknown)
	fmt.Fprintf(w, "  Privileged         %d\n", inv.Summary.Privileged)
	fmt.Fprintf(w, "  With runtime PID   %d\n", inv.Summary.WithRuntimePID)
	fmt.Fprintf(w, "  With executable    %d\n", inv.Summary.WithExecutablePath)
	fmt.Fprintf(w, "  Config provenance  %d\n", inv.Summary.WithConfigurationSource)
	fmt.Fprintf(w, "  Path integrity     %d\n", inv.Summary.PathIntegrityAssessed)
	fmt.Fprintf(w, "  Path complete      %d\n", inv.Summary.PathIntegrityComplete)
	fmt.Fprintf(w, "  Path degraded      %d\n", inv.Summary.PathIntegrityDegraded)
	fmt.Fprintf(w, "  Priv path assessed %d\n", inv.Summary.PrivilegedPathAssessed)
	fmt.Fprintf(w, "  Priv weak exec     %d\n", inv.Summary.PrivilegedWeakExecutable)
	fmt.Fprintf(w, "  Priv weak config   %d\n", inv.Summary.PrivilegedWeakConfiguration)
	fmt.Fprintf(w, "  Priv weak search   %d\n", inv.Summary.PrivilegedWeakSearchPath)
	fmt.Fprintf(w, "  Exposure classified %d\n", inv.Summary.ExposureClassified)
	fmt.Fprintf(w, "  Remote capable     %d\n", inv.Summary.RemoteCapable)
	fmt.Fprintf(w, "  Active remote role %d\n", inv.Summary.ActiveRemoteCapable)
	fmt.Fprintf(w, "  Legacy remote role %d\n", inv.Summary.LegacyRemoteCapable)
	fmt.Fprintf(w, "  Insecure remote    %d\n", inv.Summary.InsecureRemoteCapable)
	if inv.Platform == "windows" {
		fmt.Fprintf(w, "  Security assessed  %d\n", inv.Summary.WindowsSecurityAssessed)
		fmt.Fprintf(w, "  Security complete  %d\n", inv.Summary.WindowsSecurityComplete)
		fmt.Fprintf(w, "  Security degraded  %d\n", inv.Summary.WindowsSecurityDegraded)
		fmt.Fprintf(w, "  Unquoted paths     %d\n", inv.Summary.UnquotedServicePaths)
		fmt.Fprintf(w, "  Writable code      %d\n", inv.Summary.WritableExecutables)
		fmt.Fprintf(w, "  Writable dirs      %d\n", inv.Summary.WritableDirectories)
		fmt.Fprintf(w, "  Weak service ACLs  %d\n", inv.Summary.WeakServiceACLs)
		fmt.Fprintf(w, "  Control-only ACLs  %d\n", inv.Summary.ControlOnlyServiceACLs)
		fmt.Fprintf(w, "  Admin svc accounts %d\n", inv.Summary.AdminServiceAccounts)
		fmt.Fprintf(w, "  Interactive svc    %d\n", inv.Summary.InteractiveServices)
		fmt.Fprintf(w, "  Weak recovery      %d\n", inv.Summary.WeakRecoveryCommands)
		fmt.Fprintln(w, "  Component coverage observed/degraded/denied/unavailable/N/A")
		renderSecurityCoverage(w, "SCM configuration", inv.Summary.WindowsSecurityCoverage.BaseConfiguration)
		renderSecurityCoverage(w, "Executable path", inv.Summary.WindowsSecurityCoverage.ExecutablePath)
		renderSecurityCoverage(w, "Executable ACL", inv.Summary.WindowsSecurityCoverage.ExecutableACL)
		renderSecurityCoverage(w, "Executable dir ACL", inv.Summary.WindowsSecurityCoverage.ExecutableDirectoryACL)
		renderSecurityCoverage(w, "Path resolution", inv.Summary.WindowsSecurityCoverage.ExecutableResolution)
		renderSecurityCoverage(w, "Service object", inv.Summary.WindowsSecurityCoverage.ServiceObject)
		renderSecurityCoverage(w, "Registry metadata", inv.Summary.WindowsSecurityCoverage.RegistryMetadata)
		renderSecurityCoverage(w, "Registry ACL", inv.Summary.WindowsSecurityCoverage.RegistryACL)
		renderSecurityCoverage(w, "ServiceDll", inv.Summary.WindowsSecurityCoverage.ServiceDLL)
		renderSecurityCoverage(w, "Recovery command", inv.Summary.WindowsSecurityCoverage.RecoveryCommand)
		renderSecurityCoverage(w, "Service account", inv.Summary.WindowsSecurityCoverage.Account)
		renderSecurityCoverage(w, "Path integrity", inv.Summary.WindowsSecurityCoverage.PathIntegrity)
	}
	if inv.Platform == "linux" {
		fmt.Fprintf(w, "  systemd assessed   %d\n", inv.Summary.SystemdHardeningAssessed)
		fmt.Fprintf(w, "  NoNewPrivileges    %d\n", inv.Summary.SystemdNoNewPrivileges)
		fmt.Fprintf(w, "  ProtectSystem      %d\n", inv.Summary.SystemdProtectSystem)
		fmt.Fprintf(w, "  ProtectHome        %d\n", inv.Summary.SystemdProtectHome)
		fmt.Fprintf(w, "  PrivateTmp         %d\n", inv.Summary.SystemdPrivateTmp)
		fmt.Fprintf(w, "  Capability bounded %d\n", inv.Summary.SystemdCapabilityBounded)
		fmt.Fprintf(w, "  Namespace restrict %d\n", inv.Summary.SystemdNamespaceRestricted)
	}

	fmt.Fprintln(w, "\nPROVIDERS")
	if len(inv.Sources) == 0 {
		fmt.Fprintln(w, "  No provider status returned.")
	}
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-28s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", src.Reason)
		}
	}

	fmt.Fprintln(w, "\nSERVICES")
	if len(inv.Services) == 0 {
		fmt.Fprintln(w, "  No service records were returned by the available local provider.")
	}
	for _, s := range inv.Services {
		path := s.ExecutablePath
		if path == "" {
			path = "UNAVAILABLE"
		}
		fmt.Fprintf(w, "  %-34s %-12s %-11s %-22s %s\n", truncate(s.Name, 34), truncate(s.RuntimeState, 12), truncate(s.StartMode, 11), truncate(s.Account, 22), truncate(path, 64))
		if verbose {
			fmt.Fprintf(w, "    id:          %s\n", s.ID)
			fmt.Fprintf(w, "    manager:     %s\n", s.Manager)
			if s.ServiceType != "" {
				fmt.Fprintf(w, "    type:        %s\n", s.ServiceType)
			}
			if s.Description != "" {
				fmt.Fprintf(w, "    description: %s\n", truncate(s.Description, 120))
			}
			fmt.Fprintf(w, "    runtime:     %s", s.RuntimeState)
			if s.SubState != "" {
				fmt.Fprintf(w, "/%s", s.SubState)
			}
			if s.RuntimePID > 0 {
				fmt.Fprintf(w, " pid=%d", s.RuntimePID)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "    privilege:   %s\n", s.PrivilegeContext)
			if s.DefinitionState != "" {
				fmt.Fprintf(w, "    definition:  %s\n", s.DefinitionState)
			}
			if s.DefinitionPath != "" {
				fmt.Fprintf(w, "    config-path: %s\n", truncate(s.DefinitionPath, 120))
			}
			fmt.Fprintf(w, "    provenance:  %s\n", truncate(s.ConfigurationSource, 120))
			fmt.Fprintf(w, "    source:      %s\n", s.CollectionSource)
			fmt.Fprintf(w, "    confidence:  %s\n", s.Confidence)
			if ws := s.WindowsSecurity; ws != nil {
				fmt.Fprintf(w, "    win-security: %s\n", ws.State)
				fmt.Fprintf(w, "      components:         object=%s exe=%s exe-dir=%s registry=%s registry-acl=%s account=%s\n", ws.Components.ServiceObject, ws.Components.ExecutableACL, ws.Components.ExecutableDirectoryACL, ws.Components.RegistryMetadata, ws.Components.RegistryACL, ws.Components.Account)
				fmt.Fprintf(w, "      optional-components:dll=%s dll-dir=%s recovery=%s recovery-dir=%s\n", ws.Components.ServiceDLLACL, ws.Components.ServiceDLLDirectoryACL, ws.Components.RecoveryExecutableACL, ws.Components.RecoveryExecutableDirACL)
				fmt.Fprintf(w, "      executable-resolution:%s unquoted=%t\n", ws.ExecutableResolution, ws.UnquotedExecutablePath)
				fmt.Fprintf(w, "      executable-acl:     %s broad-write=%t owner=%s inherited-write=%t\n", ws.ExecutableACL.State, ws.ExecutableACL.BroadWriteGranted, fallbackRender(ws.ExecutableACL.OwnerSID, "UNKNOWN"), ws.ExecutableACL.InheritedWrite)
				fmt.Fprintf(w, "      executable-dir-acl: %s broad-write=%t owner=%s inherited-write=%t\n", ws.ExecutableDirectoryACL.State, ws.ExecutableDirectoryACL.BroadWriteGranted, fallbackRender(ws.ExecutableDirectoryACL.OwnerSID, "UNKNOWN"), ws.ExecutableDirectoryACL.InheritedWrite)
				if ws.ServiceDLLPath != "" {
					fmt.Fprintf(w, "      service-dll:        %s\n", truncate(ws.ServiceDLLPath, 120))
					fmt.Fprintf(w, "      service-dll-acl:    %s broad-write=%t\n", ws.ServiceDLLACL.State, ws.ServiceDLLACL.BroadWriteGranted)
				}
				fmt.Fprintf(w, "      service-object-acl: %s weak=%t dangerous=%t control-only=%t\n", ws.ServiceACL.State, ws.ServiceACL.Weak, ws.ServiceACL.Dangerous, ws.ServiceACL.ControlOnly)
				fmt.Fprintf(w, "      account-local-admin:%s\n", ws.AccountAdminState)
				fmt.Fprintf(w, "      registry-metadata:  %s interactive=%t\n", ws.RegistryState, ws.InteractiveProcess)
				fmt.Fprintf(w, "      registry-acl:       %s broad-write=%t owner=%s inherited-write=%t\n", ws.RegistryACL.State, ws.RegistryACL.BroadWriteGranted, fallbackRender(ws.RegistryACL.OwnerSID, "UNKNOWN"), ws.RegistryACL.InheritedWrite)
				if ws.FailureCommandPresent {
					path := ws.FailureExecutablePath
					if path == "" {
						path = "UNRESOLVED"
					}
					fmt.Fprintf(w, "      failure-executable: %s unquoted=%t\n", truncate(path, 120), ws.FailureExecutableUnquoted)
				}
				for _, d := range ws.Degraded {
					fmt.Fprintf(w, "      degraded:           %s\n", truncate(d, 120))
				}
			}
			if ep := s.Exposure; ep != nil {
				fmt.Fprintf(w, "    exposure:       %s family=%s role=%s activity=%s\n", ep.State, ep.Family, ep.Role, ep.Activity)
				fmt.Fprintf(w, "      remote=%t legacy=%t deprecated=%t cleartext-capable=%t insecure-by-design=%t reachability=%s\n", ep.RemoteCapable, ep.Legacy, ep.Deprecated, ep.CleartextCapable, ep.InsecureByDesign, ep.NetworkReachability)
				if len(ep.RiskTags) > 0 {
					fmt.Fprintf(w, "      risk-tags:      %s\n", strings.Join(ep.RiskTags, ", "))
				}
			}
			if pi := s.PathIntegrity; pi != nil {
				fmt.Fprintf(w, "    path-integrity:  %s privileged=%t basis=%s\n", pi.State, pi.Privileged, pi.PrivilegeBasis)
				fmt.Fprintf(w, "      executable:    %s weak-write=%t %s\n", pi.Executable.State, pi.Executable.LowerPrivilegeWritable, truncate(pi.Executable.Path, 100))
				fmt.Fprintf(w, "      executable-dir:%s weak-write=%t %s\n", pi.ExecutableDirectory.State, pi.ExecutableDirectory.LowerPrivilegeWritable, truncate(pi.ExecutableDirectory.Path, 100))
				fmt.Fprintf(w, "      configuration: %s weak-write=%t %s\n", pi.Configuration.State, pi.Configuration.LowerPrivilegeWritable, truncate(pi.Configuration.Path, 100))
				fmt.Fprintf(w, "      config-dir:     %s weak-write=%t %s\n", pi.ConfigurationDirectory.State, pi.ConfigurationDirectory.LowerPrivilegeWritable, truncate(pi.ConfigurationDirectory.Path, 100))
				if pi.ServiceDLL != nil {
					fmt.Fprintf(w, "      service-dll:    %s weak-write=%t %s\n", pi.ServiceDLL.State, pi.ServiceDLL.LowerPrivilegeWritable, truncate(pi.ServiceDLL.Path, 100))
				}
				if pi.ServiceDLLDirectory != nil {
					fmt.Fprintf(w, "      service-dll-dir:%s weak-write=%t %s\n", pi.ServiceDLLDirectory.State, pi.ServiceDLLDirectory.LowerPrivilegeWritable, truncate(pi.ServiceDLLDirectory.Path, 100))
				}
				if pi.RecoveryExecutable != nil {
					fmt.Fprintf(w, "      recovery-exe:   %s weak-write=%t %s\n", pi.RecoveryExecutable.State, pi.RecoveryExecutable.LowerPrivilegeWritable, truncate(pi.RecoveryExecutable.Path, 100))
				}
				if pi.RecoveryExecutableDirectory != nil {
					fmt.Fprintf(w, "      recovery-dir:   %s weak-write=%t %s\n", pi.RecoveryExecutableDirectory.State, pi.RecoveryExecutableDirectory.LowerPrivilegeWritable, truncate(pi.RecoveryExecutableDirectory.Path, 100))
				}
				fmt.Fprintf(w, "      resolution:     %s state=%s weak-write=%t\n", pi.SearchResolution, pi.SearchPathState, pi.SearchPathWritable)
				if len(pi.WeakRoles) > 0 {
					fmt.Fprintf(w, "      weak-roles:     %s\n", strings.Join(pi.WeakRoles, ", "))
				}
				for _, d := range pi.Degraded {
					fmt.Fprintf(w, "      degraded:       %s\n", truncate(d, 120))
				}
			}
			if sh := s.SystemdHardening; sh != nil {
				fmt.Fprintf(w, "    systemd-hardening: %s\n", sh.State)
				fmt.Fprintf(w, "      identity:            user=%s configured=%t group=%s configured=%t dynamic=%s\n", truncate(sh.User, 40), sh.UserConfigured, truncate(sh.Group, 40), sh.GroupConfigured, sh.DynamicUser)
				fmt.Fprintf(w, "      no-new-privileges:   %s\n", sh.NoNewPrivileges)
				fmt.Fprintf(w, "      filesystem:          ProtectSystem=%s ProtectHome=%s PrivateTmp=%s\n", sh.ProtectSystem, sh.ProtectHome, sh.PrivateTmp)
				fmt.Fprintf(w, "      namespaces/devices:  RestrictNamespaces=%s PrivateDevices=%s PrivateNetwork=%s\n", sh.RestrictNamespacesState, sh.PrivateDevices, sh.PrivateNetwork)
				fmt.Fprintf(w, "      capabilities:        bounding=%s ambient=%d\n", sh.CapabilityBoundingSetState, len(sh.AmbientCapabilities))
				fmt.Fprintf(w, "      kernel-surfaces:     tunables=%s modules=%s cgroups=%s\n", sh.ProtectKernelTunables, sh.ProtectKernelModules, sh.ProtectControlGroups)
				fmt.Fprintf(w, "      execution:           RestrictSUIDSGID=%s LockPersonality=%s MemoryDenyWriteExecute=%s\n", sh.RestrictSUIDSGID, sh.LockPersonality, sh.MemoryDenyWriteExecute)
				if sh.UMask != "" {
					fmt.Fprintf(w, "      umask:               %s\n", sh.UMask)
				}
				for _, d := range sh.Degraded {
					fmt.Fprintf(w, "      degraded:            %s\n", truncate(d, 120))
				}
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

func renderSecurityCoverage(w io.Writer, label string, c services.SecurityComponentCoverage) {
	fmt.Fprintf(w, "    %-20s %d/%d/%d/%d/%d\n", label, c.Observed, c.Degraded, c.Denied, c.Unavailable, c.NotApplicable)
}

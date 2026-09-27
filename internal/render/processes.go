package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/processes"
)

func ProcessesHuman(w io.Writer, inv processes.Inventory, verbose bool) {
	fmt.Fprintln(w, "PROCESS SECURITY INVENTORY")
	fmt.Fprintf(w, "  Platform          %s/%s\n", value(inv.Platform), value(inv.Architecture))
	fmt.Fprintf(w, "  Processes         %d\n", inv.Summary.Processes)
	fmt.Fprintf(w, "  Elevated          %d\n", inv.Summary.Elevated)
	fmt.Fprintf(w, "  Executable paths  %d\n", inv.Summary.WithExecutablePath)
	fmt.Fprintf(w, "  Command metadata  %d\n", inv.Summary.WithCommandMetadata)
	fmt.Fprintf(w, "  Isolated          %d\n", inv.Summary.Isolated)
	fmt.Fprintf(w, "  Deleted backing   %d\n", inv.Summary.DeletedBacking)
	fmt.Fprintf(w, "  Trust unknown     %d\n", inv.Summary.TrustUnknown)
	fmt.Fprintf(w, "  Permission weak   %d\n", inv.Summary.PermissionWeak)
	fmt.Fprintf(w, "  Permission unknown %d\n", inv.Summary.PermissionUnknown)
	fmt.Fprintf(w, "  Executable write  %d\n", inv.Summary.ExecutableWriteWeak)
	fmt.Fprintf(w, "  Parent-dir write  %d\n", inv.Summary.ParentDirectoryWeak)
	fmt.Fprintf(w, "  Privilege observed %d\n", inv.Summary.PrivilegeObserved)
	fmt.Fprintf(w, "  Privilege elevated %d\n", inv.Summary.PrivilegeElevated)
	fmt.Fprintf(w, "  Privilege excess  %d\n", inv.Summary.PrivilegeExcess)
	fmt.Fprintf(w, "  Privilege unknown %d\n", inv.Summary.PrivilegeUnknown)
	fmt.Fprintf(w, "  Identity transitions %d\n", inv.Summary.IdentityTransitions)
	fmt.Fprintf(w, "  High-impact sets  %d\n", inv.Summary.HighImpactPrivilegeSets)
	fmt.Fprintf(w, "  Memory observed   %d\n", inv.Summary.MemoryObserved)
	fmt.Fprintf(w, "  Memory unknown    %d\n", inv.Summary.MemoryUnknown)
	fmt.Fprintf(w, "  W+X processes     %d\n", inv.Summary.WritableExecutableMemory)
	fmt.Fprintf(w, "  Anonymous exec    %d\n", inv.Summary.AnonymousExecutableMemory)
	fmt.Fprintf(w, "  JIT-like contexts %d\n", inv.Summary.JITLikeContexts)
	fmt.Fprintf(w, "  Loaded modules    %d\n", inv.Summary.LoadedModules)
	fmt.Fprintf(w, "  Deleted modules   %d\n", inv.Summary.DeletedLoadedModules)
	fmt.Fprintf(w, "  Module trust fail %d\n", inv.Summary.ModuleTrustFailures)
	fmt.Fprintf(w, "  Unsigned modules  %d\n", inv.Summary.UnsignedLoadedModules)
	fmt.Fprintf(w, "  Unmanaged modules %d\n", inv.Summary.UnmanagedLoadedModules)
	fmt.Fprintf(w, "  Writable mod dirs %d\n", inv.Summary.WritableModuleLocations)
	fmt.Fprintf(w, "  Trust mismatches  %d\n", inv.Summary.ModuleTrustMismatches)
	fmt.Fprintf(w, "  Isolation observed %d\n", inv.Summary.IsolationObserved)
	fmt.Fprintf(w, "  Isolation unknown %d\n", inv.Summary.IsolationUnknown)
	fmt.Fprintf(w, "  Fully isolated    %d\n", inv.Summary.IsolationIsolated)
	fmt.Fprintf(w, "  Partial isolation %d\n", inv.Summary.IsolationPartial)
	fmt.Fprintf(w, "  Namespaced        %d\n", inv.Summary.NamespaceIsolated)
	fmt.Fprintf(w, "  Seccomp filtered  %d\n", inv.Summary.SeccompFiltered)
	fmt.Fprintf(w, "  NoNewPrivileges   %d\n", inv.Summary.NoNewPrivileges)
	fmt.Fprintf(w, "  Container context %d\n", inv.Summary.ContainerContexts)
	fmt.Fprintf(w, "  AppContainer      %d\n", inv.Summary.AppContainerContexts)
	fmt.Fprintf(w, "  Job object        %d\n", inv.Summary.JobObjectContexts)
	fmt.Fprintf(w, "  Sandbox context   %d\n", inv.Summary.SandboxContexts)
	fmt.Fprintf(w, "  Env observed      %d\n", inv.Summary.EnvironmentObserved)
	fmt.Fprintf(w, "  Env unknown       %d\n", inv.Summary.EnvironmentUnknown)
	fmt.Fprintf(w, "  Env overrides     %d\n", inv.Summary.EnvironmentOverrides)
	fmt.Fprintf(w, "  Env high-risk     %d\n", inv.Summary.EnvironmentHighRisk)
	fmt.Fprintf(w, "  Loader env hooks  %d\n", inv.Summary.LoaderEnvironmentHooks)
	fmt.Fprintf(w, "  Runtime paths     %d\n", inv.Summary.RuntimeSearchOverrides)
	fmt.Fprintf(w, "  Startup hooks     %d\n", inv.Summary.RuntimeStartupHooks)
	fmt.Fprintf(w, "  Debug controls    %d\n", inv.Summary.RuntimeDebugControls)
	fmt.Fprintf(w, "  Proxy overrides   %d\n", inv.Summary.RuntimeProxyOverrides)
	fmt.Fprintf(w, "  TLS key logging   %d\n", inv.Summary.TLSKeyLoggingContexts)

	fmt.Fprintln(w, "\nPROVIDERS")
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-26s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", src.Reason)
		}
	}

	permissions := make(map[string]processes.PathPermissionContext, len(inv.PathPermissions))
	for _, c := range inv.PathPermissions {
		permissions[c.ProcessID] = c
	}
	privileges := make(map[string]processes.RuntimePrivilegeContext, len(inv.RuntimePrivileges))
	for _, c := range inv.RuntimePrivileges {
		privileges[c.ProcessID] = c
	}
	memory := make(map[string]processes.ExecutionMemoryContext, len(inv.ExecutionMemory))
	for _, c := range inv.ExecutionMemory {
		memory[c.ProcessID] = c
	}
	modules := make(map[string]processes.LoadedModuleContext, len(inv.LoadedModules))
	for _, c := range inv.LoadedModules {
		modules[c.ProcessID] = c
	}
	isolation := make(map[string]processes.IsolationContext, len(inv.IsolationPosture))
	for _, c := range inv.IsolationPosture {
		isolation[c.ProcessID] = c
	}
	environments := make(map[string]processes.RuntimeEnvironmentContext, len(inv.RuntimeEnvironment))
	for _, c := range inv.RuntimeEnvironment {
		environments[c.ProcessID] = c
	}

	fmt.Fprintln(w, "\nPROCESSES")
	if len(inv.Processes) == 0 {
		fmt.Fprintln(w, "  No process records were returned by the available local provider.")
	}
	for _, p := range inv.Processes {
		principal := p.Principal.User
		if principal == "" {
			principal = "UNKNOWN"
		}
		path := p.ExecutablePath
		if path == "" {
			path = p.Executable
		}
		fmt.Fprintf(w, "  %-7d %-7d %-24s %-24s %s\n", p.PID, p.PPID, truncate(p.Name, 24), truncate(principal, 24), truncate(path, 52))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", p.ID)
			fmt.Fprintf(w, "    session:    %s\n", p.SessionID)
			fmt.Fprintf(w, "    state:      %s\n", p.RuntimeState)
			fmt.Fprintf(w, "    privilege:  %s — %s\n", p.PrivilegeContext, p.Principal.Context)
			fmt.Fprintf(w, "    command:    available=%t args=%d bytes=%d redacted=%t\n", p.CommandLine.Available, p.CommandLine.ArgumentCount, p.CommandLine.ByteCount, p.CommandLine.Redacted)
			fmt.Fprintf(w, "    trust:      %s — %s\n", p.Trust.State, p.Trust.Basis)
			if p.Trust.Signature != "" {
				fmt.Fprintf(w, "    signature:  %s\n", p.Trust.Signature)
			}
			fmt.Fprintf(w, "    isolation:  %s", p.Isolation.State)
			if p.Isolation.Seccomp != "" {
				fmt.Fprintf(w, " seccomp=%s", p.Isolation.Seccomp)
			}
			if p.Isolation.NoNewPrivileges {
				fmt.Fprint(w, " no-new-privileges=true")
			}
			fmt.Fprintln(w)
			if p.Isolation.Reason != "" {
				fmt.Fprintf(w, "    isolation-reason: %s\n", p.Isolation.Reason)
			}
			fmt.Fprintf(w, "    source:     %s\n", p.CollectionSource)
			fmt.Fprintf(w, "    confidence: %s\n", p.Confidence)
			if c, ok := privileges[p.ID]; ok {
				fmt.Fprintf(w, "    runtime-privilege: %s account=%s integrity=%s token=%s privilege-set=%s\n", c.State, c.AccountClass, value(c.IntegrityLevel), value(c.TokenElevation), c.PrivilegeSetState)
				if c.RealUserID != "" || c.EffectiveUserID != "" {
					fmt.Fprintf(w, "    identity:    ruid=%s euid=%s rgid=%s egid=%s transition=%t\n", value(c.RealUserID), value(c.EffectiveUserID), value(c.RealGroupID), value(c.EffectiveGroupID), c.IdentityTransition)
				}
				if len(c.HighImpactPrivileges) > 0 {
					fmt.Fprintf(w, "    high-impact: %s\n", strings.Join(c.HighImpactPrivileges, ", "))
				}
				if len(c.ExcessSignals) > 0 {
					fmt.Fprintf(w, "    privilege-signals: %s\n", strings.Join(c.ExcessSignals, "; "))
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    privilege-reason: %s\n", c.Reason)
				}
			}
			if c, ok := permissions[p.ID]; ok {
				fmt.Fprintf(w, "    permissions: %s executable-write=%t parent-write=%t broad-file=%t broad-parent=%t\n", c.State, c.UntrustedExecutableWrite, c.UntrustedParentWrite, c.BroadExecutableWrite, c.BroadParentWrite)
				if len(c.Reasons) > 0 {
					fmt.Fprintf(w, "    permission-reason: %s\n", strings.Join(c.Reasons, "; "))
				}
			}
			if c, ok := memory[p.ID]; ok {
				fmt.Fprintf(w, "    exec-memory: %s regions=%d executable=%d w+x=%d anonymous-exec=%d file-backed-exec=%d deleted-exec=%d jit-like=%t\n", c.State, c.RegionsObserved, c.ExecutableRegions, c.WritableExecutableRegions, c.AnonymousExecutableRegions, c.FileBackedExecutableRegions, c.DeletedExecutableRegions, c.JITLikeContext)
				if len(c.JITBasis) > 0 {
					fmt.Fprintf(w, "    jit-basis:    %s\n", strings.Join(c.JITBasis, ", "))
				}
				if len(c.Signals) > 0 {
					fmt.Fprintf(w, "    memory-signals: %s\n", strings.Join(c.Signals, "; "))
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    memory-reason: %s\n", c.Reason)
				}
			}
			if c, ok := isolation[p.ID]; ok {
				fmt.Fprintf(w, "    isolation-posture: %s provider=%s namespaces=%d seccomp=%s nnp=%t cgroup-scoped=%t container=%t appcontainer=%s job=%s sandbox=%s\n", c.IsolationState, c.State, c.NamespaceCount, value(c.Seccomp), c.NoNewPrivileges, c.CgroupScoped, c.ContainerHint, value(c.AppContainer), value(c.JobObject), value(c.Sandbox))
				if c.Cgroup != "" {
					fmt.Fprintf(w, "    cgroup:       %s\n", truncate(c.Cgroup, 120))
				}
				if c.ContainerRuntime != "" {
					fmt.Fprintf(w, "    container:    %s\n", c.ContainerRuntime)
				}
				if c.LSMProfile != "" {
					fmt.Fprintf(w, "    lsm-profile:  %s\n", truncate(c.LSMProfile, 120))
				}
				if len(c.Signals) > 0 {
					fmt.Fprintf(w, "    isolation-signals: %s\n", strings.Join(c.Signals, "; "))
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    isolation-detail: %s\n", c.Reason)
				}
			}
			if c, ok := environments[p.ID]; ok {
				fmt.Fprintf(w, "    environment: %s posture=%s vars=%d relevant=%d high-risk=%d redacted=%t\n", c.State, c.Posture, c.VariablesObserved, c.RelevantVariables, c.HighRiskIndicators, c.ValuesRedacted)
				if len(c.Indicators) > 0 {
					for _, ind := range c.Indicators {
						fmt.Fprintf(w, "      env: %s category=%s risk=%s components=%d relative=%d empty=%d temporary=%d\n", ind.Name, ind.Category, ind.RiskClass, ind.ComponentCount, ind.RelativeComponents, ind.EmptyComponents, ind.TemporaryComponents)
						if len(ind.PatternClasses) > 0 {
							fmt.Fprintf(w, "        patterns: %s\n", strings.Join(ind.PatternClasses, ", "))
						}
					}
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    environment-detail: %s\n", c.Reason)
				}
			}
			if c, ok := modules[p.ID]; ok {
				fmt.Fprintf(w, "    modules:     %s count=%d deleted=%d trust-fail=%d unsigned=%d unmanaged=%d writable-dirs=%d mismatches=%d\n", c.State, c.ModuleCount, c.DeletedMappings, c.ExplicitTrustFailures, c.UnsignedModules, c.UnmanagedModules, c.WritableLocationModules, c.TrustMismatches)
				limit := len(c.Modules)
				if limit > 64 {
					limit = 64
				}
				for i := 0; i < limit; i++ {
					m := c.Modules[i]
					fmt.Fprintf(w, "      module: %s trust=%s dir=%s writable=%t deleted=%t mismatch=%t\n", truncate(m.Path, 76), m.TrustState, m.DirectoryState, m.DirectoryWritable, m.DeletedBacking, m.TrustMismatch)
				}
				if len(c.Modules) > limit {
					fmt.Fprintf(w, "      ... %d additional module record(s) omitted from terminal view\n", len(c.Modules)-limit)
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    module-reason: %s\n", c.Reason)
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

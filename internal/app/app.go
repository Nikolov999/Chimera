package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/assessmentdiff"
	"github.com/Nikolov999/chimera/internal/baseline"
	"github.com/Nikolov999/chimera/internal/cli"
	"github.com/Nikolov999/chimera/internal/config"
	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/doctor"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/exporter"
	"github.com/Nikolov999/chimera/internal/filesystem"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/kernel"
	"github.com/Nikolov999/chimera/internal/lifecycle"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/persistence"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/processes"
	"github.com/Nikolov999/chimera/internal/productnorm"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
	"github.com/Nikolov999/chimera/internal/render"
	"github.com/Nikolov999/chimera/internal/report"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/scheduled"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/services"
	"github.com/Nikolov999/chimera/internal/snapshot"
	"github.com/Nikolov999/chimera/internal/software"
	"github.com/Nikolov999/chimera/internal/storage"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/terminalui"
	"github.com/Nikolov999/chimera/internal/updateposture"
	"github.com/Nikolov999/chimera/internal/version"
	"github.com/Nikolov999/chimera/internal/vulnerability"
)

type Help struct {
	Purpose      string
	Usage        string
	Examples     []string
	Output       string
	Safety       string
	Requirements string
	NextSteps    string
}

type Command struct {
	Name      string
	Lane      string
	Summary   string
	Help      Help
	MinArgs   int
	MaxArgs   int
	ArgSyntax string
	Run       func(context.Context, io.Writer, cli.Options, Runtime) error
}

type Runtime struct {
	ConfigSources   []string
	Args            []string
	SelectedProfile profile.Descriptor
	ProfileCatalog  []profile.Descriptor
	Suppressions    []suppression.Definition
}

type envelope struct {
	Command string       `json:"command"`
	Version version.Info `json:"version"`
	Data    any          `json:"data"`
}

type softwareCommandData struct {
	software.Inventory
	ProductNormalization productnorm.Result   `json:"product_normalization"`
	Lifecycle            lifecycle.Result     `json:"lifecycle"`
	UpdatePosture        updateposture.Result `json:"update_posture"`
}

type vulnerabilitiesCommandData struct {
	Software             software.Inventory               `json:"software"`
	ProductNormalization productnorm.Result               `json:"product_normalization"`
	Correlation          vulnerability.Result             `json:"vulnerability_correlation"`
	Reachability         vulnerability.ReachabilityResult `json:"vulnerability_reachability"`
	Lifecycle            lifecycle.Result                 `json:"lifecycle"`
	UpdatePosture        updateposture.Result             `json:"update_posture"`
}

type effectiveConfig struct {
	JSON                bool     `json:"json"`
	Plain               bool     `json:"plain"`
	NoColor             bool     `json:"no_color"`
	Quiet               bool     `json:"quiet"`
	Verbose             bool     `json:"verbose"`
	Timeout             string   `json:"timeout"`
	Profile             string   `json:"profile"`
	Severity            string   `json:"severity"`
	Category            string   `json:"category,omitempty"`
	Include             []string `json:"include,omitempty"`
	Exclude             []string `json:"exclude,omitempty"`
	Output              string   `json:"output,omitempty"`
	ConfigPath          string   `json:"config_path,omitempty"`
	Offline             bool     `json:"offline"`
	RefreshIntelligence bool     `json:"refresh_intelligence"`
	MaxWorkers          int      `json:"max_workers"`
	Sources             []string `json:"loaded_sources,omitempty"`
	SuppressionCount    int      `json:"suppression_count"`
}

func Run(args []string, stdout, stderr io.Writer) error {
	explicit, err := cli.FindConfigPath(args)
	if err != nil {
		return err
	}
	cfg, configErr := config.Load(explicit)
	var parsed cli.Parsed
	if configErr != nil {
		// Doctor must remain able to diagnose an invalid active configuration.
		// All other commands continue to fail closed before execution.
		fallback, parseErr := cli.Parse(args, config.Defaults())
		if parseErr != nil {
			return parseErr
		}
		if fallback.Command != "doctor" {
			return configErr
		}
		cfg = config.Result{Options: config.Defaults()}
		parsed = fallback
	} else {
		parsed, err = cli.Parse(args, cfg.Options)
		if err != nil {
			return err
		}
	}
	opts := parsed.Options
	profileRegistry, err := profile.NewRegistry(cfg.Profiles, assessment.ImplementedRules())
	if err != nil {
		return fmt.Errorf("build profile registry: %w", err)
	}
	selectedProfile, err := profileRegistry.Resolve(opts.Profile)
	if err != nil {
		return err
	}
	opts.Profile = selectedProfile.Name

	registry := commandRegistry()
	if err := validateV1CommandRegistry(registry); err != nil {
		return fmt.Errorf("validate v1 public command contract: %w", err)
	}

	if opts.Version && parsed.Command == "" {
		parsed.Command = "version"
	}
	if parsed.Command == "" {
		if opts.Help {
			return printRootHelp(stdout, opts, registry)
		}
		return printLauncher(stdout, opts, registry)
	}
	if parsed.Command == "help" {
		if len(parsed.Args) == 0 {
			return printRootHelp(stdout, opts, registry)
		}
		cmd, ok := registry[parsed.Args[0]]
		if !ok {
			return unknownCommand(parsed.Args[0], registry)
		}
		return printCommandHelp(stdout, opts, cmd)
	}

	cmd, ok := registry[parsed.Command]
	if !ok {
		return unknownCommand(parsed.Command, registry)
	}
	if opts.Help {
		return printCommandHelp(stdout, opts, cmd)
	}
	if err := validateCommandArgs(cmd, parsed.Args); err != nil {
		return err
	}
	// keeps network access explicit and maintenance-scoped: the
	// refresh flag is never honored by scan/observe/assessment commands.
	if opts.RefreshIntelligence && parsed.Command != "intelligence" {
		return fmt.Errorf("--refresh-intelligence is only valid with the intelligence maintenance command")
	}

	out := stdout
	var f *os.File
	if opts.Output != "" {
		f, err = os.Create(opts.Output)
		if err != nil {
			return fmt.Errorf("create output %q: %w", opts.Output, err)
		}
		defer f.Close()
		out = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	rt := Runtime{ConfigSources: cfg.Sources, Args: append([]string(nil), parsed.Args...), SelectedProfile: selectedProfile, ProfileCatalog: profileRegistry.Catalog(), Suppressions: append([]suppression.Definition(nil), cfg.Suppressions...)}

	commandOut := out
	var humanHeaders *terminalui.HeaderWriter
	if !opts.JSON && parsed.Command != "export" {
		terminal := terminalContext(out, opts)
		if terminal.ColorMode != terminalui.ColorPlain {
			humanHeaders = terminalui.NewHeaderWriter(out, terminal.ColorMode)
			commandOut = humanHeaders
		}
	}
	runErr := cmd.Run(ctx, commandOut, opts, rt)
	if humanHeaders != nil {
		if flushErr := humanHeaders.Flush(); flushErr != nil && runErr == nil {
			return fmt.Errorf("flush terminal presentation: %w", flushErr)
		}
	}
	if runErr != nil {
		return runErr
	}
	if f != nil {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("flush output %q: %w", opts.Output, err)
		}
		if opts.Verbose && !opts.JSON {
			fmt.Fprintf(stderr, "chimera: wrote %s\n", opts.Output)
		}
	}
	return nil
}

func commandRegistry() map[string]Command {
	cmds := []Command{
		{
			Name: "scan", Lane: "Assess", Summary: "Run the bounded full assessment over all implemented categories.",
			Help: Help{
				Purpose:      "Collect one normalized live-host evidence snapshot, evaluate every implemented rule category through a bounded worker pool, and return a deterministic full assessment.",
				Usage:        "chimera scan [global options]",
				Examples:     []string{"chimera scan", "chimera scan --severity HIGH", "chimera scan --category network", "chimera scan --include CHM-CORE-005 --exclude identity", "chimera scan --json --output assessment.json"},
				Output:       "Deterministic assessment state, privilege-aware collection context, evidence-quality accounting, complete rule-selection decisions, normalized host inventories, findings, vulnerability/lifecycle context, and machine-readable provenance across all implemented security domains.",
				Safety:       "Read-only. The scan only collects local evidence and evaluates implemented rules; it does not exploit, probe remote services, capture packets, dump credentials, or mutate the host.",
				Requirements: "No elevation required. Standard execution explicitly identifies evidence classes that may become deeper with elevation; restricted or timed-out evidence remains explicit and --max-workers bounds concurrent category evaluation.",
				NextSteps:    "Use --severity, --category, --include and --exclude to constrain assessment scope; inspect individual results with chimera finding, chimera explain and chimera evidence.",
			},
			Run: runScan,
		},
		{
			Name: "baseline", Lane: "Assess", Summary: "Evaluate the active profile as a deterministic host security baseline.",
			Help: Help{
				Purpose:      "Run the same full normalized assessment used by chimera scan, reduce every selected profile-adjusted rule to deterministic PASS/WARN/FAIL/UNKNOWN/NOT_APPLICABLE baseline states, and project mapped checks into the benchmark-neutral CIS-inspired control-concept crosswalk.",
				Usage:        "chimera baseline [global options]",
				Examples:     []string{"chimera baseline", "chimera baseline --profile server", "chimera baseline --profile high-security --json", "chimera baseline --category network --verbose"},
				Output:       "chimera.baseline/v2 with assessment identity, active profile, complete profile and rule-selection decisions, FULL/PARTIAL coverage accounting, per-rule baseline results, and chimera.cis-inspired-mapping/v1 concept alignment derived from the exact scan findings.",
				Safety:       "Read-only. Baseline and CIS-inspired concept mapping reuse Chimera's local evidence collectors and findings; they perform no exploitation, authentication attempts, packet capture, credential extraction, host mutation, or scan-time intelligence refresh. The mapping makes no official CIS benchmark, certification, or compliance claim.",
				Requirements: "No elevation required. Restricted evidence remains UNKNOWN/UNDETERMINED through the existing finding model. The default command evaluates all profile-adjusted rules; severity/category/include/exclude options intentionally produce PARTIAL baseline coverage.",
				NextSteps:    "Use chimera finding/explain/evidence with a baseline rule's finding ID for exact provenance. preserves raw baseline state while surfacing any active or expired finding suppressions separately.",
			},
			Run: runBaseline,
		},
		{
			Name: "exposure", Lane: "Assess", Summary: "Assess externally or broadly reachable host exposure and its local controls.",
			Help: Help{
				Purpose:      "Project the full normalized assessment into the network, firewall, service, container/developer-surface, and cross-domain findings that describe reachable host exposure.",
				Usage:        "chimera exposure [global options]",
				Examples:     []string{"chimera exposure", "chimera exposure --profile server", "chimera exposure --json"},
				Output:       "A deterministic chimera.workflow-view/v1 exposure projection with the source assessment ID, profile/selection provenance, scoped findings, and independently recomputed priority ranking.",
				Safety:       "Read-only. Reuses the ordinary local assessment collectors and does not connect to listeners, probe services, capture traffic, or modify firewall/network state.",
				Requirements: "No elevation required. Restricted firewall, listener-owner, or service evidence remains explicit rather than inferred.",
				NextSteps:    "Use chimera finding <id> or chimera evidence <id> for exact evidence provenance, and chimera remediation for prioritized non-destructive guidance.",
			},
			Run: runExposure,
		},
		{
			Name: "hardening", Lane: "Assess", Summary: "Assess security-control and trust-boundary hardening across the host.",
			Help: Help{
				Purpose:      "Project the full normalized assessment into kernel, runtime, service, identity, network, filesystem, storage, container, persistence, secret-storage, and correlation hardening findings.",
				Usage:        "chimera hardening [global options]",
				Examples:     []string{"chimera hardening", "chimera hardening --profile high-security", "chimera hardening --json"},
				Output:       "A deterministic chimera.workflow-view/v1 hardening projection with profile/selection provenance, scoped findings, and priority ranking.",
				Safety:       "Read-only. It evaluates observed security controls and configuration metadata without enabling, disabling, or changing them.",
				Requirements: "No elevation required; elevated execution may deepen evidence where the operating system restricts defensive configuration visibility.",
				NextSteps:    "Use chimera baseline for complete profile PASS/WARN/FAIL/UNKNOWN coverage and chimera remediation for grouped fixes.",
			},
			Run: runHardening,
		},
		{
			Name: "misconfigurations", Lane: "Assess", Summary: "Assess host configuration weaknesses across security-relevant control planes.",
			Help: Help{
				Purpose:      "Project service, scheduler, firewall, authentication, filesystem, storage, container, persistence, secret-storage, and correlated configuration weaknesses from the full assessment.",
				Usage:        "chimera misconfigurations [global options]",
				Examples:     []string{"chimera misconfigurations", "chimera misconfigurations --severity HIGH", "chimera misconfigurations --json"},
				Output:       "A deterministic chimera.workflow-view/v1 misconfiguration projection over the same normalized evidence and stable rule engine used by chimera scan.",
				Safety:       "Read-only. Configuration is inspected but never rewritten, remediated, or security-control state changed.",
				Requirements: "No elevation required. Inaccessible configuration is reported as degraded, denied, unavailable, or unknown.",
				NextSteps:    "Inspect a returned finding with chimera explain <id>, then use chimera remediation for the corresponding non-destructive guidance.",
			},
			Run: runMisconfigurations,
		},
		{
			Name: "relationships", Lane: "Investigate", Summary: "Inspect proven cross-domain security relationships and composite findings.",
			Help: Help{
				Purpose:      "Show composite correlations that join process, service, filesystem, network, identity, and related evidence using stable identifiers and explicit evidence dependencies.",
				Usage:        "chimera relationships [global options]",
				Examples:     []string{"chimera relationships", "chimera relationships --verbose", "chimera relationships --json"},
				Output:       "A correlation-only chimera.workflow-view/v1 projection with finding provenance and deterministic priority ranking.",
				Safety:       "Read-only. Relationships are derived from already collected local metadata; no process injection, service interaction, authentication, or network probing occurs.",
				Requirements: "Relationship confidence depends on available ownership, PID, path, listener, account, and privilege evidence; unresolved joins remain UNKNOWN.",
				NextSteps:    "Use chimera evidence <id> to inspect every normalized fact supporting a relationship finding.",
			},
			Run: runRelationships,
		},
		{
			Name: "surface", Lane: "Investigate", Summary: "Inspect the consolidated local service and network attack surface.",
			Help: Help{
				Purpose:      "Project listener, firewall, service, container/developer-interface, and correlation findings into one local attack-surface view.",
				Usage:        "chimera surface [global options]",
				Examples:     []string{"chimera surface", "chimera surface --profile server", "chimera surface --json"},
				Output:       "A deterministic chimera.workflow-view/v1 surface projection tied to the exact assessment ID, profile, selection policy, findings, and priorities.",
				Safety:       "Read-only and non-probing. The view relies on local listener/configuration metadata and never connects to exposed endpoints.",
				Requirements: "No elevation required; listener ownership and firewall-policy gaps remain explicit when the platform denies deeper evidence.",
				NextSteps:    "Use chimera exposure for the assessment-oriented view and chimera evidence <id> for exact provenance.",
			},
			Run: runSurface,
		},
		{
			Name: "summary", Lane: "Report", Summary: "Return a compact assessment summary and highest-priority active findings.",
			Help: Help{
				Purpose:      "Run the same full assessment as chimera scan but return a compact operational summary with collection quality and the highest-priority actionable findings.",
				Usage:        "chimera summary [global options]",
				Examples:     []string{"chimera summary", "chimera summary --profile workstation", "chimera summary --json"},
				Output:       "chimera.summary-view/v1 with assessment identity, state, finding/evidence counts, suppression state, bounded limitations, and the top ten actionable priorities.",
				Safety:       "Read-only. Uses the ordinary local assessment workflow and performs no remediation or unexpected outbound network activity.",
				Requirements: "No elevation required. The summary preserves degraded/denied/unavailable evidence counts instead of hiding collection limitations.",
				NextSteps:    "Use chimera scan for the complete assessment, chimera report for enterprise reporting, or chimera finding <id> for one top-priority result.",
			},
			Run: runSummary,
		},
		{
			Name: "rules", Lane: "Maintain", Summary: "Inspect the complete stable rule catalog and active profile/selection state.",
			Help: Help{
				Purpose:      "List every implemented stable Chimera rule with category, base/effective severity, profile applicability, selection outcome, expected state, risk, remediation, and references.",
				Usage:        "chimera rules [global options]",
				Examples:     []string{"chimera rules", "chimera rules --profile server", "chimera rules --category network --json"},
				Output:       "chimera.rule-catalog/v1 derived directly from the executable rule registry and the active profile/selection policy; no host collection is required.",
				Safety:       "Metadata-only and read-only. The command does not collect host evidence or access the network.",
				Requirements: "A valid profile and rule selection. Unknown categories/rule selectors fail closed through the shared selection engine.",
				NextSteps:    "Use chimera findings to evaluate the selected rules against live evidence or chimera baseline for profile-level PASS/WARN/FAIL/UNKNOWN results.",
			},
			Run: runRules,
		},
		{
			Name: "diff", Lane: "Investigate", Summary: "Compare two saved Chimera assessment snapshots.", MinArgs: 2, MaxArgs: 2, ArgSyntax: "<before.json> <after.json>",
			Help: Help{
				Purpose:      "Compare two saved chimera scan JSON assessments for the same host and classify finding changes without recollecting host evidence.",
				Usage:        "chimera diff <before.json> <after.json> [--json]",
				Examples:     []string{"chimera diff before.json after.json", "chimera diff before.json after.json --verbose", "chimera diff before.json after.json --json --output diff.json"},
				Output:       "chimera.assessment-diff/v1 with same-host verification, assessment/rule/profile/intelligence/suppression provenance changes, deterministic NEW/RESOLVED/REGRESSED/IMPROVED/UNCHANGED and scope-change classifications, current/new suppression counts, and timestamp-stable evidence-change detection.",
				Safety:       "Read-only local file comparison. The command does not collect live host evidence, contact the network, refresh intelligence, execute assessment content, or modify either input file.",
				Requirements: "Pass two JSON files produced by chimera scan --json. Both must contain valid Chimera scan/finding/selection/snapshot contracts and the same deterministic host fingerprint; cross-host comparisons fail closed.",
				NextSteps:    "Review REGRESSED and NEW findings first. If profile, rule-set, selection, intelligence, or suppression provenance changed, use the provenance section to separate host drift from assessment-policy drift.",
			},
			Run: runDiff,
		},
		{
			Name: "kernel", Lane: "Observe", Summary: "Inventory the live kernel and operating-system hardening baseline.",
			Help: Help{
				Purpose:      "Collect normalized kernel and operating-system identity, release/build/channel, boot state, local update indicators, and hardening-capability availability without performing exploit or active network probing.",
				Usage:        "chimera kernel [global options]",
				Examples:     []string{"chimera kernel", "chimera kernel --verbose", "chimera kernel --json", "chimera kernel --json --output kernel.json"},
				Output:       "chimera.kernel/v9 inventory plus chimera.evidence/v1 observations for OS/kernel identity, boot metadata, Secure Boot, kernel/code-integrity controls, ASLR/memory mitigations, kernel pointer/debug exposure, unprivileged kernel feature exposure, loaded module/driver trust provenance, vulnerable-driver intelligence correlation, and LSM/mandatory-access-control posture.",
				Safety:       "Read-only local inspection only. correlates local installed/loaded driver identities against pinned local vulnerable-driver intelligence and may hash a matched local driver file within a strict size bound. reads local mandatory-access, sandbox, SIP, and isolation policy metadata only. It never opens driver devices, sends IOCTLs, loads/unloads drivers, changes signing policy, exploits vulnerabilities, or performs network access.",
				Requirements: "No elevation required. Permission-limited or unsupported evidence remains explicit, and the collector performs no update installation or surprise network access.",
				NextSteps:    "Use chimera findings --category kernel or chimera scan --category kernel to evaluate the core kernel hardening rule pack against this evidence.",
			},
			Run: runKernel,
		},
		{
			Name: "software", Lane: "Observe", Summary: "Inventory software and attribute important executable paths to package/application provenance.",
			Help: Help{
				Purpose:      "Collect a normalized, read-only inventory of installed packages/applications, major runtimes/frameworks/toolchains, security-relevant server/infrastructure software, browsers/high-risk clients, package/application provenance, and exact product normalization against the pinned intelligence catalog, plus lifecycle/support evaluation and local missing-security-update/patch posture using native cached OS/package metadata.",
				Usage:        "chimera software [global options]",
				Examples:     []string{"chimera software", "chimera software --verbose", "chimera software --json", "chimera software --json --output software.json"},
				Output:       "chimera.software/v5 inventory plus chimera.product-normalization/v1 exact product mappings, chimera.lifecycle/v1 support/EOL results, and chimera.update-posture/v1 pending-update/security classification with provider freshness and normalized evidence.",
				Safety:       "Read-only local inventory. performs only local file/path metadata and native package-receipt ownership queries. performs deterministic local identity normalization and version comparison only. compares observed versions only against pinned local lifecycle records. consults local/cached native update metadata without refreshing repositories or contacting update services. It does not execute target binaries, modify packages/services, install/remove/update software, connect to services, probe vulnerabilities, access credentials, or perform network access.",
				Requirements: "No elevation required. Chimera uses native package/application metadata, PATH-resolved runtime executables, local process/service identity providers, Linux package databases, macOS package receipts, and conservative Windows installation-root metadata; denied, degraded, unavailable, unmanaged, portable-candidate, and unknown provenance remain explicit.",
				NextSteps:    "CVE correlation, runtime/exposure reachability, lifecycle support evaluation, and update posture are active. Use chimera vulnerabilities for CVE/reachability/lifecycle/update context.",
			},
			Run: runSoftware,
		},
		{
			Name: "processes", Lane: "Observe", Summary: "Inventory live processes and their security context.",
			Help: Help{
				Purpose:      "Collect a normalized read-only live process inventory covering PID/PPID, executable identity/path, principal, session, privilege context, runtime state, redacted command-line metadata, trust/provenance context, and observable isolation state. enriches trust with local signing/package provenance where supported; adds normalized execution-location evidence; adds executable and parent-directory permission-boundary evidence using POSIX mode/ownership metadata on Unix and NTFS ACL metadata on Windows; adds normalized runtime privilege evidence for Unix real/effective identities, Linux capabilities, and Windows token elevation/integrity/privilege sets. adds metadata-only executable-memory posture covering W+X and anonymous/private executable mappings where safely observable. adds loaded DLL/shared-library/dylib inventory with backing state, signature/package provenance, module-directory write-boundary analysis, and process-to-module trust mismatch context. adds normalized process-isolation posture covering Linux namespaces/seccomp/NoNewPrivileges/cgroups/LSM context, Windows AppContainer/job-object membership, and macOS app-sandbox entitlement evidence where defensibly observable. adds dangerous runtime-environment configuration evidence for loader/search-path overrides, preload/startup/profiler hooks, debugger controls, proxy overrides, TLS key logging, and runtime-specific injection/debug options while permanently omitting environment values from output. evaluates the complete runtime evidence set through stable CHM-PRC rules, including environment/isolation correlations and compound privileged-boundary findings.",
				Usage:        "chimera processes [global options]",
				Examples:     []string{"chimera processes", "chimera processes --verbose", "chimera processes --json", "chimera processes --json --output processes.json"},
				Output:       "chimera.processes/v1 inventory plus normalized chimera.evidence/v1 process observations. trust states include local signature/package provenance where defensibly observable. emits additive process.location.<id> evidence, emits process.permission.<id>, and emits process.privilege.<id>, emits process.memory.<id>, and emits process.modules.<id>, emits process.isolation.<id>, and emits process.environment.<id> without replacing chimera.processes/v1. adds the consolidated CHM-PRC runtime-security rule pack over those normalized observations. Command-line values, process-memory contents, and environment values are never emitted; only bounded classification metadata is retained.",
				Safety:       "Read-only local process inspection, trust/provenance verification, permission metadata, runtime privilege metadata, process-isolation metadata, and redacted environment classification. Linux reads bounded /proc/<pid>/environ data but immediately discards values after classification; Windows/macOS intentionally avoid cross-process environment extraction when that would require process-memory or value-bearing process interfaces. Chimera does not duplicate or impersonate tokens, change UIDs/GIDs/capabilities, inject, attach a debugger, suspend/terminate processes, read process memory, dump credentials, execute target binaries, mutate packages/signatures, or perform network activity.",
				Requirements: "No elevation required. Restricted process paths, principals, command metadata, trust, isolation, environment metadata, token, integrity, capability, or privilege-set evidence remain explicit as unavailable/unknown instead of being invented.",
				NextSteps:    "consolidated runtime-security rules remain active. Windows, Linux systemd, macOS launchd, service privilege-to-path correlation, and legacy/unnecessary service-exposure rules are active through chimera findings/scan. scheduled-execution permission rules are active through chimera findings/scan, with the underlying scheduler inventory available through chimera scheduled.",
			},
			Run: runProcesses,
		},
		{
			Name: "services", Lane: "Observe", Summary: "Inventory local services/daemons and their security-relevant execution context.",
			Help: Help{
				Purpose:      "Collect a normalized, read-only service inventory covering service definition, executable path, service account, start mode, runtime PID/state, privilege context, native service manager, and configuration provenance. Windows inspects service ImagePath/ACL/security posture. Linux records effective systemd identity and sandbox controls. macOS assesses launchd plist/executable ownership, broad-write posture, account context, redacted environment-variable names, and dangerous launch configuration. correlates privileged service identities with executable, configuration, and search/resolution path integrity on Windows, Linux, and macOS. classifies legacy, deprecated, cleartext-capable, insecure-by-design, and profile-sensitive remote-capable service roles from local service identity/state without claiming network reachability.",
				Usage:        "chimera services [global options]",
				Examples:     []string{"chimera services", "chimera services --verbose", "chimera services --json", "chimera services --json --output services.json"},
				Output:       "chimera.services/v1 inventory plus normalized chimera.evidence/v1 service observations. Windows records add windows_security/service.security.<id>; Linux systemd records add systemd_hardening/service.systemd.<id>; macOS launchd records add launchd_hardening/service.launchd.<id> with definition/executable/path ownership and permissions, account posture, redacted environment-variable names, and dangerous-configuration indicators. adds path_integrity/service.path_integrity.<id> evidence with lower-privilege write posture and search-resolution state. adds exposure/service.exposure.<id> evidence with family, role, activity, legacy/deprecated/cleartext/insecure classification, and explicit network_reachability=NOT_ASSESSED. Raw command arguments, recovery-command values, and launchd environment values are not retained.",
				Safety:       "Read-only local service metadata and security-posture inspection. Windows uses local SCM/registry/ACL metadata. Linux uses systemctl show effective properties or conservative direct unit-file metadata. macOS decodes local launchd plists and inspects local filesystem metadata while redacting environment values. performs read-only ACL/ownership/permission correlation only and never attempts path replacement or service execution. performs deterministic local service-class classification only and does not open sockets or assert listener reachability. Chimera does not start, stop, restart, enable, disable, install, delete, reconfigure, connect to, authenticate to, or probe services.",
				Requirements: "No elevation required. Restricted manager/configuration/ACL/systemd/launchd/path metadata remains explicit as degraded or unavailable. Windows security-descriptor, Linux manager, and macOS launchd/filesystem visibility can vary with the caller context; Chimera never silently elevates.",
				NextSteps:    "Use chimera findings --category service or chimera scan --category service to evaluate the CHM-SVC rules. Use chimera findings --category scheduled or chimera scan --category scheduled for the CHM-SCH permission rules.",
			},
			Run: runServices,
		},
		{
			Name: "scheduled", Lane: "Observe", Summary: "Inventory local scheduled execution and its account/action/path posture.",
			Help: Help{
				Purpose:      "Collect the normalized, read-only scheduler evidence used by CHM-SCH rules: Windows Scheduled Tasks, Linux systemd timers/cron, and macOS launchd schedules with account, visibility, action/script, working-directory, definition, and local permission posture.",
				Usage:        "chimera scheduled [global options]",
				Examples:     []string{"chimera scheduled", "chimera scheduled --verbose", "chimera scheduled --json", "chimera scheduled --json --output scheduled.json"},
				Output:       "chimera.scheduled/v2 inventory plus normalized chimera.evidence/v1 scheduled.item.<id> observations. Command argument values are never retained; the collector stores only argument presence plus a derived local script path for recognized interpreters, and evaluates file/directory mode or Windows DACL posture without changing permissions.",
				Safety:       "Read-only local scheduled-execution metadata collection. Chimera does not create, modify, delete, enable, disable, trigger, run, stop, or reschedule tasks/timers/jobs; it does not execute recorded actions or reveal stored command argument values.",
				Requirements: "No elevation required. Restricted task, cron, timer, launchd, account, or path metadata is reported as degraded/unavailable instead of inferred. Deeper visibility may require the OS to grant additional read permissions.",
				NextSteps:    "Use chimera findings --category scheduled or chimera scan --category scheduled to evaluate the CHM-SCH rules over this evidence.",
			},
			Run: runScheduled,
		},
		{
			Name: "network", Lane: "Observe", Summary: "Inventory listening and bound local TCP/UDP exposure.",
			Help: Help{
				Purpose:      "Collect the normalized local network exposure inventory: listening TCP and bound UDP endpoints, owning process/service where defensibly observable, address family, and interface-binding classification for loopback, specific non-loopback, or all-interface exposure.",
				Usage:        "chimera network [global options]",
				Examples:     []string{"chimera network", "chimera network --verbose", "chimera network --json", "chimera network --json --output network.json"},
				Output:       "chimera.network/v1 inventory plus normalized chimera.evidence/v1 network.endpoint.<id> observations. Each endpoint records TCP LISTEN or UDP BOUND state, IPv4/IPv6 family, local address/port, interface-binding class, and local process/service ownership where available.",
				Safety:       "Read-only local socket metadata collection only. Chimera does not connect to endpoints, send probes, capture packets, alter firewall rules, bind sockets, terminate processes, or perform remote network activity.",
				Requirements: "No elevation required. Linux uses local /proc socket/fd metadata, Windows uses local Get-NetTCPConnection/Get-NetUDPEndpoint plus process/service metadata, and macOS uses local lsof socket metadata. Permission-restricted ownership remains explicitly unavailable/degraded.",
				NextSteps:    "Use chimera findings --category network or chimera scan --category network to evaluate external-bind rules, sensitive-service exposure rules, legacy/cleartext-capable protocol exposure rules, remote-management posture, SSH security rules over local configuration, permissions, forwarding, authentication, and algorithm evidence, and SMB/file-sharing rules over protocol, signing, encryption, guest/anonymous, and exported-share configuration evidence. evaluates these together with CHM-FW rules through the consolidated network/firewall exposure rule pack.",
			},
			Run: runNetwork,
		},
		{
			Name: "firewall", Lane: "Observe", Summary: "Inventory local host-firewall posture and native provider state.",
			Help: Help{
				Purpose:      "Collect the normalized local firewall inventory across Windows Defender Firewall, Linux nftables/iptables/firewalld/UFW, and macOS pf/Application Firewall where locally observable; evaluates enabled/default-policy posture; correlates non-loopback listeners with defensible local firewall restrictions; evaluates overly broad source ranges, any-interface exposure, broad management exceptions, and conflicting permissive policy from the same local evidence.",
				Usage:        "chimera firewall [global options]",
				Examples:     []string{"chimera firewall", "chimera firewall --verbose", "chimera firewall --json", "chimera firewall --json --output firewall.json"},
				Output:       "chimera.firewall/v2 provider/policy inventory, parsed inbound restriction metadata where safely observable, and per-listener coverage records. Normalized evidence includes firewall.provider.<id>, firewall.policy.<id>, firewall.restriction.<id>, and firewall.listener_coverage.<endpoint-id>.",
				Safety:       "Read-only local firewall metadata collection only. Chimera does not add, delete, enable, disable, reload, flush, replace, or test firewall rules; it does not open sockets, send probes, capture traffic, or contact remote systems.",
				Requirements: "No elevation required. Native providers may restrict detailed policy or rule visibility; denied and unavailable evidence remains explicit. Missing alternative Linux firewall frameworks are NOT_APPLICABLE rather than treated as host failure.",
				NextSteps:    "Use chimera findings --category firewall or chimera scan --category firewall to evaluate CHM-FW rules, including listener coverage and broad firewall exceptions. freezes those rules together with CHM-NET-001 through CHM-NET-029 in the consolidated network/firewall exposure pack.",
			},
			Run: runFirewall,
		},
		{
			Name: "accounts", Lane: "Observe", Summary: "Inventory local accounts, groups, privilege membership, and authentication posture metadata.",
			Help: Help{
				Purpose:      "Collect the normalized local account and group inventory for Windows, Linux, and macOS. evaluates privileged-account posture; adds explicit empty/passwordless-account assessment; adds read-only Windows UAC and local security-policy assessment; adds Windows credential-protection posture for LSA protection, Credential Guard, WDigest, cached domain logons, VBS context, and LM-hash storage; adds Linux sudo/sudoers posture for NOPASSWD breadth, unrestricted command grants, environment preservation, writable referenced code, and sudoers/include integrity. adds Linux PAM/login.defs authentication posture for permissive PAM chains, failure lockout, password quality, password ageing, password hashing, and authentication-policy path integrity. adds macOS FileVault/SecureToken identity relationships, loginwindow controls, authorizationdb posture, and local-administrator authorization context. adds cross-platform metadata-only SSH key/authorized_keys posture covering ownership, permissions/ACLs, weak writable paths, recognized private-key candidates, and privileged-account authorized-key access without reading private-key or authorized_keys contents. freezes all CHM-ID-001 through CHM-ID-043 checks into one deterministic identity/authentication rule pack validated by chimera doctor and consumed by scan/findings with profile-aware identity severity floors.",
				Usage:        "chimera accounts [global options]",
				Examples:     []string{"chimera accounts", "chimera accounts --verbose", "chimera accounts --json", "chimera accounts --json --output accounts.json"},
				Output:       "chimera.accounts/v1 inventory with deterministic local account/group records and chimera.evidence/v1 account.item.<id> / account.group.<id> observations. adds derived empty-password/password-required summary counts. adds normalized account.policy.* evidence for Windows UAC, elevation prompting, remote token filtering, Guest/account sharing posture, blank-password remote-use restriction, and anonymous-access security options. adds account.credential_protection.* evidence for LSA protected-process configuration, Credential Guard/VBS runtime state, WDigest credential caching, cached domain logon policy, domain membership, and LM-hash storage posture. adds account.sudo.* evidence for parsed sudoers grants, scoped environment-risk metadata, referenced executable/script write boundaries, and sudoers/include ownership/permissions. adds account.linux_auth.* evidence for parsed PAM module metadata, login.defs password policy, faillock/pwquality/pwhistory tuning, and authentication configuration integrity. adds account.macos_authorization.* evidence for FileVault state, SecureToken/FileVault identity relationships, loginwindow controls, and selected authorizationdb rights. adds account.ssh_key.* provider/summary/path evidence for .ssh directories, authorized_keys files, recognized private-key candidates, ownership, Unix mode or Windows ACL breadth, and privileged-account key access. Private-key and authorized_keys contents are never read or emitted. Credential values, recovery keys, token secrets, password hashes, and arbitrary PAM option values are never emitted.",
				Safety:       "Read-only local account metadata inspection. Chimera does not authenticate, change passwords, enable/disable users, add/remove group membership, retrieve plaintext credentials, retain password hashes, read private keys, or mutate account policy.",
				Requirements: "No elevation required. Linux /etc/shadow metadata is optional and, when readable, only a derived password-state token and non-secret aging metadata are retained; hash strings are never stored or emitted. Restricted account/group/authentication/policy evidence remains explicit as unavailable or denied. Windows policy and credential-protection collection reads local registry and CIM/Device Guard metadata only. macOS authorization posture uses read-only OpenDirectory, fdesetup, sysadminctl, defaults, and security authorizationdb metadata when available; restricted FileVault-user metadata remains DENIED/UNAVAILABLE rather than inferred.",
				NextSteps:    "Use chimera findings --category identity or chimera scan --category identity to evaluate the consolidated authentication posture pack containing CHM-ID-001 through CHM-ID-043 across local accounts, Windows UAC/credential protection, Linux sudo/PAM/login policy, macOS local authorization, and SSH key/authorized_keys posture.",
			},
			Run: runAccounts,
		},
		{
			Name: "filesystem", Lane: "Observe", Summary: "Inventory filesystem security boundaries, privileged executables, and writable launch surfaces.",
			Help: Help{
				Purpose:      "Collect the normalized filesystem security inventory: all evidence plus read-only network-share security metadata for mounted SMB/NFS filesystems and locally configured NFS exports.",
				Usage:        "chimera filesystem [global options]",
				Examples:     []string{"chimera filesystem", "chimera filesystem --verbose", "chimera filesystem --json", "chimera filesystem --json --output filesystem.json"},
				Output:       "chimera.filesystem/v1 inventory plus normalized chimera.evidence/v1 filesystem.permission_capability, filesystem.summary, filesystem.source.<id>, filesystem.path.<id>, filesystem.executable.<id>, filesystem.search_path.<id>, filesystem.privileged_executable.<id>, filesystem.sensitive_file.<id>, filesystem.acl_boundary.<id>, filesystem.temp_directory.<id>, filesystem.mount.<id>, and filesystem.network_share.<id> observations. network-share records preserve mounted/exported direction, SMB/NFS protocol, local/remote endpoint metadata, bounded non-secret security options, access mode, guest/anonymous state, broad-access/write classification, dangerous-option tags, source, confidence, and degradation. CHM-FS-017 through CHM-FS-020 assess guest/anonymous mounted shares, broad NFS export scope, NFS root/identity-mapping boundaries, and legacy or permission-bypass mount options. Locally exported SMB shares continue to use the SMB provider/rules instead of being redundantly enumerated here.",
				Safety:       "Read-only local filesystem and share-configuration metadata collection only. Chimera does not connect to network shares, enumerate remote servers, authenticate, probe services, read files over shares, read sensitive file contents, expose secret-bearing mount-option values, alter ownership/permissions/ACLs, mount or unmount filesystems, create/delete files, or execute paths.",
				Requirements: "No elevation required. Denied, missing, unsupported, or provider-limited evidence remains explicit. Mounted-share evidence is derived from Chimera's existing local mount inventory. Linux reads /etc/exports and /etc/exports.d/*.exports when present; macOS reads /etc/exports when present; Windows uses the local PowerShell NFS provider when installed. Missing NFS providers/configuration are OBSERVED-empty or NOT_APPLICABLE as appropriate, while denied/partial metadata remains DEGRADED, DENIED, or UNAVAILABLE rather than inferred.",
				NextSteps:    "Use chimera findings --category filesystem or chimera scan --category filesystem with the desired profile to evaluate CHM-FS-001 through CHM-FS-020. consolidates these checks with storage encryption, swap/pagefile, and hibernation findings into one frozen filesystem/storage rule pack.",
			},
			Run: runFilesystem,
		},
		{
			Name: "storage", Lane: "Observe", Summary: "Assess local storage, swap/pagefile, and hibernation protection without modifying host state.",
			Help: Help{
				Purpose:      "Collect the storage-protection inventory: BitLocker/LUKS/FileVault volume posture plus active swap/pagefile at-rest protection and hibernation/persistent-sleep exposure where locally observable.",
				Usage:        "chimera storage [global options]",
				Examples:     []string{"chimera storage", "chimera storage --verbose", "chimera storage --json", "chimera storage --json --output storage.json"},
				Output:       "chimera.storage/v1 inventory with storage.volume.<id>, storage.swap.<id>, storage.hibernation, storage.source.<id>, and storage.summary evidence. Swap/pagefile records report active backing, size/use metadata, normalized encryption state, and the evidence basis. Hibernation records report support/configuration, image/resume target metadata, normalized PROTECTED/EXPOSED/UNKNOWN exposure, and platform-specific non-secret power-security settings.",
				Safety:       "Read-only local metadata collection. Chimera does not read pagefile, swap, or hibernation-image contents; it does not hibernate/resume the host; unlock, decrypt, encrypt, suspend, or resume storage protection; mount/unmount storage; retrieve recovery keys; or modify power configuration.",
				Requirements: "No elevation is required by Chimera. Windows uses local registry/CIM plus BitLocker context; Linux uses /proc/swaps, /sys/power, /proc/cmdline, and read-only block metadata; macOS uses sysctl, pmset, and FileVault/APFS volume context. Missing or denied metadata remains UNKNOWN/UNAVAILABLE rather than inferred.",
				NextSteps:    "Use chimera findings --category storage or chimera scan --category storage to evaluate CHM-STG-001 through CHM-STG-004. freezes these with CHM-FS-001 through CHM-FS-020 in the consolidated filesystem/storage rule pack.",
			},
			Run: runStorage,
		},
		{
			Name: "containers", Lane: "Observe", Summary: "Inventory local container runtimes, orchestration posture, virtualization/hypervisor management surfaces, and developer/debug interfaces.",
			Help: Help{
				Purpose:      "Collect the Docker/containerd/Podman, Kubernetes, virtualization/hypervisor, and local developer/debug-interface posture and evaluate profile-aware developer-surface exposure through the shared findings engine. Developer-surface collection retains only redacted activation metadata and normalized listener binding/exposure; full command lines are not emitted.",
				Usage:        "chimera containers [global options]",
				Examples:     []string{"chimera containers", "chimera containers --verbose", "chimera containers --json", "chimera containers --json --output containers.json"},
				Output:       "chimera.containers/v1 inventory plus normalized chimera.evidence/v1 container.summary, container.source.<id>, container.runtime.<id>, container.runtime_endpoint.<id>, container.instance.<id>, container.security.<id>, container.config.<id>, container.orchestration.*, container.virtualization.hypervisor.<id>, and container.virtualization.management_interface.<id>, and container.developer.surface.<id> observations. retains the redacted developer-surface records and adds CHM-CTR-023 through CHM-CTR-025 profile-aware findings over exposure, host-role fit, and exposure-resolution quality.",
				Safety:       "Read-only local runtime, orchestration, and virtualization posture inspection. Chimera does not start/stop/restart containers or VMs, attach to guests, enumerate guest filesystems, contact Kubernetes clusters, connect to hypervisor management APIs, change service state, alter socket/device permissions, retain kubeconfig credential values, or create outbound network traffic. Developer-surface collection uses transient local process command-line metadata only to classify supported debug/developer interfaces; full command lines and argument values are not retained. evaluates only normalized local evidence and never connects to those interfaces.",
				Requirements: "No elevation required by Chimera. Docker/Podman local CLI and runtime access are required for per-container security posture. Hypervisor presence is derived from local binaries, known installation paths, service-control metadata, and safely inspectable local management sockets/devices. Unsupported ACL/service detail remains UNKNOWN rather than inferred. Group-writable libvirt/KVM-style interfaces are reported as GROUP_CONTROLLED, while world-writable interfaces are classified BROAD.",
				NextSteps:    "Use chimera containers --verbose and chimera findings --category containers to review developer-surface evidence and CHM-CTR-023 through CHM-CTR-025 profile-aware results. persistence account/privilege correlation is available through chimera persistence and chimera findings --category persistence; startup/login exposure rules are available through chimera findings --category persistence; freezes the persistence and secret-storage findings into the validated persistence/secret rule pack; evaluates core and intelligence posture through the declarative Rule Engine v2 while retaining those frozen IDs; adds explicit evidence dependencies and bounded composite conditions without changing those frozen IDs.",
			},
			Run: runContainers,
		},
		{
			Name: "persistence", Lane: "Observe", Summary: "Inventory local persistence and startup execution mechanisms.",
			Help: Help{
				Purpose:      "Collect the read-only persistence inventory and expose startup/login assessment context across service definitions, scheduled execution, Windows Run/RunOnce keys and Startup folders, Linux systemd/XDG startup mechanisms and cron-derived entries, plus macOS launchd/login-item posture where locally observable.",
				Usage:        "chimera persistence [global options]",
				Examples:     []string{"chimera persistence", "chimera persistence --verbose", "chimera persistence --json", "chimera persistence --json --output persistence.json"},
				Output:       "chimera.persistence/v1 inventory plus normalized chimera.evidence/v1 persistence.summary, persistence.source.<id>, and persistence.entry.<id> observations. Each entry carries path-integrity metadata plus execution-account privilege correlation; rules consume the same normalized entry evidence to assess system-wide startup control and user/login broad-write exposure. Separate persistence.privilege.<id> observations record resolved high-privilege, non-privileged, or unresolved execution context without credential material. Command argument values are not retained.",
				Safety:       "Read-only local metadata inspection. Chimera does not create, modify, enable, disable, trigger, execute, delete, or otherwise alter persistence mechanisms. Registry command values, desktop Exec values, and similar startup commands are parsed transiently and argument values are discarded from output. Path integrity reads ownership/mode/DACL metadata only and never opens target content for analysis.",
				Requirements: "No elevation required. Restricted service, scheduler, registry, startup-folder, systemd, XDG, launchd, login-item, or path-permission metadata remains DENIED/UNAVAILABLE/DEGRADED rather than being inferred. Windows path integrity uses local Get-Acl metadata; Linux/macOS use local ownership/mode metadata. Providers remain local-only.",
				NextSteps:    "Use chimera findings --category persistence to review CHM-PER-001/002 path-integrity, CHM-PER-003 critical weak-path/high-privilege correlation, and CHM-PER-004/005 startup/login exposure results. consolidates these CHM-PER rules with CHM-SEC-001 through CHM-SEC-007 in the validated persistence/secret-storage rule pack; adds the declarative Rule Engine v2 without changing these stable IDs; adds dependency-aware composite evaluation over normalized evidence.",
			},
			Run: runPersistence,
		},
		{
			Name: "secrets", Lane: "Observe", Summary: "Inventory secret-bearing paths, redacted plaintext-secret indicators, private-key permissions, and cloud/developer credential-file posture.",
			Help: Help{
				Purpose:      "Collect the read-only secret-storage posture inventory, bounded plaintext-secret risk indicators, private-key ownership/access-mode/ACL posture, and cloud/developer credential-file permission posture on Windows, Linux, and macOS. Credential values and private-key material are never retained or rendered.",
				Usage:        "chimera secrets [global options]",
				Examples:     []string{"chimera secrets", "chimera secrets --verbose", "chimera secrets --json", "chimera secrets --json --output secrets.json"},
				Output:       "chimera.secrets/v1 inventory plus normalized chimera.evidence/v1 secret_storage.summary, secret_storage.plaintext_risk, secret_storage.private_key_permissions, secret_storage.credential_file_posture, secret_storage.source.<id>, and secret_storage.item.<id> observations. classifies AWS/Azure/GCP/Kubernetes/Git/npm/pip and similar local credential/config paths and evaluates broad read/write exposure from normalized permission metadata without extracting credential values.",
				Safety:       "Strictly read-only. Chimera may read only the bounded local text content already permitted by redacted indicator classification; private-key and credential-file permission rules add no credential/key-content reads. Credential stores are not decrypted. Chimera does not authenticate, change ACLs/permissions, create files, or contact remote services.",
				Requirements: "No elevation required. Linux/macOS use POSIX ownership/mode metadata; Windows uses local Get-Acl DACL/owner metadata when PowerShell is available. assesses broad read access only for credential-bearing/mixed files and broad write access for credential plus security-relevant client configuration files. Restricted coverage remains UNKNOWN rather than inferred.",
				NextSteps:    "Use chimera findings --category secrets to review CHM-SEC-001/002 plaintext-secret findings, CHM-SEC-003/004/005 private-key posture, and CHM-SEC-006/007 cloud/developer credential-file read/write exposure. validates these together with CHM-PER-001 through CHM-PER-005 as one frozen persistence/secret-storage rule pack; adds the declarative Rule Engine v2 without changing these stable IDs; adds dependency-aware composite evaluation over normalized evidence.",
			},
			Run: runSecrets,
		},
		{
			Name: "vulnerabilities", Lane: "Assess", Summary: "Correlate observed software versions with pinned vulnerability intelligence.",
			Help: Help{
				Purpose:      "Collect local software inventory, resolve exact product identities, and compare observed versions against explicit affected ranges in the pinned vulnerability-intelligence store.",
				Usage:        "chimera vulnerabilities [global options]",
				Examples:     []string{"chimera vulnerabilities", "chimera vulnerabilities --verbose", "chimera vulnerabilities --json", "CHIMERA_INTELLIGENCE_DIR=/opt/chimera/intelligence chimera vulnerabilities --json"},
				Output:       "chimera.vulnerability-correlation/v1 results plus chimera.vulnerability-reachability/v1 context for AFFECTED components, chimera.lifecycle/v1 support/EOL status, and chimera.update-posture/v1 local/cached missing-update posture.",
				Safety:       "Read-only local correlation and local runtime metadata only. Chimera does not send exploit probes, connect to target services, capture packets, authenticate, execute target software, refresh repositories, retrieve credentials, or mutate the host. Reachability context is observational and does not claim exploitability.",
				Requirements: "No elevation required. Evidence quality depends on local inventory, process/service/socket visibility, and a valid pinned intelligence store. Restricted runtime ownership or listener evidence remains UNKNOWN/DEGRADED instead of being inferred.",
				NextSteps:    "missing-security-update posture is active using native local/cached update metadata with no repository refresh or update installation.",
			},
			Run: runVulnerabilities,
		},
		{
			Name: "intelligence", Lane: "Maintain", Summary: "Inspect, explicitly refresh, or roll back the pinned local vulnerability and lifecycle intelligence store.", MaxArgs: 1, ArgSyntax: "[rollback]",
			Help: Help{
				Purpose:      "Load and strictly validate Chimera's local versioned intelligence store. also provides an explicit signed Ed25519 refresh workflow with digest-addressed immutable snapshots, atomic active-pointer switching, anti-downgrade checks, persisted provenance, and one-step validated rollback.",
				Usage:        "chimera intelligence [rollback] [global options]",
				Examples:     []string{"chimera intelligence", "chimera intelligence --json", "CHIMERA_INTELLIGENCE_DIR=/opt/chimera/intelligence CHIMERA_INTELLIGENCE_REFRESH_URL=https://updates.example/chimera/intelligence.json CHIMERA_INTELLIGENCE_TRUSTED_KEY_FILE=/etc/chimera/intelligence.pub chimera intelligence --refresh-intelligence", "CHIMERA_INTELLIGENCE_DIR=/opt/chimera/intelligence chimera intelligence rollback --json"},
				Output:       "Ordinary inspection returns chimera.intelligence/v1. Explicit refresh returns chimera.intelligence-refresh-result/v1 plus the activated store; rollback returns chimera.intelligence-rollback-result/v1.",
				Safety:       "Ordinary inspection and rollback are local-only; rollback performs no network access. Network access occurs only when --refresh-intelligence is explicitly supplied to this command. Signed candidates are strictly validated before activation, ordinary scans never refresh intelligence, and no assessment command mutates the host.",
				Requirements: "No elevation required. Refresh requires CHIMERA_INTELLIGENCE_DIR, an HTTPS CHIMERA_INTELLIGENCE_REFRESH_URL, and one trusted Ed25519 public key via CHIMERA_INTELLIGENCE_TRUSTED_KEY or CHIMERA_INTELLIGENCE_TRUSTED_KEY_FILE. Existing flat manifest.json stores remain supported and are migrated into digest-addressed snapshots on first refresh.",
				NextSteps:    "Use chimera intelligence to verify the active version/digest after refresh. Use chimera intelligence rollback for an explicit local one-step rollback to the previous validated snapshot.",
			},
			Run: runIntelligence,
		},
		{
			Name: "overview", Lane: "Observe", Summary: "Collect a real live-host security overview.",
			Help: Help{
				Purpose:      "Collect core host identity, OS/kernel, boot/uptime, privilege, CPU, memory, process/listener counts, and major security-control posture.",
				Usage:        "chimera overview [global options]",
				Examples:     []string{"chimera overview", "chimera overview --json", "chimera overview --verbose --timeout 15s", "chimera overview --json --output host-overview.json"},
				Output:       "Human terminal view or the same collected data in structured JSON, including chimera.privilege/v1 effective privilege, collection tier, elevation state, and optional deeper-evidence notes.",
				Safety:       "Read-only. Uses local files, local OS APIs/commands, and no active service probing. Elevation is never attempted automatically.",
				Requirements: "No elevation required. Restricted evidence is reported as unavailable/denied rather than invented, and non-elevated execution remains a supported collection tier.",
				NextSteps:    "Use --verbose to inspect privilege-gated evidence classes and degraded evidence. Elevation is optional and only increases visibility where the operating system requires it.",
			},
			Run: runOverview,
		},
		{
			Name: "findings", Lane: "Investigate", Summary: "Evaluate implemented rules against live normalized evidence.",
			Help: Help{
				Purpose:      "Collect overview plus kernel evidence and evaluate Chimera's implemented core and kernel hardening rules into stable findings.",
				Usage:        "chimera findings [global options]",
				Examples:     []string{"chimera findings", "chimera findings --category kernel", "chimera findings --severity HIGH", "chimera findings --include CHM-KRN-001", "chimera findings --json"},
				Output:       "Stable finding records, the per-rule selection ledger, and the suppression audit ledger with owner, reason, expiry, source, match scope, and matched finding IDs.",
				Safety:       "Read-only. Rules evaluate normalized local evidence and do not probe, exploit, or mutate the host.",
				Requirements: "No elevation required. Restricted evidence produces UNKNOWN rather than an invented result.",
				NextSteps:    "Use --verbose for evidence/selection/suppression audit details or --json for the complete finding, selection, and suppression contracts.",
			},
			Run: runFindings,
		},
		{
			Name: "finding", Lane: "Investigate", Summary: "Inspect one finding by stable finding ID.", MinArgs: 1, MaxArgs: 1, ArgSyntax: "<id>",
			Help: Help{
				Purpose:      "Rebuild one finding from the current normalized evidence snapshot, show the exact rule that produced it, and preserve evidence provenance plus a deterministic reproducibility digest.",
				Usage:        "chimera finding <id> [global options]",
				Examples:     []string{"chimera finding CHM-F-0123456789ABCDEF", "chimera finding CHM-F-0123456789ABCDEF --verbose", "chimera finding CHM-F-0123456789ABCDEF --json"},
				Output:       "Focused finding record, rule metadata, normalized evidence provenance, reproducibility metadata, and any active suppression audit records.",
				Safety:       "Read-only. The command only recollects local evidence and re-evaluates implemented rules; it does not exploit, probe remote services, or mutate the host.",
				Requirements: "Pass one stable finding ID emitted by chimera findings or chimera scan.",
				NextSteps:    "Use chimera explain <id> for a decision-oriented explanation or chimera evidence <id> for provenance-only output.",
			},
			Run: runFinding,
		},
		{
			Name: "explain", Lane: "Investigate", Summary: "Explain why one finding reached its current state.", MinArgs: 1, MaxArgs: 1, ArgSyntax: "<id>",
			Help: Help{
				Purpose:      "Explain one stable finding from normalized evidence, including observed versus expected state, applicability, confidence, risk, remediation, provenance, and reproducibility metadata.",
				Usage:        "chimera explain <id> [global options]",
				Examples:     []string{"chimera explain CHM-F-0123456789ABCDEF", "chimera explain CHM-F-0123456789ABCDEF --json"},
				Output:       "Human decision explanation or the complete finding-inspection contract in JSON.",
				Safety:       "Read-only local evidence evaluation only.",
				Requirements: "Pass one stable finding ID emitted by chimera findings or chimera scan.",
				NextSteps:    "Use chimera evidence <id> to isolate the exact evidence records and collection provenance behind the finding.",
			},
			Run: runExplain,
		},
		{
			Name: "evidence", Lane: "Investigate", Summary: "Show exact normalized evidence provenance for one finding.", MinArgs: 1, MaxArgs: 1, ArgSyntax: "<id>",
			Help: Help{
				Purpose:      "Show the exact normalized evidence records consumed by the rule behind one finding, including source, state, confidence, collection time, degradation reason, and reproducibility digest.",
				Usage:        "chimera evidence <id> [global options]",
				Examples:     []string{"chimera evidence CHM-F-0123456789ABCDEF", "chimera evidence CHM-F-0123456789ABCDEF --json"},
				Output:       "Finding identity plus provenance-only evidence records and deterministic evidence digest.",
				Safety:       "Read-only. Secret values are not introduced by this command; it only renders evidence already present in the normalized finding inputs.",
				Requirements: "Pass one stable finding ID emitted by chimera findings or chimera scan.",
				NextSteps:    "Use chimera finding <id> to see the complete finding or chimera explain <id> for the decision explanation.",
			},
			Run: runEvidence,
		},
		{
			Name: "remediation", Lane: "Report", Summary: "Prioritize and group non-destructive remediation guidance for active findings.",
			Help: Help{
				Purpose:      "Build the remediation view from the current normalized assessment, risk priority, active profile, rule selection, and suppression policy. Active FAIL/WARN findings are grouped by priority band, category, and affected component; UNKNOWN findings are held for more evidence and suppressed findings remain outside the actionable fix queue.",
				Usage:        "chimera remediation [global options]",
				Examples:     []string{"chimera remediation", "chimera remediation --severity HIGH", "chimera remediation --category network", "chimera remediation --profile server --verbose", "chimera remediation --json --output remediation.json"},
				Output:       "chimera.remediation/v1 with deterministic priority/category/component groups, flat actionable remediation records, raw severity, priority score/rank, affected object, evidence keys, precise rule-authored guidance, verification guidance, and non-actionable accounting.",
				Safety:       "Read-only guidance only. Chimera does not apply fixes, execute remediation commands, restart services, install updates, change permissions, modify firewall/security controls, or otherwise mutate the host.",
				Requirements: "No elevation required beyond the evidence visibility already used by the assessment. UNKNOWN evidence is never converted into a remediation action, and active suppressions are respected without deleting raw findings.",
				NextSteps:    "Review highest-ranked actions first, make changes only through approved administration/change-control workflows, then rerun Chimera to verify the affected rule no longer returns FAIL/WARN.",
			},
			Run: runRemediation,
		},
		{
			Name: "report", Lane: "Report", Summary: "Build the complete enterprise assessment report from one assessment snapshot.", MaxArgs: 1, ArgSyntax: "[assessment.json]",
			Help: Help{
				Purpose:      "Run the bounded live-host assessment once, or consume one saved chimera scan JSON snapshot without recollecting the host, and assemble the enterprise report from that immutable normalized assessment.",
				Usage:        "chimera report [assessment.json] [global options]",
				Examples:     []string{"chimera report", "chimera report scan.json --json", "chimera report --profile server", "chimera report scan.json --json --output assessment-report.json"},
				Output:       "chimera.enterprise-report/v1 in human or JSON form, including host metadata, assessment identity/state, evidence quality, complete normalized findings, prioritization, remediation, rule-set and intelligence provenance, suppression audit data, and limitations.",
				Safety:       "Read-only. Reporting either performs one ordinary local assessment or renders an already saved immutable scan snapshot; it never recollects when a snapshot path is supplied, applies remediation, changes host configuration, refreshes intelligence implicitly, or performs unexpected network activity.",
				Requirements: "No elevation required beyond the evidence visibility already used by chimera scan. A supplied assessment.json must be a valid Chimera scan envelope/raw scan result with intact deterministic snapshot provenance.",
				NextSteps:    "Use chimera export <json|text|csv|sarif> --output <path> for automation, archival, SIEM/CI ingestion, or enterprise reporting workflows.",
			},
			Run: runReport,
		},
		{
			Name: "export", Lane: "Report", Summary: "Export the complete enterprise assessment as JSON, text, CSV, or SARIF.", MinArgs: 1, MaxArgs: 1, ArgSyntax: "<json|text|csv|sarif>",
			Help: Help{
				Purpose:      "Run one bounded assessment, build the stable enterprise report, and serialize it without banner or ANSI output into JSON, structured text, finding-oriented CSV, or SARIF 2.1.0.",
				Usage:        "chimera export <json|text|csv|sarif> [global options]",
				Examples:     []string{"chimera export json --output assessment.json", "chimera export text --output assessment.txt", "chimera export csv --output findings.csv", "chimera export sarif --output assessment.sarif"},
				Output:       "Machine-safe banner/ANSI-free export. JSON preserves the full enterprise-report contract; text preserves report/provenance/remediation sections; CSV emits deterministic finding rows with repeated assessment provenance; SARIF 2.1.0 emits non-PASS findings, rule metadata, priority context, suppression state, and assessment provenance.",
				Safety:       "Read-only serialization only. Export does not upload results, contact a server, mutate the host, or execute remediation.",
				Requirements: "Exactly one format argument: json, text, csv, or sarif. Use --output <path> to write atomically through Chimera's existing output path handling; stdout is supported when --output is omitted.",
				NextSteps:    "Store exports according to organizational handling requirements because host metadata and security findings may be sensitive.",
			},
			Run: runExport,
		},
		{
			Name: "profiles", Lane: "Maintain", Summary: "List and inspect built-in and custom enterprise assessment profiles.",
			Help: Help{
				Purpose:      "Show Chimera's built-in and custom enterprise assessment profiles, inheritance, environment policy, rule/category applicability, severity floors/overrides, expected services/ports, and allowed policy exceptions without changing raw evidence.",
				Usage:        "chimera profiles [--profile <name>] [--json]",
				Examples:     []string{"chimera profiles", "chimera profiles --profile workstation", "chimera profiles --profile prod-web --config chimera.json --json"},
				Output:       "Profile catalog plus the active resolved descriptor, inheritance behavior, enterprise environment policy, and effective decisions over the implemented plus profile-generated rule catalog.",
				Safety:       "The profiles command collects no host evidence. During assessment, profiles only transform rule applicability/severity and evaluate declared expected-service/expected-port policy against already normalized local evidence.",
				Requirements: "Built-ins: default, workstation, server, developer, high-security, minimal. Custom profiles are defined under custom_profiles in Chimera JSON configuration and must extend a built-in or another valid custom profile.",
				NextSteps:    "Run chimera scan --profile <name> to apply the resolved profile. Custom profile rule toggles, severity overrides, and environment policy remain deterministic and read-only.",
			},
			Run: runProfiles,
		},
		{
			Name: "doctor", Lane: "Maintain", Summary: "Diagnose collector, dependency, permission, config, platform, and intelligence health.",
			Help: Help{
				Purpose:      "Run a read-only local health assessment of Chimera itself: platform support, current collector contract health, external provider availability, permission degradation, configuration validity, and local intelligence freshness state.",
				Usage:        "chimera doctor [global options]",
				Examples:     []string{"chimera doctor", "chimera doctor --verbose", "chimera doctor --json", "chimera doctor --offline --json"},
				Output:       "chimera.doctor/v1 health result with deterministic check groups, overall state, current privilege context, dependency/provider paths, configuration validation, intelligence-state diagnostics, and required stable-contract validation for the service/scheduler, network/firewall, and identity/authentication rule packs.",
				Safety:       "Read-only. Doctor does not install tools, alter permissions, elevate, modify configuration, refresh intelligence, contact the network, or change host security controls.",
				Requirements: "No elevation required. Missing optional providers are reported as warnings; missing required platform providers are explicit failures.",
				NextSteps:    "Correct FAIL checks first, then review WARN checks for evidence that is intentionally unavailable or permission-gated.",
			},
			Run: runDoctor,
		},
		{
			Name: "config", Lane: "Maintain", Summary: "Show the effective Chimera configuration.",
			Help: Help{
				Purpose:      "Display merged defaults, discovered config files, explicit config, and CLI overrides used by this invocation.",
				Usage:        "chimera config [global options]",
				Examples:     []string{"chimera config", "chimera config --json", "chimera config --config ./chimera.json"},
				Output:       "Effective configuration and loaded config-source paths.",
				Safety:       "Read-only. Configuration files are never modified.",
				Requirements: "Config files use JSON. Unknown keys and invalid values fail closed.",
				NextSteps:    "Use --config <path> for an explicit highest-precedence configuration file.",
			},
			Run: runConfig,
		},
		{
			Name: "version", Lane: "Maintain", Summary: "Show Chimera version/build metadata.",
			Help: Help{
				Purpose:      "Show product version, source commit metadata, and build date.",
				Usage:        "chimera version [--json]",
				Examples:     []string{"chimera version", "chimera --version", "chimera version --json"},
				Output:       "Human text or structured JSON.",
				Safety:       "No host inspection is performed.",
				Requirements: "None.",
				NextSteps:    "Release builds can inject Version, Commit, and BuildDate using Go linker flags.",
			},
			Run: runVersion,
		},
	}
	out := make(map[string]Command, len(cmds))
	for _, c := range cmds {
		out[c.Name] = c
	}
	return out
}

func appliedProfile(rt Runtime) (profile.Applied, error) {
	return profile.Apply(rt.SelectedProfile, assessment.ImplementedRules())
}

func appliedSelection(applied profile.Applied, opts cli.Options) (selection.Applied, error) {
	return selection.Apply(applied.Rules, selection.Request{
		Severity: assessment.Severity(opts.Severity),
		Category: opts.Category,
		Include:  append([]string(nil), opts.Include...),
		Exclude:  append([]string(nil), opts.Exclude...),
	})
}

func runScan(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	data, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return err
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "scan", Version: version.Current(), Data: data})
	}
	render.ScanHuman(w, data, opts.Verbose)
	return nil
}

func runBaseline(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	assessmentResult, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return fmt.Errorf("run baseline assessment: %w", err)
	}
	data, err := baseline.Build(assessmentResult)
	if err != nil {
		return fmt.Errorf("build baseline result: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "baseline", Version: version.Current(), Data: data})
	}
	render.BaselineHuman(w, data, opts.Verbose)
	return nil
}

type remediationCommandData struct {
	Profile      profile.Descriptor `json:"profile"`
	Selection    selection.Report   `json:"selection"`
	Suppressions suppression.Report `json:"suppressions"`
	Remediation  remediation.Result `json:"remediation"`
}

func runRemediation(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	assessmentResult, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return fmt.Errorf("run remediation assessment: %w", err)
	}
	if assessmentResult.Remediation == nil {
		return fmt.Errorf("remediation result is unavailable")
	}
	data := remediationCommandData{
		Profile: assessmentResult.Profile.Descriptor, Selection: assessmentResult.Selection,
		Suppressions: assessmentResult.Suppressions, Remediation: *assessmentResult.Remediation,
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "remediation", Version: version.Current(), Data: data})
	}
	render.RemediationHuman(w, data.Remediation, opts.Verbose)
	return nil
}

func runReport(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	var (
		data report.Result
		err  error
	)
	if len(rt.Args) == 1 {
		frozen, loadErr := scan.LoadAssessmentSnapshotFile(rt.Args[0])
		if loadErr != nil {
			return fmt.Errorf("load report assessment snapshot: %w", loadErr)
		}
		data, err = report.BuildFromAssessmentSnapshot(frozen, rt.Args[0])
	} else {
		assessmentResult, runErr := executeFullAssessment(ctx, opts, rt)
		if runErr != nil {
			return fmt.Errorf("run report assessment: %w", runErr)
		}
		frozen, freezeErr := scan.FreezeAssessmentSnapshot(assessmentResult)
		if freezeErr != nil {
			return fmt.Errorf("freeze report assessment snapshot: %w", freezeErr)
		}
		data, err = report.BuildFromAssessmentSnapshot(frozen, "live-assessment")
	}
	if err != nil {
		return fmt.Errorf("build enterprise report: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "report", Version: version.Current(), Data: data})
	}
	render.ReportHuman(w, data, opts.Verbose)
	return nil
}

func runExport(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	format, err := exporter.ParseFormat(rt.Args[0])
	if err != nil {
		return err
	}
	assessmentResult, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return fmt.Errorf("run export assessment: %w", err)
	}
	frozen, err := scan.FreezeAssessmentSnapshot(assessmentResult)
	if err != nil {
		return fmt.Errorf("freeze export assessment snapshot: %w", err)
	}
	data, err := report.BuildFromAssessmentSnapshot(frozen, "live-assessment")
	if err != nil {
		return fmt.Errorf("build enterprise report for export: %w", err)
	}
	if err := exporter.Write(w, format, data); err != nil {
		return fmt.Errorf("export %s: %w", format, err)
	}
	return nil
}

func executeFullAssessment(ctx context.Context, opts cli.Options, rt Runtime) (scan.Result, error) {
	applied, err := appliedProfile(rt)
	if err != nil {
		return scan.Result{}, fmt.Errorf("apply assessment profile: %w", err)
	}
	selected, err := appliedSelection(applied, opts)
	if err != nil {
		return scan.Result{}, fmt.Errorf("apply rule selection: %w", err)
	}
	var kernelInventory kernel.Inventory
	var softwareInventory software.Inventory
	var processInventory processes.Inventory
	var serviceInventory services.Inventory
	var scheduledInventory scheduled.Inventory
	var networkInventory netinv.Inventory
	var firewallInventory firewall.Inventory
	var remoteManagement remotemgmt.Report
	var accountInventory accounts.Inventory
	var filesystemInventory filesystem.Inventory
	var storageInventory storage.Inventory
	var containerInventory containerinv.Inventory
	var persistenceInventory persistence.Inventory
	var secretInventory secretinv.Inventory
	var updateInventory updateposture.Result
	// pins intelligence once, before any rule evaluation, so every
	// correlation and provenance record in this scan uses the exact same local
	// snapshot even if the backing manifest changes while the scan is running.
	intelSession := intelligence.Open(intelligence.LoadOptions{Offline: opts.Offline})
	kernelCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		kernelInventory = kernel.Collect(ctx)
		return kernelInventory.Evidence, kernelInventory.Degraded
	}
	softwareCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		if runtime.GOOS == "windows" {
			activity := make([]software.HostActivityHint, 0, len(processInventory.Processes)+len(serviceInventory.Services)*2)
			for _, p := range processInventory.Processes {
				activity = append(activity, software.HostActivityHint{Kind: "process", Name: p.Name, Path: p.ExecutablePath})
			}
			for _, svc := range serviceInventory.Services {
				activity = append(activity, software.HostActivityHint{Kind: "service", Name: svc.Name, Path: svc.ExecutablePath})
				if strings.TrimSpace(svc.DisplayName) != "" && !strings.EqualFold(svc.Name, svc.DisplayName) {
					activity = append(activity, software.HostActivityHint{Kind: "service", Name: svc.DisplayName, Path: svc.ExecutablePath})
				}
			}
			softwareInventory = software.CollectWithHostActivity(ctx, activity)
		} else {
			softwareInventory = software.Collect(ctx)
		}
		return softwareInventory.Evidence, softwareInventory.Degraded
	}
	processCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		processInventory = processes.Collect(ctx)
		return processInventory.Evidence, processInventory.Degraded
	}
	serviceCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		serviceInventory = services.Collect(ctx)
		return serviceInventory.Evidence, serviceInventory.Degraded
	}
	scheduledCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		scheduledInventory = scheduled.Collect(ctx)
		return scheduledInventory.Evidence, scheduledInventory.Degraded
	}
	networkCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		networkInventory = netinv.Collect(ctx)
		return networkInventory.Evidence, networkInventory.Degraded
	}
	firewallCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		firewallInventory = firewall.Collect(ctx).WithListenerCoverage(networkInventory)
		return firewallInventory.Evidence, firewallInventory.Degraded
	}
	remoteManagementCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		remoteManagement = remotemgmt.Collect(ctx, serviceInventory, networkInventory, firewallInventory)
		return remoteManagement.Evidence, remoteManagement.Degraded
	}
	accountCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		accountInventory = accounts.Collect(ctx)
		return accountInventory.Evidence, accountInventory.Degraded
	}
	filesystemCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		filesystemInventory = filesystem.Collect(ctx)
		return filesystemInventory.Evidence, filesystemInventory.Degraded
	}
	storageCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		storageInventory = storage.Collect(ctx)
		return storageInventory.Evidence, storageInventory.Degraded
	}
	containerCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		if runtime.GOOS == "windows" {
			containerInventory = containerinv.CollectWithNetwork(ctx, networkInventory)
		} else {
			containerInventory = containerinv.Collect(ctx)
		}
		return containerInventory.Evidence, containerInventory.Degraded
	}
	persistenceCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		persistenceInventory = persistence.CollectFrom(ctx, serviceInventory, scheduledInventory, accountInventory)
		return persistenceInventory.Evidence, persistenceInventory.Degraded
	}
	secretCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		secretInventory = secretinv.Collect(ctx)
		return secretInventory.Evidence, secretInventory.Degraded
	}
	updateCollector := func(ctx context.Context) ([]evidence.Observation, []string) {
		updateInventory = updateposture.Collect(ctx)
		if updateInventory.State == updateposture.StateComplete {
			return updateInventory.Evidence, nil
		}
		reasons := append([]string(nil), updateInventory.Limitations...)
		if len(reasons) == 0 {
			reasons = []string{"update posture collection state is " + string(updateInventory.State)}
		}
		return updateInventory.Evidence, reasons
	}
	intelligenceCollector := func(context.Context) ([]evidence.Observation, []string) {
		return append([]evidence.Observation(nil), intelSession.Evidence...), intelSession.DegradationReasons()
	}
	softwareDependencies := []string(nil)
	containerDependencies := []string(nil)
	containerLane := reliability.ProviderLaneNativeLight
	remoteManagementPriority := 20
	storagePriority := 20
	if runtime.GOOS == "windows" {
		softwareDependencies = []string{"processes", "services"}
		// Post-117 Fix59: integrated Windows container/developer-surface
		// collection consumes the already-normalized network inventory instead of
		// launching a second hidden Get-Net*/CIM acquisition. The remaining
		// Win32_Process classification stage is admitted through the management
		// lane so scheduler accounting matches the real Windows workload.
		containerDependencies = []string{"network"}
		containerLane = reliability.ProviderLanePowerShellCIM
		// Post-117 Fix56: storage is admitted before optional/later management
		// work, and remote-management becomes the highest-priority ready
		// PowerShell/CIM collector as soon as services -> network -> firewall
		// have satisfied its dependency chain. Linux/macOS retain the existing
		// priority contract.
		storagePriority = 8
		remoteManagementPriority = 4
	}
	collectors := []scan.NamedEvidenceCollector{
		// Post-117 Fix44: Windows providers are explicitly assigned to host-resource
		// execution lanes. Network is intentionally admitted before unrelated
		// management work because firewall and remote-management depend on it. The
		// declaration order remains unchanged so evidence ownership/merge semantics
		// stay deterministic.
		{Name: "kernel", Priority: 7, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: kernelCollector},
		{Name: "software", Priority: 20, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Dependencies: softwareDependencies, Collect: softwareCollector},
		{Name: "processes", Priority: 10, BudgetClass: reliability.ProviderBudgetHeavy, Lane: reliability.ProviderLaneHeavySecurity, Collect: processCollector, Validate: func() error { return processInventory.Validate() }},
		{Name: "services", Priority: 6, BudgetClass: reliability.ProviderBudgetHeavy, Lane: reliability.ProviderLaneHeavySecurity, Collect: serviceCollector, Validate: func() error { return serviceInventory.Validate() }},
		{Name: "scheduled", Priority: 12, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: scheduledCollector, Validate: func() error { return scheduledInventory.Validate() }},
		{Name: "network", Priority: 5, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: networkCollector, Validate: func() error { return networkInventory.Validate() }},
		{Name: "firewall", Priority: 5, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Dependencies: []string{"network"}, Collect: firewallCollector, Validate: func() error { return firewallInventory.Validate() }},
		{Name: "remote-management", Priority: remoteManagementPriority, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Dependencies: []string{"services", "network", "firewall"}, Collect: remoteManagementCollector, Validate: func() error { return remoteManagement.Validate() }},
		{Name: "accounts", Priority: 12, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: accountCollector, Validate: func() error { return accountInventory.Validate() }},
		{Name: "filesystem", Priority: 15, BudgetClass: reliability.ProviderBudgetHeavy, Lane: reliability.ProviderLaneHeavySecurity, Collect: filesystemCollector, Validate: func() error { return filesystemInventory.Validate() }},
		{Name: "storage", Priority: storagePriority, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: storageCollector, Validate: func() error { return storageInventory.Validate() }},
		{Name: "containers", Priority: 50, BudgetClass: reliability.ProviderBudgetMedium, Lane: containerLane, Dependencies: containerDependencies, Collect: containerCollector, Validate: func() error { return containerInventory.Validate() }},
		{Name: "persistence", Priority: 20, BudgetClass: reliability.ProviderBudgetHeavy, Lane: reliability.ProviderLaneHeavySecurity, Dependencies: []string{"services", "scheduled", "accounts"}, Collect: persistenceCollector, Validate: func() error { return persistenceInventory.Validate() }},
		{Name: "secrets", Priority: 30, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: secretCollector, Validate: func() error { return secretInventory.Validate() }},
		{Name: "update-posture", Priority: 40, BudgetClass: reliability.ProviderBudgetMedium, Lane: reliability.ProviderLanePowerShellCIM, Collect: updateCollector, Validate: func() error { return updateInventory.Validate() }},
		{Name: "intelligence", Priority: 60, BudgetClass: reliability.ProviderBudgetFast, Lane: reliability.ProviderLaneNativeLight, Collect: intelligenceCollector},
	}

	data, err := scan.RunNamed(ctx, opts.MaxWorkers, overview.Collect, selected.Rules, collectors...)
	if err != nil {
		return scan.Result{}, fmt.Errorf("run full scan: %w", err)
	}
	suppressedFindings, suppressionReport, err := suppression.Apply(data.Findings, rt.Suppressions, applied.Rules, data.AssessedAt)
	if err != nil {
		return scan.Result{}, fmt.Errorf("apply finding suppressions: %w", err)
	}
	if err := scan.ApplySuppressionResult(&data, suppressedFindings, suppressionReport); err != nil {
		return scan.Result{}, fmt.Errorf("attach finding suppressions: %w", err)
	}
	providerUsable := func(name string) bool { return scan.ProviderUsable(data.Collection, name) }
	if providerUsable("kernel") {
		data.Kernel = &kernelInventory
	}
	if providerUsable("software") {
		data.Software = &softwareInventory
	}
	if providerUsable("processes") {
		data.Processes = &processInventory
	}
	if providerUsable("services") {
		data.Services = &serviceInventory
	}
	if providerUsable("scheduled") {
		data.Scheduled = &scheduledInventory
	}
	if providerUsable("network") {
		data.Network = &networkInventory
	}
	if providerUsable("firewall") {
		data.Firewall = &firewallInventory
	}
	if providerUsable("remote-management") {
		data.RemoteManagement = &remoteManagement
	}
	if providerUsable("accounts") {
		data.Accounts = &accountInventory
	}
	if providerUsable("filesystem") {
		data.Filesystem = &filesystemInventory
	}
	if providerUsable("storage") {
		data.Storage = &storageInventory
	}
	if providerUsable("containers") {
		data.Containers = &containerInventory
	}
	if providerUsable("persistence") {
		data.Persistence = &persistenceInventory
	}
	if providerUsable("secrets") {
		data.Secrets = &secretInventory
	}
	data.Profile = scan.ProfileResult{Descriptor: applied.Profile, RuleDecisions: applied.Decisions}
	data.Selection = selected.Report
	loadedIntel, intelErr := intelSession.Loaded, intelSession.Error()
	intelProv := intelligenceProvenance(intelSession)
	var norm productnorm.Result
	if providerUsable("software") {
		norm = normalizationForInventory(softwareInventory, loadedIntel, intelErr)
	} else {
		versionName, digest := "unknown", ""
		if intelErr == nil {
			versionName, digest = loadedIntel.Metadata.Version, loadedIntel.Metadata.Digest
		}
		norm = productnorm.Unavailable(data.AssessedAt, versionName, digest, "software provider was quarantined or unavailable under the reliability boundary")
	}
	if err := norm.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate product normalization: %w", err)
	}
	data.ProductNormalization = &norm
	corr := correlationForNormalization(norm, loadedIntel, intelErr)
	if err := corr.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate vulnerability correlation: %w", err)
	}
	data.VulnerabilityCorrelation = &corr
	runtimeContext := vulnerability.CollectRuntimeSnapshot(ctx)
	reach := vulnerability.Contextualize(corr, softwareInventory, runtimeContext)
	if err := reach.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate vulnerability reachability: %w", err)
	}
	data.VulnerabilityReachability = &reach
	priority := prioritization.Compute(data.Findings, &reach)
	if err := priority.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate risk prioritization: %w", err)
	}
	data.Prioritization = &priority
	remediationView, err := remediation.Build(data.Findings, priority, remediation.EvaluationCoverage{
		SelectedRules: data.Summary.Evaluation.SelectedRules, EvaluatedRules: data.Summary.Evaluation.EvaluatedRules,
		NotEvaluatedRules: data.Summary.Evaluation.NotEvaluatedRules, Percent: data.Summary.Evaluation.Percent,
		Complete: data.Summary.Evaluation.Complete,
	})
	if err != nil {
		return scan.Result{}, fmt.Errorf("build remediation view: %w", err)
	}
	data.Remediation = &remediationView
	life := lifecycleForInventory(data.Overview, softwareInventory, loadedIntel, intelErr)
	if err := life.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate lifecycle assessment: %w", err)
	}
	data.Lifecycle = &life
	updates := updateInventory
	if !providerUsable("update-posture") {
		updates = updateposture.Unavailable(data.AssessedAt, "update posture provider was quarantined or unavailable under the reliability boundary")
	}
	if err := updates.Validate(); err != nil {
		return scan.Result{}, fmt.Errorf("validate update posture: %w", err)
	}
	data.UpdatePosture = &updates
	if (corr.State != "COMPLETE" || reach.State != "COMPLETE" || life.State != "COMPLETE" || updates.State != updateposture.StateComplete) && data.State == scan.StateComplete {
		data.State = scan.StateDegraded
	}
	normProv := normalizationProvenance(norm)
	corrProv := vulnerabilityCorrelationProvenance(corr)
	reachProv := vulnerabilityReachabilityProvenance(reach)
	lifeProv := lifecycleProvenance(life)
	updateProv := updatePostureProvenance(updates)
	priorityProv := riskPrioritizationProvenance(priority)
	data.Snapshot, err = snapshot.Build(snapshot.Input{
		StartedAt: data.Timing.StartedAt, CollectedAt: latestCollectionTime(data.Overview.CollectedAt, kernelInventory.CollectedAt, softwareInventory.CollectedAt, processInventory.CollectedAt, serviceInventory.CollectedAt, scheduledInventory.CollectedAt, networkInventory.CollectedAt, firewallInventory.CollectedAt, remoteManagement.CollectedAt, accountInventory.CollectedAt, filesystemInventory.CollectedAt, storageInventory.CollectedAt, containerInventory.CollectedAt, persistenceInventory.CollectedAt, secretInventory.CollectedAt, updates.CollectedAt), AssessedAt: data.AssessedAt, CompletedAt: data.Timing.CompletedAt,
		Overview: data.Overview, Kernel: data.Kernel, Software: data.Software, Processes: data.Processes, Services: data.Services, Scheduled: data.Scheduled, Network: data.Network, Firewall: data.Firewall, RemoteManagement: data.RemoteManagement, Accounts: data.Accounts, Filesystem: data.Filesystem, Storage: data.Storage, Containers: data.Containers, Persistence: data.Persistence, Secrets: data.Secrets, Options: opts, ConfigSources: rt.ConfigSources, Suppressions: data.Suppressions, Profile: applied.Profile, Rules: applied.Rules, Selection: selected.Report, Evaluation: snapshot.EvaluationProvenance{SelectedRules: data.Summary.Evaluation.SelectedRules, EvaluatedRules: data.Summary.Evaluation.EvaluatedRules, NotEvaluatedRules: data.Summary.Evaluation.NotEvaluatedRules, Percent: data.Summary.Evaluation.Percent, Complete: data.Summary.Evaluation.Complete}, Tool: version.Current(), Intelligence: &intelProv, ProductNormalization: &normProv, VulnerabilityCorrelation: &corrProv, VulnerabilityReachability: &reachProv, RiskPrioritization: &priorityProv, Lifecycle: &lifeProv, UpdatePosture: &updateProv,
	})
	if err != nil {
		return scan.Result{}, fmt.Errorf("build deterministic assessment snapshot: %w", err)
	}
	return data, nil
}

func runDiff(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	data, err := assessmentdiff.CompareFiles(rt.Args[0], rt.Args[1])
	if err != nil {
		return fmt.Errorf("compare assessments: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "diff", Version: version.Current(), Data: data})
	}
	render.AssessmentDiffHuman(w, data, opts.Verbose)
	return nil
}

func latestCollectionTime(times ...time.Time) time.Time {
	var latest time.Time
	for _, t := range times {
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}

func runKernel(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := kernel.Collect(ctx)
	if err := evidence.ValidateAll(data.Evidence); err != nil {
		return fmt.Errorf("validate kernel evidence: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "kernel", Version: version.Current(), Data: data})
	}
	render.KernelHuman(w, data, opts.Verbose)
	return nil
}

func runSoftware(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := software.Collect(ctx)
	if err := evidence.ValidateAll(data.Evidence); err != nil {
		return fmt.Errorf("validate software evidence: %w", err)
	}
	intelSession := intelligence.Open(intelligence.LoadOptions{Offline: opts.Offline})
	loadedIntel, intelErr := intelSession.Loaded, intelSession.Error()
	norm := normalizationForInventory(data, loadedIntel, intelErr)
	if err := norm.Validate(); err != nil {
		return fmt.Errorf("validate product normalization: %w", err)
	}
	o := overview.Collect(ctx)
	life := lifecycleForInventory(o, data, loadedIntel, intelErr)
	if err := life.Validate(); err != nil {
		return fmt.Errorf("validate lifecycle assessment: %w", err)
	}
	updates := updateposture.Collect(ctx)
	if err := updates.Validate(); err != nil {
		return fmt.Errorf("validate update posture: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "software", Version: version.Current(), Data: softwareCommandData{Inventory: data, ProductNormalization: norm, Lifecycle: life, UpdatePosture: updates}})
	}
	render.SoftwareHuman(w, data, opts.Verbose)
	render.ProductNormalizationHuman(w, norm, opts.Verbose)
	render.LifecycleHuman(w, life, opts.Verbose)
	render.UpdatePostureHuman(w, updates, opts.Verbose)
	return nil
}

func runProcesses(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := processes.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate process inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "processes", Version: version.Current(), Data: data})
	}
	render.ProcessesHuman(w, data, opts.Verbose)
	return nil
}

func runServices(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := services.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate service inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "services", Version: version.Current(), Data: data})
	}
	render.ServicesHuman(w, data, opts.Verbose)
	return nil
}

func runScheduled(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := scheduled.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate scheduled-execution inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "scheduled", Version: version.Current(), Data: data})
	}
	render.ScheduledHuman(w, data, opts.Verbose)
	return nil
}

func runNetwork(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := netinv.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate network inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "network", Version: version.Current(), Data: data})
	}
	render.NetworkHuman(w, data, opts.Verbose)
	return nil
}

func runFirewall(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	net := netinv.Collect(ctx)
	if err := net.Validate(); err != nil {
		return fmt.Errorf("validate network inventory for firewall correlation: %w", err)
	}
	data := firewall.Collect(ctx).WithListenerCoverage(net)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate firewall inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "firewall", Version: version.Current(), Data: data})
	}
	render.FirewallHuman(w, data, opts.Verbose)
	return nil
}

func runAccounts(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := accounts.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate account inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "accounts", Version: version.Current(), Data: data})
	}
	render.AccountsHuman(w, data, opts.Verbose)
	return nil
}

func runFilesystem(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := filesystem.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate filesystem inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "filesystem", Version: version.Current(), Data: data})
	}
	render.FilesystemHuman(w, data, opts.Verbose)
	return nil
}

func runStorage(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := storage.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate storage inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "storage", Version: version.Current(), Data: data})
	}
	render.StorageHuman(w, data, opts.Verbose)
	return nil
}

func runContainers(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := containerinv.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate container inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "containers", Version: version.Current(), Data: data})
	}
	render.ContainersHuman(w, data, opts.Verbose)
	return nil
}

func runPersistence(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := persistence.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate persistence inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "persistence", Version: version.Current(), Data: data})
	}
	render.PersistenceHuman(w, data, opts.Verbose)
	return nil
}

func runSecrets(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := secretinv.Collect(ctx)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate secret-storage inventory: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "secrets", Version: version.Current(), Data: data})
	}
	render.SecretsHuman(w, data, opts.Verbose)
	return nil
}

func runVulnerabilities(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	inv := software.Collect(ctx)
	if err := evidence.ValidateAll(inv.Evidence); err != nil {
		return fmt.Errorf("validate software evidence: %w", err)
	}
	intelSession := intelligence.Open(intelligence.LoadOptions{Offline: opts.Offline})
	loaded, intelErr := intelSession.Loaded, intelSession.Error()
	norm := normalizationForInventory(inv, loaded, intelErr)
	if err := norm.Validate(); err != nil {
		return fmt.Errorf("validate product normalization: %w", err)
	}
	corr := correlationForNormalization(norm, loaded, intelErr)
	if err := corr.Validate(); err != nil {
		return fmt.Errorf("validate vulnerability correlation: %w", err)
	}
	runtimeContext := vulnerability.CollectRuntimeSnapshot(ctx)
	reach := vulnerability.Contextualize(corr, inv, runtimeContext)
	if err := reach.Validate(); err != nil {
		return fmt.Errorf("validate vulnerability reachability: %w", err)
	}
	o := overview.Collect(ctx)
	life := lifecycleForInventory(o, inv, loaded, intelErr)
	if err := life.Validate(); err != nil {
		return fmt.Errorf("validate lifecycle assessment: %w", err)
	}
	updates := updateposture.Collect(ctx)
	if err := updates.Validate(); err != nil {
		return fmt.Errorf("validate update posture: %w", err)
	}
	data := vulnerabilitiesCommandData{Software: inv, ProductNormalization: norm, Correlation: corr, Reachability: reach, Lifecycle: life, UpdatePosture: updates}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "vulnerabilities", Version: version.Current(), Data: data})
	}
	render.VulnerabilityCorrelationHuman(w, corr, opts.Verbose)
	render.VulnerabilityReachabilityHuman(w, reach, corr, opts.Verbose)
	render.LifecycleHuman(w, life, opts.Verbose)
	render.UpdatePostureHuman(w, updates, opts.Verbose)
	return nil
}

func runIntelligence(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	if len(rt.Args) == 1 {
		if rt.Args[0] != "rollback" {
			return fmt.Errorf("unknown intelligence action %q; supported positional action: rollback", rt.Args[0])
		}
		if opts.RefreshIntelligence {
			return fmt.Errorf("intelligence rollback cannot be combined with --refresh-intelligence")
		}
		result, err := intelligence.Rollback(strings.TrimSpace(os.Getenv(intelligence.EnvDirectory)), time.Time{})
		if err != nil {
			return fmt.Errorf("roll back vulnerability intelligence: %w", err)
		}
		if opts.JSON {
			return render.JSON(w, envelope{Command: "intelligence.rollback", Version: version.Current(), Data: result})
		}
		render.IntelligenceRollbackHuman(w, result)
		return nil
	}

	if opts.RefreshIntelligence {
		result, err := intelligence.RefreshFromEnvironment(ctx)
		if err != nil {
			return fmt.Errorf("refresh vulnerability intelligence: %w", err)
		}
		session := intelligence.Open(intelligence.LoadOptions{})
		if err := session.Error(); err != nil {
			return fmt.Errorf("load activated vulnerability intelligence: %w", err)
		}
		data := struct {
			Refresh      intelligence.RefreshResult `json:"refresh"`
			Intelligence intelligence.Loaded        `json:"intelligence"`
		}{Refresh: result, Intelligence: session.Loaded}
		if opts.JSON {
			return render.JSON(w, envelope{Command: "intelligence.refresh", Version: version.Current(), Data: data})
		}
		render.IntelligenceRefreshHuman(w, result)
		render.IntelligenceHuman(w, session.Loaded, opts.Verbose)
		return nil
	}

	session := intelligence.Open(intelligence.LoadOptions{Offline: opts.Offline})
	if err := session.Error(); err != nil {
		return fmt.Errorf("load vulnerability intelligence: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "intelligence", Version: version.Current(), Data: session.Loaded})
	}
	render.IntelligenceHuman(w, session.Loaded, opts.Verbose)
	return nil
}

func intelligenceProvenance(session intelligence.Session) snapshot.IntelligenceProvenance {
	if loadErr := session.Error(); loadErr != nil {
		source := strings.TrimSpace(os.Getenv(intelligence.EnvDirectory))
		if source == "" {
			source = "embedded vulnerability intelligence store"
		}
		return snapshot.IntelligenceProvenance{
			State: "UNAVAILABLE", Version: "unknown", Source: source, Mode: session.Status.Mode,
			Freshness: session.Status.Freshness, MaxAgeSeconds: session.Status.MaxAgeSeconds,
			ReadOnly: true, NetworkAccess: false, Reason: loadErr.Error(),
		}
	}
	m := session.Loaded.Metadata
	return snapshot.IntelligenceProvenance{
		State: m.State, Schema: m.Schema, Version: m.Version, Source: m.Source,
		DigestAlgorithm: m.DigestAlgorithm, Digest: m.Digest, RetrievedAt: m.RetrievedAt,
		SourceCount: m.SourceCount, ProductCount: m.ProductCount, VulnerabilityCount: m.VulnerabilityCount, LifecycleCount: m.LifecycleCount,
		Mode: session.Status.Mode, Freshness: session.Status.Freshness, AgeSeconds: session.Status.AgeSeconds,
		MaxAgeSeconds: session.Status.MaxAgeSeconds, ReadOnly: session.Status.ReadOnly, NetworkAccess: session.Status.NetworkAccess,
		Reason: session.Status.Reason,
	}
}

func normalizationForInventory(inv software.Inventory, loaded intelligence.Loaded, loadErr error) productnorm.Result {
	if loadErr != nil {
		return productnorm.Unavailable(inv.CollectedAt, "unknown", "", "pinned vulnerability intelligence unavailable: "+loadErr.Error())
	}
	return productnorm.NormalizeInventory(inv, loaded)
}

func normalizationProvenance(norm productnorm.Result) snapshot.ProductNormalizationProvenance {
	return snapshot.ProductNormalizationProvenance{
		State: norm.State, Schema: norm.Schema, EngineVersion: norm.EngineVersion,
		IntelligenceVersion: norm.IntelligenceVersion, IntelligenceDigest: norm.IntelligenceDigest,
		CandidateCount: norm.Summary.Candidates, MatchedCount: norm.Summary.Matched, AmbiguousCount: norm.Summary.Ambiguous,
		Reason: norm.Reason,
	}
}

func correlationForNormalization(norm productnorm.Result, loaded intelligence.Loaded, loadErr error) vulnerability.Result {
	if loadErr != nil {
		return vulnerability.Unavailable(norm.EvaluatedAt, "unknown", "", "pinned vulnerability intelligence unavailable: "+loadErr.Error())
	}
	return vulnerability.Correlate(norm, loaded)
}

func vulnerabilityCorrelationProvenance(c vulnerability.Result) snapshot.VulnerabilityCorrelationProvenance {
	return snapshot.VulnerabilityCorrelationProvenance{
		State: c.State, Schema: c.Schema, EngineVersion: c.EngineVersion, IntelligenceVersion: c.IntelligenceVersion,
		IntelligenceDigest: c.IntelligenceDigest, EvaluationCount: c.Summary.Evaluations, AffectedCount: c.Summary.Affected,
		UnresolvedCount: c.Summary.Unresolved, Reason: c.Reason,
	}
}

func vulnerabilityReachabilityProvenance(r vulnerability.ReachabilityResult) snapshot.VulnerabilityReachabilityProvenance {
	return snapshot.VulnerabilityReachabilityProvenance{
		State: r.State, Schema: r.Schema, CollectorVersion: r.CollectorVersion,
		EvaluationCount: r.Summary.Evaluations, AffectedEvaluationCount: r.Summary.AffectedEvaluations,
		InstalledOnlyCount: r.Summary.InstalledOnly, RunningCount: r.Summary.Running, ServiceBackedCount: r.Summary.ServiceBacked,
		ListeningCount: r.Summary.Listening, PrivilegedCount: r.Summary.Privileged, UnknownCount: r.Summary.Unknown, Reason: r.Reason,
	}
}

func riskPrioritizationProvenance(r prioritization.Result) snapshot.RiskPrioritizationProvenance {
	return snapshot.RiskPrioritizationProvenance{
		Schema: r.Schema, EngineVersion: r.EngineVersion, FindingCount: r.Summary.Findings,
		ActionableFindingCount: r.Summary.ActionableFindings, VulnerabilityCount: r.Summary.Vulnerabilities,
		CriticalFindingCount: r.Summary.CriticalFindings, HighFindingCount: r.Summary.HighFindings,
	}
}

func lifecycleForInventory(o overview.Overview, inv software.Inventory, loaded intelligence.Loaded, loadErr error) lifecycle.Result {
	if loadErr != nil {
		at := inv.CollectedAt
		if at.IsZero() {
			at = o.CollectedAt
		}
		return lifecycle.Unavailable(at, "unknown", "", "pinned lifecycle intelligence unavailable: "+loadErr.Error())
	}
	return lifecycle.Evaluate(o, inv, loaded)
}

func lifecycleProvenance(r lifecycle.Result) snapshot.LifecycleProvenance {
	return snapshot.LifecycleProvenance{
		State: r.State, Schema: r.Schema, EngineVersion: r.EngineVersion, IntelligenceVersion: r.IntelligenceVersion, IntelligenceDigest: r.IntelligenceDigest,
		CandidateCount: r.Summary.Candidates, WithIntelligenceCount: r.Summary.WithIntelligence, SupportedCount: r.Summary.Supported, EndOfLifeCount: r.Summary.EndOfLife, UnsupportedCount: r.Summary.Unsupported, UnknownCount: r.Summary.Unknown, Reason: r.Reason,
	}
}

func updatePostureProvenance(r updateposture.Result) snapshot.UpdatePostureProvenance {
	return snapshot.UpdatePostureProvenance{
		State: string(r.State), Schema: r.Schema, CollectorVersion: r.CollectorVersion,
		PendingCount: r.Summary.Pending, SecurityCount: r.Summary.Security, OtherCount: r.Summary.Other, UnknownClassificationCount: r.Summary.UnknownClassification,
		RebootRequired: r.Summary.RebootRequired, FreshProviders: r.Summary.FreshProviders, StaleProviders: r.Summary.StaleProviders, UnknownFreshnessProviders: r.Summary.UnknownFreshnessProviders,
		Reason: strings.Join(r.Limitations, "; "),
	}
}

func runOverview(ctx context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	data := overview.Collect(ctx)
	if opts.JSON {
		return render.JSON(w, envelope{Command: "overview", Version: version.Current(), Data: data})
	}
	render.OverviewHuman(w, data, opts.Verbose)
	return nil
}

func runFindings(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	applied, err := appliedProfile(rt)
	if err != nil {
		return fmt.Errorf("apply assessment profile: %w", err)
	}
	selected, err := appliedSelection(applied, opts)
	if err != nil {
		return fmt.Errorf("apply rule selection: %w", err)
	}
	o, k, observations, assessedAt, err := collectAssessmentEvidence(ctx)
	if err != nil {
		return fmt.Errorf("collect assessment evidence: %w", err)
	}
	_ = k
	findings, err := assessment.EvaluateRules(selected.Rules, observations, assessedAt)
	if err != nil {
		return fmt.Errorf("evaluate findings: %w", err)
	}
	findings, suppressionReport, err := suppression.Apply(findings, rt.Suppressions, applied.Rules, assessedAt)
	if err != nil {
		return fmt.Errorf("apply finding suppressions: %w", err)
	}
	priority := prioritization.Compute(findings, nil)
	if err := priority.Validate(); err != nil {
		return fmt.Errorf("validate risk prioritization: %w", err)
	}
	data := struct {
		Schema         string                 `json:"finding_schema"`
		Evidence       string                 `json:"evidence_schema"`
		Profile        profile.Descriptor     `json:"profile"`
		RuleDecisions  []profile.RuleDecision `json:"profile_rule_decisions"`
		Selection      selection.Report       `json:"selection"`
		Findings       []assessment.Finding   `json:"findings"`
		Suppressions   suppression.Report     `json:"suppressions"`
		Prioritization prioritization.Result  `json:"prioritization"`
	}{Schema: assessment.SchemaVersion, Evidence: o.EvidenceSchema, Profile: applied.Profile, RuleDecisions: applied.Decisions, Selection: selected.Report, Findings: findings, Suppressions: suppressionReport, Prioritization: priority}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "findings", Version: version.Current(), Data: data})
	}
	render.ProfileHeaderHuman(w, applied.Profile, applied.Decisions)
	render.SelectionHuman(w, selected.Report, opts.Verbose)
	render.SuppressionsHuman(w, suppressionReport, opts.Verbose)
	render.PrioritizationHuman(w, priority, opts.Verbose)
	render.FindingsHuman(w, findings, opts.Verbose)
	return nil
}

type profiledInspection struct {
	assessment.FindingInspection
	Profile       profile.Descriptor             `json:"profile"`
	RulePolicy    profile.RuleDecision           `json:"profile_rule_policy"`
	Selection     selection.Report               `json:"selection"`
	RuleSelection selection.Decision             `json:"rule_selection"`
	Suppressions  suppression.Report             `json:"suppressions"`
	Priority      prioritization.FindingPriority `json:"priority"`
}

func inspectCurrentFinding(ctx context.Context, id string, opts cli.Options, rt Runtime) (profiledInspection, error) {
	applied, err := appliedProfile(rt)
	if err != nil {
		return profiledInspection{}, err
	}
	selected, err := appliedSelection(applied, opts)
	if err != nil {
		return profiledInspection{}, fmt.Errorf("apply rule selection: %w", err)
	}
	targetRuleID := ""
	for _, rule := range applied.Rules {
		if strings.EqualFold(assessment.StableFindingID(rule.ID, rule.AffectedObject), strings.TrimSpace(id)) {
			targetRuleID = rule.ID
			break
		}
	}
	if targetRuleID == "" {
		return profiledInspection{}, fmt.Errorf("finding %q not found in the implemented rule catalog", id)
	}
	selectionDecision, ok := selection.DecisionFor(selected.Report, targetRuleID)
	if !ok {
		return profiledInspection{}, fmt.Errorf("selection decision for rule %q is unavailable", targetRuleID)
	}
	if selectionDecision.Outcome != selection.OutcomeSelected {
		return profiledInspection{}, fmt.Errorf("finding %q is %s by current selection policy: %s", id, strings.ToLower(string(selectionDecision.Outcome)), selectionDecision.Reason)
	}
	_, _, observations, assessedAt, err := collectAssessmentEvidence(ctx)
	if err != nil {
		return profiledInspection{}, fmt.Errorf("collect assessment evidence: %w", err)
	}
	inspection, err := assessment.InspectFinding(selected.Rules, observations, assessedAt, id)
	if err != nil {
		return profiledInspection{}, err
	}
	allFindings, err := assessment.EvaluateRules(selected.Rules, observations, assessedAt)
	if err != nil {
		return profiledInspection{}, fmt.Errorf("evaluate findings for suppression audit: %w", err)
	}
	allFindings, suppressionReport, err := suppression.Apply(allFindings, rt.Suppressions, applied.Rules, assessedAt)
	if err != nil {
		return profiledInspection{}, fmt.Errorf("apply finding suppressions: %w", err)
	}
	for _, candidate := range allFindings {
		if strings.EqualFold(candidate.ID, inspection.Finding.ID) {
			inspection.Finding = candidate
			break
		}
	}
	decision, ok := profile.DecisionFor(applied, inspection.Finding.RuleID)
	if !ok {
		return profiledInspection{}, fmt.Errorf("profile decision for rule %q is unavailable", inspection.Finding.RuleID)
	}
	priorityResult := prioritization.Compute([]assessment.Finding{inspection.Finding}, nil)
	if err := priorityResult.Validate(); err != nil {
		return profiledInspection{}, fmt.Errorf("validate finding priority: %w", err)
	}
	return profiledInspection{FindingInspection: inspection, Profile: applied.Profile, RulePolicy: decision, Selection: selected.Report, RuleSelection: selectionDecision, Suppressions: suppressionReport, Priority: priorityResult.Findings[0]}, nil
}

func collectAssessmentEvidence(ctx context.Context) (overview.Overview, kernel.Inventory, []evidence.Observation, time.Time, error) {
	o := overview.Collect(ctx)
	k := kernel.Collect(ctx)
	p := processes.Collect(ctx)
	sv := services.Collect(ctx)
	if err := sv.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate service inventory: %w", err)
	}
	sch := scheduled.Collect(ctx)
	if err := sch.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate scheduled-execution inventory: %w", err)
	}
	net := netinv.Collect(ctx)
	if err := net.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate network inventory: %w", err)
	}
	fw := firewall.Collect(ctx).WithListenerCoverage(net)
	if err := fw.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate firewall inventory: %w", err)
	}
	rm := remotemgmt.Collect(ctx, sv, net, fw)
	if err := rm.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate remote-management posture: %w", err)
	}
	ac := accounts.Collect(ctx)
	if err := ac.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate account inventory: %w", err)
	}
	fs := filesystem.Collect(ctx)
	if err := fs.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate filesystem inventory: %w", err)
	}
	st := storage.Collect(ctx)
	if err := st.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate storage inventory: %w", err)
	}
	ct := containerinv.Collect(ctx)
	if err := ct.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate container inventory: %w", err)
	}
	per := persistence.CollectFrom(ctx, sv, sch, ac)
	if err := per.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate persistence inventory: %w", err)
	}
	sec := secretinv.Collect(ctx)
	if err := sec.Validate(); err != nil {
		return o, k, nil, time.Time{}, fmt.Errorf("validate secret-storage inventory: %w", err)
	}
	observations := append([]evidence.Observation(nil), o.Evidence...)
	observations = append(observations, k.Evidence...)
	observations = append(observations, p.Evidence...)
	observations = append(observations, sv.Evidence...)
	observations = append(observations, sch.Evidence...)
	observations = append(observations, net.Evidence...)
	observations = append(observations, fw.Evidence...)
	observations = append(observations, rm.Evidence...)
	observations = append(observations, ac.Evidence...)
	observations = append(observations, fs.Evidence...)
	observations = append(observations, st.Evidence...)
	observations = append(observations, ct.Evidence...)
	observations = append(observations, per.Evidence...)
	observations = append(observations, sec.Evidence...)
	if err := evidence.ValidateAll(observations); err != nil {
		return o, k, nil, time.Time{}, err
	}
	assessedAt := latestCollectionTime(o.CollectedAt, k.CollectedAt, p.CollectedAt, sv.CollectedAt, sch.CollectedAt, net.CollectedAt, fw.CollectedAt, rm.CollectedAt, ac.CollectedAt, fs.CollectedAt, st.CollectedAt, ct.CollectedAt, per.CollectedAt, sec.CollectedAt)
	return o, k, observations, assessedAt, nil
}

func runFinding(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	inspection, err := inspectCurrentFinding(ctx, rt.Args[0], opts, rt)
	if err != nil {
		return fmt.Errorf("inspect finding: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "finding", Version: version.Current(), Data: inspection})
	}
	render.ProfileHeaderHuman(w, inspection.Profile, []profile.RuleDecision{inspection.RulePolicy})
	render.SelectionDecisionHuman(w, inspection.Selection, inspection.RuleSelection)
	render.SuppressionsHuman(w, inspection.Suppressions, opts.Verbose)
	render.FindingPriorityHuman(w, inspection.Priority, opts.Verbose)
	render.FindingInspectionHuman(w, inspection.FindingInspection, opts.Verbose)
	return nil
}

func runExplain(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	inspection, err := inspectCurrentFinding(ctx, rt.Args[0], opts, rt)
	if err != nil {
		return fmt.Errorf("explain finding: %w", err)
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "explain", Version: version.Current(), Data: inspection})
	}
	render.ProfileHeaderHuman(w, inspection.Profile, []profile.RuleDecision{inspection.RulePolicy})
	render.SelectionDecisionHuman(w, inspection.Selection, inspection.RuleSelection)
	render.SuppressionsHuman(w, inspection.Suppressions, opts.Verbose)
	render.FindingPriorityHuman(w, inspection.Priority, opts.Verbose)
	render.FindingExplanationHuman(w, inspection.FindingInspection, opts.Verbose)
	return nil
}

func runEvidence(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	inspection, err := inspectCurrentFinding(ctx, rt.Args[0], opts, rt)
	if err != nil {
		return fmt.Errorf("inspect finding evidence: %w", err)
	}
	if opts.JSON {
		data := struct {
			InspectionSchema string                     `json:"inspection_schema"`
			FindingID        string                     `json:"finding_id"`
			RuleID           string                     `json:"rule_id"`
			EvidenceSchema   string                     `json:"evidence_schema"`
			Profile          profile.Descriptor         `json:"profile"`
			RulePolicy       profile.RuleDecision       `json:"profile_rule_policy"`
			Selection        selection.Report           `json:"selection"`
			RuleSelection    selection.Decision         `json:"rule_selection"`
			Provenance       []assessment.EvidenceRef   `json:"provenance"`
			Reproducibility  assessment.Reproducibility `json:"reproducibility"`
			Suppressions     suppression.Report         `json:"suppressions"`
		}{
			InspectionSchema: inspection.Schema, FindingID: inspection.Finding.ID, RuleID: inspection.Finding.RuleID,
			EvidenceSchema: inspection.EvidenceSchema, Profile: inspection.Profile, RulePolicy: inspection.RulePolicy,
			Selection: inspection.Selection, RuleSelection: inspection.RuleSelection, Provenance: inspection.Provenance, Reproducibility: inspection.Reproducible, Suppressions: inspection.Suppressions,
		}
		return render.JSON(w, envelope{Command: "evidence", Version: version.Current(), Data: data})
	}
	render.ProfileHeaderHuman(w, inspection.Profile, []profile.RuleDecision{inspection.RulePolicy})
	render.SelectionDecisionHuman(w, inspection.Selection, inspection.RuleSelection)
	render.SuppressionsHuman(w, inspection.Suppressions, opts.Verbose)
	render.FindingEvidenceHuman(w, inspection.FindingInspection, opts.Verbose)
	return nil
}

func runProfiles(_ context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	applied, err := appliedProfile(rt)
	if err != nil {
		return fmt.Errorf("apply assessment profile: %w", err)
	}
	data := struct {
		Schema        string                 `json:"profile_schema"`
		Active        profile.Descriptor     `json:"active"`
		Catalog       []profile.Descriptor   `json:"catalog"`
		RuleDecisions []profile.RuleDecision `json:"rule_decisions"`
	}{Schema: profile.SchemaVersion, Active: applied.Profile, Catalog: append([]profile.Descriptor(nil), rt.ProfileCatalog...), RuleDecisions: applied.Decisions}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "profiles", Version: version.Current(), Data: data})
	}
	render.ProfilesHuman(w, applied.Profile, data.Catalog, applied.Decisions)
	return nil
}

func runVersion(_ context.Context, w io.Writer, opts cli.Options, _ Runtime) error {
	info := version.Current()
	if opts.JSON {
		return render.JSON(w, envelope{Command: "version", Version: info, Data: info})
	}
	fmt.Fprintf(w, "IRONCLAD Chimera %s\ncommit: %s\nbuild date: %s\n", info.Version, info.Commit, info.BuildDate)
	return nil
}

func runDoctor(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	data := doctor.Run(ctx, doctor.Options{
		ExplicitConfig:      opts.ConfigPath,
		LoadedConfigSources: append([]string(nil), rt.ConfigSources...),
		Offline:             opts.Offline,
		RefreshIntelligence: opts.RefreshIntelligence,
	})
	if opts.JSON {
		return render.JSON(w, envelope{Command: "doctor", Version: version.Current(), Data: data})
	}
	render.DoctorHuman(w, data, opts.Verbose)
	return nil
}

func runConfig(_ context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	data := configView(opts, rt.ConfigSources, len(rt.Suppressions))
	if opts.JSON {
		return render.JSON(w, envelope{Command: "config", Version: version.Current(), Data: data})
	}
	fmt.Fprintln(w, "EFFECTIVE CONFIG")
	fmt.Fprintf(w, "  timeout              %s\n", data.Timeout)
	fmt.Fprintf(w, "  profile              %s\n", data.Profile)
	fmt.Fprintf(w, "  severity             %s\n", data.Severity)
	fmt.Fprintf(w, "  category             %s\n", display(data.Category))
	fmt.Fprintf(w, "  include              %s\n", list(data.Include))
	fmt.Fprintf(w, "  exclude              %s\n", list(data.Exclude))
	fmt.Fprintf(w, "  json                 %t\n", data.JSON)
	fmt.Fprintf(w, "  plain                %t\n", data.Plain)
	fmt.Fprintf(w, "  no-color             %t\n", data.NoColor)
	fmt.Fprintf(w, "  quiet                %t\n", data.Quiet)
	fmt.Fprintf(w, "  verbose              %t\n", data.Verbose)
	fmt.Fprintf(w, "  offline              %t\n", data.Offline)
	fmt.Fprintf(w, "  refresh-intelligence %t\n", data.RefreshIntelligence)
	fmt.Fprintf(w, "  max-workers          %d\n", data.MaxWorkers)
	fmt.Fprintf(w, "  suppressions         %d\n", data.SuppressionCount)
	fmt.Fprintf(w, "  output               %s\n", display(data.Output))
	fmt.Fprintf(w, "  explicit config      %s\n", display(data.ConfigPath))
	fmt.Fprintln(w, "\nLOADED CONFIG SOURCES")
	if len(data.Sources) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		for _, s := range data.Sources {
			fmt.Fprintln(w, "  "+s)
		}
	}
	return nil
}

func configView(opts cli.Options, sources []string, suppressionCount int) effectiveConfig {
	return effectiveConfig{
		JSON: opts.JSON, Plain: opts.Plain, NoColor: opts.NoColor, Quiet: opts.Quiet, Verbose: opts.Verbose,
		Timeout: opts.Timeout.String(), Profile: opts.Profile, Severity: opts.Severity, Category: opts.Category,
		Include: append([]string(nil), opts.Include...), Exclude: append([]string(nil), opts.Exclude...), Output: opts.Output,
		ConfigPath: opts.ConfigPath, Offline: opts.Offline, RefreshIntelligence: opts.RefreshIntelligence,
		MaxWorkers: opts.MaxWorkers, Sources: append([]string(nil), sources...), SuppressionCount: suppressionCount,
	}
}

const rootSummary = "Terminal-first, read-only live-host vulnerability, exposure and misconfiguration assessment."

func terminalContext(w io.Writer, opts cli.Options) terminalui.Context {
	return terminalui.New(w, terminalui.Options{
		JSON: opts.JSON, Plain: opts.Plain, NoColor: opts.NoColor, Quiet: opts.Quiet,
	})
}

func printLauncher(w io.Writer, opts cli.Options, registry map[string]Command) error {
	if opts.JSON {
		type item struct {
			Name    string `json:"name"`
			Lane    string `json:"lane"`
			Summary string `json:"summary"`
		}
		items := make([]item, 0, len(registry))
		for _, c := range sortedCommands(registry) {
			items = append(items, item{Name: c.Name, Lane: c.Lane, Summary: c.Summary})
		}
		return render.JSON(w, envelope{Command: "launcher", Version: version.Current(), Data: map[string]any{"implemented_commands": items}})
	}

	terminal := terminalContext(w, opts)
	if banner := terminalui.BannerText(terminal, version.Current().Version); banner != "" {
		fmt.Fprintln(w, banner)
	}
	rootWidth := terminal.Width
	if rootWidth <= 0 || rootWidth > 80 {
		rootWidth = 80
	}
	for _, line := range terminalui.WrapWords(rootSummary, rootWidth) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, terminalui.Accent("Workflows", terminal.ColorMode))
	for _, lane := range laneOrder() {
		commands := commandsForLane(registry, lane)
		if len(commands) == 0 {
			continue
		}
		paths := make([]string, 0, len(commands))
		for _, cmd := range commands {
			paths = append(paths, "chimera "+cmd.Name)
		}
		writeRootWorkflowRows(w, lane, paths, terminal.Width)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, terminalui.Accent("Start", terminal.ColorMode))
	fmt.Fprintln(w, "  chimera overview")
	fmt.Fprintln(w, "  chimera scan")
	fmt.Fprintln(w, "  chimera --help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, terminalui.Dim("Machine output: chimera overview --json", terminal.ColorMode))
	return nil
}

func writeRootWorkflowRows(w io.Writer, label string, paths []string, width int) {
	limit := width
	if limit <= 0 || limit > 80 {
		limit = 80
	}
	const labelWidth = 12
	firstPrefix := fmt.Sprintf("  %-*s ", labelWidth, label)
	continuationPrefix := strings.Repeat(" ", len([]rune(firstPrefix)))
	line := firstPrefix
	for _, path := range paths {
		addition := path
		if line != firstPrefix && line != continuationPrefix {
			addition = "  " + path
		}
		if len([]rune(line+addition)) > limit && line != firstPrefix && line != continuationPrefix {
			fmt.Fprintln(w, line)
			line = continuationPrefix + path
			continue
		}
		line += addition
	}
	if line != firstPrefix && line != continuationPrefix {
		fmt.Fprintln(w, line)
	}
}

type rootHelpOption struct {
	Flag        string
	Description string
}

type rootHelpOptionGroup struct {
	Title   string
	Options []rootHelpOption
}

func printRootHelp(w io.Writer, opts cli.Options, registry map[string]Command) error {
	if opts.JSON {
		return printLauncher(w, opts, registry)
	}
	terminal := terminalContext(w, opts)
	fmt.Fprintln(w, terminalui.Accent("CHIMERA HELP", terminal.ColorMode))
	fmt.Fprintln(w, rootSummary)
	fmt.Fprintln(w)

	fmt.Fprintln(w, terminalui.Accent("Navigation", terminal.ColorMode))
	fmt.Fprintln(w, "  chimera                        Open the compact root menu")
	fmt.Fprintln(w, "  chimera <command> --help       Open detailed help for one command")
	fmt.Fprintln(w, "  chimera help <command>         Equivalent explicit command-help route")
	fmt.Fprintln(w, "  chimera --version              Show the Chimera version")
	fmt.Fprintln(w)

	fmt.Fprintln(w, terminalui.Accent("Commands", terminal.ColorMode))
	fmt.Fprintln(w, terminalui.Dim("Every registered Chimera command, grouped by workflow. Usage lines include command-specific arguments and options.", terminal.ColorMode))
	fmt.Fprintln(w)
	for _, lane := range laneOrder() {
		commands := commandsForLane(registry, lane)
		if len(commands) == 0 {
			continue
		}
		fmt.Fprintln(w, terminalui.Accent(lane, terminal.ColorMode))
		if description := laneDescription(lane); description != "" {
			fmt.Fprintf(w, "  %s\n", description)
		}
		for _, cmd := range commands {
			fmt.Fprintf(w, "\n  %-22s %s\n", cmd.Name, cmd.Summary)
			fmt.Fprintf(w, "    %s\n", terminalui.Dim("Usage: "+cmd.Help.Usage, terminal.ColorMode))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, terminalui.Accent("Global options", terminal.ColorMode))
	fmt.Fprintln(w, terminalui.Dim("Global options may be placed before or after a command.", terminal.ColorMode))
	fmt.Fprintln(w)
	for _, group := range rootHelpOptionGroups() {
		fmt.Fprintln(w, terminalui.Accent(group.Title, terminal.ColorMode))
		for _, option := range group.Options {
			fmt.Fprintf(w, "  %-32s %s\n", option.Flag, option.Description)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, terminalui.Accent("Help model", terminal.ColorMode))
	fmt.Fprintln(w, "  chimera --help                 Complete command and global-option reference")
	fmt.Fprintln(w, "  chimera <command> --help       Purpose, usage, examples, output, safety, requirements and next steps")
	fmt.Fprintln(w, "  chimera help <command>         Equivalent explicit command-help route")
	fmt.Fprintln(w)
	fmt.Fprintln(w, terminalui.Dim("Machine registry: chimera --json", terminal.ColorMode))
	return nil
}

func rootHelpOptionGroups() []rootHelpOptionGroup {
	return []rootHelpOptionGroup{
		{
			Title: "Output & presentation",
			Options: []rootHelpOption{
				{Flag: "--json", Description: "Emit machine-readable JSON output."},
				{Flag: "--plain", Description: "Use plain human-readable output without decorative styling."},
				{Flag: "--no-color", Description: "Disable ANSI color output."},
				{Flag: "--quiet", Description: "Suppress nonessential operator output."},
				{Flag: "--verbose", Description: "Enable additional evidence and diagnostic detail."},
				{Flag: "--output <path>", Description: "Write command output to a file."},
			},
		},
		{
			Title: "Assessment scope",
			Options: []rootHelpOption{
				{Flag: "--profile <name>", Description: "Select an assessment profile."},
				{Flag: "--severity <level>", Description: "Set the minimum severity: INFO, LOW, MEDIUM, HIGH or CRITICAL."},
				{Flag: "--category <name>", Description: "Restrict assessment scope to one category."},
				{Flag: "--include <selector>", Description: "Include a rule or category selector; repeatable."},
				{Flag: "--exclude <selector>", Description: "Exclude a rule or category selector; repeatable."},
			},
		},
		{
			Title: "Configuration & intelligence",
			Options: []rootHelpOption{
				{Flag: "--config <path>", Description: "Load configuration from a specific file."},
				{Flag: "--offline", Description: "Require offline operation and prohibit intelligence refresh."},
				{Flag: "--refresh-intelligence", Description: "Refresh signed vulnerability intelligence for the intelligence command only."},
			},
		},
		{
			Title: "Execution",
			Options: []rootHelpOption{
				{Flag: "--timeout <duration>", Description: "Set the command execution timeout."},
				{Flag: "--max-workers <n>", Description: fmt.Sprintf("Set bounded assessment concurrency from 1 to %d.", reliability.MaxWorkers)},
				{Flag: "-h, --help", Description: "Show complete root help or detailed command help."},
				{Flag: "-V, --version", Description: "Show the Chimera version."},
			},
		},
	}
}

func printCommandHelp(w io.Writer, opts cli.Options, cmd Command) error {
	if opts.JSON {
		data := map[string]any{"name": cmd.Name, "lane": cmd.Lane, "summary": cmd.Summary, "purpose": cmd.Help.Purpose, "usage": cmd.Help.Usage, "examples": cmd.Help.Examples, "output": cmd.Help.Output, "safety": cmd.Help.Safety, "requirements": cmd.Help.Requirements, "next_steps": cmd.Help.NextSteps}
		return render.JSON(w, envelope{Command: "help", Version: version.Current(), Data: data})
	}
	terminal := terminalContext(w, opts)
	section := func(name string, lines []string) {
		fmt.Fprintln(w, terminalui.Accent(name, terminal.ColorMode))
		for _, line := range lines {
			for _, part := range strings.Split(strings.TrimSpace(line), "\n") {
				fmt.Fprintf(w, "  %s\n", part)
			}
		}
		fmt.Fprintln(w)
	}
	section("Purpose", []string{cmd.Help.Purpose})
	section("Usage", []string{cmd.Help.Usage})
	examples := cmd.Help.Examples
	if len(examples) == 0 {
		examples = []string{cmd.Help.Usage}
	}
	section("Examples", examples)
	section("Output", []string{cmd.Help.Output})
	section("Safety", []string{cmd.Help.Safety})
	section("Requirements", []string{cmd.Help.Requirements})
	section("Next steps", []string{cmd.Help.NextSteps})
	return nil
}

func laneOrder() []string {
	return []string{"Observe", "Assess", "Investigate", "Report", "Maintain"}
}

func commandsForLane(registry map[string]Command, lane string) []Command {
	out := make([]Command, 0)
	for _, cmd := range registry {
		if cmd.Lane == lane {
			out = append(out, cmd)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func laneDescription(lane string) string {
	switch lane {
	case "Observe":
		return "Inspect normalized live-host inventory and security-relevant local evidence."
	case "Assess":
		return "Evaluate exposure, hardening, vulnerabilities and misconfiguration posture."
	case "Investigate":
		return "Trace findings, evidence, relationships, changes and consolidated attack surface."
	case "Report":
		return "Summarize, report, export and review remediation guidance from assessment results."
	case "Maintain":
		return "Inspect configuration, profiles, rules, diagnostics, version and intelligence state."
	default:
		return ""
	}
}

func validateCommandArgs(cmd Command, args []string) error {
	if len(args) < cmd.MinArgs {
		usage := cmd.Help.Usage
		if usage == "" {
			usage = "chimera " + cmd.Name
		}
		return fmt.Errorf("command %q requires %s; usage: %s", cmd.Name, cmd.ArgSyntax, usage)
	}
	if len(args) > cmd.MaxArgs {
		if cmd.MaxArgs == 0 {
			return fmt.Errorf("command %q does not accept positional arguments: %s", cmd.Name, strings.Join(args, " "))
		}
		return fmt.Errorf("command %q accepts at most %d positional argument(s); usage: %s", cmd.Name, cmd.MaxArgs, cmd.Help.Usage)
	}
	return nil
}

func unknownCommand(name string, registry map[string]Command) error {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return fmt.Errorf("unknown command %q; implemented commands: %s", name, strings.Join(names, ", "))
}

func sortedCommands(registry map[string]Command) []Command {
	out := make([]Command, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	laneOrder := map[string]int{"Observe": 0, "Assess": 1, "Investigate": 2, "Report": 3, "Maintain": 4}
	sort.Slice(out, func(i, j int) bool {
		li, lj := laneOrder[out[i].Lane], laneOrder[out[j].Lane]
		if li != lj {
			return li < lj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func display(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}
func list(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

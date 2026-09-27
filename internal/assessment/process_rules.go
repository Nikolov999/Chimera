package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/processes"
)

const maxProcessRuleEvidence = 128

// ProcessRules implements executable-trust, execution-location,
// executable/parent-path permission, runtime privilege-excess,
// executable-memory metadata, loaded-module trust, // isolation, and runtime-environment evidence. consolidates
// these into the concrete runtime-security rule pack. The rules consume
// normalized read-only evidence; they never open for content, execute, inject
// into, suspend, or otherwise manipulate a process.
func ProcessRules() []Rule {
	rules := []Rule{
		processExplicitTrustFailureRule(),
		processUnsignedExecutableRule(),
		privilegedProcessTrustRule(),
		privilegedProcessProvenanceRule(),
		privilegedCriticalExecutionLocationRule(),
		privilegedWeakExecutionLocationRule(),
		sensitiveProcessExecutionLocationRule(),
		privilegedExecutablePermissionRule(),
		privilegedParentPermissionRule(),
		sensitiveProcessPermissionRule(),
		effectiveIdentityTransitionRule(),
		highImpactRuntimePrivilegeRule(),
		windowsTokenIntegrityRule(),
		writableExecutableMemoryRule(),
		anonymousExecutableMemoryRule(),
		loadedModuleTrustRule(),
		privilegedLoadedModuleLocationRule(),
		loadedModuleProvenanceMismatchRule(),
		privilegedRuntimeEnvironmentRule(),
		sensitiveRuntimeEnvironmentRule(),
		unsafeRuntimeSearchPathRule(),
		uncontainedHighRiskRuntimeRule(),
		compoundPrivilegedRuntimeBoundaryRule(),
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func processExplicitTrustFailureRule() Rule {
	return Rule{
		ID:             "CHM-PRC-001",
		Title:          "Live executables have no explicit trust failure",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.executable_trust",
		ExpectedState:  "no live executable has an invalid, untrusted, revoked, hash-mismatched, or deleted backing identity",
		Risk:           "A process executing from an explicitly untrusted signature or deleted backing file has weakened provenance and can indicate tampering, replacement, or execution outside the expected software trust boundary.",
		Remediation:    "Identify the affected executable from the evidence, validate it against the operating-system or vendor package/signing source, replace or remove untrusted binaries through supported software-management procedures, and investigate unexpected deleted-backing execution.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			bad := make([]processEvidenceItem, 0)
			unresolved := 0
			for _, item := range items {
				state := normalizeTrustState(item.Process.Trust.State)
				switch state {
				case "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "UNTRUSTED", "REVOKED", "HASH_MISMATCH", "DELETED_BACKING":
					bad = append(bad, item)
				case "UNKNOWN", "PROVENANCE_UNKNOWN", "UNCLASSIFIED_PATH", "SYSTEM_OR_MANAGED_PATH", "":
					unresolved++
				}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processItemsConfidence(bad), ObservedState: fmt.Sprintf("%d live executable(s) have an explicit trust/backing failure", len(bad)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(bad)}
			}
			conf := evidence.ConfidenceHigh
			observed := "0 explicit executable trust failures"
			if unresolved > 0 {
				conf = evidence.ConfidenceMedium
				observed = fmt.Sprintf("0 explicit executable trust failures; %d trust state(s) unresolved", unresolved)
			}
			return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: observed, Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
		},
	}
}

func processUnsignedExecutableRule() Rule {
	return Rule{
		ID:             "CHM-PRC-002",
		Title:          "Unsigned live executables are absent where signature validation is available",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.executable_signature",
		ExpectedState:  "live executables are signed where the platform exposes a native executable-signature trust mechanism",
		Risk:           "Unsigned executables can bypass an important software provenance signal and deserve review when the operating system normally provides executable-signature verification.",
		Remediation:    "Confirm whether the unsigned executable is expected for the host role. Prefer vendor-signed or platform-managed software, reinstall altered software from a trusted source, and remove unexpected unsigned binaries after dependency review.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			if processPlatform(idx) == "linux" {
				keys := processInventoryEvidenceKeys(idx, items)
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Linux uses package/application provenance for ; a universal executable-signature requirement is not applicable", Applicability: NotApplicable, EvidenceKeys: keys}
			}
			unsigned := make([]processEvidenceItem, 0)
			verifierObserved := false
			unresolved := 0
			for _, item := range items {
				state := normalizeTrustState(item.Process.Trust.State)
				switch state {
				case "SIGNED_VALID", "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "REVOKED", "HASH_MISMATCH", "UNSIGNED":
					verifierObserved = true
				}
				if state == "UNSIGNED" {
					unsigned = append(unsigned, item)
				}
				if state == "UNKNOWN" || state == "PROVENANCE_UNKNOWN" || state == "UNCLASSIFIED_PATH" || state == "SYSTEM_OR_MANAGED_PATH" || state == "" {
					unresolved++
				}
			}
			if len(unsigned) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processItemsConfidence(unsigned), ObservedState: fmt.Sprintf("%d unsigned live executable(s) observed", len(unsigned)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(unsigned)}
			}
			if !verifierObserved {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("native executable-signature result unavailable across %d process record(s)", len(items)), Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			conf := evidence.ConfidenceHigh
			observed := "0 unsigned live executables observed"
			if unresolved > 0 {
				conf = evidence.ConfidenceMedium
				observed = fmt.Sprintf("0 unsigned live executables observed; %d signature state(s) unresolved", unresolved)
			}
			return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: observed, Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
		},
	}
}

func privilegedProcessTrustRule() Rule {
	return Rule{
		ID:             "CHM-PRC-003",
		Title:          "Privileged live executables have no explicit trust failure",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_executable_trust",
		ExpectedState:  "privileged live processes have no unsigned, invalid, untrusted, revoked, hash-mismatched, or deleted executable backing",
		Risk:           "An explicitly untrusted or unsigned executable running as SYSTEM/root-equivalent code materially weakens the host trust boundary and increases the impact of binary replacement or tampering.",
		Remediation:    "Validate each affected privileged executable against its trusted vendor or package source, replace altered or unsigned binaries through supported software-management procedures, and investigate unexpected deleted-backing execution.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			privileged := make([]processEvidenceItem, 0)
			bad := make([]processEvidenceItem, 0)
			unresolved := make([]processEvidenceItem, 0)
			kernelThreads := linuxKernelThreadRuleIDs(idx, items)
			for _, item := range items {
				if !item.Process.Principal.Elevated {
					continue
				}
				if _, kernelThread := kernelThreads[item.Process.ID]; kernelThread {
					continue
				}
				privileged = append(privileged, item)
				state := normalizeTrustState(item.Process.Trust.State)
				switch state {
				case "UNSIGNED", "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "UNTRUSTED", "REVOKED", "HASH_MISMATCH", "DELETED_BACKING":
					bad = append(bad, item)
				case "UNKNOWN", "PROVENANCE_UNKNOWN", "UNCLASSIFIED_PATH", "SYSTEM_OR_MANAGED_PATH", "":
					unresolved = append(unresolved, item)
				}
			}
			if len(privileged) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processItemsConfidence(bad), ObservedState: fmt.Sprintf("%d of %d privileged process executable(s) have an explicit trust failure", len(bad), len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no explicit privileged executable trust failures; %d of %d trust state(s) unresolved", len(unresolved), len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 explicit trust failures across %d privileged process executable(s)", len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(privileged)}
		},
	}
}

func privilegedProcessProvenanceRule() Rule {
	return Rule{
		ID:             "CHM-PRC-004",
		Title:          "Privileged live executables have defensible software provenance",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.privileged_executable_provenance",
		ExpectedState:  "privileged live executables are signed-valid or package/application-managed when the platform can establish provenance",
		Risk:           "Privileged executables with unmanaged or unresolved provenance are harder to validate against a trusted software source and can conceal unauthorized replacement or locally introduced binaries.",
		Remediation:    "Confirm the origin and operational need of each affected privileged executable. Prefer vendor-signed or package/application-managed software and record intentional unmanaged binaries in an enterprise baseline before reassessment.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			privileged := make([]processEvidenceItem, 0)
			weak := make([]processEvidenceItem, 0)
			unresolved := make([]processEvidenceItem, 0)
			for _, item := range items {
				if !item.Process.Principal.Elevated {
					continue
				}
				privileged = append(privileged, item)
				state := normalizeTrustState(item.Process.Trust.State)
				switch state {
				case "SIGNED_VALID", "PACKAGE_MANAGED", "APPLICATION_MANAGED":
					// Defensible provenance established.
				case "UNMANAGED":
					weak = append(weak, item)
				case "UNSIGNED", "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "UNTRUSTED", "REVOKED", "HASH_MISMATCH", "DELETED_BACKING":
					weak = append(weak, item)
				default:
					unresolved = append(unresolved, item)
				}
			}
			if len(privileged) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(weak) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processItemsConfidence(weak), ObservedState: fmt.Sprintf("%d of %d privileged process executable(s) have unmanaged or weak provenance", len(weak), len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(weak)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%d of %d privileged process provenance state(s) unresolved", len(unresolved), len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("all %d privileged process executable(s) have defensible provenance", len(privileged)), Applicability: Applicable, EvidenceKeys: processEvidenceKeys(privileged)}
		},
	}
}

type processEvidenceItem struct {
	Key     string
	Process processes.Process
	Obs     evidence.Observation
}

func processItems(idx Index) ([]processEvidenceItem, evidence.State) {
	items := make([]processEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.item.") || obs.State != evidence.StateObserved {
			continue
		}
		p, ok := obs.Value.(processes.Process)
		if !ok {
			continue
		}
		items = append(items, processEvidenceItem{Key: key, Process: p, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Process.PID != items[j].Process.PID {
			return items[i].Process.PID < items[j].Process.PID
		}
		return items[i].Key < items[j].Key
	})
	state := evidence.StateUnavailable
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.source.") {
			continue
		}
		if obs.State == evidence.StateObserved {
			state = evidence.StateObserved
			break
		}
		state = obs.State
	}
	return items, state
}

func processInventoryUnavailable(idx Index, state evidence.State) Evaluation {
	keys := []string{}
	if _, ok := idx["process.inventory.count"]; ok {
		keys = append(keys, "process.inventory.count")
	}
	for key := range idx {
		if strings.HasPrefix(key, "process.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxProcessRuleEvidence {
		keys = keys[:maxProcessRuleEvidence]
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "process inventory unavailable or contained no usable process records (provider state " + string(state) + ")", Applicability: Undetermined, EvidenceKeys: keys}
}

func processEvidenceKeys(items []processEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return keys
}

func processInventoryEvidenceKeys(idx Index, items []processEvidenceItem) []string {
	keys := []string{}
	if _, ok := idx["process.inventory.summary"]; ok {
		keys = append(keys, "process.inventory.summary")
	} else if _, ok := idx["process.inventory.count"]; ok {
		keys = append(keys, "process.inventory.count")
	}
	remaining := maxProcessRuleEvidence - len(keys)
	if remaining > 0 {
		itemKeys := processEvidenceKeys(items)
		if len(itemKeys) > remaining {
			itemKeys = itemKeys[:remaining]
		}
		keys = append(keys, itemKeys...)
	}
	return keys
}

func processItemsConfidence(items []processEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		r := processConfidenceRank(item.Obs.Confidence)
		if r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func processPlatform(idx Index) string {
	if o, ok := idx["process.platform"]; ok && o.State == evidence.StateObserved {
		return strings.ToLower(strings.TrimSpace(fmt.Sprint(o.Value)))
	}
	return ""
}

func processConfidenceRank(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceExact:
		return 4
	case evidence.ConfidenceHigh:
		return 3
	case evidence.ConfidenceMedium:
		return 2
	case evidence.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func normalizeTrustState(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// linuxKernelThreadRuleIDs mirrors the collector's conservative kthreadd-tree
// classification using only normalized process evidence already present in the
// rule index. Kernel threads are real privileged runtime records, but they have
// no userspace executable, PATH location, or executable provenance boundary.
// Excluding them from userspace-executable rule denominators prevents hundreds
// of structurally inapplicable UNKNOWN states from obscuring the processes that
// can actually load/execute a userspace binary.
func linuxKernelThreadRuleIDs(idx Index, items []processEvidenceItem) map[string]struct{} {
	out := map[string]struct{}{}
	if processPlatform(idx) != "linux" {
		return out
	}
	byPID := make(map[int]processEvidenceItem, len(items))
	for _, item := range items {
		if item.Process.PID > 0 {
			byPID[item.Process.PID] = item
		}
	}
	kernelPID := map[int]struct{}{}
	if item, ok := byPID[2]; ok && linuxKernelThreadRuleShape(item.Process) {
		kernelPID[2] = struct{}{}
		out[item.Process.ID] = struct{}{}
	}
	for changed := true; changed; {
		changed = false
		for _, item := range items {
			p := item.Process
			if p.PID <= 0 || p.PID == 2 || !linuxKernelThreadRuleShape(p) {
				continue
			}
			if _, known := kernelPID[p.PID]; known {
				continue
			}
			if _, parentKernel := kernelPID[p.PPID]; !parentKernel {
				continue
			}
			kernelPID[p.PID] = struct{}{}
			out[p.ID] = struct{}{}
			changed = true
		}
	}
	return out
}

func linuxKernelThreadRuleShape(p processes.Process) bool {
	return strings.TrimSpace(p.ExecutablePath) == "" &&
		p.CommandLine.Available && p.CommandLine.ArgumentCount == 0 && p.CommandLine.ByteCount == 0
}

// linuxProcessLifecycleRuleNotApplicable recognizes the explicit per-process
// lifecycle records emitted when a Linux PID disappears between the base /proc
// snapshot and a secondary enrichment read. The UNKNOWN record remains in raw
// evidence, but it is not a missing-security-state vote for rules whose subject
// ceased to exist before that enrichment boundary could be evaluated.
func linuxProcessLifecycleRuleNotApplicable(p processes.Process, state, source, reason string) bool {
	if !strings.EqualFold(strings.TrimSpace(p.CollectionSource), "Linux procfs") && !strings.EqualFold(strings.TrimSpace(p.CollectionSource), "linux procfs") {
		return false
	}
	if strings.ToUpper(strings.TrimSpace(state)) != "UNKNOWN" {
		return false
	}
	source = strings.ToLower(strings.TrimSpace(source))
	reason = strings.ToLower(strings.TrimSpace(reason))
	return strings.Contains(source, "lifecycle-aware") || strings.Contains(reason, "process exited before")
}

func privilegedCriticalExecutionLocationRule() Rule {
	return Rule{
		ID:             "CHM-PRC-005",
		Title:          "Privileged processes avoid high-risk execution locations",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_execution_location",
		ExpectedState:  "privileged processes do not execute from temporary, Downloads, removable, network-backed, or deleted-backing locations",
		Risk:           "A privileged process executing from a transient, user-controlled, removable, network-backed, or deleted location crosses a weak trust boundary and increases the impact of executable replacement or unintended code execution.",
		Remediation:    "Validate the process purpose and executable origin. Move privileged executables to an appropriately controlled system or application location, restore trusted backing files when deleted, and remove unnecessary privileged execution from transient, removable, or network-backed paths.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			locations := processLocationItems(idx, items)
			if len(locations) == 0 {
				return processLocationUnavailable(idx, items)
			}
			privileged := 0
			bad := make([]processLocationEvidenceItem, 0)
			unresolved := make([]processLocationEvidenceItem, 0)
			for _, item := range locations {
				if !item.Process.Principal.Elevated {
					continue
				}
				privileged++
				if item.Location.DeletedBacking || item.Location.Temporary || item.Location.Downloads || item.Location.Removable || item.Location.NetworkBacked {
					bad = append(bad, item)
				} else if item.Location.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if privileged == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processLocationConfidence(bad), ObservedState: fmt.Sprintf("%d of %d privileged process executable(s) run from high-risk locations", len(bad), privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no high-risk privileged execution locations observed; %d of %d location state(s) unresolved", len(unresolved), privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 high-risk locations across %d privileged process executable(s)", privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(locationsForPrivileged(locations))}
		},
	}
}

func privilegedWeakExecutionLocationRule() Rule {
	return Rule{
		ID:             "CHM-PRC-006",
		Title:          "Privileged processes avoid user-writable or weakly controlled locations",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_execution_boundary",
		ExpectedState:  "privileged executable paths are not rooted in user-writable or otherwise weakly controlled locations",
		Risk:           "A privileged process launched from a user-writable or weakly controlled path can allow lower-trust principals to influence a high-impact execution boundary. supplies the location risk signal; separately validates executable and parent-directory write permissions.",
		Remediation:    "Relocate privileged executables to controlled system/application roots and review the affected path. Use the path-permission findings to confirm whether the executable or its parent directories are actually writable by lower-trust principals.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			locations := processLocationItems(idx, items)
			if len(locations) == 0 {
				return processLocationUnavailable(idx, items)
			}
			privileged := 0
			weak := make([]processLocationEvidenceItem, 0)
			unresolved := make([]processLocationEvidenceItem, 0)
			kernelThreads := linuxKernelThreadRuleIDs(idx, items)
			for _, item := range locations {
				if !item.Process.Principal.Elevated {
					continue
				}
				if _, kernelThread := kernelThreads[item.Process.ID]; kernelThread {
					continue
				}
				privileged++
				critical := item.Location.DeletedBacking || item.Location.Temporary || item.Location.Downloads || item.Location.Removable || item.Location.NetworkBacked
				if !critical && (item.Location.UserWritable || item.Location.WeakControl) {
					weak = append(weak, item)
				} else if item.Location.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if privileged == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(weak) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processLocationConfidence(weak), ObservedState: fmt.Sprintf("%d of %d privileged process executable(s) use user-writable or weakly controlled location classes", len(weak), privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(weak)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak privileged location class observed; %d of %d location state(s) unresolved", len(unresolved), privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 user-writable/weak location classes across %d privileged process executable(s)", privileged), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(locationsForPrivileged(locations))}
		},
	}
}

func sensitiveProcessExecutionLocationRule() Rule {
	return Rule{
		ID:             "CHM-PRC-007",
		Title:          "Security-sensitive processes avoid weak execution locations",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.sensitive_execution_location",
		ExpectedState:  "security-sensitive processes execute from controlled local locations",
		Risk:           "Security, authentication, remote-management, orchestration, or host-control processes executing from user-controlled or transient locations can weaken a sensitive host boundary even when the process itself is not reported as elevated.",
		Remediation:    "Confirm that the affected sensitive process is expected and installed from a trusted source. Use a controlled application/system location and remove transient, user-profile, removable, network-backed, or deleted-backing execution where it is not explicitly required.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			locations := processLocationItems(idx, items)
			if len(locations) == 0 {
				return processLocationUnavailable(idx, items)
			}
			sensitive := 0
			bad := make([]processLocationEvidenceItem, 0)
			unresolved := make([]processLocationEvidenceItem, 0)
			for _, item := range locations {
				if item.Process.Principal.Elevated || !isSensitiveProcess(item.Process, processPlatform(idx)) {
					continue
				}
				sensitive++
				if item.Location.WeakControl || item.Location.UserWritable || item.Location.Temporary || item.Location.Downloads || item.Location.Removable || item.Location.NetworkBacked || item.Location.DeletedBacking {
					bad = append(bad, item)
				} else if item.Location.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if sensitive == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no non-privileged security-sensitive process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processLocationConfidence(bad), ObservedState: fmt.Sprintf("%d of %d non-privileged security-sensitive process executable(s) use weak execution locations", len(bad), sensitive), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak sensitive-process location observed; %d of %d location state(s) unresolved", len(unresolved), sensitive), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 weak locations across %d non-privileged security-sensitive process executable(s)", sensitive), Applicability: Applicable, EvidenceKeys: processLocationEvidenceKeys(locations)}
		},
	}
}

func privilegedExecutablePermissionRule() Rule {
	return Rule{
		ID:             "CHM-PRC-008",
		Title:          "Privileged process executables reject untrusted write access",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_executable_permissions",
		ExpectedState:  "privileged live executable files are not writable or ACL-controlled by principals outside the trusted privileged boundary",
		Risk:           "Write or owner-level control over an executable used by a SYSTEM/root-equivalent process can permit lower-trust principals to replace or modify code that later executes with elevated authority.",
		Remediation:    "Remove unnecessary write/modify/ownership grants from the executable, restore trusted ownership, and reinstall or repair the component through its supported package/vendor mechanism. Preserve only explicitly required privileged write principals.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			perms := processPermissionItems(idx, items)
			if len(perms) == 0 {
				return processPermissionUnavailable(idx, items)
			}
			privileged := 0
			bad := make([]processPermissionEvidenceItem, 0)
			unresolved := make([]processPermissionEvidenceItem, 0)
			for _, item := range perms {
				if !item.Process.Principal.Elevated {
					continue
				}
				privileged++
				if item.Permission.UntrustedExecutableWrite {
					bad = append(bad, item)
				} else if item.Permission.Executable.State != "OBSERVED" || item.Permission.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if privileged == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processPermissionConfidence(bad), ObservedState: fmt.Sprintf("%d of %d privileged executable file(s) permit untrusted write/ownership control", len(bad), privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no untrusted executable write observed; %d of %d privileged executable permission state(s) unresolved", len(unresolved), privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 untrusted executable-write boundaries across %d privileged process(es)", privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(permissionsForPrivileged(perms))}
		},
	}
}

func privilegedParentPermissionRule() Rule {
	return Rule{
		ID:             "CHM-PRC-009",
		Title:          "Privileged process parent directories reject untrusted replacement access",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_parent_directory_permissions",
		ExpectedState:  "parent directories in privileged executable paths do not grant untrusted principals replacement-capable write access",
		Risk:           "A writable parent directory can weaken an otherwise protected privileged executable by allowing path replacement, rename, or directory-entry manipulation before a future privileged launch.",
		Remediation:    "Remove broad or low-trust write/modify grants from the affected parent directory, restore trusted ownership, and relocate the executable beneath a controlled system/application root when shared write access is operationally required elsewhere.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			perms := processPermissionItems(idx, items)
			if len(perms) == 0 {
				return processPermissionUnavailable(idx, items)
			}
			privileged := 0
			bad := make([]processPermissionEvidenceItem, 0)
			unresolved := make([]processPermissionEvidenceItem, 0)
			for _, item := range perms {
				if !item.Process.Principal.Elevated {
					continue
				}
				privileged++
				if item.Permission.UntrustedParentWrite {
					bad = append(bad, item)
					continue
				}
				unknown := false
				for _, n := range item.Permission.Parents {
					if n.State != "OBSERVED" {
						unknown = true
						break
					}
				}
				if unknown || item.Permission.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if privileged == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged live process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processPermissionConfidence(bad), ObservedState: fmt.Sprintf("%d of %d privileged executable path(s) contain an untrusted-writable parent directory", len(bad), privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no untrusted parent-directory write observed; %d of %d privileged path permission chain(s) unresolved", len(unresolved), privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 untrusted parent-directory write boundaries across %d privileged process path(s)", privileged), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(permissionsForPrivileged(perms))}
		},
	}
}

func sensitiveProcessPermissionRule() Rule {
	return Rule{
		ID:             "CHM-PRC-010",
		Title:          "Security-sensitive process paths avoid broad write access",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.sensitive_path_permissions",
		ExpectedState:  "non-privileged security-sensitive process executables and their parent paths are not broadly writable",
		Risk:           "Broad write access to authentication, remote-management, orchestration, or host-control executable paths can permit peer or lower-trust users to influence security-sensitive code even when the current process is not elevated.",
		Remediation:    "Restrict executable and parent-directory write access to the minimum operational principals, restore expected ownership, and use controlled installation paths for security-sensitive components.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			perms := processPermissionItems(idx, items)
			if len(perms) == 0 {
				return processPermissionUnavailable(idx, items)
			}
			platform := processPlatform(idx)
			sensitive := 0
			bad := make([]processPermissionEvidenceItem, 0)
			unresolved := make([]processPermissionEvidenceItem, 0)
			for _, item := range perms {
				if item.Process.Principal.Elevated || !isSensitiveProcess(item.Process, platform) {
					continue
				}
				sensitive++
				if item.Permission.BroadExecutableWrite || item.Permission.BroadParentWrite || item.Permission.UntrustedExecutableWrite || item.Permission.UntrustedParentWrite {
					bad = append(bad, item)
				} else if item.Permission.State == "UNKNOWN" {
					unresolved = append(unresolved, item)
				}
			}
			if sensitive == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no non-privileged security-sensitive process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processPermissionConfidence(bad), ObservedState: fmt.Sprintf("%d of %d non-privileged security-sensitive process path(s) have broad or untrusted write access", len(bad), sensitive), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(bad)}
			}
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad sensitive-process path write observed; %d of %d permission state(s) unresolved", len(unresolved), sensitive), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 broad-write path boundaries across %d non-privileged security-sensitive process(es)", sensitive), Applicability: Applicable, EvidenceKeys: processPermissionEvidenceKeys(perms)}
		},
	}
}

func effectiveIdentityTransitionRule() Rule {
	return Rule{
		ID:             "CHM-PRC-011",
		Title:          "Effective identity transitions are explicit and reviewable",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.runtime_identity",
		ExpectedState:  "live Unix processes do not unexpectedly run with effective user/group identities different from their real identities",
		Risk:           "A real-to-effective identity transition can grant authority not implied by the originating user or group. Setuid/setgid transitions may be intentional, but unexpected transitions materially change the process security boundary.",
		Remediation:    "Confirm that each observed real/effective UID or GID transition is required and tied to a trusted setuid/setgid or launch mechanism. Remove unnecessary elevation paths and restore normal ownership/mode configuration through supported administration procedures.",
		Evaluate: func(idx Index) Evaluation {
			platform := processPlatform(idx)
			if platform == "windows" {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "real/effective UID/GID transitions are not a Windows process-token concept", Applicability: NotApplicable, EvidenceKeys: processPrivilegeInventoryKeys(idx)}
			}
			items := processPrivilegeItems(idx)
			if len(items) == 0 {
				return processPrivilegeUnavailable(idx)
			}
			bad := make([]processPrivilegeEvidenceItem, 0)
			unknown := make([]processPrivilegeEvidenceItem, 0)
			for _, item := range items {
				if item.Privilege.State == "UNKNOWN" {
					unknown = append(unknown, item)
					continue
				}
				if item.Privilege.IdentityTransition {
					bad = append(bad, item)
				}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processPrivilegeConfidence(bad), ObservedState: fmt.Sprintf("%d live process(es) have a real/effective user or group identity transition", len(bad)), Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(bad)}
			}
			if len(unknown) == len(items) {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime identity transition evidence is unavailable", Applicability: Undetermined, EvidenceKeys: processPrivilegeEvidenceKeys(unknown)}
			}
			conf := evidence.ConfidenceHigh
			observed := "0 real/effective identity transitions observed"
			if len(unknown) > 0 {
				conf = evidence.ConfidenceMedium
				observed = fmt.Sprintf("0 real/effective identity transitions observed; %d process state(s) unresolved", len(unknown))
			}
			return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: observed, Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(items)}
		},
	}
}

func highImpactRuntimePrivilegeRule() Rule {
	return Rule{
		ID:             "CHM-PRC-012",
		Title:          "High-impact runtime privilege sets are constrained",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.runtime_privilege_set",
		ExpectedState:  "high-impact Linux capabilities or Windows token privileges are not enabled for lower-trust user contexts without explicit operational need",
		Risk:           "Capabilities such as SYS_ADMIN/SYS_PTRACE/SYS_MODULE or Windows token privileges such as SeDebug/SeTcb/SeLoadDriver can bypass ordinary process, filesystem, or identity boundaries. Their presence in lower-trust contexts materially increases compromise impact.",
		Remediation:    "Remove unnecessary capability or token-privilege grants, run the workload under the least-privileged service/account model available, and document any required exception with the exact privilege set and process role.",
		Evaluate: func(idx Index) Evaluation {
			items := processPrivilegeItems(idx)
			if len(items) == 0 {
				return processPrivilegeUnavailable(idx)
			}
			applicable := 0
			bad := make([]processPrivilegeEvidenceItem, 0)
			unknown := make([]processPrivilegeEvidenceItem, 0)
			for _, item := range items {
				switch item.Privilege.PrivilegeSetState {
				case "NOT_APPLICABLE":
					continue
				case "UNAVAILABLE", "UNKNOWN", "":
					unknown = append(unknown, item)
					continue
				}
				applicable++
				if privilegeHasExcessSetSignal(item.Privilege) {
					bad = append(bad, item)
				}
			}
			if applicable == 0 && len(unknown) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "generic per-process privilege-set assessment is not applicable to this platform provider", Applicability: NotApplicable, EvidenceKeys: processPrivilegeEvidenceKeys(items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processPrivilegeConfidence(bad), ObservedState: fmt.Sprintf("%d process(es) carry high-impact runtime privileges outside a root/system service context", len(bad)), Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(bad)}
			}
			if applicable == 0 && len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime privilege-set metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processPrivilegeEvidenceKeys(unknown)}
			}
			conf := evidence.ConfidenceHigh
			observed := fmt.Sprintf("0 excess high-impact privilege sets across %d assessed process(es)", applicable)
			if len(unknown) > 0 {
				conf = evidence.ConfidenceMedium
				observed += fmt.Sprintf("; %d process state(s) unresolved", len(unknown))
			}
			return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: observed, Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(items)}
		},
	}
}

func windowsTokenIntegrityRule() Rule {
	return Rule{
		ID:             "CHM-PRC-013",
		Title:          "Windows token integrity is consistent with account context",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.windows_token_integrity",
		ExpectedState:  "high/system integrity tokens are limited to expected elevated or system contexts and are observable",
		Risk:           "A high or SYSTEM integrity token materially expands process authority. A SYSTEM-integrity token under a non-SYSTEM identity is especially inconsistent and elevated interactive user tokens should be intentional and minimized.",
		Remediation:    "Validate the process owner, launch path, UAC/service configuration, and operational need for elevation. Remove unnecessary Run as administrator/service elevation and investigate any SYSTEM-integrity token whose account identity is not SYSTEM.",
		Evaluate: func(idx Index) Evaluation {
			if processPlatform(idx) != "windows" {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Windows token integrity levels are not applicable on this platform", Applicability: NotApplicable, EvidenceKeys: processPrivilegeInventoryKeys(idx)}
			}
			items := processPrivilegeItems(idx)
			if len(items) == 0 {
				return processPrivilegeUnavailable(idx)
			}
			critical := make([]processPrivilegeEvidenceItem, 0)
			review := make([]processPrivilegeEvidenceItem, 0)
			unknown := make([]processPrivilegeEvidenceItem, 0)
			for _, item := range items {
				if item.Privilege.TokenElevation == "UNKNOWN" || item.Privilege.IntegrityLevel == "" || item.Privilege.IntegrityLevel == "UNKNOWN" {
					unknown = append(unknown, item)
					continue
				}
				if containsString(item.Privilege.ExcessSignals, "system-integrity-non-system-account") {
					critical = append(critical, item)
					continue
				}
				if item.Privilege.ElevatedUserContext {
					review = append(review, item)
				}
			}
			if len(critical) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processPrivilegeConfidence(critical), ObservedState: fmt.Sprintf("%d process(es) have SYSTEM integrity under a non-SYSTEM account identity", len(critical)), Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(critical)}
			}
			if len(review) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processPrivilegeConfidence(review), ObservedState: fmt.Sprintf("%d interactive/user-context process(es) have high or system-level token integrity", len(review)), Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(review)}
			}
			if len(unknown) == len(items) {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Windows token integrity metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processPrivilegeEvidenceKeys(unknown)}
			}
			conf := evidence.ConfidenceHigh
			observed := "no inconsistent or elevated user-context token integrity observed"
			if len(unknown) > 0 {
				conf = evidence.ConfidenceMedium
				observed += fmt.Sprintf("; %d process token(s) unresolved", len(unknown))
			}
			return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: observed, Applicability: Applicable, EvidenceKeys: processPrivilegeEvidenceKeys(items)}
		},
	}
}

func writableExecutableMemoryRule() Rule {
	return Rule{
		ID:             "CHM-PRC-014",
		Title:          "Writable and executable memory mappings are constrained",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.writable_executable_memory",
		ExpectedState:  "live processes do not retain writable+executable memory mappings unless an explicitly reviewable runtime requirement exists",
		Risk:           "Memory that is simultaneously writable and executable weakens write-xor-execute boundaries and can increase the impact of code-generation defects or memory corruption. Legitimate JIT runtimes can create such mappings, so the observation is contextual evidence rather than automatic malware attribution.",
		Remediation:    "Review the owning process and runtime requirement. Prefer W^X/JIT hardening modes that separate writable and executable phases, update the runtime where appropriate, and investigate unexpected writable+executable mappings in privileged or non-JIT processes.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			memory := processMemoryItems(idx, items)
			if len(memory) == 0 {
				return processMemoryUnavailable(idx, items)
			}
			critical := make([]processMemoryEvidenceItem, 0)
			review := make([]processMemoryEvidenceItem, 0)
			unknown := make([]processMemoryEvidenceItem, 0)
			unsupported := 0
			assessed := 0
			for _, item := range memory {
				switch strings.ToUpper(strings.TrimSpace(item.Memory.State)) {
				case "OBSERVED", "DEGRADED":
					assessed++
				case "UNSUPPORTED", "NOT_APPLICABLE":
					unsupported++
					continue
				default:
					unknown = append(unknown, item)
					continue
				}
				if item.Memory.WritableExecutableRegions <= 0 {
					continue
				}
				if item.Process.Principal.Elevated && !item.Memory.JITLikeContext {
					critical = append(critical, item)
				} else {
					review = append(review, item)
				}
			}
			if len(critical) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processMemoryConfidence(critical), ObservedState: fmt.Sprintf("%d privileged non-JIT process(es) retain writable+executable memory mappings", len(critical)), Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(critical)}
			}
			if len(review) > 0 {
				jit := 0
				for _, item := range review {
					if item.Memory.JITLikeContext {
						jit++
					}
				}
				observed := fmt.Sprintf("%d process(es) retain writable+executable memory mappings", len(review))
				if jit > 0 {
					observed += fmt.Sprintf("; %d are JIT-like runtime contexts requiring contextual review", jit)
				}
				return Evaluation{Status: StatusWarn, Confidence: processMemoryConfidence(review), ObservedState: observed, Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(review)}
			}
			if assessed == 0 && unsupported == len(memory) {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "per-process writable+executable mapping metadata is not supported by the current platform provider", Applicability: NotApplicable, EvidenceKeys: processMemoryEvidenceKeys(memory)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no writable+executable mapping observed in available evidence; %d process mapping state(s) unresolved", len(unknown)), Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 writable+executable mappings across %d assessed process(es)", assessed), Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(memory)}
		},
	}
}

func anonymousExecutableMemoryRule() Rule {
	return Rule{
		ID:             "CHM-PRC-015",
		Title:          "Anonymous executable mappings are explicit and reviewable",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.anonymous_executable_memory",
		ExpectedState:  "anonymous/private executable mappings are absent or attributable to an expected dynamic-code/JIT runtime context",
		Risk:           "Anonymous executable memory can be required by JIT compilers and dynamic-code runtimes, but it also removes normal file/package provenance from executable pages. It is therefore a review signal, not proof of malicious execution.",
		Remediation:    "Confirm that each anonymous executable mapping belongs to an expected runtime with a documented dynamic-code requirement. Apply runtime hardening and least privilege, update obsolete runtimes, and investigate unexpected anonymous executable mappings in privileged or non-JIT processes.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			memory := processMemoryItems(idx, items)
			if len(memory) == 0 {
				return processMemoryUnavailable(idx, items)
			}
			review := make([]processMemoryEvidenceItem, 0)
			unknown := make([]processMemoryEvidenceItem, 0)
			unsupported := 0
			assessed := 0
			nonJIT := 0
			privilegedNonJIT := 0
			regions := 0
			for _, item := range memory {
				switch strings.ToUpper(strings.TrimSpace(item.Memory.State)) {
				case "OBSERVED", "DEGRADED":
					assessed++
				case "UNSUPPORTED", "NOT_APPLICABLE":
					unsupported++
					continue
				default:
					unknown = append(unknown, item)
					continue
				}
				if item.Memory.AnonymousExecutableRegions <= 0 {
					continue
				}
				review = append(review, item)
				regions += item.Memory.AnonymousExecutableRegions
				if !item.Memory.JITLikeContext {
					nonJIT++
					if item.Process.Principal.Elevated {
						privilegedNonJIT++
					}
				}
			}
			if len(review) > 0 {
				observed := fmt.Sprintf("%d anonymous/private executable region(s) across %d process(es)", regions, len(review))
				if nonJIT == 0 {
					observed += "; all observed owners match JIT-like runtime context, which is contextual evidence rather than an automatic safety determination"
				} else {
					observed += fmt.Sprintf("; %d owner process(es) have no JIT-like context", nonJIT)
					if privilegedNonJIT > 0 {
						observed += fmt.Sprintf(" and %d are privileged", privilegedNonJIT)
					}
				}
				return Evaluation{Status: StatusWarn, Confidence: processMemoryConfidence(review), ObservedState: observed, Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(review)}
			}
			if assessed == 0 && unsupported == len(memory) {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "per-process anonymous executable mapping metadata is not supported by the current platform provider", Applicability: NotApplicable, EvidenceKeys: processMemoryEvidenceKeys(memory)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no anonymous executable mapping observed in available evidence; %d process mapping state(s) unresolved", len(unknown)), Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 anonymous/private executable mappings across %d assessed process(es)", assessed), Applicability: Applicable, EvidenceKeys: processMemoryEvidenceKeys(memory)}
		},
	}
}

func loadedModuleTrustRule() Rule {
	return Rule{
		ID:             "CHM-PRC-016",
		Title:          "Loaded modules have no explicit trust or backing failure",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.loaded_module_trust",
		ExpectedState:  "loaded DLL/shared-library/dylib mappings have present backing and no invalid, untrusted, revoked, or hash-mismatched trust state",
		Risk:           "A live process retaining a deleted or explicitly untrusted executable module weakens module provenance and can indicate replacement, tampering, or execution outside the expected software trust boundary.",
		Remediation:    "Identify each affected module and owning process, validate the module against its vendor/package source, replace altered or untrusted software through supported package/application management, and investigate unexpected deleted-backing mappings.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			mods := processModuleItems(idx, items)
			if len(mods) == 0 {
				return processModulesUnavailable(idx, items)
			}
			bad := make([]processModuleEvidenceItem, 0)
			unknown := make([]processModuleEvidenceItem, 0)
			unsupported := 0
			assessed := 0
			badModules := 0
			for _, item := range mods {
				switch strings.ToUpper(strings.TrimSpace(item.Modules.State)) {
				case "OBSERVED", "DEGRADED":
					assessed++
				case "UNSUPPORTED", "NOT_APPLICABLE":
					unsupported++
					continue
				default:
					unknown = append(unknown, item)
					continue
				}
				count := item.Modules.DeletedMappings + item.Modules.ExplicitTrustFailures
				if count > 0 {
					badModules += count
					bad = append(bad, item)
				}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processModuleConfidence(bad), ObservedState: fmt.Sprintf("%d deleted or explicitly untrusted loaded-module mapping(s) across %d process(es)", badModules, len(bad)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(bad)}
			}
			if assessed == 0 && unsupported == len(mods) {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "loaded-module trust metadata is not supported by the current platform provider", Applicability: NotApplicable, EvidenceKeys: processModuleEvidenceKeys(mods)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no explicit module trust failure observed in available evidence; %d process module state(s) unresolved", len(unknown)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 explicit loaded-module trust/backing failures across %d assessed process(es)", assessed), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(mods)}
		},
	}
}

func privilegedLoadedModuleLocationRule() Rule {
	return Rule{
		ID:             "CHM-PRC-017",
		Title:          "Loaded modules are not sourced from weak writable directories",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.loaded_module_directory_control",
		ExpectedState:  "privileged processes do not load executable modules from directories writable outside the trusted privilege boundary",
		Risk:           "A writable directory supplying a DLL/shared-library/dylib to a privileged process can permit module replacement or search-path hijacking across a privilege boundary.",
		Remediation:    "Move affected modules to trusted system or application directories, remove broad/untrusted write grants from module directories, and ensure privileged software resolves libraries only from controlled locations.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			mods := processModuleItems(idx, items)
			if len(mods) == 0 {
				return processModulesUnavailable(idx, items)
			}
			critical := make([]processModuleEvidenceItem, 0)
			review := make([]processModuleEvidenceItem, 0)
			unknown := make([]processModuleEvidenceItem, 0)
			locations := 0
			for _, item := range mods {
				state := strings.ToUpper(strings.TrimSpace(item.Modules.State))
				if linuxProcessLifecycleRuleNotApplicable(item.Process, state, item.Modules.Source, item.Modules.Reason) {
					continue
				}
				if state != "OBSERVED" && state != "DEGRADED" {
					if state != "UNSUPPORTED" && state != "NOT_APPLICABLE" {
						unknown = append(unknown, item)
					}
					continue
				}
				if item.Modules.WritableLocationModules <= 0 {
					continue
				}
				locations += item.Modules.WritableLocationModules
				if item.Process.Principal.Elevated {
					critical = append(critical, item)
				} else {
					review = append(review, item)
				}
			}
			if len(critical) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processModuleConfidence(critical), ObservedState: fmt.Sprintf("%d weak writable loaded-module location(s) observed; %d privileged process(es) cross the trust boundary", locations, len(critical)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(critical)}
			}
			if len(review) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processModuleConfidence(review), ObservedState: fmt.Sprintf("%d weak writable loaded-module location(s) observed across %d non-privileged process(es)", locations, len(review)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(review)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no weak loaded-module location observed in available evidence; %d process module state(s) unresolved", len(unknown)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no loaded modules were observed in directories writable outside the assessed trust boundary", Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(mods)}
		},
	}
}

func loadedModuleProvenanceMismatchRule() Rule {
	return Rule{
		ID:             "CHM-PRC-018",
		Title:          "Loaded module provenance aligns with process trust",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.loaded_module_provenance",
		ExpectedState:  "trusted or managed processes do not load unsigned, unmanaged, or otherwise weaker-provenance modules without an explicit baseline",
		Risk:           "A signed or package-managed process loading a weaker-provenance module can invalidate assumptions based on the main executable alone and expand the effective code trust boundary.",
		Remediation:    "Review each mismatched module, establish its vendor/package origin, replace unexpected unsigned or unmanaged modules with trusted equivalents, and baseline intentionally local plugins only after ownership and directory controls are verified.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			mods := processModuleItems(idx, items)
			if len(mods) == 0 {
				return processModulesUnavailable(idx, items)
			}
			critical := make([]processModuleEvidenceItem, 0)
			review := make([]processModuleEvidenceItem, 0)
			mismatches := 0
			for _, item := range mods {
				if item.Modules.TrustMismatches <= 0 {
					continue
				}
				mismatches += item.Modules.TrustMismatches
				if item.Process.Principal.Elevated {
					critical = append(critical, item)
				} else {
					review = append(review, item)
				}
			}
			if len(critical) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processModuleConfidence(critical), ObservedState: fmt.Sprintf("%d loaded-module provenance mismatch(es) include %d privileged process(es)", mismatches, len(critical)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(critical)}
			}
			if len(review) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: processModuleConfidence(review), ObservedState: fmt.Sprintf("%d loaded-module provenance mismatch(es) across %d process(es)", mismatches, len(review)), Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(review)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no loaded-module provenance mismatch observed in available evidence", Applicability: Applicable, EvidenceKeys: processModuleEvidenceKeys(mods)}
		},
	}
}

func privilegedRuntimeEnvironmentRule() Rule {
	return Rule{
		ID:             "CHM-PRC-019",
		Title:          "Privileged processes avoid high-risk runtime environment hooks",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.privileged_runtime_environment",
		ExpectedState:  "privileged processes do not inherit loader injection, startup/profiler hooks, or other high-risk runtime environment controls",
		Risk:           "High-risk loader, profiler, startup, or runtime hooks can redirect code loading or execution before ordinary application logic. When inherited by a privileged process they materially widen the privilege boundary even when the main executable is trusted.",
		Remediation:    "Remove unexpected high-risk runtime environment settings from the privileged service, launcher, shell, scheduled execution context, or parent process. Preserve only explicitly required settings and validate the referenced runtime components through trusted package/application management.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			envs := processEnvironmentItems(idx, items)
			if len(envs) == 0 {
				return processEnvironmentUnavailable(idx, items)
			}
			bad := make([]processEnvironmentEvidenceItem, 0)
			unknown := make([]processEnvironmentEvidenceItem, 0)
			privileged := 0
			for _, item := range envs {
				if !item.Process.Principal.Elevated {
					continue
				}
				state := strings.ToUpper(strings.TrimSpace(item.Environment.State))
				if linuxProcessLifecycleRuleNotApplicable(item.Process, state, item.Environment.Source, item.Environment.Reason) {
					continue
				}
				privileged++
				if state != "OBSERVED" && state != "DEGRADED" {
					unknown = append(unknown, item)
					continue
				}
				if item.Environment.HighRiskIndicators > 0 || item.Environment.LoaderHooks > 0 || item.Environment.StartupHooks > 0 {
					bad = append(bad, item)
				}
			}
			if privileged == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processEnvironmentConfidence(bad), ObservedState: fmt.Sprintf("%d privileged process(es) carry high-risk runtime environment hooks", len(bad)), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(bad)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no high-risk privileged runtime environment hook observed in available evidence; %d of %d privileged environment state(s) unresolved", len(unknown), privileged), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 high-risk runtime environment hooks across %d privileged process(es)", privileged), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(envs)}
		},
	}
}

func sensitiveRuntimeEnvironmentRule() Rule {
	return Rule{
		ID:             "CHM-PRC-020",
		Title:          "Security-sensitive processes avoid dangerous runtime overrides",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.sensitive_runtime_environment",
		ExpectedState:  "security-sensitive processes do not inherit high-risk loader/startup hooks, debugger controls, or TLS key logging without an explicit operational requirement",
		Risk:           "Authentication, remote-management, orchestration, and host-control processes are high-impact targets. Runtime hooks, debugger controls, or TLS key logging in those processes can weaken code-loading, confidentiality, or control boundaries.",
		Remediation:    "Review the affected process launch environment, remove unexpected loader/startup/debug/TLS-key-logging settings, and move required debugging or instrumentation into a controlled development or maintenance workflow rather than the normal sensitive-service runtime.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			envs := processEnvironmentItems(idx, items)
			if len(envs) == 0 {
				return processEnvironmentUnavailable(idx, items)
			}
			platform := processPlatform(idx)
			bad := make([]processEnvironmentEvidenceItem, 0)
			unknown := make([]processEnvironmentEvidenceItem, 0)
			sensitive := 0
			for _, item := range envs {
				if !isSensitiveProcess(item.Process, platform) {
					continue
				}
				sensitive++
				state := strings.ToUpper(strings.TrimSpace(item.Environment.State))
				if state != "OBSERVED" && state != "DEGRADED" {
					unknown = append(unknown, item)
					continue
				}
				if item.Environment.HighRiskIndicators > 0 || item.Environment.DebugControls > 0 || item.Environment.TLSKeyLogging {
					bad = append(bad, item)
				}
			}
			if sensitive == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no recognized security-sensitive process records observed", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
			}
			if len(bad) > 0 {
				status := StatusWarn
				for _, item := range bad {
					if item.Process.Principal.Elevated {
						status = StatusFail
						break
					}
				}
				return Evaluation{Status: status, Confidence: processEnvironmentConfidence(bad), ObservedState: fmt.Sprintf("%d of %d security-sensitive process(es) carry dangerous runtime overrides", len(bad), sensitive), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(bad)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("no dangerous sensitive-process runtime override observed in available evidence; %d of %d environment state(s) unresolved", len(unknown), sensitive), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 dangerous runtime overrides across %d security-sensitive process(es)", sensitive), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(envs)}
		},
	}
}

func unsafeRuntimeSearchPathRule() Rule {
	return Rule{
		ID:             "CHM-PRC-021",
		Title:          "Runtime and loader search paths avoid weak components",
		Category:       "process",
		Severity:       SeverityMedium,
		AffectedObject: "process.runtime_search_path_control",
		ExpectedState:  "loader and language-runtime search paths do not contain relative, empty/current-directory, or temporary components",
		Risk:           "Relative, empty, current-directory, or temporary search-path components can cause runtimes or loaders to resolve executable code from locations outside the intended software trust boundary.",
		Remediation:    "Replace weak runtime or loader search-path components with absolute paths under controlled directories, remove empty/current-directory elements, and avoid temporary directories in privileged or sensitive launch environments.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			envs := processEnvironmentItems(idx, items)
			if len(envs) == 0 {
				return processEnvironmentUnavailable(idx, items)
			}
			bad := make([]processEnvironmentEvidenceItem, 0)
			unknown := make([]processEnvironmentEvidenceItem, 0)
			assessed := 0
			weakComponents := 0
			for _, item := range envs {
				state := strings.ToUpper(strings.TrimSpace(item.Environment.State))
				if state != "OBSERVED" && state != "DEGRADED" {
					unknown = append(unknown, item)
					continue
				}
				assessed++
				for _, ind := range item.Environment.Indicators {
					if ind.Category != "LOADER_PATH" && ind.Category != "RUNTIME_SEARCH_PATH" {
						continue
					}
					count := ind.RelativeComponents + ind.EmptyComponents + ind.TemporaryComponents
					if count > 0 {
						weakComponents += count
						bad = append(bad, item)
						break
					}
				}
			}
			if len(bad) > 0 {
				status := StatusWarn
				for _, item := range bad {
					if item.Process.Principal.Elevated {
						status = StatusFail
						break
					}
				}
				return Evaluation{Status: status, Confidence: processEnvironmentConfidence(bad), ObservedState: fmt.Sprintf("%d weak runtime/loader search-path component(s) across %d process(es)", weakComponents, len(bad)), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(bad)}
			}
			if assessed == 0 && len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime/loader search-path evidence is unavailable", Applicability: Undetermined, EvidenceKeys: processEnvironmentEvidenceKeys(unknown)}
			}
			if len(unknown) > 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak runtime/loader search-path components observed across %d assessed process(es); %d environment state(s) unresolved", assessed, len(unknown)), Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(envs)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no relative, empty/current-directory, or temporary runtime/loader search-path components observed", Applicability: Applicable, EvidenceKeys: processEnvironmentEvidenceKeys(envs)}
		},
	}
}

func uncontainedHighRiskRuntimeRule() Rule {
	return Rule{
		ID:             "CHM-PRC-022",
		Title:          "High-risk runtime hooks are not combined with an uncontained process context",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.runtime_hook_isolation",
		ExpectedState:  "processes carrying high-risk runtime hooks are either absent or accompanied by observable containment controls",
		Risk:           "High-risk runtime injection or startup controls have greater impact when the owning process is running directly in the host context without observable sandbox, namespace, AppContainer, seccomp, or equivalent containment evidence.",
		Remediation:    "Remove unnecessary high-risk runtime hooks. Where instrumentation is required, isolate the workload using supported platform containment controls and keep the launch environment under a controlled privilege boundary.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			envs := processEnvironmentItems(idx, items)
			isos := processIsolationItems(idx, items)
			if len(envs) == 0 {
				return processEnvironmentUnavailable(idx, items)
			}
			if len(isos) == 0 {
				return processIsolationUnavailable(idx, items)
			}
			isoByID := make(map[string]processIsolationEvidenceItem, len(isos))
			for _, item := range isos {
				isoByID[item.Process.ID] = item
			}
			badEnv := make([]processEnvironmentEvidenceItem, 0)
			badIso := make([]processIsolationEvidenceItem, 0)
			unknownIso := make([]processIsolationEvidenceItem, 0)
			unresolvedHighRisk := 0
			highRisk := 0
			privilegedBad := false
			for _, envItem := range envs {
				if envItem.Environment.HighRiskIndicators <= 0 {
					continue
				}
				highRisk++
				iso, ok := isoByID[envItem.Process.ID]
				if !ok || !isIsolationObservable(iso.Isolation) {
					unresolvedHighRisk++
					if ok {
						unknownIso = append(unknownIso, iso)
					}
					continue
				}
				if isolationIsContained(iso.Isolation) {
					continue
				}
				badEnv = append(badEnv, envItem)
				badIso = append(badIso, iso)
				if envItem.Process.Principal.Elevated {
					privilegedBad = true
				}
			}
			if len(badEnv) > 0 {
				status := StatusWarn
				if privilegedBad {
					status = StatusFail
				}
				keys := mergeProcessEvidenceKeys(processEnvironmentEvidenceKeys(badEnv), processIsolationEvidenceKeys(badIso))
				return Evaluation{Status: status, Confidence: lowerProcessConfidence(processEnvironmentConfidence(badEnv), processIsolationConfidence(badIso)), ObservedState: fmt.Sprintf("%d process(es) combine high-risk runtime hooks with host/uncontained isolation posture", len(badEnv)), Applicability: Applicable, EvidenceKeys: keys}
			}
			if highRisk > 0 && unresolvedHighRisk > 0 {
				keys := processIsolationEvidenceKeys(unknownIso)
				if len(keys) == 0 {
					keys = processInventoryEvidenceKeys(idx, items)
				}
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("high-risk runtime hooks are present but containment state is unresolved for %d process(es)", unresolvedHighRisk), Applicability: Applicable, EvidenceKeys: keys}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("no uncontained high-risk runtime hook combinations observed across %d high-risk environment context(s)", highRisk), Applicability: Applicable, EvidenceKeys: mergeProcessEvidenceKeys(processEnvironmentEvidenceKeys(envs), processIsolationEvidenceKeys(isos))}
		},
	}
}

func compoundPrivilegedRuntimeBoundaryRule() Rule {
	return Rule{
		ID:             "CHM-PRC-023",
		Title:          "Privileged processes do not combine multiple runtime trust-boundary weaknesses",
		Category:       "process",
		Severity:       SeverityHigh,
		AffectedObject: "process.compound_privileged_runtime_boundary",
		ExpectedState:  "no privileged process combines two or more independent weak runtime trust-boundary signals",
		Risk:           "Multiple independent weaknesses around one privileged process compound impact. Weak executable provenance, writable paths, executable-memory anomalies, module trust problems, high-risk environment hooks, and absent containment can reinforce one another even when each signal alone is contextual.",
		Remediation:    "Review each affected privileged process as one trust boundary. Restore trusted executable/module provenance, remove broad write access and unsafe runtime hooks, eliminate unexplained executable-memory anomalies, and apply appropriate platform containment before accepting the process as hardened.",
		Evaluate: func(idx Index) Evaluation {
			items, inventoryState := processItems(idx)
			if len(items) == 0 {
				return processInventoryUnavailable(idx, inventoryState)
			}
			locs := mapLocationItemsByID(processLocationItems(idx, items))
			perms := mapPermissionItemsByID(processPermissionItems(idx, items))
			mems := mapMemoryItemsByID(processMemoryItems(idx, items))
			mods := mapModuleItemsByID(processModuleItems(idx, items))
			envs := mapEnvironmentItemsByID(processEnvironmentItems(idx, items))
			bad := make([]processEvidenceItem, 0)
			keys := []string{}
			for _, item := range items {
				if !item.Process.Principal.Elevated {
					continue
				}
				weak := 0
				trust := normalizeTrustState(item.Process.Trust.State)
				switch trust {
				case "UNSIGNED", "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "UNTRUSTED", "REVOKED", "HASH_MISMATCH", "DELETED_BACKING":
					weak++
				}
				if v, ok := locs[item.Process.ID]; ok && (strings.EqualFold(v.Location.State, "WEAK") || v.Location.WeakControl) {
					weak++
					keys = append(keys, v.Key)
				}
				if v, ok := perms[item.Process.ID]; ok && (v.Permission.UntrustedExecutableWrite || v.Permission.UntrustedParentWrite || strings.EqualFold(v.Permission.State, "WEAK")) {
					weak++
					keys = append(keys, v.Key)
				}
				if v, ok := mems[item.Process.ID]; ok && (v.Memory.WritableExecutableRegions > 0 || v.Memory.DeletedExecutableRegions > 0 || (v.Memory.AnonymousExecutableRegions > 0 && !v.Memory.JITLikeContext)) {
					weak++
					keys = append(keys, v.Key)
				}
				if v, ok := mods[item.Process.ID]; ok && (v.Modules.DeletedMappings > 0 || v.Modules.ExplicitTrustFailures > 0 || v.Modules.WritableLocationModules > 0 || v.Modules.TrustMismatches > 0) {
					weak++
					keys = append(keys, v.Key)
				}
				if v, ok := envs[item.Process.ID]; ok && v.Environment.HighRiskIndicators > 0 {
					weak++
					keys = append(keys, v.Key)
				}
				if weak >= 2 {
					bad = append(bad, item)
					keys = append(keys, item.Key)
				}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: processItemsConfidence(bad), ObservedState: fmt.Sprintf("%d privileged process(es) combine at least two independent runtime trust-boundary weaknesses", len(bad)), Applicability: Applicable, EvidenceKeys: mergeProcessEvidenceKeys(keys)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged process combines two or more observed runtime trust-boundary weaknesses", Applicability: Applicable, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
		},
	}
}

type processIsolationEvidenceItem struct {
	Key       string
	Isolation processes.IsolationContext
	Process   processes.Process
	Obs       evidence.Observation
}

func processIsolationItems(idx Index, processItems []processEvidenceItem) []processIsolationEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processIsolationEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.isolation.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.IsolationContext)
		if !ok {
			continue
		}
		p, ok := byID[c.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processIsolationEvidenceItem{Key: key, Isolation: c, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processIsolationUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "process-isolation metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processIsolationEvidenceKeys(items []processIsolationEvidenceItem) []string {
	keys := make([]string, 0, len(items)*2)
	for _, item := range items {
		keys = append(keys, item.Key, "process.item."+item.Process.ID)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return mergeProcessEvidenceKeys(keys)
}

func processIsolationConfidence(items []processIsolationEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	return confidenceFromProcessRank(rank)
}

func isIsolationObservable(c processes.IsolationContext) bool {
	state := strings.ToUpper(strings.TrimSpace(c.State))
	return state == "OBSERVED" || state == "DEGRADED"
}

func isolationIsContained(c processes.IsolationContext) bool {
	state := strings.ToUpper(strings.TrimSpace(c.IsolationState))
	if state == "ISOLATED" || state == "PARTIAL" {
		return true
	}
	if c.NoNewPrivileges || c.NamespaceCount > 0 || c.CgroupScoped || c.NestedPIDNamespace {
		return true
	}
	seccomp := strings.ToUpper(strings.TrimSpace(c.Seccomp))
	if seccomp == "FILTER" || seccomp == "STRICT" {
		return true
	}
	if strings.EqualFold(c.AppContainer, "TRUE") || strings.EqualFold(c.JobObject, "TRUE") {
		return true
	}
	sandbox := strings.ToUpper(strings.TrimSpace(c.Sandbox))
	return sandbox == "ENTITLED" || sandbox == "PROFILED" || sandbox == "ENFORCED"
}

type processEnvironmentEvidenceItem struct {
	Key         string
	Environment processes.RuntimeEnvironmentContext
	Process     processes.Process
	Obs         evidence.Observation
}

func processEnvironmentItems(idx Index, processItems []processEvidenceItem) []processEnvironmentEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processEnvironmentEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.environment.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.RuntimeEnvironmentContext)
		if !ok {
			continue
		}
		p, ok := byID[c.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processEnvironmentEvidenceItem{Key: key, Environment: c, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processEnvironmentUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime-environment metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processEnvironmentEvidenceKeys(items []processEnvironmentEvidenceItem) []string {
	keys := make([]string, 0, len(items)*2)
	for _, item := range items {
		keys = append(keys, item.Key, "process.item."+item.Process.ID)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return mergeProcessEvidenceKeys(keys)
}

func processEnvironmentConfidence(items []processEnvironmentEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	return confidenceFromProcessRank(rank)
}

func confidenceFromProcessRank(rank int) evidence.Confidence {
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func lowerProcessConfidence(a, b evidence.Confidence) evidence.Confidence {
	if processConfidenceRank(a) <= processConfidenceRank(b) {
		return a
	}
	return b
}

func mergeProcessEvidenceKeys(groups ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, group := range groups {
		for _, key := range group {
			if strings.TrimSpace(key) == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
			if len(out) >= maxProcessRuleEvidence {
				return out
			}
		}
	}
	return out
}

func mapLocationItemsByID(items []processLocationEvidenceItem) map[string]processLocationEvidenceItem {
	out := make(map[string]processLocationEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}
func mapPermissionItemsByID(items []processPermissionEvidenceItem) map[string]processPermissionEvidenceItem {
	out := make(map[string]processPermissionEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}
func mapMemoryItemsByID(items []processMemoryEvidenceItem) map[string]processMemoryEvidenceItem {
	out := make(map[string]processMemoryEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}
func mapModuleItemsByID(items []processModuleEvidenceItem) map[string]processModuleEvidenceItem {
	out := make(map[string]processModuleEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}
func mapEnvironmentItemsByID(items []processEnvironmentEvidenceItem) map[string]processEnvironmentEvidenceItem {
	out := make(map[string]processEnvironmentEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}
func mapIsolationItemsByID(items []processIsolationEvidenceItem) map[string]processIsolationEvidenceItem {
	out := make(map[string]processIsolationEvidenceItem, len(items))
	for _, item := range items {
		out[item.Process.ID] = item
	}
	return out
}

type processModuleEvidenceItem struct {
	Key     string
	Modules processes.LoadedModuleContext
	Process processes.Process
	Obs     evidence.Observation
}

func processModuleItems(idx Index, processItems []processEvidenceItem) []processModuleEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processModuleEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.modules.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.LoadedModuleContext)
		if !ok {
			continue
		}
		p, ok := byID[c.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processModuleEvidenceItem{Key: key, Modules: c, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processModulesUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "loaded-module metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processModuleEvidenceKeys(items []processModuleEvidenceItem) []string {
	keys := make([]string, 0, len(items)*2)
	for _, item := range items {
		keys = append(keys, item.Key, "process.item."+item.Process.ID)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	if len(keys) > maxProcessRuleEvidence {
		keys = keys[:maxProcessRuleEvidence]
	}
	return keys
}

func processModuleConfidence(items []processModuleEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

type processMemoryEvidenceItem struct {
	Key     string
	Memory  processes.ExecutionMemoryContext
	Process processes.Process
	Obs     evidence.Observation
}

func processMemoryItems(idx Index, processItems []processEvidenceItem) []processMemoryEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processMemoryEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.memory.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.ExecutionMemoryContext)
		if !ok {
			continue
		}
		p, ok := byID[c.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processMemoryEvidenceItem{Key: key, Memory: c, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processMemoryUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "executable-memory metadata is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processMemoryEvidenceKeys(items []processMemoryEvidenceItem) []string {
	keys := make([]string, 0, len(items)*2)
	for _, item := range items {
		keys = append(keys, item.Key)
		processKey := "process.item." + item.Process.ID
		keys = append(keys, processKey)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	if len(keys) > maxProcessRuleEvidence {
		keys = keys[:maxProcessRuleEvidence]
	}
	return keys
}

func processMemoryConfidence(items []processMemoryEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

type processPrivilegeEvidenceItem struct {
	Key       string
	Privilege processes.RuntimePrivilegeContext
	Obs       evidence.Observation
}

func processPrivilegeItems(idx Index) []processPrivilegeEvidenceItem {
	out := make([]processPrivilegeEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.privilege.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.RuntimePrivilegeContext)
		if !ok {
			continue
		}
		out = append(out, processPrivilegeEvidenceItem{Key: key, Privilege: c, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Privilege.PID != out[j].Privilege.PID {
			return out[i].Privilege.PID < out[j].Privilege.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processPrivilegeUnavailable(idx Index) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime privilege evidence is unavailable", Applicability: Undetermined, EvidenceKeys: processPrivilegeInventoryKeys(idx)}
}

func processPrivilegeInventoryKeys(idx Index) []string {
	keys := []string{}
	for _, key := range []string{"process.inventory.summary", "process.inventory.count"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	for key := range idx {
		if strings.HasPrefix(key, "process.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxProcessRuleEvidence {
		keys = keys[:maxProcessRuleEvidence]
	}
	return keys
}

func processPrivilegeEvidenceKeys(items []processPrivilegeEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return keys
}

func processPrivilegeConfidence(items []processPrivilegeEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func privilegeHasExcessSetSignal(c processes.RuntimePrivilegeContext) bool {
	for _, signal := range c.ExcessSignals {
		switch signal {
		case "non-root-high-impact-effective-capabilities", "non-root-high-impact-permitted-capabilities", "high-impact-ambient-capabilities", "user-or-unknown-account-high-impact-token-privileges":
			return true
		}
	}
	return false
}

func containsString(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

type processPermissionEvidenceItem struct {
	Key        string
	Permission processes.PathPermissionContext
	Process    processes.Process
	Obs        evidence.Observation
}

func processPermissionItems(idx Index, processItems []processEvidenceItem) []processPermissionEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processPermissionEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.permission.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(processes.PathPermissionContext)
		if !ok {
			continue
		}
		p, ok := byID[c.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processPermissionEvidenceItem{Key: key, Permission: c, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processPermissionUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "executable/parent permission evidence is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processPermissionEvidenceKeys(items []processPermissionEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return keys
}

func processPermissionConfidence(items []processPermissionEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		if r := processConfidenceRank(item.Obs.Confidence); r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func permissionsForPrivileged(items []processPermissionEvidenceItem) []processPermissionEvidenceItem {
	out := make([]processPermissionEvidenceItem, 0)
	for _, item := range items {
		if item.Process.Principal.Elevated {
			out = append(out, item)
		}
	}
	return out
}

type processLocationEvidenceItem struct {
	Key      string
	Location processes.LocationContext
	Process  processes.Process
	Obs      evidence.Observation
}

func processLocationItems(idx Index, processItems []processEvidenceItem) []processLocationEvidenceItem {
	byID := make(map[string]processes.Process, len(processItems))
	for _, item := range processItems {
		byID[item.Process.ID] = item.Process
	}
	out := make([]processLocationEvidenceItem, 0, len(processItems))
	for key, obs := range idx {
		if !strings.HasPrefix(key, "process.location.") || obs.State != evidence.StateObserved {
			continue
		}
		loc, ok := obs.Value.(processes.LocationContext)
		if !ok {
			continue
		}
		p, ok := byID[loc.ProcessID]
		if !ok {
			continue
		}
		out = append(out, processLocationEvidenceItem{Key: key, Location: loc, Process: p, Obs: obs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Process.PID != out[j].Process.PID {
			return out[i].Process.PID < out[j].Process.PID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func processLocationUnavailable(idx Index, items []processEvidenceItem) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "execution-location evidence is unavailable", Applicability: Undetermined, EvidenceKeys: processInventoryEvidenceKeys(idx, items)}
}

func processLocationEvidenceKeys(items []processLocationEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
		if len(keys) >= maxProcessRuleEvidence {
			break
		}
	}
	return keys
}

func processLocationConfidence(items []processLocationEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		r := processConfidenceRank(item.Obs.Confidence)
		if r < rank {
			rank = r
		}
	}
	switch rank {
	case 4:
		return evidence.ConfidenceExact
	case 3:
		return evidence.ConfidenceHigh
	case 2:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func locationsForPrivileged(items []processLocationEvidenceItem) []processLocationEvidenceItem {
	out := make([]processLocationEvidenceItem, 0)
	for _, item := range items {
		if item.Process.Principal.Elevated {
			out = append(out, item)
		}
	}
	return out
}

func isSensitiveProcess(p processes.Process, platform string) bool {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(p.Executable))
	}
	name = strings.TrimSuffix(name, ".exe")
	sets := map[string]map[string]struct{}{
		"windows": {
			"lsass": {}, "winlogon": {}, "services": {}, "smss": {}, "csrss": {}, "wininit": {},
			"sshd": {}, "wsmprovhost": {}, "docker daemon": {}, "dockerd": {}, "containerd": {}, "kubelet": {},
		},
		"linux": {
			"sshd": {}, "sudo": {}, "polkitd": {}, "cron": {}, "crond": {}, "dockerd": {}, "containerd": {},
			"kubelet": {}, "libvirtd": {}, "virtqemud": {}, "systemd-logind": {},
		},
		"darwin": {
			"sshd": {}, "securityd": {}, "authd": {}, "opendirectoryd": {}, "loginwindow": {}, "screensharingd": {},
		},
	}
	_, ok := sets[platform][name]
	return ok
}

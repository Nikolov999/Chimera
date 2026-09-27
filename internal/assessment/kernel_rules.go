package assessment

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// KernelRules returns the concrete hardening rule pack for the
// runtime platform over normalized kernel evidence emitted by Phases 010-018.
func KernelRules() []Rule {
	return KernelRulesForPlatform(runtime.GOOS)
}

// KernelRulesForPlatform returns the deterministic platform projection of the
// v1 kernel rule catalog. Rules never perform collection themselves; they only
// evaluate the immutable evidence snapshot.
func KernelRulesForPlatform(platform string) []Rule {
	rules := []Rule{
		boolExpectationRule("CHM-KRN-001", "Secure Boot is enabled", SeverityHigh, "kernel.secure_boot.enabled", true,
			"Secure Boot should be enabled when the observed boot platform supports it.",
			"A disabled Secure Boot policy weakens the boot trust boundary and can permit unsigned or untrusted boot components.",
			"Enable Secure Boot using the platform/vendor-supported firmware and operating-system procedure after validating boot-chain compatibility."),
		moduleTrustAggregateRule(),
		vulnerableDriverAggregateRule(),
	}

	switch platform {
	case "linux":
		rules = append(rules, linuxKernelRules()...)
	case "windows":
		rules = append(rules, windowsKernelRules()...)
	case "darwin":
		rules = append(rules, darwinKernelRules()...)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func linuxKernelRules() []Rule {
	return []Rule{
		boolExpectationRule("CHM-KRN-LNX-001", "Linux kernel lockdown is enabled", SeverityMedium, "kernel.integrity.linux_kernel_lockdown.enabled", true,
			"Kernel lockdown should be enabled on systems whose boot/security model relies on it.",
			"Without lockdown, privileged users or compromised privileged processes may retain broader access to kernel interfaces that weaken measured/verified boot guarantees.",
			"Enable the distribution-supported kernel lockdown policy, preferably integrity or confidentiality mode as appropriate for the host."),
		boolExpectationRule("CHM-KRN-LNX-002", "Linux module signature enforcement is enabled", SeverityHigh, "kernel.integrity.linux_module_signature_enforcement.enabled", true,
			"The kernel module loader should reject unsigned loadable modules where the platform supports signature enforcement.",
			"Permitting unsigned kernel modules weakens the kernel trust boundary and can allow untrusted code to execute in kernel context after privilege compromise.",
			"Enable the distribution/kernel-supported module-signature enforcement policy and use appropriately signed modules."),
		stringExpectationRule("CHM-KRN-LNX-003", "Linux ASLR uses full randomization", SeverityMedium, "kernel.mitigation.linux_aslr.state", []string{"FULL"},
			"Linux address-space randomization should use the strongest locally exposed system setting.",
			"Reduced or disabled address-space randomization makes memory-corruption exploitation more reliable when another vulnerability is present.",
			"Set kernel.randomize_va_space to the distribution-recommended full-randomization value after compatibility review."),
		boolExpectationRule("CHM-KRN-LNX-004", "Linux low-address mmap protection is enabled", SeverityMedium, "kernel.mitigation.linux_mmap_min_addr.enabled", true,
			"The low virtual-address mapping guard should be enabled.",
			"Allowing mappings at address zero or very low addresses can weaken defenses against classes of null-pointer dereference vulnerabilities.",
			"Set vm.mmap_min_addr to the distribution-supported non-zero baseline appropriate for the host."),
		boolExpectationRule("CHM-KRN-LNX-005", "Linux kernel pointer exposure is restricted", SeverityMedium, "kernel.debug.linux_kptr_restrict.exposed", false,
			"Kernel pointer disclosure should be restricted for unprivileged contexts.",
			"Broad kernel pointer disclosure can reduce address-randomization effectiveness and aid exploitation of a separate kernel flaw.",
			"Set kernel.kptr_restrict to a distribution-supported restrictive value."),
		boolExpectationRule("CHM-KRN-LNX-006", "Linux kernel log access is restricted", SeverityMedium, "kernel.debug.linux_dmesg_restrict.exposed", false,
			"Unprivileged kernel log access should be restricted.",
			"Kernel logs can disclose addresses, device state, faults, and other information useful for local privilege-escalation chains.",
			"Enable kernel.dmesg_restrict or the equivalent distribution-supported policy."),
		boolExpectationRule("CHM-KRN-LNX-007", "Linux ptrace access is restricted", SeverityMedium, "kernel.debug.linux_ptrace_scope.exposed", false,
			"Same-user cross-process tracing should be constrained by an explicit ptrace policy.",
			"Broad ptrace access can expose process memory and weaken process-to-process security boundaries after account compromise.",
			"Use an appropriate restrictive kernel.yama.ptrace_scope value for the host role."),
		boolExpectationRule("CHM-KRN-LNX-008", "Linux unprivileged BPF is restricted", SeverityHigh, "kernel.unprivileged.linux_unprivileged_bpf.exposed", false,
			"Unprivileged BPF kernel access should be restricted unless explicitly required.",
			"Unprivileged BPF materially increases reachable kernel attack surface for local users and sandboxed workloads.",
			"Disable or permanently restrict unprivileged BPF using the kernel/distribution-supported policy when it is not required."),
		boolExpectationRule("CHM-KRN-LNX-009", "Linux unprivileged userfaultfd kernel-fault handling is restricted", SeverityMedium, "kernel.unprivileged.linux_unprivileged_userfaultfd.exposed", false,
			"Unprivileged userfaultfd access to kernel-fault handling should be restricted unless explicitly required.",
			"Unrestricted userfaultfd can enlarge the local kernel attack surface and has historically been useful in exploitation chains.",
			"Restrict vm.unprivileged_userfaultfd according to the workload and distribution baseline."),
		linuxPerfEventRule(),
		linuxMandatoryAccessRule(),
	}
}

func windowsKernelRules() []Rule {
	return []Rule{
		stringExpectationRule("CHM-KRN-WIN-001", "Windows code integrity policy is enforcing", SeverityHigh, "kernel.integrity.windows_code_integrity_policy.state", []string{"ENFORCED"},
			"Windows code-integrity policy should be enforcing where the platform exposes an applicable policy.",
			"Disabled or audit-only code integrity weakens prevention of untrusted kernel or protected code execution.",
			"Enable an appropriate Windows code-integrity policy after validating driver and application compatibility."),
		boolExpectationRule("CHM-KRN-WIN-002", "Windows test signing is disabled", SeverityHigh, "kernel.integrity.windows_test_signing.enabled", false,
			"Test-signing mode should be disabled on production systems.",
			"Test-signing mode weakens normal trust requirements for kernel drivers and can expand the trusted code base.",
			"Disable Windows test-signing mode using the supported boot configuration workflow and reboot if required."),
		boolExpectationRule("CHM-KRN-WIN-003", "Windows DEP is enabled", SeverityHigh, "kernel.mitigation.windows_dep.enabled", true,
			"Data Execution Prevention should be enabled.",
			"Disabled DEP weakens a foundational memory-execution boundary and can increase exploit reliability.",
			"Enable DEP using supported Windows system policy and validate application compatibility."),
		notStringRule("CHM-KRN-WIN-004", "Windows system ASLR is not explicitly disabled", SeverityMedium, "kernel.mitigation.windows_aslr.state", []string{"DISABLED", "MIXED_WITH_EXPLICIT_DISABLE"},
			"Windows system ASLR should not be explicitly disabled.",
			"Explicitly disabling ASLR removes a key memory-layout randomization defense.",
			"Restore Windows system mitigation policy so ASLR is enabled or left at a secure platform default."),
		boolExpectationRule("CHM-KRN-WIN-005", "Windows kernel debugging is disabled", SeverityHigh, "kernel.debug.windows_kernel_debugging.exposed", false,
			"Kernel debugging should be disabled on normal production endpoints and servers.",
			"Enabled kernel debugging exposes a powerful privileged diagnostic surface and weakens the normal kernel security boundary.",
			"Disable kernel debugging through supported BCD policy unless the host is an intentionally isolated debugging system."),
		boolExpectationRule("CHM-KRN-WIN-006", "Windows boot debugging is disabled", SeverityHigh, "kernel.debug.windows_boot_debugging.exposed", false,
			"Boot debugging should be disabled on normal production systems.",
			"Boot debugging exposes privileged early-boot diagnostics that are unnecessary on most deployed hosts.",
			"Disable boot debugging through supported BCD policy unless it is explicitly required in an isolated diagnostic environment."),
		stringExpectationWarnRule("CHM-KRN-WIN-007", "Windows HVCI is running", SeverityMedium, "kernel.integrity.windows_hvci.state", []string{"RUNNING"},
			"HVCI should be running on compatible high-assurance Windows systems.",
			"HVCI not running removes a hardware-backed code-integrity isolation layer that can reduce kernel attack surface.",
			"Enable Memory Integrity/HVCI where hardware, driver, and workload compatibility permit."),
		stringExpectationWarnRule("CHM-KRN-WIN-008", "Windows VBS isolation is running", SeverityMedium, "kernel.mandatory_access.windows_vbs_isolation.state", []string{"RUNNING"},
			"Virtualization-Based Security should be running where supported and appropriate for the host profile.",
			"Without VBS, Windows loses an isolation boundary used by several credential and code-integrity protections.",
			"Enable VBS through supported Windows security policy where platform and workload compatibility permit."),
	}
}

func darwinKernelRules() []Rule {
	return []Rule{
		stringExpectationRule("CHM-KRN-MAC-001", "macOS AMFI boot-policy bypass is absent", SeverityHigh, "kernel.integrity.macos_amfi_boot_policy.state", []string{"NO_BOOT_ARG_BYPASS_OBSERVED"},
			"No recognized AMFI/code-signing disable boot argument should be active.",
			"AMFI bypass or disable boot arguments weaken application and code-signing trust enforcement.",
			"Remove unsupported AMFI/code-signing bypass boot arguments using the platform-supported recovery/boot-policy workflow."),
		stringExpectationRule("CHM-KRN-MAC-002", "macOS ASLR disable override is absent", SeverityHigh, "kernel.mitigation.macos_aslr_boot_policy.state", []string{"NO_DISABLE_OVERRIDE_OBSERVED"},
			"No recognized ASLR-disabling boot argument should be active.",
			"Disabling ASLR makes memory-corruption exploitation more reliable when another vulnerability is present.",
			"Remove ASLR-disabling boot arguments through the supported macOS boot configuration workflow."),
		boolExpectationRule("CHM-KRN-MAC-003", "macOS system executable PIE posture is enabled", SeverityMedium, "kernel.mitigation.macos_system_binary_pie.enabled", true,
			"Standard system executables should retain position-independent executable posture.",
			"Loss of PIE weakens address randomization for affected executables.",
			"Restore affected system components from trusted Apple-provided software and investigate unsupported modifications."),
		boolExpectationRule("CHM-KRN-MAC-004", "macOS kernel-debug boot arguments are absent", SeverityHigh, "kernel.debug.macos_kernel_debug_boot_args.exposed", false,
			"Recognized kernel-debug boot arguments should be absent on normal production systems.",
			"Kernel-debug boot settings expose privileged diagnostic behavior and can weaken normal kernel security boundaries.",
			"Remove kernel-debug boot arguments unless the Mac is an intentionally isolated diagnostic system."),
		boolExpectationRule("CHM-KRN-MAC-005", "macOS System Integrity Protection is enabled", SeverityHigh, "kernel.mandatory_access.macos_sip.enabled", true,
			"System Integrity Protection should be enabled.",
			"Disabled SIP weakens protection of system files, processes, and other platform integrity boundaries.",
			"Re-enable SIP through the supported macOS recovery environment after resolving any compatibility dependency."),
	}
}

func boolExpectationRule(id, title string, sev Severity, key string, want bool, expected, risk, remediation string) Rule {
	return Rule{ID: id, Title: title, Category: "kernel", Severity: sev, AffectedObject: key, ExpectedState: expected, Risk: risk, Remediation: remediation,
		Evaluate: func(idx Index) Evaluation { return evalBool(idx, key, want, false) }}
}

func notStringRule(id, title string, sev Severity, key string, denied []string, expected, risk, remediation string) Rule {
	bad := make(map[string]struct{}, len(denied))
	for _, v := range denied {
		bad[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}
	return Rule{ID: id, Title: title, Category: "kernel", Severity: sev, AffectedObject: key, ExpectedState: expected, Risk: risk, Remediation: remediation,
		Evaluate: func(idx Index) Evaluation {
			o, ok := idx[key]
			if !ok {
				return unknownEval(key, "evidence key missing")
			}
			if o.State == evidence.StateNotApplicable {
				return notApplicableEval(o, key)
			}
			if o.State != evidence.StateObserved {
				return unavailableEval(o, key)
			}
			v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
			if _, found := bad[v]; found {
				return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			}
			return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
		}}
}

func stringExpectationRule(id, title string, sev Severity, key string, allowed []string, expected, risk, remediation string) Rule {
	return stringExpectationRuleWithMismatch(id, title, sev, key, allowed, StatusFail, expected, risk, remediation)
}

func stringExpectationWarnRule(id, title string, sev Severity, key string, allowed []string, expected, risk, remediation string) Rule {
	return stringExpectationRuleWithMismatch(id, title, sev, key, allowed, StatusWarn, expected, risk, remediation)
}

func stringExpectationRuleWithMismatch(id, title string, sev Severity, key string, allowed []string, mismatch Status, expected, risk, remediation string) Rule {
	allow := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		allow[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}
	return Rule{ID: id, Title: title, Category: "kernel", Severity: sev, AffectedObject: key, ExpectedState: expected, Risk: risk, Remediation: remediation,
		Evaluate: func(idx Index) Evaluation {
			o, ok := idx[key]
			if !ok {
				return unknownEval(key, "evidence key missing")
			}
			if o.State == evidence.StateNotApplicable {
				return notApplicableEval(o, key)
			}
			if o.State != evidence.StateObserved {
				return unavailableEval(o, key)
			}
			v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
			if _, ok := allow[v]; ok {
				return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			}
			return Evaluation{Status: mismatch, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
		}}
}

func evalBool(idx Index, key string, want bool, warn bool) Evaluation {
	o, ok := idx[key]
	if !ok {
		fallback := strings.TrimSuffix(strings.TrimSuffix(key, ".enabled"), ".exposed") + ".state"
		if stateObs, found := idx[fallback]; found {
			if stateObs.State == evidence.StateNotApplicable {
				return notApplicableEval(stateObs, fallback)
			}
			if stateObs.State != evidence.StateObserved {
				return unavailableEval(stateObs, fallback)
			}
		}
		return unknownEval(key, "evidence key missing")
	}
	if o.State == evidence.StateNotApplicable {
		return notApplicableEval(o, key)
	}
	if o.State != evidence.StateObserved {
		return unavailableEval(o, key)
	}
	b, ok := observationBool(o.Value)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "non-boolean evidence value: " + fmt.Sprint(o.Value), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if b == want {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	status := StatusFail
	if warn {
		status = StatusWarn
	}
	return Evaluation{Status: status, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
}

func observationBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		return b, err == nil
	default:
		return false, false
	}
}

func unknownEval(key, reason string) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: reason, Applicability: Undetermined, EvidenceKeys: []string{key}}
}
func unavailableEval(o evidence.Observation, key string) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
}
func notApplicableEval(o evidence.Observation, key string) Evaluation {
	return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: NotApplicable, EvidenceKeys: []string{key}}
}

func linuxPerfEventRule() Rule {
	const key = "kernel.unprivileged.linux_perf_event_paranoid.state"
	return Rule{ID: "CHM-KRN-LNX-010", Title: "Linux performance-event access is restricted", Category: "kernel", Severity: SeverityMedium, AffectedObject: key,
		ExpectedState: "kernel.perf_event_paranoid should restrict unprivileged access to privileged performance data", Risk: "Broad performance-event access can expose sensitive execution data and enlarge local kernel attack surface.", Remediation: "Use a restrictive kernel.perf_event_paranoid value appropriate for the workload.",
		Evaluate: func(idx Index) Evaluation {
			o, ok := idx[key]
			if !ok {
				return unknownEval(key, "evidence key missing")
			}
			if o.State == evidence.StateNotApplicable {
				return notApplicableEval(o, key)
			}
			if o.State != evidence.StateObserved {
				return unavailableEval(o, key)
			}
			v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
			switch v {
			case "STRONGLY_RESTRICTED":
				return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			case "RESTRICTED":
				return Evaluation{Status: StatusWarn, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			default:
				return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			}
		}}
}

func linuxMandatoryAccessRule() Rule {
	keys := []string{"kernel.mandatory_access.linux_selinux.state", "kernel.mandatory_access.linux_apparmor.state", "kernel.mandatory_access.linux_lsm_stack.state"}
	return Rule{ID: "CHM-KRN-LNX-011", Title: "Linux mandatory-access-control policy is active", Category: "kernel", Severity: SeverityMedium, AffectedObject: "kernel.mandatory_access",
		ExpectedState: "an applicable mandatory-access-control framework should be active and enforcing where supported", Risk: "A host without an active mandatory-access-control policy has fewer containment boundaries after a service or process compromise.", Remediation: "Enable and enforce the distribution-supported SELinux, AppArmor, or equivalent LSM policy appropriate for the host.",
		Evaluate: func(idx Index) Evaluation {
			observed := []string{}
			evidenceKeys := []string{}
			for _, key := range keys {
				if o, ok := idx[key]; ok {
					evidenceKeys = append(evidenceKeys, key)
					if o.State == evidence.StateObserved {
						observed = append(observed, strings.ToUpper(fmt.Sprint(o.Value)))
					}
				}
			}
			if len(evidenceKeys) == 0 {
				return unknownEval("kernel.mandatory_access", "mandatory-access evidence missing")
			}
			for _, v := range observed {
				if v == "ENFORCING" || v == "ENABLED" || v == "ACTIVE" {
					return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: strings.Join(observed, "; "), Applicability: Applicable, EvidenceKeys: evidenceKeys}
				}
			}
			if len(observed) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: strings.Join(observed, "; "), Applicability: Applicable, EvidenceKeys: evidenceKeys}
			}
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "mandatory-access state unavailable", Applicability: Applicable, EvidenceKeys: evidenceKeys}
		}}
}

func moduleTrustAggregateRule() Rule {
	return Rule{ID: "CHM-KRN-020", Title: "Loaded kernel components have defensible trust provenance", Category: "kernel", Severity: SeverityHigh, AffectedObject: "kernel.loaded_modules.trust",
		ExpectedState: "no loaded kernel module/driver is observed unsigned, test-signed, signature-invalid, or missing its backing component", Risk: "Untrusted or weakly attributable code running in kernel context has system-wide impact and can bypass user-mode security boundaries.", Remediation: "Remove or replace untrusted kernel components with vendor-supported signed versions and investigate deleted/missing backing files before returning the host to normal service.",
		Evaluate: func(idx Index) Evaluation {
			keys := []string{}
			bad := []string{}
			unresolved := 0
			for key, o := range idx {
				if !strings.HasPrefix(key, "kernel.module.") || !(strings.HasSuffix(key, ".load_state") || strings.HasSuffix(key, ".flags") || strings.HasSuffix(key, ".trust_state") || strings.HasSuffix(key, ".backing_state")) {
					continue
				}
				keys = append(keys, key)
				if o.State != evidence.StateObserved {
					unresolved++
					continue
				}
				v := strings.ToUpper(fmt.Sprint(o.Value))
				if strings.Contains(v, "UNSIGNED") || strings.Contains(v, "TEST_SIGNED") || strings.Contains(v, "SIGNATURE_INVALID") || strings.Contains(v, "DELETED_BACKING") || strings.Contains(v, "DELETED_OR_MISSING") || strings.Contains(v, "UNTRUSTED_OR_INVALID") {
					bad = append(bad, key+"="+v)
				}
			}
			sort.Strings(keys)
			sort.Strings(bad)
			if len(keys) == 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "loaded-module trust evidence missing", Applicability: Undetermined, EvidenceKeys: []string{"kernel.module.*"}}
			}
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: strings.Join(bad, "; "), Applicability: Applicable, EvidenceKeys: keys}
			}
			if unresolved > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no explicit untrusted component observed; %d trust facts unresolved", unresolved), Applicability: Applicable, EvidenceKeys: keys}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no unsigned, test-signed, signature-invalid, or deleted-backing loaded kernel component observed", Applicability: Applicable, EvidenceKeys: keys}
		}}
}

func vulnerableDriverAggregateRule() Rule {
	key := "kernel.vulnerable_driver.intelligence.matches"
	return Rule{ID: "CHM-KRN-021", Title: "No known-vulnerable driver identity is present", Category: "kernel", Severity: SeverityHigh, AffectedObject: "kernel.vulnerable_drivers",
		ExpectedState: "local vulnerable-driver intelligence should produce zero identity matches", Risk: "A known-vulnerable driver can expose privileged kernel attack surface even when the weakness is not actively exploited.", Remediation: "Remove, disable, or update the matched driver using vendor-supported remediation after confirming the exact affected version/hash and operational dependency.",
		Evaluate: func(idx Index) Evaluation {
			entriesKey := "kernel.vulnerable_driver.intelligence.platform_entries"
			if entries, ok := idx[entriesKey]; ok && entries.State == evidence.StateObserved {
				if count, parsed := intValue(entries.Value); parsed && count == 0 {
					return Evaluation{Status: StatusPass, Confidence: entries.Confidence, ObservedState: "no vulnerable-driver intelligence entries apply to this platform", Applicability: NotApplicable, EvidenceKeys: []string{entriesKey}}
				}
			}
			o, ok := idx[key]
			if !ok {
				return unknownEval(key, "vulnerable-driver intelligence result missing")
			}
			if o.State != evidence.StateObserved {
				return unavailableEval(o, key)
			}
			n, ok := intValue(o.Value)
			if !ok {
				return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "non-numeric match count", Applicability: Applicable, EvidenceKeys: []string{key}}
			}
			keys := []string{key}
			if n == 0 {
				return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "0 identity matches", Applicability: Applicable, EvidenceKeys: keys}
			}
			for k := range idx {
				if strings.HasPrefix(k, "kernel.vulnerable_driver.") && strings.HasSuffix(k, ".assessment") {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d known-vulnerable driver identity match(es); exact affected version/hash confirmation may still be unresolved", n), Applicability: Applicable, EvidenceKeys: keys}
		}}
}

func intValue(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), x == float64(int(x))
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	default:
		return 0, false
	}
}

package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

type launchdSecurityEvidenceItem struct {
	ID       string
	Key      string
	ItemKey  string
	Service  services.Service
	Security services.LaunchdHardening
	Obs      evidence.Observation
}

// LaunchdServiceRules implements the macOS launchd hardening catalog.
// It evaluates plist/filesystem metadata only and never loads or executes jobs.
func LaunchdServiceRules() []Rule {
	return []Rule{
		launchdDefinitionIntegrityRule(), launchdExecutableIntegrityRule(), launchdExecutableParentRule(),
		launchdEnvironmentRule(), launchdProgramPathRule(), launchdAccountRule(), launchdDangerousConfigurationRule(),
	}
}

func launchdDefinitionIntegrityRule() Rule {
	return Rule{
		ID: "CHM-SVC-016", Title: "launchd definitions have secure ownership and permissions", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.definition.integrity", ExpectedState: "launchd plist definitions are not broadly writable and privileged definitions are root-owned",
		Risk:        "A writable or incorrectly owned launchd definition can weaken a persistence or privileged execution boundary.",
		Remediation: "Restore trusted ownership and remove group/other write access from launchd plist definitions according to the intended deployment model.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				s := i.Security
				return s.DefinitionBroadlyWritable || (launchdPrivileged(i.Service) && s.DefinitionOwner != "0" && !strings.EqualFold(s.DefinitionOwner, "root") && !strings.EqualFold(s.DefinitionOwner, "UNKNOWN"))
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd definition(s) have weak write/ownership posture", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			unknown := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				return strings.EqualFold(i.Security.DefinitionOwner, "UNKNOWN") || i.Security.DefinitionMode == ""
			})
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("definition ownership/permission posture unresolved for %d launchd definition(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: fmt.Sprintf("%d launchd definition(s) have no detected broad-write/ownership weakness", len(items)), Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdExecutableIntegrityRule() Rule {
	return Rule{
		ID: "CHM-SVC-017", Title: "launchd executables have secure ownership and permissions", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.executable.integrity", ExpectedState: "launchd executables are not broadly writable and privileged launchd executables are root-owned",
		Risk:        "A writable or untrusted-owner executable launched by launchd can turn configuration access into code execution under the job identity.",
		Remediation: "Restore trusted executable ownership and remove unnecessary group/other write access; reinstall the owning software if provenance is uncertain.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				s := i.Security
				return s.ExecutableBroadlyWritable || (s.ExecutableState == "OBSERVED" && launchdPrivileged(i.Service) && s.ExecutableOwner != "0" && !strings.EqualFold(s.ExecutableOwner, "root") && !strings.EqualFold(s.ExecutableOwner, "UNKNOWN"))
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd executable(s) have weak ownership/write posture", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			unknown := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool { return i.Security.ExecutableState != "OBSERVED" })
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("executable metadata unresolved for %d launchd job(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: fmt.Sprintf("%d launchd executable(s) have no detected ownership/write weakness", len(items)), Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdExecutableParentRule() Rule {
	return Rule{
		ID: "CHM-SVC-018", Title: "launchd executable directories resist broad modification", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.executable.parent_integrity", ExpectedState: "directories containing launchd executables are not broadly writable",
		Risk:        "A broadly writable parent directory can allow replacement or path substitution even when the current executable itself is protected.",
		Remediation: "Remove unnecessary group/other write permissions from launchd executable directories and restore trusted directory ownership.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool { return i.Security.ExecutableParentBroadlyWritable })
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd executable parent directorie(s) are broadly writable", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			unknown := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool { return i.Security.ExecutableParentState != "OBSERVED" })
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("executable parent metadata unresolved for %d launchd job(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: "no broadly writable launchd executable parent directories detected", Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdEnvironmentRule() Rule {
	return Rule{
		ID: "CHM-SVC-019", Title: "launchd jobs avoid dangerous dynamic-loader environment overrides", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.environment.loader_overrides", ExpectedState: "no launchd job defines dangerous DYLD loader override variables",
		Risk:        "Dynamic-loader environment overrides can alter library resolution or injection behavior for launched processes, especially across privileged boundaries.",
		Remediation: "Remove unneeded DYLD_* loader override variables from the launchd plist and use explicit trusted application/library paths instead.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool { return len(i.Security.DangerousEnvironmentKeys) > 0 })
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd job(s) define security-relevant DYLD environment overrides; values remain redacted", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: "no dangerous launchd dynamic-loader environment keys detected", Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdProgramPathRule() Rule {
	return Rule{
		ID: "CHM-SVC-020", Title: "launchd program paths are absolute and avoid weak privileged locations", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.program.path", ExpectedState: "launchd program paths are absolute and privileged jobs do not execute from weak user/temp/removable locations",
		Risk:        "Relative or weakly controlled executable locations make launch resolution and privileged execution boundaries less defensible.",
		Remediation: "Use an absolute executable path under a trusted system/application directory and move privileged launchd payloads out of user, temporary, or removable locations.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				return !i.Security.ProgramAbsolute || i.Security.PrivilegedWeakPath
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd job(s) use a relative program path or a weak privileged executable location", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: "launchd program paths are absolute with no detected privileged weak-location use", Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdAccountRule() Rule {
	return Rule{
		ID: "CHM-SVC-021", Title: "launchd job identities match daemon/agent boundaries", Category: "service", Severity: SeverityMedium,
		AffectedObject: "launchd.account.posture", ExpectedState: "launch daemons/agents have resolved identities and launch agents do not explicitly run as root",
		Risk:        "Unexpected or unresolved launchd identities can broaden execution privilege or make the effective security boundary ambiguous.",
		Remediation: "Use the least-privileged intended account and avoid root LaunchAgents; verify UserName/GroupName and the launch domain for custom jobs.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				return strings.EqualFold(i.Service.ServiceType, "LaunchAgent") && launchdPrivileged(i.Service)
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d LaunchAgent job(s) resolve to root identity", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			unknown := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool {
				return strings.EqualFold(i.Service.Account, "UNKNOWN") || strings.TrimSpace(i.Service.Account) == ""
			})
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("launchd identity unresolved for %d job(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: "launchd job identities are resolved with no root LaunchAgent detected", Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdDangerousConfigurationRule() Rule {
	return Rule{
		ID: "CHM-SVC-022", Title: "privileged launchd jobs avoid dangerous launch configuration", Category: "service", Severity: SeverityHigh,
		AffectedObject: "launchd.configuration.dangerous", ExpectedState: "no privileged launchd job combines root execution with weak path, directory, environment, or agent configuration",
		Risk:        "Multiple weak launchd configuration choices can materially weaken the integrity of privileged startup or persistence execution.",
		Remediation: "Remove the reported dangerous launch configuration, protect working/root directories, avoid root LaunchAgents and loader overrides, and keep privileged payloads in trusted locations.",
		Evaluate: func(idx Index) Evaluation {
			if ev, done := launchdRuleApplicability(idx); done {
				return ev
			}
			items, state := launchdSecurityItems(idx)
			if len(items) == 0 {
				return launchdSecurityUnavailable(idx, state)
			}
			bad := filterLaunchdItems(items, func(i launchdSecurityEvidenceItem) bool { return len(i.Security.DangerousConfiguration) > 0 })
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: launchdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d launchd job(s) contain dangerous launch-configuration indicators", len(bad)), Applicability: Applicable, EvidenceKeys: launchdEvidenceKeys(bad)}
			}
			return Evaluation{Status: StatusPass, Confidence: launchdSecurityConfidence(items), ObservedState: "no dangerous launchd configuration indicators detected", Applicability: Applicable, EvidenceKeys: launchdInventoryKeys(idx, items)}
		},
	}
}

func launchdRuleApplicability(idx Index) (Evaluation, bool) {
	platform := ""
	if o, ok := idx["service.platform"]; ok && o.State == evidence.StateObserved {
		platform = strings.ToLower(strings.TrimSpace(fmt.Sprint(o.Value)))
	}
	if platform == "" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service platform evidence unavailable", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	if platform != "darwin" {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "macOS launchd hardening assessment is not applicable on " + platform, Applicability: NotApplicable, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	return Evaluation{}, false
}
func launchdSecurityItems(idx Index) ([]launchdSecurityEvidenceItem, evidence.State) {
	servicesByID := map[string]services.Service{}
	itemKeys := map[string]string{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.item.") || obs.State != evidence.StateObserved {
			continue
		}
		svc, ok := obs.Value.(services.Service)
		if !ok {
			continue
		}
		servicesByID[svc.ID] = svc
		itemKeys[svc.ID] = key
	}
	items := []launchdSecurityEvidenceItem{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.launchd.") || obs.State != evidence.StateObserved {
			continue
		}
		sec, ok := obs.Value.(services.LaunchdHardening)
		if !ok {
			continue
		}
		id := strings.TrimPrefix(key, "service.launchd.")
		svc, ok := servicesByID[id]
		if !ok || !strings.EqualFold(svc.Manager, "launchd") {
			continue
		}
		items = append(items, launchdSecurityEvidenceItem{ID: id, Key: key, ItemKey: itemKeys[id], Service: svc, Security: sec, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Service.Name) != strings.ToLower(items[j].Service.Name) {
			return strings.ToLower(items[i].Service.Name) < strings.ToLower(items[j].Service.Name)
		}
		return items[i].ID < items[j].ID
	})
	state := evidence.StateUnavailable
	if o, ok := idx["service.source.darwin_launchd_hardening"]; ok {
		state = o.State
	}
	return items, state
}
func launchdSecurityUnavailable(idx Index, state evidence.State) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "macOS launchd hardening metadata unavailable or contained no launchd records (provider state " + string(state) + ")", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "service.inventory.summary", "service.inventory.count", "service.source.darwin_launchd_hardening")}
}
func launchdPrivileged(s services.Service) bool {
	return strings.EqualFold(s.PrivilegeContext, "ROOT") || strings.EqualFold(s.Account, "root") || strings.TrimSpace(s.Account) == "0"
}
func filterLaunchdItems(items []launchdSecurityEvidenceItem, p func(launchdSecurityEvidenceItem) bool) []launchdSecurityEvidenceItem {
	out := []launchdSecurityEvidenceItem{}
	for _, i := range items {
		if p(i) {
			out = append(out, i)
		}
	}
	return out
}
func launchdEvidenceKeys(items []launchdSecurityEvidenceItem) []string {
	keys := []string{}
	for _, i := range items {
		keys = append(keys, i.Key)
		if i.ItemKey != "" {
			keys = append(keys, i.ItemKey)
		}
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
	}
	if len(keys) > maxServiceRuleEvidence {
		keys = keys[:maxServiceRuleEvidence]
	}
	return uniqueStrings(keys)
}
func launchdInventoryKeys(idx Index, items []launchdSecurityEvidenceItem) []string {
	keys := existingKeys(idx, "service.inventory.summary", "service.source.darwin_launchd_hardening")
	for _, k := range launchdEvidenceKeys(items) {
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
		keys = append(keys, k)
	}
	return uniqueStrings(keys)
}
func launchdSecurityConfidence(items []launchdSecurityEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	for _, i := range items {
		if i.Security.State == "DEGRADED" || i.Obs.Confidence == evidence.ConfidenceMedium {
			return evidence.ConfidenceMedium
		}
		if i.Obs.Confidence == evidence.ConfidenceLow {
			return evidence.ConfidenceLow
		}
	}
	return evidence.ConfidenceHigh
}

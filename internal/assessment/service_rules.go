package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

const maxServiceRuleEvidence = 128

type serviceSecurityEvidenceItem struct {
	ID       string
	Key      string
	ItemKey  string
	Service  services.Service
	Security services.WindowsSecurity
	Obs      evidence.Observation
}

// ServiceRules returns the implemented service-security catalog through .
// Rules evaluate normalized read-only evidence only; they never start, stop,
// reconfigure, exploit, or actively probe services.
func ServiceRules() []Rule {
	rules := []Rule{
		windowsUnquotedServicePathRule(),
		windowsWritableServiceBinaryRule(),
		windowsWritableServiceDirectoryRule(),
		windowsWeakServiceObjectACLRule(),
		windowsAdminServiceAccountRule(),
		windowsInteractiveServiceRule(),
		windowsRecoveryCommandRule(),
	}
	rules = append(rules, SystemdServiceRules()...)
	rules = append(rules, LaunchdServiceRules()...)
	rules = append(rules, ServicePathCorrelationRules()...)
	rules = append(rules, ServiceExposureRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func windowsUnquotedServicePathRule() Rule {
	return Rule{
		ID:             "CHM-SVC-001",
		Title:          "Windows service executable paths are safely quoted",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.windows.unquoted_executable_path",
		ExpectedState:  "service executable paths containing whitespace are quoted",
		Risk:           "An unquoted Windows service executable path containing spaces can cause the Service Control Manager to resolve unintended executable-name prefixes. The condition is materially more dangerous when an affected prefix or directory is writable by a lower-privileged principal.",
		Remediation:    "Quote the complete service executable path in the service ImagePath while preserving required arguments, then validate the service definition and restart only through an approved maintenance workflow.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			bad := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.UnquotedExecutablePath })
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: serviceSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d Windows service executable path(s) are unquoted and contain whitespace", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 unquoted executable paths across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsWritableServiceBinaryRule() Rule {
	return Rule{
		ID:             "CHM-SVC-002",
		Title:          "Windows service executable components are not broadly writable",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.windows.executable_acl",
		ExpectedState:  "service executable and service DLL ACLs do not grant write-equivalent access to broad low-privilege principals",
		Risk:           "Broad write access to a service executable or service-loaded DLL weakens the service code-integrity boundary and can permit lower-privileged users to replace code that the service later executes.",
		Remediation:    "Remove broad write/modify/delete/ownership grants from the affected executable or service DLL. Keep write access limited to trusted administrators, installers, or a narrowly scoped deployment principal.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			bad := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				return i.Security.ExecutableACL.BroadWriteGranted || i.Security.ServiceDLLACL.BroadWriteGranted
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service(s) have broadly writable executable or service-DLL ACLs", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				return aclUnresolved(i.Security.ExecutableACL) || aclApplicableUnresolved(i.Security.ServiceDLLACL)
			})
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad executable write grant observed; ACL state unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 broadly writable executable components across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsWritableServiceDirectoryRule() Rule {
	return Rule{
		ID:             "CHM-SVC-003",
		Title:          "Windows service executable directories are not broadly writable",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.windows.executable_directory_acl",
		ExpectedState:  "directories containing service executables and service DLLs do not grant write-equivalent access to broad low-privilege principals",
		Risk:           "A broadly writable directory containing service code can weaken replacement and search-path boundaries even when the executable file itself currently has restrictive permissions.",
		Remediation:    "Restrict write access on the affected service executable/DLL directory to trusted administrative or deployment principals and move service code out of user-writable locations.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			bad := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				return i.Security.ExecutableDirectoryACL.BroadWriteGranted || i.Security.ServiceDLLDirectoryACL.BroadWriteGranted
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service(s) execute code from broadly writable directories", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				return aclUnresolved(i.Security.ExecutableDirectoryACL) || aclApplicableUnresolved(i.Security.ServiceDLLDirectoryACL)
			})
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad service-directory write grant observed; directory ACL state unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 broadly writable service-code directories across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsWeakServiceObjectACLRule() Rule {
	return Rule{
		ID:             "CHM-SVC-004",
		Title:          "Windows service object ACLs restrict low-privilege control",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.windows.service_object_acl",
		ExpectedState:  "broad low-privilege principals are not granted service configuration, ownership, DACL, generic-write/all, start, stop, or pause control",
		Risk:           "Weak Service Control Manager object permissions can allow lower-privileged users to reconfigure a service or exercise operational control over it. Change-config, DACL, owner, generic-write, and generic-all rights are especially sensitive.",
		Remediation:    "Remove unnecessary service-object ACEs for Everyone, Authenticated Users, Users, Guests, Anonymous, or Interactive Users. Preserve only the minimum query/start/stop rights explicitly required by the service's operational model.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			dangerous := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.ServiceACL.Dangerous })
			if len(dangerous) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service object ACL(s) grant dangerous write/configuration control to broad low-privilege principals", len(dangerous)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(dangerous)}
			}
			control := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.ServiceACL.ControlOnly })
			if len(control) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service object ACL(s) grant start/stop/pause control to broad low-privilege principals", len(control)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(control)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.ServiceACL.State != "OBSERVED" })
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak service-object ACL observed; descriptor state unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 weak service-object ACLs across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsAdminServiceAccountRule() Rule {
	return Rule{
		ID:             "CHM-SVC-005",
		Title:          "Windows services avoid custom local-administrator accounts",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.windows.account_privilege",
		ExpectedState:  "services use built-in service identities or narrowly scoped service accounts rather than custom accounts directly present in the local Administrators group",
		Risk:           "A custom service account with local-administrator membership combines reusable account identity with broad host authority and can unnecessarily expand the blast radius of credential or service compromise.",
		Remediation:    "Move the service to a dedicated least-privileged service identity or managed service account and grant only the local rights and resource permissions required by the workload.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			bad := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				return i.Security.AccountAdminState == "YES" && !isBuiltinWindowsServiceAccount(i.Service.Account)
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service(s) run under custom accounts directly present in local Administrators", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.AccountAdminState == "UNKNOWN" })
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no custom local-admin service account observed; membership unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 custom local-administrator service accounts across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsInteractiveServiceRule() Rule {
	return Rule{
		ID:             "CHM-SVC-006",
		Title:          "Windows services do not use interactive-process launch mode",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.windows.interactive_process",
		ExpectedState:  "SERVICE_INTERACTIVE_PROCESS is not enabled for local services",
		Risk:           "Interactive service launch mode is a legacy boundary that unnecessarily couples service execution to an interactive desktop context and is inappropriate for modern hardened service configurations.",
		Remediation:    "Remove the interactive-service type flag and redesign any required user interaction through a separate least-privileged client process or supported IPC mechanism.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			bad := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.InteractiveProcess })
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service(s) use interactive-process launch mode", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.RegistryState != "OBSERVED" })
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no interactive service observed; registry launch metadata unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 interactive-process services across %d assessed Windows service(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsRecoveryCommandRule() Rule {
	return Rule{
		ID:             "CHM-SVC-007",
		Title:          "Windows service recovery commands preserve executable-path integrity",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.windows.failure_command",
		ExpectedState:  "configured service failure commands use safely quoted executable paths whose executable and containing directory are not broadly writable",
		Risk:           "A service recovery command executes in the service recovery context. Unquoted or broadly writable recovery executables/directories can introduce a second privileged execution path separate from the normal service binary.",
		Remediation:    "Remove unnecessary failure commands. For required recovery programs, quote the complete executable path and restrict executable and directory write access to trusted administrative or deployment principals.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := windowsServiceRuleApplicability(idx); ok {
				return ev
			}
			items, state := serviceSecurityItems(idx)
			if len(items) == 0 {
				return serviceSecurityUnavailable(idx, state)
			}
			configured := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool { return i.Security.FailureCommandPresent })
			bad := filterServiceSecurity(configured, func(i serviceSecurityEvidenceItem) bool {
				return i.Security.FailureExecutableUnquoted || i.Security.FailureExecutableACL.BroadWriteGranted || i.Security.FailureExecutableDirectoryACL.BroadWriteGranted
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d Windows service recovery command(s) have unquoted or broadly writable executable paths", len(bad)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(bad)}
			}
			unresolved := filterServiceSecurity(items, func(i serviceSecurityEvidenceItem) bool {
				if i.Security.RegistryState != "OBSERVED" {
					return true
				}
				if !i.Security.FailureCommandPresent {
					return false
				}
				return strings.TrimSpace(i.Security.FailureExecutablePath) == "" || aclUnresolved(i.Security.FailureExecutableACL) || aclUnresolved(i.Security.FailureExecutableDirectoryACL)
			})
			if len(unresolved) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak recovery command observed; recovery metadata unresolved for %d of %d service(s)", len(unresolved), len(items)), Applicability: Applicable, EvidenceKeys: serviceSecurityEvidenceKeys(unresolved)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d configured recovery command(s) assessed; 0 weak recovery executable paths", len(configured)), Applicability: Applicable, EvidenceKeys: serviceSecurityInventoryKeys(idx, items)}
		},
	}
}

func windowsServiceRuleApplicability(idx Index) (Evaluation, bool) {
	platform := ""
	if o, ok := idx["service.platform"]; ok && o.State == evidence.StateObserved {
		platform = strings.ToLower(strings.TrimSpace(fmt.Sprint(o.Value)))
	}
	if platform == "" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service platform evidence unavailable", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	if platform != "windows" {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Windows service path/ACL assessment is not applicable on " + platform, Applicability: NotApplicable, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	return Evaluation{}, false
}

func serviceSecurityItems(idx Index) ([]serviceSecurityEvidenceItem, evidence.State) {
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
	items := make([]serviceSecurityEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.security.") || obs.State != evidence.StateObserved {
			continue
		}
		sec, ok := obs.Value.(services.WindowsSecurity)
		if !ok {
			continue
		}
		id := strings.TrimPrefix(key, "service.security.")
		svc, ok := servicesByID[id]
		if !ok {
			continue
		}
		items = append(items, serviceSecurityEvidenceItem{ID: id, Key: key, ItemKey: itemKeys[id], Service: svc, Security: sec, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Service.Name) != strings.ToLower(items[j].Service.Name) {
			return strings.ToLower(items[i].Service.Name) < strings.ToLower(items[j].Service.Name)
		}
		return items[i].ID < items[j].ID
	})
	state := evidence.StateUnavailable
	if o, ok := idx["service.source.windows_service_security"]; ok {
		state = o.State
	}
	return items, state
}

func serviceSecurityUnavailable(idx Index, state evidence.State) Evaluation {
	keys := existingKeys(idx, "service.inventory.summary", "service.inventory.count", "service.source.windows_service_security")
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Windows service path/ACL metadata unavailable or contained no usable security records (provider state " + string(state) + ")", Applicability: Undetermined, EvidenceKeys: keys}
}

func serviceSecurityEvidenceKeys(items []serviceSecurityEvidenceItem) []string {
	keys := make([]string, 0, len(items)*2)
	for _, item := range items {
		keys = append(keys, item.Key)
		if item.ItemKey != "" {
			keys = append(keys, item.ItemKey)
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

func serviceSecurityInventoryKeys(idx Index, items []serviceSecurityEvidenceItem) []string {
	keys := existingKeys(idx, "service.inventory.summary", "service.source.windows_service_security")
	for _, key := range serviceSecurityEvidenceKeys(items) {
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

func serviceSecurityConfidence(items []serviceSecurityEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		r := confidenceRankAssessment(item.Obs.Confidence)
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

func confidenceRankAssessment(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceExact:
		return 4
	case evidence.ConfidenceHigh:
		return 3
	case evidence.ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func filterServiceSecurity(items []serviceSecurityEvidenceItem, predicate func(serviceSecurityEvidenceItem) bool) []serviceSecurityEvidenceItem {
	out := make([]serviceSecurityEvidenceItem, 0)
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func aclUnresolved(acl services.WindowsACLPosture) bool {
	return acl.State != "OBSERVED"
}

func aclApplicableUnresolved(acl services.WindowsACLPosture) bool {
	return acl.State != "OBSERVED" && acl.State != "NOT_APPLICABLE"
}

func isBuiltinWindowsServiceAccount(account string) bool {
	a := strings.ToLower(strings.TrimSpace(account))
	a = strings.ReplaceAll(a, "/", `\`)
	switch a {
	case "localsystem", "system", `nt authority\system`, "localservice", `nt authority\localservice`, "networkservice", `nt authority\networkservice`:
		return true
	default:
		return false
	}
}

func existingKeys(idx Index, candidates ...string) []string {
	keys := make([]string, 0, len(candidates))
	for _, key := range candidates {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok || v == "" {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

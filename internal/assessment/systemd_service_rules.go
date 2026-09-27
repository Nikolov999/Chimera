package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

type systemdSecurityEvidenceItem struct {
	ID       string
	Key      string
	ItemKey  string
	Service  services.Service
	Security services.SystemdHardening
	Obs      evidence.Observation
}

func SystemdServiceRules() []Rule {
	rules := []Rule{
		systemdServiceIdentityRule(),
		systemdNoNewPrivilegesRule(),
		systemdFilesystemProtectionRule(),
		systemdPrivateTmpRule(),
		systemdCapabilityBoundingRule(),
		systemdNamespaceKernelIsolationRule(),
		systemdAmbientCapabilitiesRule(),
		systemdAdditionalHardeningRule(),
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func systemdServiceIdentityRule() Rule {
	return Rule{
		ID:             "CHM-SVC-008",
		Title:          "Linux systemd services use a deliberate service identity",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.linux.systemd.identity",
		ExpectedState:  "enabled or running privileged systemd services use an explicitly configured User= identity, DynamicUser=yes, or a deliberately reviewed root requirement",
		Risk:           "A service that implicitly inherits root has the full system service-manager privilege boundary unless other sandbox controls meaningfully constrain it. Implicit root execution can make accidental over-privilege harder to distinguish from a deliberate requirement.",
		Remediation:    "Where the service does not require root, configure a dedicated User=/Group= or DynamicUser=yes. Where root is required, document the requirement and apply the strongest compatible systemd sandbox, capability, filesystem, and namespace restrictions.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			items, state := systemdSecurityItems(idx)
			items = filterSystemdItems(items, systemdRelevantService)
			if len(items) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			if degraded := filterSystemdItems(items, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("effective service identity", degraded, len(items))
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				return strings.EqualFold(i.Service.PrivilegeContext, "ROOT") && !i.Security.UserConfigured && i.Security.DynamicUser != "YES"
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d enabled/running systemd service(s) implicitly execute as root without User= or DynamicUser=yes", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("no implicit-root identity condition across %d enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdNoNewPrivilegesRule() Rule {
	return Rule{
		ID:             "CHM-SVC-009",
		Title:          "Linux systemd services prevent acquisition of new privileges",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.linux.systemd.no_new_privileges",
		ExpectedState:  "NoNewPrivileges=yes for enabled or running services where compatible",
		Risk:           "Without NoNewPrivileges, a service process or its descendants may gain additional privilege through set-user-ID/set-group-ID binaries or file capabilities when other controls permit it.",
		Remediation:    "Set NoNewPrivileges=yes for services that do not require privilege-gaining transitions, then validate startup and required helper behavior in an approved maintenance workflow.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			items, state := systemdSecurityItems(idx)
			items = filterSystemdItems(items, systemdRelevantService)
			if len(items) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			if degraded := filterSystemdItems(items, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("NoNewPrivileges", degraded, len(items))
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return i.Security.NoNewPrivileges == "NO" })
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d enabled/running systemd service(s) have NoNewPrivileges disabled", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return i.Security.NoNewPrivileges == "UNKNOWN" })
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("NoNewPrivileges unresolved for %d of %d enabled/running systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("NoNewPrivileges enabled across %d assessed enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdFilesystemProtectionRule() Rule {
	return Rule{
		ID:             "CHM-SVC-010",
		Title:          "Linux systemd services restrict system and home filesystem access",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.linux.systemd.filesystem_protection",
		ExpectedState:  "ProtectSystem is enabled and ProtectHome is enabled/read-only/tmpfs where compatible",
		Risk:           "Services with unrestricted write/read visibility into system and home paths have a broader filesystem impact boundary if the service is compromised or misbehaves.",
		Remediation:    "Use ProtectSystem=full or strict and ProtectHome=yes, read-only, or tmpfs where compatible. Add narrowly scoped ReadWritePaths/BindPaths exceptions instead of leaving the whole filesystem unrestricted.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			items, state := systemdSecurityItems(idx)
			items = filterSystemdItems(items, systemdRelevantService)
			if len(items) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			if degraded := filterSystemdItems(items, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("filesystem hardening", degraded, len(items))
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				return i.Security.ProtectSystem == "NO" || i.Security.ProtectHome == "NO"
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d enabled/running systemd service(s) leave ProtectSystem or ProtectHome disabled", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				return i.Security.ProtectSystem == "UNKNOWN" || i.Security.ProtectHome == "UNKNOWN"
			})
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("filesystem hardening unresolved for %d of %d enabled/running systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("ProtectSystem and ProtectHome enabled across %d assessed enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdPrivateTmpRule() Rule {
	return Rule{
		ID:             "CHM-SVC-011",
		Title:          "Linux systemd services isolate temporary directories",
		Category:       "service",
		Severity:       SeverityLow,
		AffectedObject: "service.linux.systemd.private_tmp",
		ExpectedState:  "PrivateTmp=yes or disconnected for enabled or running services where compatible",
		Risk:           "A shared host temporary namespace increases accidental data exposure and cross-service file interaction opportunities compared with a private temporary directory view.",
		Remediation:    "Set PrivateTmp=yes or PrivateTmp=disconnected where compatible with the service's IPC and filesystem requirements.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			items, state := systemdSecurityItems(idx)
			items = filterSystemdItems(items, systemdRelevantService)
			if len(items) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			if degraded := filterSystemdItems(items, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("PrivateTmp", degraded, len(items))
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return i.Security.PrivateTmp == "NO" })
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d enabled/running systemd service(s) have PrivateTmp disabled", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return i.Security.PrivateTmp == "UNKNOWN" })
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("PrivateTmp unresolved for %d of %d enabled/running systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("temporary-directory isolation enabled across %d assessed enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdCapabilityBoundingRule() Rule {
	return Rule{
		ID:             "CHM-SVC-012",
		Title:          "Privileged Linux systemd services constrain capability bounding sets",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.linux.systemd.capability_bounding_set",
		ExpectedState:  "privileged enabled or running services use a reduced CapabilityBoundingSet or an empty capability set when compatible",
		Risk:           "A root service retaining an effectively unrestricted capability set preserves broad kernel and discretionary-access authority even when other process-level controls are present.",
		Remediation:    "Reduce CapabilityBoundingSet to only the capabilities the service requires. Prefer an empty set for services that need no Linux capabilities and validate functionality after the change.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			all, state := systemdSecurityItems(idx)
			if len(all) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			relevant := filterSystemdItems(all, systemdRelevantService)
			if degraded := filterSystemdItems(relevant, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("capability-bounding posture", degraded, len(relevant))
			}
			items := filterSystemdItems(all, func(i systemdSecurityEvidenceItem) bool {
				return systemdRelevantService(i) && strings.EqualFold(i.Service.PrivilegeContext, "ROOT")
			})
			if len(items) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled/running privileged systemd service required capability-bounding evaluation", Applicability: Applicable, EvidenceKeys: existingKeys(idx, "service.inventory.summary", "service.source.linux_systemd_hardening")}
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				return i.Security.CapabilityBoundingSetState == "UNRESTRICTED"
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusFail, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d privileged enabled/running systemd service(s) retain an effectively unrestricted capability bounding set", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return i.Security.CapabilityBoundingSetState == "UNKNOWN" })
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("capability bounding-set posture unresolved for %d of %d privileged systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("capability bounding sets constrained across %d privileged enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdNamespaceKernelIsolationRule() Rule {
	return Rule{
		ID:             "CHM-SVC-013",
		Title:          "Privileged Linux systemd services constrain namespaces and kernel-management surfaces",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.linux.systemd.namespace_kernel_isolation",
		ExpectedState:  "privileged services use namespace restrictions and/or ProtectKernelTunables/ProtectKernelModules/ProtectControlGroups/PrivateDevices as compatible with their role",
		Risk:           "A privileged service with unrestricted namespace creation and direct access to kernel-management surfaces retains a broad host-control boundary if compromised.",
		Remediation:    "Enable RestrictNamespaces and compatible ProtectKernelTunables, ProtectKernelModules, ProtectControlGroups, or PrivateDevices controls. Keep only the namespace and kernel-management access required by the service.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			all, state := systemdSecurityItems(idx)
			if len(all) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			relevant := filterSystemdItems(all, systemdRelevantService)
			if degraded := filterSystemdItems(relevant, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("namespace/kernel isolation posture", degraded, len(relevant))
			}
			items := filterSystemdItems(all, func(i systemdSecurityEvidenceItem) bool {
				return systemdRelevantService(i) && strings.EqualFold(i.Service.PrivilegeContext, "ROOT")
			})
			if len(items) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled/running privileged systemd service required namespace/kernel isolation evaluation", Applicability: Applicable, EvidenceKeys: existingKeys(idx, "service.inventory.summary", "service.source.linux_systemd_hardening")}
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				s := i.Security
				return s.RestrictNamespacesState == "UNRESTRICTED" && s.PrivateDevices == "NO" && s.ProtectKernelTunables == "NO" && s.ProtectKernelModules == "NO" && s.ProtectControlGroups == "NO"
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d privileged systemd service(s) expose namespaces and kernel-management surfaces without the assessed isolation controls", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				s := i.Security
				return s.RestrictNamespacesState == "UNKNOWN" || s.PrivateDevices == "UNKNOWN" || s.ProtectKernelTunables == "UNKNOWN" || s.ProtectKernelModules == "UNKNOWN" || s.ProtectControlGroups == "UNKNOWN"
			})
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("namespace/kernel isolation posture unresolved for %d of %d privileged systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("namespace or kernel-management isolation present across %d privileged enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdAmbientCapabilitiesRule() Rule {
	return Rule{
		ID:             "CHM-SVC-014",
		Title:          "Linux systemd services avoid unnecessary ambient capabilities",
		Category:       "service",
		Severity:       SeverityHigh,
		AffectedObject: "service.linux.systemd.ambient_capabilities",
		ExpectedState:  "AmbientCapabilities is empty unless a narrowly scoped service requirement is documented",
		Risk:           "Ambient capabilities are inherited across exec boundaries and can preserve elevated kernel authority for service descendants. High-impact capabilities materially expand the service's host-control surface.",
		Remediation:    "Remove AmbientCapabilities entries that are not strictly required. Prefer a narrowly reduced CapabilityBoundingSet and a non-root service identity where possible.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			items, state := systemdSecurityItems(idx)
			items = filterSystemdItems(items, systemdRelevantService)
			if len(items) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			if degraded := filterSystemdItems(items, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("ambient-capability posture", degraded, len(items))
			}
			high := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				return hasHighImpactCapability(i.Security.AmbientCapabilities)
			})
			if len(high) > 0 {
				return Evaluation{Status: StatusFail, Confidence: systemdSecurityConfidence(high), ObservedState: fmt.Sprintf("%d systemd service(s) grant high-impact ambient capabilities", len(high)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(high)}
			}
			any := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool { return len(i.Security.AmbientCapabilities) > 0 })
			if len(any) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(any), ObservedState: fmt.Sprintf("%d systemd service(s) configure ambient capabilities", len(any)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(any)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("no ambient capabilities across %d assessed enabled/running systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdAdditionalHardeningRule() Rule {
	return Rule{
		ID:             "CHM-SVC-015",
		Title:          "Privileged Linux systemd services apply additional execution hardening",
		Category:       "service",
		Severity:       SeverityMedium,
		AffectedObject: "service.linux.systemd.additional_hardening",
		ExpectedState:  "privileged services enable compatible RestrictSUIDSGID, LockPersonality, and MemoryDenyWriteExecute controls",
		Risk:           "Leaving all secondary execution-boundary controls disabled preserves avoidable privilege-transition, personality, and executable-memory surface in privileged services.",
		Remediation:    "Enable RestrictSUIDSGID=yes, LockPersonality=yes, and MemoryDenyWriteExecute=yes where compatible. Document required exceptions such as legitimate JIT execution rather than globally disabling unrelated hardening controls.",
		Evaluate: func(idx Index) Evaluation {
			if ev, ok := systemdRuleApplicability(idx); ok {
				return ev
			}
			all, state := systemdSecurityItems(idx)
			if len(all) == 0 {
				return systemdSecurityUnavailable(idx, state)
			}
			relevant := filterSystemdItems(all, systemdRelevantService)
			if degraded := filterSystemdItems(relevant, systemdHardeningDegraded); len(degraded) > 0 {
				return systemdDegradedEvaluation("additional execution-hardening posture", degraded, len(relevant))
			}
			items := filterSystemdItems(all, func(i systemdSecurityEvidenceItem) bool {
				return systemdRelevantService(i) && strings.EqualFold(i.Service.PrivilegeContext, "ROOT")
			})
			if len(items) == 0 {
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled/running privileged systemd service required additional-hardening evaluation", Applicability: Applicable, EvidenceKeys: existingKeys(idx, "service.inventory.summary", "service.source.linux_systemd_hardening")}
			}
			bad := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				s := i.Security
				return s.RestrictSUIDSGID == "NO" && s.LockPersonality == "NO" && s.MemoryDenyWriteExecute == "NO"
			})
			if len(bad) > 0 {
				return Evaluation{Status: StatusWarn, Confidence: systemdSecurityConfidence(bad), ObservedState: fmt.Sprintf("%d privileged systemd service(s) disable RestrictSUIDSGID, LockPersonality, and MemoryDenyWriteExecute together", len(bad)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(bad)}
			}
			unknown := filterSystemdItems(items, func(i systemdSecurityEvidenceItem) bool {
				s := i.Security
				return s.RestrictSUIDSGID == "UNKNOWN" || s.LockPersonality == "UNKNOWN" || s.MemoryDenyWriteExecute == "UNKNOWN"
			})
			if len(unknown) > 0 {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("additional execution-hardening posture unresolved for %d of %d privileged systemd service(s)", len(unknown), len(items)), Applicability: Applicable, EvidenceKeys: systemdEvidenceKeys(unknown)}
			}
			return Evaluation{Status: StatusPass, Confidence: systemdSecurityConfidence(items), ObservedState: fmt.Sprintf("at least one assessed additional execution-hardening control is enabled for each of %d privileged systemd service(s)", len(items)), Applicability: Applicable, EvidenceKeys: systemdInventoryKeys(idx, items)}
		},
	}
}

func systemdRuleApplicability(idx Index) (Evaluation, bool) {
	platform := ""
	if o, ok := idx["service.platform"]; ok && o.State == evidence.StateObserved {
		platform = strings.ToLower(strings.TrimSpace(fmt.Sprint(o.Value)))
	}
	if platform == "" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service platform evidence unavailable", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	if platform != "linux" {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Linux systemd hardening assessment is not applicable on " + platform, Applicability: NotApplicable, EvidenceKeys: existingKeys(idx, "service.platform")}, true
	}
	return Evaluation{}, false
}

func systemdSecurityItems(idx Index) ([]systemdSecurityEvidenceItem, evidence.State) {
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
	items := make([]systemdSecurityEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.systemd.") || obs.State != evidence.StateObserved {
			continue
		}
		sec, ok := obs.Value.(services.SystemdHardening)
		if !ok {
			continue
		}
		id := strings.TrimPrefix(key, "service.systemd.")
		svc, ok := servicesByID[id]
		if !ok || !strings.EqualFold(svc.Manager, "systemd") {
			continue
		}
		items = append(items, systemdSecurityEvidenceItem{ID: id, Key: key, ItemKey: itemKeys[id], Service: svc, Security: sec, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Service.Name) != strings.ToLower(items[j].Service.Name) {
			return strings.ToLower(items[i].Service.Name) < strings.ToLower(items[j].Service.Name)
		}
		return items[i].ID < items[j].ID
	})
	state := evidence.StateUnavailable
	if o, ok := idx["service.source.linux_systemd_hardening"]; ok {
		state = o.State
	}
	return items, state
}

func systemdRelevantService(i systemdSecurityEvidenceItem) bool {
	state := strings.ToUpper(strings.TrimSpace(i.Service.RuntimeState))
	mode := strings.ToUpper(strings.TrimSpace(i.Service.StartMode))
	return state == "RUNNING" || state == "ACTIVE" || mode == "ENABLED" || mode == "ENABLED_RUNTIME"
}

func systemdSecurityUnavailable(idx Index, state evidence.State) Evaluation {
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Linux systemd hardening metadata unavailable or contained no enabled/running service records (provider state " + string(state) + ")", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "service.inventory.summary", "service.inventory.count", "service.source.linux_systemd_hardening")}
}

func filterSystemdItems(items []systemdSecurityEvidenceItem, predicate func(systemdSecurityEvidenceItem) bool) []systemdSecurityEvidenceItem {
	out := make([]systemdSecurityEvidenceItem, 0)
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func systemdEvidenceKeys(items []systemdSecurityEvidenceItem) []string {
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

func systemdInventoryKeys(idx Index, items []systemdSecurityEvidenceItem) []string {
	keys := existingKeys(idx, "service.inventory.summary", "service.source.linux_systemd_hardening")
	for _, key := range systemdEvidenceKeys(items) {
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

func systemdSecurityConfidence(items []systemdSecurityEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := 4
	for _, item := range items {
		r := confidenceRankAssessment(item.Obs.Confidence)
		if item.Security.State == "DEGRADED" && r > 2 {
			r = 2
		}
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

func systemdHardeningDegraded(i systemdSecurityEvidenceItem) bool {
	return i.Security.State != "COMPLETE"
}

func systemdDegradedEvaluation(subject string, degraded []systemdSecurityEvidenceItem, total int) Evaluation {
	if total < len(degraded) {
		total = len(degraded)
	}
	return Evaluation{
		Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, Applicability: Applicable,
		ObservedState: fmt.Sprintf("%s is not fully resolved for %d of %d relevant systemd service(s) because effective merged properties are unavailable", subject, len(degraded), total),
		EvidenceKeys:  systemdEvidenceKeys(degraded),
	}
}

func hasHighImpactCapability(caps []string) bool {
	for _, cap := range caps {
		switch strings.ToLower(strings.TrimSpace(cap)) {
		case "cap_sys_admin", "cap_sys_module", "cap_sys_ptrace", "cap_sys_rawio", "cap_dac_override", "cap_dac_read_search":
			return true
		}
	}
	return false
}

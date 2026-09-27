package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

type serviceExposureEvidenceItem struct {
	ID       string
	Key      string
	ItemKey  string
	Service  services.Service
	Exposure services.ServiceExposurePosture
	Obs      evidence.Observation
}

// ServiceExposureRules implements . These rules classify local
// service definitions conservatively and reason about their potential remote
// role. They do not assert listener reachability; that is introduced by the
// dedicated network inventory in .
func ServiceExposureRules() []Rule {
	profileRule := profileInconsistentRemoteServiceRule()
	return []Rule{
		{
			ID:             "CHM-SVC-027",
			Title:          "Legacy or insecure remote-capable service classes are disabled",
			Category:       "service",
			Severity:       SeverityHigh,
			AffectedObject: "service.exposure.legacy_insecure",
			ExpectedState:  "legacy, deprecated, or insecure-by-design remote-capable service classes are disabled and inactive",
			Risk:           "Legacy remote services can rely on cleartext authentication, trust-based access, unauthenticated transfer, or obsolete protocol assumptions. An enabled or active instance expands host attack surface even before network reachability is considered.",
			Remediation:    "Disable and remove the legacy service when it is not required. Where a business function remains necessary, migrate to a supported encrypted/authenticated replacement and verify the replacement through the relevant service and network hardening checks.",
			Evaluate: func(idx Index) Evaluation {
				items, usable := serviceExposureItems(idx)
				if len(items) == 0 {
					return serviceExposureEmpty(idx, usable)
				}
				bad := filterServiceExposure(items, func(i serviceExposureEvidenceItem) bool {
					return serviceExposureEnabled(i.Exposure) && i.Exposure.RemoteCapable && (i.Exposure.InsecureByDesign || i.Exposure.Deprecated)
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled/active legacy, deprecated, or insecure-by-design remote-capable service class(es) detected", len(bad)), Applicability: Applicable, EvidenceKeys: serviceExposureEvidenceKeys(bad)}
				}
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 enabled/active legacy, deprecated, or insecure-by-design service classes across %d assessed service record(s)", len(items)), Applicability: Applicable, EvidenceKeys: serviceExposureInventoryKeys(idx, items)}
			},
		},
		{
			ID:             "CHM-SVC-028",
			Title:          "Cleartext-capable legacy file-transfer services are minimized",
			Category:       "service",
			Severity:       SeverityMedium,
			AffectedObject: "service.exposure.legacy_file_transfer",
			ExpectedState:  "legacy cleartext-capable file-transfer services are disabled unless explicitly required and separately protected",
			Risk:           "An FTP-class service can permit cleartext credentials or data depending on configuration. Service identity alone cannot prove that cleartext mode is enabled, so Chimera reports active capability without claiming insecure transport is in use.",
			Remediation:    "Prefer a modern encrypted transfer mechanism. If the service is required, restrict its network exposure and confirm protocol/TLS/authentication settings during the later network and service-specific assessment phases.",
			Evaluate: func(idx Index) Evaluation {
				items, usable := serviceExposureItems(idx)
				if len(items) == 0 {
					return serviceExposureEmpty(idx, usable)
				}
				bad := filterServiceExposure(items, func(i serviceExposureEvidenceItem) bool {
					return serviceExposureEnabled(i.Exposure) && i.Exposure.Family == "FTP" && i.Exposure.CleartextCapable
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled/active FTP-class service(s) can support cleartext transfer; transport configuration and reachability are not yet asserted", len(bad)), Applicability: Applicable, EvidenceKeys: serviceExposureEvidenceKeys(bad)}
				}
				return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled/active FTP-class legacy file-transfer service detected", Applicability: Applicable, EvidenceKeys: serviceExposureInventoryKeys(idx, items)}
			},
		},
		profileRule,
	}
}

func profileInconsistentRemoteServiceRule() Rule {
	evaluate := func(profileName string, idx Index) Evaluation {
		items, usable := serviceExposureItems(idx)
		if len(items) == 0 {
			return serviceExposureEmpty(idx, usable)
		}
		profileName = strings.ToLower(strings.TrimSpace(profileName))
		if profileName == "" {
			profileName = "default"
		}
		active := filterServiceExposure(items, func(i serviceExposureEvidenceItem) bool {
			return serviceExposureEnabled(i.Exposure) && i.Exposure.RemoteCapable && !i.Exposure.InsecureByDesign && !i.Exposure.Deprecated
		})
		mismatch := filterServiceExposure(active, func(i serviceExposureEvidenceItem) bool {
			return remoteRoleUnexpectedForProfile(profileName, i.Exposure.Role)
		})
		if len(mismatch) > 0 {
			return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("profile %s: %d enabled/active remote-capable service(s) belong to roles that normally require explicit justification for this host profile", profileName, len(mismatch)), Applicability: Applicable, EvidenceKeys: serviceExposureEvidenceKeys(mismatch)}
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("profile %s: no enabled/active classified remote service role conflicts with the profile baseline", profileName), Applicability: Applicable, EvidenceKeys: serviceExposureInventoryKeys(idx, active)}
	}
	return Rule{
		ID:              "CHM-SVC-029",
		Title:           "Remote-capable service classes fit the selected assessment profile",
		Category:        "service",
		Severity:        SeverityMedium,
		AffectedObject:  "service.exposure.profile_fit",
		ExpectedState:   "enabled remote-capable service classes are consistent with the selected workstation/server/developer/high-security role",
		Risk:            "A service can be correctly configured yet still be unnecessary for the host's role. Unneeded remote-capable services increase reachable code and administrative surface once bound to non-loopback interfaces.",
		Remediation:     "Confirm that each flagged service supports an explicit host role. Disable services that are not required; for justified services, retain the selected profile and use later listener/firewall rules to verify that exposure is appropriately constrained.",
		Evaluate:        func(idx Index) Evaluation { return evaluate("default", idx) },
		EvaluateProfile: evaluate,
	}
}

func remoteRoleUnexpectedForProfile(profileName, role string) bool {
	role = strings.ToUpper(strings.TrimSpace(role))
	switch profileName {
	case "workstation":
		switch role {
		case "WEB_SERVER", "DATABASE", "CONTAINER_DAEMON", "ADMIN_CONSOLE", "DEVELOPER_INTERFACE", "REMOTE_REGISTRY":
			return true
		}
	case "server":
		switch role {
		case "DEVELOPER_INTERFACE", "REMOTE_DESKTOP":
			return true
		}
	case "high-security":
		return role != "UNKNOWN"
	case "developer", "default":
		return role == "REMOTE_REGISTRY"
	}
	return false
}

func serviceExposureItems(idx Index) ([]serviceExposureEvidenceItem, bool) {
	byID := map[string]services.Service{}
	itemKeys := map[string]string{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.item.") || obs.State != evidence.StateObserved {
			continue
		}
		svc, ok := obs.Value.(services.Service)
		if !ok {
			continue
		}
		byID[svc.ID] = svc
		itemKeys[svc.ID] = key
	}
	items := make([]serviceExposureEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.exposure.") || obs.State != evidence.StateObserved {
			continue
		}
		ep, ok := obs.Value.(services.ServiceExposurePosture)
		if !ok {
			continue
		}
		id := strings.TrimPrefix(key, "service.exposure.")
		svc, ok := byID[id]
		if !ok {
			continue
		}
		items = append(items, serviceExposureEvidenceItem{ID: id, Key: key, ItemKey: itemKeys[id], Service: svc, Exposure: ep, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Service.Name) != strings.ToLower(items[j].Service.Name) {
			return strings.ToLower(items[i].Service.Name) < strings.ToLower(items[j].Service.Name)
		}
		return items[i].ID < items[j].ID
	})
	return items, serviceProviderUsable(idx)
}

func serviceProviderUsable(idx Index) bool {
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.source.") {
			continue
		}
		if strings.Contains(key, "service_path_integrity") || strings.Contains(key, "hardening") || strings.Contains(key, "security") {
			continue
		}
		if obs.State == evidence.StateObserved {
			return true
		}
	}
	if obs, ok := idx["service.inventory.count"]; ok && obs.State == evidence.StateObserved {
		if n, ok := obs.Value.(int); ok && n > 0 {
			return true
		}
	}
	return false
}

func serviceExposureEmpty(idx Index, providerUsable bool) Evaluation {
	keys := existingKeys(idx, "service.inventory.count", "service.inventory.summary", "service.inventory.provider")
	if providerUsable {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "service provider returned no classified remote-capable service records", Applicability: Applicable, EvidenceKeys: keys}
	}
	for key := range idx {
		if strings.HasPrefix(key, "service.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service inventory provider unavailable or yielded no usable service records; remote service class posture cannot be determined", Applicability: Undetermined, EvidenceKeys: uniqueStrings(keys)}
}

func filterServiceExposure(items []serviceExposureEvidenceItem, predicate func(serviceExposureEvidenceItem) bool) []serviceExposureEvidenceItem {
	out := make([]serviceExposureEvidenceItem, 0)
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func serviceExposureEnabled(p services.ServiceExposurePosture) bool {
	return p.Activity == "ACTIVE" || p.Activity == "ENABLED_INACTIVE"
}

func serviceExposureEvidenceKeys(items []serviceExposureEvidenceItem) []string {
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

func serviceExposureInventoryKeys(idx Index, items []serviceExposureEvidenceItem) []string {
	keys := existingKeys(idx, "service.inventory.summary", "service.inventory.count")
	for _, key := range serviceExposureEvidenceKeys(items) {
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

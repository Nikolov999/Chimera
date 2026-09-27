package assessment

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

type networkExposureEvidenceItem struct {
	EndpointKey string
	Endpoint    netinv.Endpoint
	ServiceKey  string
	ExposureKey string
	Service     *services.Service
	Exposure    *services.ServiceExposurePosture
}

// NetworkRules implements external-bind exposure assessment plus
// sensitive-service exposure assessment, legacy /
// cleartext-capable protocol exposure assessment, remote-management
// configuration/exposure posture assessment, SSH hardening, and SMB/file-sharing security assessment. These rules only consume
// normalized local listener/service evidence; they never connect to, probe, or
// otherwise interact with the observed endpoints.
func NetworkRules() []Rule {
	rules := []Rule{
		externalBindRule(
			"CHM-NET-001",
			"Wildcard-bound services fit the selected host profile",
			SeverityMedium,
			"network.exposure.wildcard",
			"services bind to all interfaces only when their role is appropriate for the selected host profile",
			"A wildcard bind can make a service reachable through every matching local interface, including interfaces added or reconfigured later. Unexpected wildcard exposure increases attack surface even when the service itself is legitimate.",
			"Bind the service to loopback or the minimum required interface/address, or document the service role in the host profile and constrain reachability with later firewall controls.",
			bindingWildcard,
		),
		externalBindRule(
			"CHM-NET-002",
			"Public-interface service bindings fit the selected host profile",
			SeverityMedium,
			"network.exposure.public",
			"services use explicitly public/global addresses only when their role is appropriate for the selected host profile",
			"A service explicitly bound to a public/global address can be reachable beyond the local host when upstream routing and firewall policy permit it. Unexpected public-interface exposure materially increases the reachable attack surface.",
			"Bind the service to loopback or a required private/interface-specific address when public reachability is unnecessary, and verify later firewall policy for any intentionally public service.",
			bindingPublic,
		),
		externalBindRule(
			"CHM-NET-003",
			"Non-loopback service bindings fit the selected host profile",
			SeverityLow,
			"network.exposure.non_loopback",
			"services bind to specific non-loopback interfaces only when their role is appropriate for the selected host profile",
			"A service bound beyond loopback is reachable from at least one host interface when routing and local policy allow it. An unexpected role-to-interface combination can expose development, administration, database, or infrastructure services to peers on the attached network.",
			"Restrict the service to loopback or the minimum required interface/address unless remote access is part of the selected host role, then verify the corresponding firewall restrictions.",
			bindingNonLoopback,
		),
	}
	rules = append(rules, SensitiveServiceExposureRules()...)
	rules = append(rules, LegacyProtocolExposureRules()...)
	rules = append(rules, RemoteManagementRules()...)
	rules = append(rules, SSHSecurityRules()...)
	rules = append(rules, SMBSecurityRules()...)
	return rules
}

type bindingKind int

const (
	bindingWildcard bindingKind = iota
	bindingPublic
	bindingNonLoopback
)

func externalBindRule(id, title string, severity Severity, affectedObject, expected, risk, remediation string, kind bindingKind) Rule {
	evaluate := func(profileName string, idx Index) Evaluation {
		items, providerUsable := networkExposureItems(idx)
		candidates := filterNetworkBinding(items, kind)
		if len(candidates) == 0 {
			if len(items) == 0 && !providerUsable {
				return networkExposureUnavailable(idx)
			}
			return Evaluation{
				Status: StatusPass, Confidence: evidence.ConfidenceHigh,
				ObservedState: fmt.Sprintf("profile %s: no %s endpoint bindings require assessment", normalizeProfileName(profileName), bindingKindName(kind)),
				Applicability: Applicable, EvidenceKeys: networkInventoryEvidenceKeys(idx),
			}
		}

		profileName = normalizeProfileName(profileName)
		unexpected := make([]networkExposureEvidenceItem, 0)
		unresolved := make([]networkExposureEvidenceItem, 0)
		for _, item := range candidates {
			role, remoteCapable, classified := networkServiceRole(item)
			if profileName == "high-security" {
				// High-security treats any externally bound listener as requiring
				// explicit justification; service-role evidence still enriches
				// the finding where it is available.
				unexpected = append(unexpected, item)
				continue
			}
			if !classified {
				unresolved = append(unresolved, item)
				continue
			}
			if !remoteCapable {
				// A live listening/bound endpoint proves network capability, but
				// an explicitly non-remote service classification is retained as
				// authoritative for role policy rather than overridden here.
				continue
			}
			if networkRoleUnexpected(profileName, kind, role) {
				unexpected = append(unexpected, item)
			}
		}

		if len(unexpected) > 0 {
			return Evaluation{
				Status: StatusWarn, Confidence: networkExposureConfidence(unexpected),
				ObservedState: fmt.Sprintf("profile %s: %d %s endpoint(s) are associated with service roles that require explicit exposure justification", profileName, len(unexpected), bindingKindName(kind)),
				Applicability: Applicable, EvidenceKeys: networkExposureEvidenceKeys(unexpected),
			}
		}
		if len(unresolved) > 0 {
			return Evaluation{
				Status: StatusUnknown, Confidence: evidence.ConfidenceLow,
				ObservedState: fmt.Sprintf("profile %s: %d %s endpoint(s) could not be mapped to a classified service role, so exposure intent cannot be determined defensibly", profileName, len(unresolved), bindingKindName(kind)),
				Applicability: Applicable, EvidenceKeys: networkExposureEvidenceKeys(unresolved),
			}
		}
		return Evaluation{
			Status: StatusPass, Confidence: evidence.ConfidenceHigh,
			ObservedState: fmt.Sprintf("profile %s: observed %s endpoint bindings are consistent with classified service roles", profileName, bindingKindName(kind)),
			Applicability: Applicable, EvidenceKeys: networkExposureEvidenceKeys(candidates),
		}
	}

	return Rule{
		ID: id, Title: title, Category: "network", Severity: severity,
		AffectedObject: affectedObject, ExpectedState: expected, Risk: risk, Remediation: remediation,
		Evaluate:        func(idx Index) Evaluation { return evaluate("default", idx) },
		EvaluateProfile: evaluate,
	}
}

func networkExposureItems(idx Index) ([]networkExposureEvidenceItem, bool) {
	servicesByID := map[string]services.Service{}
	serviceItemKeys := map[string]string{}
	exposureByID := map[string]services.ServiceExposurePosture{}
	exposureKeys := map[string]string{}

	for key, obs := range idx {
		if strings.HasPrefix(key, "service.item.") && obs.State == evidence.StateObserved {
			if svc, ok := obs.Value.(services.Service); ok {
				servicesByID[svc.ID] = svc
				serviceItemKeys[svc.ID] = key
			}
		}
		if strings.HasPrefix(key, "service.exposure.") && obs.State == evidence.StateObserved {
			if p, ok := obs.Value.(services.ServiceExposurePosture); ok {
				id := strings.TrimPrefix(key, "service.exposure.")
				exposureByID[id] = p
				exposureKeys[id] = key
			}
		}
	}

	nameToID := map[string]string{}
	pidToID := map[int]string{}
	for id, svc := range servicesByID {
		for _, name := range []string{svc.Name, svc.DisplayName} {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				if _, exists := nameToID[name]; !exists {
					nameToID[name] = id
				}
			}
		}
		if svc.RuntimePID > 0 {
			if _, exists := pidToID[svc.RuntimePID]; !exists {
				pidToID[svc.RuntimePID] = id
			}
		}
	}

	items := make([]networkExposureEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "network.endpoint.") || obs.State != evidence.StateObserved {
			continue
		}
		ep, ok := obs.Value.(netinv.Endpoint)
		if !ok {
			continue
		}
		item := networkExposureEvidenceItem{EndpointKey: key, Endpoint: ep}
		serviceID := ""
		if name := strings.ToLower(strings.TrimSpace(ep.Owner.ServiceName)); name != "" {
			serviceID = nameToID[name]
		}
		if serviceID == "" && ep.Owner.PID > 0 {
			serviceID = pidToID[ep.Owner.PID]
		}
		if serviceID != "" {
			if svc, ok := servicesByID[serviceID]; ok {
				svcCopy := svc
				item.Service = &svcCopy
				item.ServiceKey = serviceItemKeys[serviceID]
			}
			if p, ok := exposureByID[serviceID]; ok {
				pCopy := p
				item.Exposure = &pCopy
				item.ExposureKey = exposureKeys[serviceID]
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i].Endpoint, items[j].Endpoint
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.AddressFamily != b.AddressFamily {
			return a.AddressFamily < b.AddressFamily
		}
		if a.LocalAddress != b.LocalAddress {
			return a.LocalAddress < b.LocalAddress
		}
		if a.LocalPort != b.LocalPort {
			return a.LocalPort < b.LocalPort
		}
		return a.ID < b.ID
	})
	return items, networkProviderUsable(idx)
}

func networkProviderUsable(idx Index) bool {
	for key, obs := range idx {
		if strings.HasPrefix(key, "network.source.") && obs.State == evidence.StateObserved {
			return true
		}
	}
	if obs, ok := idx["network.inventory.count"]; ok && obs.State == evidence.StateObserved {
		if n, ok := obs.Value.(int); ok && n > 0 {
			return true
		}
	}
	return false
}

func filterNetworkBinding(items []networkExposureEvidenceItem, kind bindingKind) []networkExposureEvidenceItem {
	out := make([]networkExposureEvidenceItem, 0)
	for _, item := range items {
		ep := item.Endpoint
		match := false
		switch kind {
		case bindingWildcard:
			match = ep.InterfaceBinding.IsWildcard || ep.InterfaceBinding.Class == "ALL_INTERFACES"
		case bindingPublic:
			match = !ep.InterfaceBinding.IsWildcard && isPublicBoundAddress(ep.LocalAddress)
		case bindingNonLoopback:
			// Keep this rule distinct from wildcard and explicit public-address
			// rules so one endpoint does not create redundant warnings.
			match = !ep.InterfaceBinding.IsWildcard && !isPublicBoundAddress(ep.LocalAddress) && ep.InterfaceBinding.Class == "NON_LOOPBACK"
		}
		if match {
			out = append(out, item)
		}
	}
	return out
}

func isPublicBoundAddress(address string) bool {
	host := strings.TrimSpace(strings.Trim(address, "[]"))
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func networkServiceRole(item networkExposureEvidenceItem) (role string, remoteCapable bool, classified bool) {
	if item.Exposure == nil {
		return "UNKNOWN", false, false
	}
	p := item.Exposure
	if !strings.EqualFold(p.State, "CLASSIFIED") || strings.TrimSpace(p.Role) == "" || strings.EqualFold(p.Role, "UNKNOWN") {
		return "UNKNOWN", p.RemoteCapable, false
	}
	return strings.ToUpper(strings.TrimSpace(p.Role)), p.RemoteCapable, true
}

func networkRoleUnexpected(profileName string, kind bindingKind, role string) bool {
	role = strings.ToUpper(strings.TrimSpace(role))
	switch profileName {
	case "workstation":
		if kind == bindingWildcard || kind == bindingPublic {
			return true // any classified remote-capable service needs explicit external exposure justification on a workstation
		}
		return roleIn(role, "WEB_SERVER", "DATABASE", "CONTAINER_DAEMON", "ADMIN_CONSOLE", "DEVELOPER_INTERFACE", "REMOTE_REGISTRY", "LEGACY_INFORMATION", "LEGACY_IDENTITY", "LEGACY_DIAGNOSTIC")
	case "server":
		if kind == bindingWildcard || kind == bindingPublic {
			return roleIn(role, "DEVELOPER_INTERFACE", "REMOTE_REGISTRY", "ADMIN_CONSOLE", "DATABASE", "CONTAINER_DAEMON")
		}
		return roleIn(role, "DEVELOPER_INTERFACE", "REMOTE_REGISTRY")
	case "developer":
		if kind == bindingWildcard || kind == bindingPublic {
			return roleIn(role, "DEVELOPER_INTERFACE", "DATABASE", "CONTAINER_DAEMON", "ADMIN_CONSOLE", "REMOTE_REGISTRY")
		}
		return roleIn(role, "DEVELOPER_INTERFACE", "ADMIN_CONSOLE", "REMOTE_REGISTRY")
	case "default":
		if kind == bindingWildcard || kind == bindingPublic {
			return roleIn(role, "DEVELOPER_INTERFACE", "DATABASE", "CONTAINER_DAEMON", "ADMIN_CONSOLE", "REMOTE_REGISTRY", "LEGACY_INFORMATION", "LEGACY_IDENTITY", "LEGACY_DIAGNOSTIC")
		}
		return roleIn(role, "DEVELOPER_INTERFACE", "ADMIN_CONSOLE", "REMOTE_REGISTRY")
	default:
		return false
	}
}

func roleIn(role string, roles ...string) bool {
	for _, candidate := range roles {
		if role == candidate {
			return true
		}
	}
	return false
}

func normalizeProfileName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "default"
	}
	return name
}

func bindingKindName(kind bindingKind) string {
	switch kind {
	case bindingWildcard:
		return "wildcard/all-interface"
	case bindingPublic:
		return "public/global-address"
	default:
		return "specific non-loopback"
	}
}

func networkExposureConfidence(items []networkExposureEvidenceItem) evidence.Confidence {
	confidence := evidence.ConfidenceExact
	for _, item := range items {
		if item.Exposure == nil || item.Endpoint.Confidence == evidence.ConfidenceLow || item.Endpoint.Owner.State == "UNAVAILABLE" {
			return evidence.ConfidenceLow
		}
		if item.Endpoint.Confidence == evidence.ConfidenceMedium || item.Exposure.State != "CLASSIFIED" {
			confidence = evidence.ConfidenceMedium
		} else if confidence == evidence.ConfidenceExact {
			confidence = evidence.ConfidenceHigh
		}
	}
	if confidence == evidence.ConfidenceExact {
		return evidence.ConfidenceHigh
	}
	return confidence
}

func networkExposureEvidenceKeys(items []networkExposureEvidenceItem) []string {
	keys := make([]string, 0, len(items)*3)
	for _, item := range items {
		keys = append(keys, item.EndpointKey)
		if item.ServiceKey != "" {
			keys = append(keys, item.ServiceKey)
		}
		if item.ExposureKey != "" {
			keys = append(keys, item.ExposureKey)
		}
	}
	sort.Strings(keys)
	return uniqueStrings(keys)
}

func networkInventoryEvidenceKeys(idx Index) []string {
	keys := existingKeys(idx, "network.inventory.count", "network.inventory.summary")
	for key := range idx {
		if strings.HasPrefix(key, "network.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return uniqueStrings(keys)
}

func networkExposureUnavailable(idx Index) Evaluation {
	keys := networkInventoryEvidenceKeys(idx)
	return Evaluation{
		Status: StatusUnknown, Confidence: evidence.ConfidenceLow,
		ObservedState: "network listener providers are unavailable or produced no usable normalized endpoint evidence; external-bind exposure cannot be determined",
		Applicability: Undetermined, EvidenceKeys: keys,
	}
}

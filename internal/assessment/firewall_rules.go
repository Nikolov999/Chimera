package assessment

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	fwinv "github.com/Nikolov999/chimera/internal/firewall"
)

type firewallProviderEvidence struct {
	Key      string
	Provider fwinv.ProviderStatus
}

type firewallPolicyEvidence struct {
	Key    string
	Policy fwinv.Policy
}

// FirewallRules implements firewall posture, listener-to-firewall correlation,
// and broad-exception analysis. The rules consume only normalized local network/firewall
// evidence. They do not test reachability, inject packets, or mutate firewall state.
func FirewallRules() []Rule {
	return []Rule{
		{
			ID: "CHM-FW-001", Title: "Effective host firewall protection is enabled", Category: "firewall", Severity: SeverityHigh,
			AffectedObject: "firewall.enabled", ExpectedState: "at least one applicable local host-firewall provider is enabled without a partially disabled required profile",
			Risk:        "A host with no enabled local firewall layer can expose listening services according to interface and upstream network reachability alone. A partially disabled profile can leave one network category materially less protected than the others.",
			Remediation: "Enable the platform host firewall for the required network profiles/scopes. If multiple firewall frameworks are installed, keep one intentional effective policy path and verify that its active profiles cover the host's attached networks.",
			Evaluate:    evaluateFirewallEnabled,
		},
		{
			ID: "CHM-FW-002", Title: "Enabled firewall scopes use a restrictive inbound default", Category: "firewall", Severity: SeverityHigh,
			AffectedObject: "firewall.default_inbound", ExpectedState: "enabled firewall scopes default inbound traffic to BLOCK, DENY, DROP, or REJECT where the provider exposes default-policy semantics",
			Risk:        "An allow-by-default inbound policy makes newly listening or incompletely covered services reachable unless an explicit deny rule happens to constrain them. This weakens the firewall from a default-deny boundary into an exception-dependent control.",
			Remediation: "Set applicable inbound/default policies to block or deny by default and create narrowly scoped allow rules only for required services and source networks. Preserve provider-specific semantics and validate policy before deployment.",
			Evaluate:    evaluateFirewallDefaultInbound,
		},
		{
			ID: "CHM-FW-003", Title: "Firewall does not expose a proven allow-all inbound posture", Category: "firewall", Severity: SeverityCritical,
			AffectedObject: "firewall.allow_all_inbound", ExpectedState: "no enabled firewall scope combines an allow/accept inbound default with zero observable active rules",
			Risk:        "An enabled firewall scope whose inbound default is allow/accept and whose observable rule set is empty provides no effective inbound filtering for that scope.",
			Remediation: "Replace the allow/accept inbound default with a deny-by-default policy and add only the minimum required inbound exceptions. Re-run Chimera after the native firewall reports the intended active rule set.",
			Evaluate:    evaluateFirewallAllowAll,
		},
		{
			ID: "CHM-FW-004", Title: "Security-relevant listeners have defensible local firewall restrictions", Category: "firewall", Severity: SeverityHigh,
			AffectedObject: "firewall.listener_coverage", ExpectedState: "every non-loopback TCP/UDP listener has PRESENT local firewall restriction coverage, or explicit AMBIGUOUS/UNAVAILABLE evidence rather than an invented protection claim",
			Risk:        "A service bound beyond loopback without a defensible local firewall restriction can be reachable from attached networks according to routing and upstream controls. Ambiguous coverage also weakens confidence in exposure prioritization.",
			Remediation: "Constrain the listener to the required interface, or add a narrowly scoped inbound firewall rule for the required protocol, port, source range, application, or service. Resolve provider-permission gaps and rerun Chimera until coverage is explicit.",
			Evaluate:    evaluateFirewallListenerCoverage,
		},
		{
			ID: "CHM-FW-005", Title: "Inbound allow exceptions constrain remote source scope", Category: "firewall", Severity: SeverityHigh,
			AffectedObject: "firewall.exception.remote_scope", ExpectedState: "inbound allow/accept exceptions use explicit, appropriately bounded remote-source selectors instead of ANY or Internet-scale source ranges",
			Risk:        "An inbound allow exception that accepts traffic from any source, or from an extremely broad network, can make the covered service reachable from substantially more systems than intended.",
			Remediation: "Replace broad inbound source selectors with the smallest required trusted subnet, host set, VPN range, or management network. Preserve required availability while avoiding Internet-wide or near-Internet-wide source ranges.",
			Evaluate:    evaluateFirewallBroadRemoteSources,
		},
		{
			ID: "CHM-FW-006", Title: "Inbound allow exceptions constrain interface and local-address scope", Category: "firewall", Severity: SeverityMedium,
			AffectedObject: "firewall.exception.interface_scope", ExpectedState: "inbound allow/accept exceptions are bound to required local addresses/interfaces when the provider can express that scope",
			Risk:        "An inbound exception with no local-address or interface constraint can apply across every matching host interface, including newly attached or less-trusted networks.",
			Remediation: "Bind the exception to the required local address, interface, firewall profile, or zone when operationally appropriate. Keep intentionally global rules documented and narrowly constrained by source, application/service, and port.",
			Evaluate:    evaluateFirewallAnyInterfaceExceptions,
		},
		{
			ID: "CHM-FW-007", Title: "Remote-management firewall exceptions are narrowly scoped", Category: "firewall", Severity: SeverityCritical,
			AffectedObject: "firewall.exception.management", ExpectedState: "remote-management/admin-service allow rules are limited to trusted source networks and do not expose management ports broadly",
			Risk:        "Broad firewall exceptions for SSH, RDP, WinRM, SMB administration, VNC, container APIs, or orchestration management endpoints materially expand the attack surface of privileged control channels.",
			Remediation: "Restrict remote-management exceptions to dedicated management/VPN networks or specific administration hosts. Disable unneeded management listeners and require the service's own strong authentication and transport protections.",
			Evaluate:    evaluateFirewallBroadManagementExceptions,
		},
		{
			ID: "CHM-FW-008", Title: "Enabled firewall scopes do not contain conflicting permissive inbound policy", Category: "firewall", Severity: SeverityHigh,
			AffectedObject: "firewall.policy.conflict", ExpectedState: "enabled firewall scopes do not mix permissive and restrictive inbound default policy",
			Risk:        "Conflicting enabled scopes or providers can create a false sense of protection when one policy is restrictive but another applicable policy still allows inbound traffic broadly.",
			Remediation: "Reconcile enabled firewall profiles/providers so inbound defaults are consistently restrictive for the host's active network roles. Remove duplicate or superseded permissive policy paths and validate the effective provider configuration.",
			Evaluate:    evaluateFirewallPermissivePolicyConflicts,
		},
	}
}

func firewallEvidence(idx Index) (providers []firewallProviderEvidence, policies []firewallPolicyEvidence, providerKeys []string, providerStates []evidence.State) {
	for key, obs := range idx {
		if strings.HasPrefix(key, "firewall.provider.") {
			// firewall.provider.available is the collector-level degradation
			// observation, not a concrete provider record.
			if key != "firewall.provider.available" {
				providerKeys = append(providerKeys, key)
				providerStates = append(providerStates, obs.State)
			}
			if obs.State == evidence.StateObserved {
				if p, ok := obs.Value.(fwinv.ProviderStatus); ok {
					providers = append(providers, firewallProviderEvidence{Key: key, Provider: p})
				}
			}
		}
		if strings.HasPrefix(key, "firewall.policy.") && obs.State == evidence.StateObserved {
			if p, ok := obs.Value.(fwinv.Policy); ok {
				policies = append(policies, firewallPolicyEvidence{Key: key, Policy: p})
			}
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Key < providers[j].Key })
	sort.Slice(policies, func(i, j int) bool { return policies[i].Key < policies[j].Key })
	sort.Strings(providerKeys)
	return providers, policies, providerKeys, providerStates
}

func evaluateFirewallEnabled(idx Index) Evaluation {
	providers, _, providerKeys, states := firewallEvidence(idx)
	enabled, mixed, disabled, unknown := 0, 0, 0, 0
	keys := make([]string, 0, len(providers))
	for _, item := range providers {
		keys = append(keys, item.Key)
		switch strings.ToUpper(strings.TrimSpace(item.Provider.Enabled)) {
		case "ENABLED":
			enabled++
		case "MIXED":
			mixed++
		case "DISABLED":
			disabled++
		default:
			unknown++
		}
	}
	if mixed > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed firewall provider(s) report MIXED enabled state; one or more profiles/scopes are disabled", mixed), Applicability: Applicable, EvidenceKeys: keys}
	}
	if enabled > 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d applicable local firewall provider(s) are enabled", enabled), Applicability: Applicable, EvidenceKeys: keys}
	}
	if disabled > 0 && unknown == 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed local firewall provider(s) are disabled and no enabled provider was observed", disabled), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(providers) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "local firewall providers were observed but no provider could be confirmed enabled", Applicability: Applicable, EvidenceKeys: keys}
	}

	if len(providerKeys) == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "firewall provider evidence is missing", Applicability: Undetermined, EvidenceKeys: []string{"firewall.provider.available"}}
	}
	allNA := true
	allUnsupported := true
	for _, s := range states {
		if s != evidence.StateNotApplicable {
			allNA = false
		}
		if s != evidence.StateUnsupported {
			allUnsupported = false
		}
	}
	if allUnsupported {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "platform firewall inventory is unsupported by this build", Applicability: NotApplicable, EvidenceKeys: providerKeys}
	}
	if allNA {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "no supported local firewall provider could be enumerated; absence of provider tooling does not prove that kernel or platform filtering is inactive", Applicability: Applicable, EvidenceKeys: providerKeys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "local firewall provider state is permission-restricted or unavailable", Applicability: Applicable, EvidenceKeys: providerKeys}
}

func evaluateFirewallDefaultInbound(idx Index) Evaluation {
	providers, policies, providerKeys, _ := firewallEvidence(idx)
	if firewallDefinitelyDisabled(providers) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "default inbound policy is not applicable because no observed firewall provider is enabled", Applicability: NotApplicable, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
	}

	enabledPolicies := enabledFirewallPolicies(policies)
	permissive := make([]string, 0)
	restrictive := make([]string, 0)
	unknown := make([]string, 0)
	for _, item := range enabledPolicies {
		switch inboundClass(item.Policy.DefaultInbound) {
		case "PERMISSIVE":
			permissive = append(permissive, item.Key)
		case "RESTRICTIVE":
			restrictive = append(restrictive, item.Key)
		default:
			unknown = append(unknown, item.Key)
		}
	}
	if len(permissive) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) default inbound traffic to ALLOW/ACCEPT", len(permissive)), Applicability: Applicable, EvidenceKeys: permissive}
	}
	if len(unknown) > 0 {
		keys := append(append([]string(nil), restrictive...), unknown...)
		sort.Strings(keys)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) do not expose a defensible default inbound action", len(unknown)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(restrictive) > 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) use a restrictive default inbound action", len(restrictive)), Applicability: Applicable, EvidenceKeys: restrictive}
	}
	if firewallHasEnabledProvider(providers) {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "an enabled firewall provider is present but no enabled scope exposes default inbound policy semantics", Applicability: Applicable, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "default inbound policy could not be assessed from available firewall evidence", Applicability: Undetermined, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
}

func evaluateFirewallAllowAll(idx Index) Evaluation {
	providers, policies, providerKeys, _ := firewallEvidence(idx)
	if firewallDefinitelyDisabled(providers) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "allow-all filtering posture is not applicable because no observed firewall provider is enabled", Applicability: NotApplicable, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
	}

	enabledPolicies := enabledFirewallPolicies(policies)
	proven := make([]string, 0)
	knownSafe := make([]string, 0)
	unresolved := make([]string, 0)
	for _, item := range enabledPolicies {
		cls := inboundClass(item.Policy.DefaultInbound)
		if cls == "PERMISSIVE" && item.Policy.RuleCountKnown && item.Policy.RuleCount == 0 {
			proven = append(proven, item.Key)
			continue
		}
		if cls == "RESTRICTIVE" {
			knownSafe = append(knownSafe, item.Key)
			continue
		}
		if cls == "PERMISSIVE" {
			// The permissive default is a CHM-FW-002 failure, but
			// non-zero/unknown rules mean we cannot additionally claim that
			// every inbound packet is allowed.
			if item.Policy.RuleCountKnown && item.Policy.RuleCount > 0 {
				knownSafe = append(knownSafe, item.Key)
			} else {
				unresolved = append(unresolved, item.Key)
			}
			continue
		}
		unresolved = append(unresolved, item.Key)
	}
	if len(proven) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) have ALLOW/ACCEPT inbound default with zero observable active rules", len(proven)), Applicability: Applicable, EvidenceKeys: proven}
	}
	if len(unresolved) > 0 {
		keys := append(append([]string(nil), knownSafe...), unresolved...)
		sort.Strings(keys)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) lack enough default-policy/rule-count evidence to exclude an allow-all posture", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(knownSafe) > 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled firewall scope has a proven rule-less ALLOW/ACCEPT inbound posture", Applicability: Applicable, EvidenceKeys: knownSafe}
	}
	if firewallHasEnabledProvider(providers) {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "enabled firewall provider observed but rule/default-policy detail is unavailable", Applicability: Applicable, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "allow-all inbound posture could not be assessed from available firewall evidence", Applicability: Undetermined, EvidenceKeys: providerEvidenceKeys(providers, providerKeys)}
}

func evaluateFirewallListenerCoverage(idx Index) Evaluation {
	keys := []string{}
	present, absent, ambiguous, unavailable := 0, 0, 0, 0
	conf := evidence.ConfidenceExact
	for key, obs := range idx {
		if !strings.HasPrefix(key, "firewall.listener_coverage.") || obs.State != evidence.StateObserved {
			continue
		}
		c, ok := obs.Value.(fwinv.ListenerCoverage)
		if !ok {
			continue
		}
		keys = append(keys, key)
		conf = lowerFindingConfidence(conf, c.Confidence)
		switch c.State {
		case fwinv.CoveragePresent:
			present++
		case fwinv.CoverageAbsent:
			absent++
		case fwinv.CoverageAmbiguous:
			ambiguous++
		case fwinv.CoverageUnavailable:
			unavailable++
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		networkKeys := []string{"network.inventory.count"}
		networkUnavailable := false
		for key, obs := range idx {
			if strings.HasPrefix(key, "network.source.") {
				networkKeys = append(networkKeys, key)
				if obs.State != evidence.StateObserved && obs.State != evidence.StateNotApplicable {
					networkUnavailable = true
				}
			}
		}
		sort.Strings(networkKeys)
		if networkUnavailable {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "listener inventory is degraded or unavailable, so absence of firewall-correlation records is not a clean result", Applicability: Applicable, EvidenceKeys: networkKeys}
		}
		// A successfully collected loopback-only/no-listener host has no security-relevant listener.
		if _, ok := idx["network.inventory.count"]; ok {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no non-loopback TCP/UDP listeners require firewall correlation", Applicability: NotApplicable, EvidenceKeys: networkKeys}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "listener-to-firewall correlation evidence is missing", Applicability: Undetermined, EvidenceKeys: []string{"firewall.listener_coverage"}}
	}
	if absent > 0 {
		return Evaluation{Status: StatusFail, Confidence: conf, ObservedState: fmt.Sprintf("%d listener(s) have no defensible local firewall restriction; present=%d ambiguous=%d unavailable=%d", absent, present, ambiguous, unavailable), Applicability: Applicable, EvidenceKeys: keys}
	}
	if ambiguous > 0 {
		return Evaluation{Status: StatusWarn, Confidence: conf, ObservedState: fmt.Sprintf("%d listener(s) have ambiguous local firewall coverage; present=%d unavailable=%d", ambiguous, present, unavailable), Applicability: Applicable, EvidenceKeys: keys}
	}
	if unavailable > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: conf, ObservedState: fmt.Sprintf("%d listener(s) cannot be correlated because firewall evidence is unavailable; present=%d", unavailable, present), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: fmt.Sprintf("%d security-relevant listener(s) have defensible local firewall restriction coverage", present), Applicability: Applicable, EvidenceKeys: keys}
}

type firewallRestrictionEvidence struct {
	Key  string
	Rule fwinv.RestrictionRule
}

func firewallRestrictions(idx Index) (rules []firewallRestrictionEvidence, providerUnavailable bool) {
	for key, obs := range idx {
		if strings.HasPrefix(key, "firewall.provider.") && key != "firewall.provider.available" {
			switch obs.State {
			case evidence.StateDenied, evidence.StateUnavailable, evidence.StateDegraded, evidence.StateUnsupported:
				providerUnavailable = true
			}
		}
		if !strings.HasPrefix(key, "firewall.restriction.") || obs.State != evidence.StateObserved {
			continue
		}
		r, ok := obs.Value.(fwinv.RestrictionRule)
		if !ok {
			continue
		}
		rules = append(rules, firewallRestrictionEvidence{Key: key, Rule: r})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Key < rules[j].Key })
	return rules, providerUnavailable
}

func enabledInboundAllows(in []firewallRestrictionEvidence) []firewallRestrictionEvidence {
	out := make([]firewallRestrictionEvidence, 0, len(in))
	for _, item := range in {
		r := item.Rule
		if !strings.EqualFold(r.Enabled, "ENABLED") || !strings.EqualFold(r.Direction, "INBOUND") {
			continue
		}
		if inboundClass(r.Action) != "PERMISSIVE" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func evaluateFirewallBroadRemoteSources(idx Index) Evaluation {
	rules, providerUnavailable := firewallRestrictions(idx)
	allows := enabledInboundAllows(rules)
	if len(allows) == 0 {
		if providerUnavailable {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "inbound exception evidence is unavailable from one or more firewall providers", Applicability: Applicable, EvidenceKeys: firewallProviderEvidenceKeys(idx)}
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled inbound allow/accept exception rules were observed", Applicability: NotApplicable, EvidenceKeys: firewallRestrictionKeys(rules)}
	}

	broad, moderate, unknown := []string{}, []string{}, []string{}
	for _, item := range allows {
		class := remoteScopeClass(item.Rule.RemoteAddresses)
		switch class {
		case "BROAD":
			broad = append(broad, item.Key)
		case "MODERATE":
			moderate = append(moderate, item.Key)
		case "UNKNOWN":
			unknown = append(unknown, item.Key)
		}
	}
	if len(broad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d inbound allow exception(s) accept ANY or Internet-scale remote source ranges", len(broad)), Applicability: Applicable, EvidenceKeys: broad}
	}
	if len(moderate) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%d inbound allow exception(s) use unusually broad remote network ranges", len(moderate)), Applicability: Applicable, EvidenceKeys: moderate}
	}
	if len(unknown) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d inbound allow exception(s) do not expose an explicit remote-source selector; provider semantics may therefore be broad", len(unknown)), Applicability: Applicable, EvidenceKeys: unknown}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d inbound allow exception(s) use bounded remote-source selectors", len(allows)), Applicability: Applicable, EvidenceKeys: firewallRestrictionKeys(allows)}
}

func evaluateFirewallAnyInterfaceExceptions(idx Index) Evaluation {
	rules, providerUnavailable := firewallRestrictions(idx)
	allows := enabledInboundAllows(rules)
	if len(allows) == 0 {
		if providerUnavailable {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "inbound exception evidence is unavailable from one or more firewall providers", Applicability: Applicable, EvidenceKeys: firewallProviderEvidenceKeys(idx)}
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled inbound allow/accept exception rules were observed", Applicability: NotApplicable, EvidenceKeys: firewallRestrictionKeys(rules)}
	}

	broad := []string{}
	contextuallyBounded := []string{}
	for _, item := range allows {
		r := item.Rule
		localBroad := selectorListIsAnyOrEmpty(r.LocalAddresses)
		interfaceBroad := selectorListIsAnyOrEmpty(r.Interfaces)
		if localBroad && interfaceBroad {
			// A globally bound rule can still be substantially constrained by a
			// specific application/service and a bounded source range. Treat that
			// as a warning-quality boundary rather than an automatic failure.
			if remoteScopeClass(r.RemoteAddresses) == "NARROW" && (strings.TrimSpace(r.Application) != "" || strings.TrimSpace(r.Service) != "") {
				contextuallyBounded = append(contextuallyBounded, item.Key)
			} else {
				broad = append(broad, item.Key)
			}
		}
	}
	if len(broad) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d inbound allow exception(s) are not constrained to a local address or interface", len(broad)), Applicability: Applicable, EvidenceKeys: broad}
	}
	if len(contextuallyBounded) > 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d globally bound exception(s) are constrained by both narrow remote scope and application/service identity", len(contextuallyBounded)), Applicability: Applicable, EvidenceKeys: contextuallyBounded}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "observed inbound allow exceptions are locally scoped by address or interface", Applicability: Applicable, EvidenceKeys: firewallRestrictionKeys(allows)}
}

func evaluateFirewallBroadManagementExceptions(idx Index) Evaluation {
	rules, providerUnavailable := firewallRestrictions(idx)
	allows := enabledInboundAllows(rules)
	management := []firewallRestrictionEvidence{}
	for _, item := range allows {
		if isManagementFirewallRule(item.Rule) {
			management = append(management, item)
		}
	}
	if len(management) == 0 {
		if providerUnavailable {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "management-exception evidence is incomplete because one or more firewall providers are unavailable", Applicability: Applicable, EvidenceKeys: firewallProviderEvidenceKeys(idx)}
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled inbound remote-management allow exceptions were identified", Applicability: NotApplicable, EvidenceKeys: firewallRestrictionKeys(rules)}
	}

	broad, uncertain, narrow := []string{}, []string{}, []string{}
	for _, item := range management {
		switch remoteScopeClass(item.Rule.RemoteAddresses) {
		case "BROAD", "MODERATE":
			broad = append(broad, item.Key)
		case "UNKNOWN":
			uncertain = append(uncertain, item.Key)
		default:
			narrow = append(narrow, item.Key)
		}
	}
	if len(broad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d remote-management/admin firewall exception(s) permit broad source ranges", len(broad)), Applicability: Applicable, EvidenceKeys: broad}
	}
	if len(uncertain) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d remote-management/admin exception(s) lack explicit remote-source scope", len(uncertain)), Applicability: Applicable, EvidenceKeys: uncertain}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d remote-management/admin exception(s) are limited to bounded source ranges", len(narrow)), Applicability: Applicable, EvidenceKeys: narrow}
}

func evaluateFirewallPermissivePolicyConflicts(idx Index) Evaluation {
	providers, policies, providerKeys, _ := firewallEvidence(idx)
	if firewallDefinitelyDisabled(providers) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "policy conflict assessment is not applicable because no observed firewall provider is enabled", Applicability: NotApplicable, EvidenceKeys: providerKeys}
	}
	permissive, restrictive, unknown := []string{}, []string{}, []string{}
	for _, item := range enabledFirewallPolicies(policies) {
		switch inboundClass(item.Policy.DefaultInbound) {
		case "PERMISSIVE":
			permissive = append(permissive, item.Key)
		case "RESTRICTIVE":
			restrictive = append(restrictive, item.Key)
		default:
			unknown = append(unknown, item.Key)
		}
	}
	if len(permissive) > 0 && len(restrictive) > 0 {
		keys := append(append([]string{}, permissive...), restrictive...)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("enabled firewall scopes conflict: %d permissive inbound default(s) and %d restrictive inbound default(s)", len(permissive), len(restrictive)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(permissive) > 0 && len(unknown) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) are consistently permissive; no conflicting restrictive scope was observed (permissive-default weakness is evaluated by CHM-FW-002)", len(permissive)), Applicability: Applicable, EvidenceKeys: permissive}
	}
	if len(restrictive) > 0 && len(unknown) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) use consistently restrictive inbound defaults", len(restrictive)), Applicability: Applicable, EvidenceKeys: restrictive}
	}
	if len(unknown) > 0 {
		keys := append(append([]string{}, restrictive...), unknown...)
		sort.Strings(keys)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d enabled firewall scope(s) lack resolvable inbound-default semantics", len(unknown)), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "enabled firewall policy conflict could not be assessed", Applicability: Undetermined, EvidenceKeys: providerKeys}
}

func firewallRestrictionKeys(in []firewallRestrictionEvidence) []string {
	keys := make([]string, 0, len(in))
	for _, item := range in {
		keys = append(keys, item.Key)
	}
	sort.Strings(keys)
	return keys
}

func firewallProviderEvidenceKeys(idx Index) []string {
	keys := []string{}
	for key := range idx {
		if strings.HasPrefix(key, "firewall.provider.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func selectorListIsAnyOrEmpty(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		x := strings.ToUpper(strings.TrimSpace(v))
		if x == "" || x == "ANY" || x == "*" || x == "0.0.0.0/0" || x == "::/0" || x == "ANYWHERE" {
			return true
		}
	}
	return false
}

// remoteScopeClass intentionally uses conservative thresholds. IPv4 /0-/7 and
// IPv6 /0-/15 are treated as Internet-scale BROAD ranges; IPv4 /8-/15 and IPv6
// /16-/31 are unusually broad MODERATE ranges. Named/provider-specific selectors
// stay UNKNOWN instead of being guessed.
func remoteScopeClass(values []string) string {
	if len(values) == 0 {
		return "UNKNOWN"
	}
	worst := "NARROW"
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		upper := strings.ToUpper(v)
		switch upper {
		case "ANY", "*", "ANYWHERE", "INTERNET":
			return "BROAD"
		case "INTRANET", "REMOTECORPNETWORK":
			if worst == "NARROW" {
				worst = "MODERATE"
			}
			continue
		case "LOCALSUBNET", "LOCALSUBNET4", "LOCALSUBNET6", "DNS", "DHCP", "WINS", "DEFAULTGATEWAY":
			continue
		}
		if v == "0.0.0.0/0" || v == "::/0" {
			return "BROAD"
		}
		if strings.Contains(v, "/") {
			parts := strings.SplitN(v, "/", 2)
			prefix := -1
			if len(parts) == 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					prefix = n
				}
			}
			if prefix < 0 {
				return "UNKNOWN"
			}
			if strings.Contains(parts[0], ":") {
				if prefix <= 15 {
					return "BROAD"
				}
				if prefix <= 31 {
					worst = "MODERATE"
				}
			} else {
				if prefix <= 7 {
					return "BROAD"
				}
				if prefix <= 15 {
					worst = "MODERATE"
				}
			}
			continue
		}
		if strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") && net.ParseIP(v) == nil {
			return "UNKNOWN"
		}
	}
	return worst
}

func isManagementFirewallRule(r fwinv.RestrictionRule) bool {
	managementPorts := map[uint16]struct{}{
		22: {}, 445: {}, 5900: {}, 5901: {}, 5985: {}, 5986: {}, 2375: {}, 2376: {}, 3389: {}, 6443: {}, 10250: {},
	}
	for _, pr := range r.LocalPorts {
		for port := range managementPorts {
			if port >= pr.Start && port <= pr.End {
				return true
			}
		}
	}
	text := strings.ToLower(strings.Join([]string{r.Application, r.Service}, " "))
	for _, token := range []string{"sshd", "ssh", "rdp", "termservice", "winrm", "smb", "vnc", "docker", "dockerd", "kube", "kubernetes", "remote management", "screen sharing"} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func lowerFindingConfidence(a, b evidence.Confidence) evidence.Confidence {
	rank := map[evidence.Confidence]int{evidence.ConfidenceLow: 1, evidence.ConfidenceMedium: 2, evidence.ConfidenceHigh: 3, evidence.ConfidenceExact: 4}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

func enabledFirewallPolicies(in []firewallPolicyEvidence) []firewallPolicyEvidence {
	out := make([]firewallPolicyEvidence, 0, len(in))
	for _, p := range in {
		if strings.EqualFold(strings.TrimSpace(p.Policy.Enabled), "ENABLED") {
			out = append(out, p)
		}
	}
	return out
}

func inboundClass(action string) string {
	v := strings.ToUpper(strings.TrimSpace(action))
	switch v {
	case "ALLOW", "ACCEPT":
		return "PERMISSIVE"
	case "BLOCK", "DENY", "DROP", "REJECT":
		return "RESTRICTIVE"
	default:
		return "UNKNOWN"
	}
}

func firewallHasEnabledProvider(in []firewallProviderEvidence) bool {
	for _, p := range in {
		v := strings.ToUpper(strings.TrimSpace(p.Provider.Enabled))
		if v == "ENABLED" || v == "MIXED" {
			return true
		}
	}
	return false
}

func firewallDefinitelyDisabled(in []firewallProviderEvidence) bool {
	if len(in) == 0 {
		return false
	}
	for _, p := range in {
		if !strings.EqualFold(strings.TrimSpace(p.Provider.Enabled), "DISABLED") {
			return false
		}
	}
	return true
}

func providerEvidenceKeys(providers []firewallProviderEvidence, fallback []string) []string {
	keys := make([]string, 0, len(providers))
	for _, p := range providers {
		keys = append(keys, p.Key)
	}
	if len(keys) == 0 {
		keys = append(keys, fallback...)
	}
	sort.Strings(keys)
	return keys
}

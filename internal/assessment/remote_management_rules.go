package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
)

type remoteManagementRuleKind struct {
	id, title, affectedObject, expected, risk, remediation string
	severity                                               Severity
	families                                               []string
}

// RemoteManagementRules implements . The rules consume only local
// service/listener/firewall/configuration evidence; they do not connect to or
// authenticate against any remote-management endpoint. SSH authentication and
// algorithm hardening deliberately remain for .
func RemoteManagementRules() []Rule {
	kinds := []remoteManagementRuleKind{
		{
			id: "CHM-NET-016", title: "SSH and Remote Login exposure is locally constrained", severity: SeverityMedium,
			affectedObject: "network.remote_management.ssh", expected: "enabled SSH/Remote Login surfaces are intentionally configured and externally bound listeners have defensible local firewall coverage",
			risk:        "An enabled SSH/Remote Login service bound beyond loopback creates an administrative entry point. Missing or unresolved host-firewall coverage increases exposure even before SSH-specific authentication hardening is evaluated.",
			remediation: "Disable SSH/Remote Login where unnecessary. Otherwise bind it to the minimum required interfaces and restrict source networks with local firewall policy. Use for SSH authentication and algorithm hardening.",
			families:    []string{"SSH"},
		},
		{
			id: "CHM-NET-017", title: "Remote Desktop exposure is locally constrained", severity: SeverityHigh,
			affectedObject: "network.remote_management.rdp", expected: "enabled RDP surfaces are intentionally configured and externally bound listeners have defensible local firewall coverage",
			risk:        "RDP provides interactive remote logon. A non-loopback RDP listener without confirmed local firewall restriction materially increases the host's administrative attack surface.",
			remediation: "Disable Remote Desktop where unnecessary. Otherwise restrict it to approved management interfaces/networks, keep Network Level Authentication enabled where supported, and enforce narrow local firewall source scope.",
			families:    []string{"RDP"},
		},
		{
			id: "CHM-NET-018", title: "WinRM exposure is locally constrained", severity: SeverityHigh,
			affectedObject: "network.remote_management.winrm", expected: "enabled WinRM surfaces are intentionally configured and externally bound listeners have defensible local firewall coverage",
			risk:        "WinRM exposes remote administration capabilities. Broad or unfiltered listener reachability can allow management attempts from unintended networks.",
			remediation: "Disable WinRM where unnecessary. Otherwise restrict listeners and firewall source scope to approved management networks and use hardened authentication/transport settings.",
			families:    []string{"WINRM"},
		},
		{
			id: "CHM-NET-019", title: "Screen-sharing and similar management exposure is locally constrained", severity: SeverityHigh,
			affectedObject: "network.remote_management.screen_sharing", expected: "screen-sharing, remote-registry, and local web administration surfaces are disabled when unnecessary or constrained to intended management networks",
			risk:        "Screen sharing, VNC, remote registry, and web administration surfaces can expose interactive or privileged management functionality to other hosts when bound beyond loopback.",
			remediation: "Disable unused screen-sharing/remote-management services. For required access, bind only to intended interfaces and apply narrowly scoped local firewall policy.",
			families:    []string{"VNC", "REMOTE_REGISTRY", "COCKPIT"},
		},
	}
	out := make([]Rule, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, remoteManagementRule(kind))
	}
	return out
}

func remoteManagementRule(kind remoteManagementRuleKind) Rule {
	eval := func(profileName string, idx Index) Evaluation {
		surfaces, inventoryAvailable := remoteManagementSurfaces(idx, kind.families)
		if len(surfaces) == 0 {
			if !inventoryAvailable {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "remote-management evidence is unavailable", Applicability: Undetermined, EvidenceKeys: remoteManagementInventoryKeys(idx)}
			}
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no matching remote-management surface was identified", Applicability: NotApplicable, EvidenceKeys: remoteManagementInventoryKeys(idx)}
		}
		enabled := make([]remoteSurfaceItem, 0)
		absent := make([]remoteSurfaceItem, 0)
		unresolved := make([]remoteSurfaceItem, 0)
		unresolvedConfig := make([]remoteSurfaceItem, 0)
		weakConfig := make([]remoteSurfaceItem, 0)
		for _, item := range surfaces {
			s := item.Surface
			if s.ConfiguredState == "UNKNOWN" && s.RuntimeState == "UNKNOWN" && s.ListenerState != "PRESENT" {
				unresolvedConfig = append(unresolvedConfig, item)
			}
			if s.ConfiguredState != "ENABLED" && s.RuntimeState != "ACTIVE" && s.ListenerState != "PRESENT" {
				continue
			}
			enabled = append(enabled, item)
			for _, tag := range s.RiskTags {
				if tag == "rdp-nla-disabled" || tag == "winrm-basic-auth-enabled" || tag == "winrm-allow-unencrypted" {
					weakConfig = append(weakConfig, item)
					break
				}
			}
			external := s.BindingState == "EXTERNAL" || s.BindingState == "ALL_INTERFACES"
			if !external {
				continue
			}
			switch s.FirewallCoverage {
			case firewall.CoverageAbsent:
				absent = append(absent, item)
			case firewall.CoverageAmbiguous, firewall.CoverageUnavailable:
				unresolved = append(unresolved, item)
			}
		}
		if len(absent) > 0 {
			return Evaluation{Status: StatusFail, Confidence: remoteSurfaceConfidence(absent), ObservedState: fmt.Sprintf("%d active/enabled matching remote-management surface(s) have external bindings with absent local firewall coverage", len(absent)), Applicability: Applicable, EvidenceKeys: remoteSurfaceKeys(absent)}
		}
		if len(unresolved) > 0 {
			return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%d active/enabled matching remote-management surface(s) have external bindings with ambiguous or unavailable local firewall coverage", len(unresolved)), Applicability: Applicable, EvidenceKeys: remoteSurfaceKeys(unresolved)}
		}
		if len(weakConfig) > 0 {
			return Evaluation{Status: StatusWarn, Confidence: remoteSurfaceConfidence(weakConfig), ObservedState: fmt.Sprintf("%d active/enabled matching remote-management surface(s) have locally observable weak management configuration controls", len(weakConfig)), Applicability: Applicable, EvidenceKeys: remoteSurfaceKeys(weakConfig)}
		}
		if len(enabled) == 0 && len(unresolvedConfig) > 0 {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d matching remote-management surface(s) have unresolved configured/runtime state", len(unresolvedConfig)), Applicability: Undetermined, EvidenceKeys: remoteSurfaceKeys(unresolvedConfig)}
		}
		// High-security hosts require explicit justification for any enabled
		// remote-management surface even when local firewall coverage exists.
		if normalizeProfileName(profileName) == "high-security" && len(enabled) > 0 {
			return Evaluation{Status: StatusWarn, Confidence: remoteSurfaceConfidence(enabled), ObservedState: fmt.Sprintf("high-security profile: %d matching remote-management surface(s) are enabled/active and require explicit operational justification", len(enabled)), Applicability: Applicable, EvidenceKeys: remoteSurfaceKeys(enabled)}
		}
		return Evaluation{Status: StatusPass, Confidence: remoteSurfaceConfidence(surfaces), ObservedState: fmt.Sprintf("%d matching remote-management surface(s) are disabled, loopback-only, inactive, or externally constrained by local firewall evidence", len(surfaces)), Applicability: Applicable, EvidenceKeys: remoteSurfaceKeys(surfaces)}
	}
	return Rule{ID: kind.id, Title: kind.title, Category: "network", Severity: kind.severity, AffectedObject: kind.affectedObject, ExpectedState: kind.expected, Risk: kind.risk, Remediation: kind.remediation, Evaluate: func(idx Index) Evaluation { return eval("default", idx) }, EvaluateProfile: eval}
}

type remoteSurfaceItem struct {
	Key     string
	Surface remotemgmt.Surface
}

func remoteManagementSurfaces(idx Index, families []string) ([]remoteSurfaceItem, bool) {
	allow := map[string]struct{}{}
	for _, f := range families {
		allow[strings.ToUpper(f)] = struct{}{}
	}
	out := []remoteSurfaceItem{}
	available := false
	for key, obs := range idx {
		if key == "remote_management.summary" && obs.State == evidence.StateObserved {
			available = true
		}
		if !strings.HasPrefix(key, "remote_management.surface.") || obs.State != evidence.StateObserved {
			continue
		}
		available = true
		s, ok := obs.Value.(remotemgmt.Surface)
		if !ok {
			continue
		}
		if _, ok := allow[strings.ToUpper(s.Family)]; !ok {
			continue
		}
		out = append(out, remoteSurfaceItem{Key: key, Surface: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, available
}
func remoteSurfaceKeys(items []remoteSurfaceItem) []string {
	out := make([]string, 0, len(items)*2+1)
	out = append(out, "remote_management.summary")
	for _, i := range items {
		out = append(out, i.Key)
		for _, id := range i.Surface.ControlIDs {
			out = append(out, "remote_management.control."+id)
		}
	}
	return uniqueEvidenceKeys(out)
}
func remoteManagementInventoryKeys(idx Index) []string {
	keys := []string{}
	for k := range idx {
		if k == "remote_management.summary" || strings.HasPrefix(k, "remote_management.control.") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return []string{"remote_management.summary"}
	}
	return keys
}
func remoteSurfaceConfidence(items []remoteSurfaceItem) evidence.Confidence {
	c := evidence.ConfidenceExact
	for _, i := range items {
		switch i.Surface.Confidence {
		case evidence.ConfidenceLow:
			return evidence.ConfidenceLow
		case evidence.ConfidenceMedium:
			c = evidence.ConfidenceMedium
		case evidence.ConfidenceHigh:
			if c == evidence.ConfidenceExact {
				c = evidence.ConfidenceHigh
			}
		}
	}
	return c
}
func uniqueEvidenceKeys(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

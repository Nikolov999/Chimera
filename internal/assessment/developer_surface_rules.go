package assessment

import (
	"fmt"
	"sort"
	"strings"

	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/evidence"
)

// DeveloperSurfaceRules is the developer-surface rule pack. It uses
// only redacted local activation/listener metadata. It does not
// connect to debug endpoints, inspect notebook/browser/debugger content, or
// infer network reachability when local listener evidence is unresolved.
func DeveloperSurfaceRules() []Rule {
	return []Rule{
		developerExposureRule(),
		developerRoleRule(),
		developerExposureResolutionRule(),
	}
}

type developerSurfaceEvidence struct {
	Key    string
	Record containerinv.DeveloperSurface
}

func developerExposureRule() Rule {
	evaluate := func(profileName string, idx Index) Evaluation {
		profileName = normalizeProfileName(profileName)
		items, unresolved, provider := developerSurfaceEvidenceItems(idx)
		if len(items) == 0 {
			return noDeveloperSurfaceEvaluation(provider, "no supported active developer/debug surface was observed")
		}

		reachable := make([]developerSurfaceEvidence, 0)
		for _, item := range items {
			if item.Record.ExposureState == "NETWORK_REACHABLE" {
				reachable = append(reachable, item)
			}
		}
		if len(reachable) > 0 {
			status := StatusFail
			if profileName == "developer" {
				// Remote development can be intentional on a developer host, but a
				// remotely reachable debug/control surface must never be silently
				// accepted merely because the developer profile is selected.
				status = StatusWarn
			}
			desc, keys := developerSurfaceDescriptions(reachable)
			return Evaluation{
				Status: status, Confidence: developerSurfaceConfidence(reachable), Applicability: Applicable,
				ObservedState: fmt.Sprintf("profile %s: %d active developer/debug surface(s) are listening beyond loopback: %s", profileName, len(reachable), strings.Join(desc, "; ")),
				EvidenceKeys:  keys,
			}
		}
		if len(unresolved) > 0 {
			desc, keys := developerSurfaceDescriptions(unresolved)
			keys = append(keys, developerProviderEvidenceKeys(idx)...)
			return Evaluation{
				Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, Applicability: Applicable,
				ObservedState: fmt.Sprintf("profile %s: developer/debug activation was observed, but network exposure could not be resolved for %d surface(s): %s", profileName, len(unresolved), strings.Join(desc, "; ")),
				EvidenceKeys:  uniqueAssessmentStrings(keys),
			}
		}
		_, keys := developerSurfaceDescriptions(items)
		return Evaluation{Status: StatusPass, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: %d active developer/debug surface(s) are limited to loopback", profileName, len(items)), EvidenceKeys: keys}
	}

	return Rule{
		ID: "CHM-CTR-023", Title: "Developer and debug interfaces avoid unexpected network exposure", Category: "containers", Severity: SeverityHigh,
		AffectedObject:  "container.developer.network_exposure",
		ExpectedState:   "active developer/debug interfaces are limited to loopback unless deliberate remote development is explicitly justified and separately constrained",
		Risk:            "Browser DevTools, notebook servers, language debuggers, remote IDEs, and ADB expose powerful development or control functionality. Accidental non-loopback binding can make that functionality reachable by other hosts and materially increase attack surface.",
		Remediation:     "Bind the developer/debug interface to loopback by default. If remote development is required, use an authenticated encrypted access path, restrict the listener to an intended management interface, and constrain source reachability with local/network firewall policy.",
		Evaluate:        func(idx Index) Evaluation { return evaluate("default", idx) },
		EvaluateProfile: evaluate,
	}
}

func developerRoleRule() Rule {
	evaluate := func(profileName string, idx Index) Evaluation {
		profileName = normalizeProfileName(profileName)
		items, _, provider := developerSurfaceEvidenceItems(idx)
		if len(items) == 0 {
			return noDeveloperSurfaceEvaluation(provider, "no supported active developer/debug surface was observed")
		}
		desc, keys := developerSurfaceDescriptions(items)
		switch profileName {
		case "high-security":
			return Evaluation{Status: StatusFail, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: %d active developer/debug surface(s) require explicit removal or documented exception: %s", profileName, len(items), strings.Join(desc, "; ")), EvidenceKeys: keys}
		case "server":
			return Evaluation{Status: StatusWarn, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: %d active developer/debug surface(s) require role justification on a service host: %s", profileName, len(items), strings.Join(desc, "; ")), EvidenceKeys: keys}
		case "developer":
			return Evaluation{Status: StatusPass, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: %d active developer/debug surface(s) are role-consistent; network exposure is assessed separately", profileName, len(items)), EvidenceKeys: keys}
		case "workstation", "default":
			return Evaluation{Status: StatusPass, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: active developer/debug tooling is not inherently a role violation; %d surface(s) are assessed separately for exposure", profileName, len(items)), EvidenceKeys: keys}
		default:
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, Applicability: Undetermined, ObservedState: "unrecognized profile cannot determine developer-surface role policy", EvidenceKeys: keys}
		}
	}

	return Rule{
		ID: "CHM-CTR-024", Title: "Active developer surfaces fit the selected host role", Category: "containers", Severity: SeverityMedium,
		AffectedObject:  "container.developer.role_fit",
		ExpectedState:   "developer/debug tooling is expected on developer and general interactive endpoints, but requires explicit justification on server and high-security profiles",
		Risk:            "Development and debugging services increase local control-plane complexity and can expose high-impact interfaces. Their presence is expected on some endpoints but is unusual on hardened or dedicated service hosts where unnecessary tooling expands attack surface.",
		Remediation:     "Remove unused developer/debug services from server or hardened hosts. Where the tooling is required, document the exception, keep it bound to loopback or an approved management path, and validate authentication and firewall restrictions.",
		Evaluate:        func(idx Index) Evaluation { return evaluate("default", idx) },
		EvaluateProfile: evaluate,
	}
}

func developerExposureResolutionRule() Rule {
	evaluate := func(profileName string, idx Index) Evaluation {
		profileName = normalizeProfileName(profileName)
		items, unresolved, provider := developerSurfaceEvidenceItems(idx)
		if len(items) == 0 {
			return noDeveloperSurfaceEvaluation(provider, "no supported active developer/debug surface was observed")
		}
		if len(unresolved) > 0 {
			desc, keys := developerSurfaceDescriptions(unresolved)
			keys = append(keys, developerProviderEvidenceKeys(idx)...)
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: listener ownership/binding could not be resolved for %d active developer/debug surface(s): %s", profileName, len(unresolved), strings.Join(desc, "; ")), EvidenceKeys: uniqueAssessmentStrings(keys)}
		}
		_, keys := developerSurfaceDescriptions(items)
		return Evaluation{Status: StatusPass, Confidence: developerSurfaceConfidence(items), Applicability: Applicable, ObservedState: fmt.Sprintf("profile %s: listener exposure is resolved for all %d active developer/debug surface(s)", profileName, len(items)), EvidenceKeys: keys}
	}

	return Rule{
		ID: "CHM-CTR-025", Title: "Developer surface listener exposure is fully resolved", Category: "containers", Severity: SeverityLow,
		AffectedObject:  "container.developer.exposure_resolution",
		ExpectedState:   "every observed active developer/debug surface has defensible local listener ownership and binding/exposure metadata",
		Risk:            "An active debugger or developer interface whose listener state cannot be resolved leaves Chimera unable to determine whether the control surface is local-only or reachable from other hosts.",
		Remediation:     "Restore access to local process and listener metadata, verify the owning process and bind address, then rerun Chimera. Treat unresolved developer-control exposure as unverified rather than assuming it is local-only.",
		Evaluate:        func(idx Index) Evaluation { return evaluate("default", idx) },
		EvaluateProfile: evaluate,
	}
}

func developerSurfaceEvidenceItems(idx Index) (items, unresolved []developerSurfaceEvidence, provider *evidence.Observation) {
	if obs, ok := idx["container.source.developer-surfaces"]; ok {
		copy := obs
		provider = &copy
	}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.developer.surface.") || obs.State != evidence.StateObserved {
			continue
		}
		rec, ok := obs.Value.(containerinv.DeveloperSurface)
		if !ok {
			continue
		}
		item := developerSurfaceEvidence{Key: key, Record: rec}
		items = append(items, item)
		if rec.ExposureState != "LOCAL_ONLY" && rec.ExposureState != "NETWORK_REACHABLE" {
			unresolved = append(unresolved, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return developerSurfaceSortKey(items[i]) < developerSurfaceSortKey(items[j]) })
	sort.Slice(unresolved, func(i, j int) bool {
		return developerSurfaceSortKey(unresolved[i]) < developerSurfaceSortKey(unresolved[j])
	})
	return items, unresolved, provider
}

func noDeveloperSurfaceEvaluation(provider *evidence.Observation, message string) Evaluation {
	if provider == nil {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceLow, ObservedState: message + "; developer-surface provider status was not included in this evidence set", Applicability: NotApplicable}
	}
	key := "container.source.developer-surfaces"
	switch provider.State {
	case evidence.StateObserved, evidence.StateNotApplicable:
		return Evaluation{Status: StatusPass, Confidence: provider.Confidence, ObservedState: message, Applicability: NotApplicable, EvidenceKeys: []string{key}}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: provider.Confidence, ObservedState: observedText(*provider), Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
}

func developerSurfaceDescriptions(items []developerSurfaceEvidence) ([]string, []string) {
	desc := make([]string, 0, minInt(len(items), 12))
	keys := make([]string, 0, minInt(len(items), 64))
	for i, item := range items {
		if i < 12 {
			target := item.Record.BindingState
			if item.Record.LocalAddress != "" || item.Record.LocalPort != 0 {
				target = fmt.Sprintf("%s:%d", fallbackDeveloperAssessment(item.Record.LocalAddress, item.Record.BindingState), item.Record.LocalPort)
			}
			desc = append(desc, fmt.Sprintf("%s (%s, %s)", item.Record.Product, target, item.Record.ExposureState))
		}
		if i < 64 {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > 12 {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-12))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func developerSurfaceSortKey(item developerSurfaceEvidence) string {
	return strings.ToLower(item.Record.Product) + "\x00" + item.Record.Kind + "\x00" + fmt.Sprintf("%010d\x00%05d\x00%s", item.Record.PID, item.Record.LocalPort, item.Key)
}

func developerSurfaceConfidence(items []developerSurfaceEvidence) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	out := evidence.ConfidenceExact
	for _, item := range items {
		switch item.Record.Confidence {
		case evidence.ConfidenceLow:
			return evidence.ConfidenceLow
		case evidence.ConfidenceMedium:
			out = evidence.ConfidenceMedium
		case evidence.ConfidenceHigh:
			if out == evidence.ConfidenceExact {
				out = evidence.ConfidenceHigh
			}
		}
	}
	return out
}

func developerProviderEvidenceKeys(idx Index) []string {
	keys := make([]string, 0, 3)
	for _, key := range []string{"container.source.developer-surfaces", "container.source.developer-process-metadata", "container.source.developer-listener-correlation"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func fallbackDeveloperAssessment(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return "unknown"
}

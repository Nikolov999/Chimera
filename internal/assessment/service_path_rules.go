package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/services"
)

type servicePathEvidenceItem struct {
	ID      string
	Key     string
	ItemKey string
	Service services.Service
	Path    services.ServicePathIntegrity
	Obs     evidence.Observation
}

// ServicePathCorrelationRules implements . These rules correlate
// service identity/privilege with read-only path-integrity metadata. They do
// not execute service binaries, test replacement, or modify ACLs/permissions.
func ServicePathCorrelationRules() []Rule {
	return []Rule{
		{
			ID:             "CHM-SVC-023",
			Title:          "Privileged service executable paths resist lower-privilege modification",
			Category:       "service",
			Severity:       SeverityHigh,
			AffectedObject: "service.privileged.executable_path_integrity",
			ExpectedState:  "privileged service executable files and containing directories are not controlled by lower-privileged principals",
			Risk:           "A privileged service whose executable or containing directory can be modified by a lower-privileged principal has a weakened code-execution trust boundary.",
			Remediation:    "Move service code to an administrator-controlled location and restrict ownership/write permissions so lower-privileged users cannot replace the executable or its containing directory.",
			Evaluate: func(idx Index) Evaluation {
				items, state := servicePathItems(idx)
				if len(items) == 0 {
					return servicePathUnavailable(idx, state)
				}
				privileged := filterServicePath(items, func(i servicePathEvidenceItem) bool { return i.Path.Privileged })
				if len(privileged) == 0 {
					return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(items), ObservedState: "0 privileged services required executable-path correlation", Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, items)}
				}
				bad := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					return i.Path.Executable.LowerPrivilegeWritable || i.Path.ExecutableDirectory.LowerPrivilegeWritable
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: servicePathConfidence(bad), ObservedState: fmt.Sprintf("%d privileged service(s) execute from a lower-privilege-writable executable or containing directory", len(bad)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(bad)}
				}
				unresolved := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					return pathPostureUnresolved(i.Path.Executable) || pathPostureUnresolved(i.Path.ExecutableDirectory)
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("executable path integrity unresolved for %d of %d privileged service(s)", len(unresolved), len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(privileged), ObservedState: fmt.Sprintf("%d privileged service executable path boundary/boundaries have no observed lower-privilege write control", len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, privileged)}
			},
		},
		{
			ID:             "CHM-SVC-024",
			Title:          "Privileged service configuration paths resist lower-privilege modification",
			Category:       "service",
			Severity:       SeverityHigh,
			AffectedObject: "service.privileged.configuration_path_integrity",
			ExpectedState:  "privileged service definitions and configuration paths are not controlled by lower-privileged principals",
			Risk:           "Writable service definitions or configuration paths can let a lower-privileged principal influence what a privileged service launches or how it is configured.",
			Remediation:    "Restrict service-definition and configuration ownership/write permissions to trusted administrators or the service manager's protected configuration boundary.",
			Evaluate: func(idx Index) Evaluation {
				items, state := servicePathItems(idx)
				if len(items) == 0 {
					return servicePathUnavailable(idx, state)
				}
				privileged := filterServicePath(items, func(i servicePathEvidenceItem) bool { return i.Path.Privileged })
				if len(privileged) == 0 {
					return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(items), ObservedState: "0 privileged services required configuration-path correlation", Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, items)}
				}
				bad := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					return i.Path.Configuration.LowerPrivilegeWritable || i.Path.ConfigurationDirectory.LowerPrivilegeWritable
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: servicePathConfidence(bad), ObservedState: fmt.Sprintf("%d privileged service(s) have a lower-privilege-writable definition/configuration boundary", len(bad)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(bad)}
				}
				unresolved := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					return pathPostureUnresolved(i.Path.Configuration) || pathPostureUnresolved(i.Path.ConfigurationDirectory)
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("configuration path integrity unresolved for %d of %d privileged service(s)", len(unresolved), len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(privileged), ObservedState: fmt.Sprintf("%d privileged service configuration boundary/boundaries have no observed lower-privilege write control", len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, privileged)}
			},
		},
		{
			ID:             "CHM-SVC-025",
			Title:          "Privileged service search and resolution paths resist lower-privilege modification",
			Category:       "service",
			Severity:       SeverityHigh,
			AffectedObject: "service.privileged.search_path_integrity",
			ExpectedState:  "privileged service executable resolution does not depend on a lower-privilege-writable search or containing path",
			Risk:           "Weak executable resolution combined with a writable search or containing path can allow a lower-privileged principal to influence which program a privileged service resolves.",
			Remediation:    "Use an explicit protected executable path, quote Windows service executable paths where required, and remove lower-privilege write access from directories participating in service executable resolution.",
			Evaluate: func(idx Index) Evaluation {
				items, state := servicePathItems(idx)
				if len(items) == 0 {
					return servicePathUnavailable(idx, state)
				}
				privileged := filterServicePath(items, func(i servicePathEvidenceItem) bool { return i.Path.Privileged })
				if len(privileged) == 0 {
					return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(items), ObservedState: "0 privileged services required search-path correlation", Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, items)}
				}
				bad := filterServicePath(privileged, func(i servicePathEvidenceItem) bool { return i.Path.SearchPathWritable })
				if len(bad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: servicePathConfidence(bad), ObservedState: fmt.Sprintf("%d privileged service(s) resolve through an observed lower-privilege-writable path boundary", len(bad)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(bad)}
				}
				unresolved := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					return (i.Path.SearchResolution == "RELATIVE" || i.Path.SearchResolution == "UNQUOTED" || i.Path.SearchResolution == "UNKNOWN") && i.Path.SearchPathState != "OBSERVED"
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("service executable search/resolution integrity unresolved for %d of %d privileged service(s)", len(unresolved), len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(privileged), ObservedState: fmt.Sprintf("%d privileged service search/resolution boundary/boundaries have no observed lower-privilege write control", len(privileged)), Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, privileged)}
			},
		},
		{
			ID:             "CHM-SVC-026",
			Title:          "Privileged services do not combine multiple weak path boundaries",
			Category:       "service",
			Severity:       SeverityHigh,
			AffectedObject: "service.privileged.compound_path_integrity",
			ExpectedState:  "no privileged service combines lower-privilege-writable executable, configuration, and search/resolution boundaries",
			Risk:           "Multiple independently observed writable boundaries around the same privileged service materially increase confidence that its execution trust boundary is weak and raise remediation priority.",
			Remediation:    "Treat the affected service as a single trust boundary: secure its executable and parent directory, service definition/configuration, and executable-resolution path together, then rerun Chimera to confirm all correlated weaknesses are removed.",
			Evaluate: func(idx Index) Evaluation {
				items, state := servicePathItems(idx)
				if len(items) == 0 {
					return servicePathUnavailable(idx, state)
				}
				privileged := filterServicePath(items, func(i servicePathEvidenceItem) bool { return i.Path.Privileged })
				compound := filterServicePath(privileged, func(i servicePathEvidenceItem) bool {
					dimensions := 0
					if i.Path.Executable.LowerPrivilegeWritable || i.Path.ExecutableDirectory.LowerPrivilegeWritable {
						dimensions++
					}
					if i.Path.Configuration.LowerPrivilegeWritable || i.Path.ConfigurationDirectory.LowerPrivilegeWritable {
						dimensions++
					}
					if i.Path.SearchPathWritable {
						dimensions++
					}
					return dimensions >= 2
				})
				if len(compound) > 0 {
					return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d privileged service(s) combine lower-privilege write control across two or more execution/configuration/resolution boundaries", len(compound)), Applicability: Applicable, EvidenceKeys: servicePathEvidenceKeys(compound)}
				}
				return Evaluation{Status: StatusPass, Confidence: servicePathConfidence(items), ObservedState: "no privileged service combines multiple observed weak path boundaries", Applicability: Applicable, EvidenceKeys: servicePathInventoryKeys(idx, privileged)}
			},
		},
	}
}

func servicePathItems(idx Index) ([]servicePathEvidenceItem, evidence.State) {
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
	items := make([]servicePathEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.path_integrity.") || obs.State != evidence.StateObserved {
			continue
		}
		pi, ok := obs.Value.(services.ServicePathIntegrity)
		if !ok {
			continue
		}
		id := strings.TrimPrefix(key, "service.path_integrity.")
		svc, ok := servicesByID[id]
		if !ok {
			continue
		}
		items = append(items, servicePathEvidenceItem{ID: id, Key: key, ItemKey: itemKeys[id], Service: svc, Path: pi, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Service.Name) != strings.ToLower(items[j].Service.Name) {
			return strings.ToLower(items[i].Service.Name) < strings.ToLower(items[j].Service.Name)
		}
		return items[i].ID < items[j].ID
	})
	state := evidence.StateUnavailable
	for key, obs := range idx {
		if strings.HasPrefix(key, "service.source.") && strings.HasSuffix(key, "service_path_integrity") {
			state = obs.State
			if state == evidence.StateObserved {
				break
			}
		}
	}
	return items, state
}

func servicePathUnavailable(idx Index, state evidence.State) Evaluation {
	keys := existingKeys(idx, "service.inventory.summary", "service.inventory.count", "service.source.windows_service_path_integrity", "service.source.linux_service_path_integrity", "service.source.darwin_service_path_integrity")
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service privilege-to-path correlation metadata unavailable or contained no usable records (provider state " + string(state) + ")", Applicability: Undetermined, EvidenceKeys: keys}
}

func filterServicePath(items []servicePathEvidenceItem, predicate func(servicePathEvidenceItem) bool) []servicePathEvidenceItem {
	out := make([]servicePathEvidenceItem, 0, len(items))
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func servicePathEvidenceKeys(items []servicePathEvidenceItem) []string {
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

func servicePathInventoryKeys(idx Index, items []servicePathEvidenceItem) []string {
	keys := existingKeys(idx, "service.inventory.summary", "service.source.windows_service_path_integrity", "service.source.linux_service_path_integrity", "service.source.darwin_service_path_integrity")
	for _, key := range servicePathEvidenceKeys(items) {
		if len(keys) >= maxServiceRuleEvidence {
			break
		}
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

func servicePathConfidence(items []servicePathEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceHigh
	}
	rank := 4
	for _, item := range items {
		r := confidenceRankAssessment(item.Obs.Confidence)
		if item.Path.State == "DEGRADED" && r > 2 {
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

func pathPostureUnresolved(p services.PathPosture) bool {
	return p.State != "OBSERVED" && p.State != "NOT_APPLICABLE"
}

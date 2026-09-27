package assessment

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
)

const maxScheduledRuleEvidence = 128

type scheduledEvidenceItem struct {
	Key   string
	Entry scheduled.Entry
	Obs   evidence.Observation
}

// ScheduledRules implements . These rules evaluate only normalized,
// read-only scheduler and local filesystem/DACL metadata. They never trigger,
// modify, enable, disable, or execute a scheduled action.
func ScheduledRules() []Rule {
	rules := []Rule{
		{
			ID:             "CHM-SCH-001",
			Title:          "Scheduled action paths resist broad write access",
			Category:       "scheduled",
			Severity:       SeverityHigh,
			AffectedObject: "scheduled.action_path_integrity",
			ExpectedState:  "scheduled action executables are not broadly writable, especially when executed with elevated authority",
			Risk:           "A scheduled action executable writable by a broad low-privilege principal can weaken the scheduler execution boundary and may allow code replacement before the next run.",
			Remediation:    "Move the scheduled action to an administrator-controlled location and restrict file write/modify/ownership rights to trusted deployment or administrative principals.",
			Evaluate: func(idx Index) Evaluation {
				items, observed := scheduledItems(idx)
				if len(items) == 0 {
					return scheduledEmptyOrUnavailable(idx, observed, "scheduled action path")
				}
				privBad := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && i.Entry.ActionPath.State == "OBSERVED" && i.Entry.ActionPath.BroadlyWritable
				})
				if len(privBad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: scheduledConfidence(privBad), ObservedState: fmt.Sprintf("%d privileged scheduled action executable(s) have an observed broad write grant", len(privBad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(privBad)}
				}
				bad := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return i.Entry.ActionPath.State == "OBSERVED" && i.Entry.ActionPath.BroadlyWritable
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: scheduledConfidence(bad), ObservedState: fmt.Sprintf("%d scheduled action executable(s) have an observed broad write grant", len(bad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(bad)}
				}
				unresolved := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && i.Entry.ActionExecutable != "" && pathUnresolved(i.Entry.ActionPath)
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("action path write posture is unresolved for %d privileged scheduled execution record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: scheduledConfidence(items), ObservedState: fmt.Sprintf("0 broad action-file write grants across %d scheduled execution record(s)", len(items)), Applicability: Applicable, EvidenceKeys: scheduledInventoryKeys(idx, items)}
			},
		},
		{
			ID:             "CHM-SCH-002",
			Title:          "Scheduled scripts and definitions use protected permissions",
			Category:       "scheduled",
			Severity:       SeverityHigh,
			AffectedObject: "scheduled.script_definition_permissions",
			ExpectedState:  "scheduled definitions, referenced scripts, and their configuration boundaries are not broadly or weakly writable",
			Risk:           "Writable scheduler definitions or referenced scripts can let a lower-privileged principal influence what a scheduled job executes or how it is configured.",
			Remediation:    "Restrict scheduler definition, script, and containing-directory permissions to trusted owners/groups. Remove broad write grants and review group-write access on privileged schedules.",
			Evaluate: func(idx Index) Evaluation {
				items, observed := scheduledItems(idx)
				if len(items) == 0 {
					return scheduledEmptyOrUnavailable(idx, observed, "scheduled script/configuration permission")
				}
				privBroad := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && scheduledScriptOrDefinitionBroad(i.Entry)
				})
				if len(privBroad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: scheduledConfidence(privBroad), ObservedState: fmt.Sprintf("%d privileged scheduled record(s) have broadly writable script/definition configuration boundaries", len(privBroad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(privBroad)}
				}
				weak := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledScriptOrDefinitionBroad(i.Entry) || scheduledScriptOrDefinitionGroupWeak(i.Entry)
				})
				if len(weak) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: scheduledConfidence(weak), ObservedState: fmt.Sprintf("%d scheduled record(s) have broad or weak group-write script/definition permissions", len(weak)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(weak)}
				}
				unresolved := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && scheduledScriptOrDefinitionUnresolved(i.Entry)
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("script/definition permission posture is unresolved for %d privileged scheduled record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: scheduledConfidence(items), ObservedState: fmt.Sprintf("no broad or weak group-write script/definition condition observed across %d scheduled record(s)", len(items)), Applicability: Applicable, EvidenceKeys: scheduledInventoryKeys(idx, items)}
			},
		},
		{
			ID:             "CHM-SCH-003",
			Title:          "Privileged schedules avoid dangerous account contexts",
			Category:       "scheduled",
			Severity:       SeverityMedium,
			AffectedObject: "scheduled.privileged_account_context",
			ExpectedState:  "privileged scheduled execution uses built-in system/root identities or a deliberately scoped non-interactive account context",
			Risk:           "A reusable custom administrator identity or interactive privileged logon context expands the credential and authority boundary of scheduled execution.",
			Remediation:    "Use a dedicated least-privileged service identity where possible. For tasks that require system authority, prefer the platform's built-in system/root execution context and avoid interactive privileged logon modes.",
			Evaluate: func(idx Index) Evaluation {
				items, observed := scheduledItems(idx)
				if len(items) == 0 {
					return scheduledEmptyOrUnavailable(idx, observed, "scheduled account")
				}
				bad := filterScheduled(items, func(i scheduledEvidenceItem) bool { return dangerousScheduledAccount(i.Entry) })
				if len(bad) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: scheduledConfidence(bad), ObservedState: fmt.Sprintf("%d privileged scheduled record(s) use a custom privileged or interactive account context", len(bad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(bad)}
				}
				return Evaluation{Status: StatusPass, Confidence: scheduledConfidence(items), ObservedState: "no dangerous privileged scheduled-account context observed", Applicability: Applicable, EvidenceKeys: scheduledInventoryKeys(idx, items)}
			},
		},
		{
			ID:             "CHM-SCH-004",
			Title:          "Hidden Windows tasks do not execute with high privilege",
			Category:       "scheduled",
			Severity:       SeverityHigh,
			AffectedObject: "scheduled.windows.hidden_high_privilege",
			ExpectedState:  "high-privilege Windows Scheduled Tasks are visible in normal Task Scheduler views unless hiding is explicitly justified",
			Risk:           "A hidden task running with SYSTEM or highest privileges reduces administrative visibility around a high-authority execution mechanism and can conceal unsafe or obsolete automation.",
			Remediation:    "Review the hidden high-privilege task, document its business requirement, remove the hidden setting when it is not required, and ensure its action, definition, and account boundaries are protected.",
			Evaluate: func(idx Index) Evaluation {
				platform := strings.ToLower(strings.TrimSpace(observedValue(idx, "scheduled.platform")))
				if platform != "windows" {
					return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "hidden Task Scheduler state is Windows-specific", Applicability: NotApplicable, EvidenceKeys: existingKeys(idx, "scheduled.platform")}
				}
				items, observed := scheduledItems(idx)
				if len(items) == 0 {
					return scheduledEmptyOrUnavailable(idx, observed, "Windows hidden-task")
				}
				bad := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && (i.Entry.HiddenState == "YES" || i.Entry.HiddenState == "HIDDEN")
				})
				if len(bad) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: scheduledConfidence(bad), ObservedState: fmt.Sprintf("%d hidden Windows Scheduled Task(s) execute with SYSTEM/highest privilege", len(bad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(bad)}
				}
				unknown := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && i.Entry.HiddenState == "UNKNOWN"
				})
				if len(unknown) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("hidden-state metadata unresolved for %d privileged Windows task(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(unknown)}
				}
				return Evaluation{Status: StatusPass, Confidence: scheduledConfidence(items), ObservedState: "0 hidden high-privilege Windows Scheduled Tasks observed", Applicability: Applicable, EvidenceKeys: scheduledInventoryKeys(idx, items)}
			},
		},
		{
			ID:             "CHM-SCH-005",
			Title:          "Scheduled execution directories resist untrusted writes",
			Category:       "scheduled",
			Severity:       SeverityHigh,
			AffectedObject: "scheduled.execution_directory_integrity",
			ExpectedState:  "working directories and directories containing scheduled action executables are not broadly writable or weakly group-writable for privileged schedules",
			Risk:           "A scheduled job that executes from or resolves components within an untrusted-writable directory can inherit a weaker file-resolution and configuration boundary than the action executable alone suggests.",
			Remediation:    "Use an explicit protected working directory and place scheduled executables in administrator-controlled directories. Remove broad write access and review group-write permissions for privileged jobs.",
			Evaluate: func(idx Index) Evaluation {
				items, observed := scheduledItems(idx)
				if len(items) == 0 {
					return scheduledEmptyOrUnavailable(idx, observed, "scheduled execution-directory")
				}
				privBroad := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && scheduledExecutionDirectoryBroad(i.Entry)
				})
				if len(privBroad) > 0 {
					return Evaluation{Status: StatusFail, Confidence: scheduledConfidence(privBroad), ObservedState: fmt.Sprintf("%d privileged scheduled record(s) use a broadly writable action or working directory", len(privBroad)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(privBroad)}
				}
				weak := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledExecutionDirectoryBroad(i.Entry) || scheduledExecutionDirectoryGroupWeak(i.Entry)
				})
				if len(weak) > 0 {
					return Evaluation{Status: StatusWarn, Confidence: scheduledConfidence(weak), ObservedState: fmt.Sprintf("%d scheduled record(s) use a broad or weakly group-writable execution directory", len(weak)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(weak)}
				}
				unresolved := filterScheduled(items, func(i scheduledEvidenceItem) bool {
					return scheduledPrivileged(i.Entry) && scheduledExecutionDirectoryUnresolved(i.Entry)
				})
				if len(unresolved) > 0 {
					return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("execution-directory posture is unresolved for %d privileged scheduled record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: scheduledEvidenceKeys(unresolved)}
				}
				return Evaluation{Status: StatusPass, Confidence: scheduledConfidence(items), ObservedState: "no broad or weak group-write scheduled execution-directory condition observed", Applicability: Applicable, EvidenceKeys: scheduledInventoryKeys(idx, items)}
			},
		},
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func scheduledItems(idx Index) ([]scheduledEvidenceItem, bool) {
	items := make([]scheduledEvidenceItem, 0)
	providerObserved := false
	for key, obs := range idx {
		if strings.HasPrefix(key, "scheduled.source.") && obs.State == evidence.StateObserved {
			providerObserved = true
		}
		if !strings.HasPrefix(key, "scheduled.item.") || obs.State != evidence.StateObserved {
			continue
		}
		entry, ok := obs.Value.(scheduled.Entry)
		if !ok {
			continue
		}
		items = append(items, scheduledEvidenceItem{Key: key, Entry: entry, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if strings.ToLower(items[i].Entry.Manager) != strings.ToLower(items[j].Entry.Manager) {
			return strings.ToLower(items[i].Entry.Manager) < strings.ToLower(items[j].Entry.Manager)
		}
		if strings.ToLower(items[i].Entry.Name) != strings.ToLower(items[j].Entry.Name) {
			return strings.ToLower(items[i].Entry.Name) < strings.ToLower(items[j].Entry.Name)
		}
		return items[i].Entry.ID < items[j].Entry.ID
	})
	return items, providerObserved
}

func scheduledEmptyOrUnavailable(idx Index, providerObserved bool, subject string) Evaluation {
	keys := scheduledBaseKeys(idx)
	if providerObserved {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "0 scheduled execution records required " + subject + " assessment", Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: subject + " evidence unavailable or no scheduled provider was observable", Applicability: Undetermined, EvidenceKeys: keys}
}

func scheduledBaseKeys(idx Index) []string {
	keys := existingKeys(idx, "scheduled.platform", "scheduled.inventory.count", "scheduled.inventory.summary")
	for key := range idx {
		if strings.HasPrefix(key, "scheduled.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxScheduledRuleEvidence {
		keys = keys[:maxScheduledRuleEvidence]
	}
	return uniqueStrings(keys)
}

func scheduledInventoryKeys(idx Index, items []scheduledEvidenceItem) []string {
	keys := scheduledBaseKeys(idx)
	for _, key := range scheduledEvidenceKeys(items) {
		if len(keys) >= maxScheduledRuleEvidence {
			break
		}
		keys = append(keys, key)
	}
	return uniqueStrings(keys)
}

func scheduledEvidenceKeys(items []scheduledEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
		if len(keys) >= maxScheduledRuleEvidence {
			break
		}
	}
	return uniqueStrings(keys)
}

func scheduledConfidence(items []scheduledEvidenceItem) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceHigh
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

func filterScheduled(items []scheduledEvidenceItem, predicate func(scheduledEvidenceItem) bool) []scheduledEvidenceItem {
	out := make([]scheduledEvidenceItem, 0, len(items))
	for _, item := range items {
		if predicate(item) {
			out = append(out, item)
		}
	}
	return out
}

func scheduledPrivileged(e scheduled.Entry) bool {
	switch strings.ToUpper(strings.TrimSpace(e.PrivilegeContext)) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT", "ADMINISTRATOR":
		return true
	default:
		return false
	}
}

func builtinScheduledPrivilegedAccount(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, ".\\")
	switch v {
	case "root", "0", "system", "localsystem", "nt authority\\system", "local service", "nt authority\\local service", "network service", "nt authority\\network service":
		return true
	default:
		return false
	}
}

func dangerousScheduledAccount(e scheduled.Entry) bool {
	if !scheduledPrivileged(e) {
		return false
	}
	acct := strings.TrimSpace(e.Account)
	if acct != "" && !strings.EqualFold(acct, "UNKNOWN") && !builtinScheduledPrivilegedAccount(acct) {
		return true
	}
	logon := strings.ToUpper(strings.TrimSpace(e.LogonType))
	return strings.Contains(logon, "INTERACTIVE")
}

func pathUnresolved(p scheduled.PathPosture) bool {
	return p.State != "OBSERVED" && p.State != "NOT_APPLICABLE"
}

func pathGroupWeak(p scheduled.PathPosture) bool {
	if p.State != "OBSERVED" || !p.GroupWritable || p.BroadlyWritable {
		return false
	}
	group := strings.TrimSpace(p.Group)
	return group != "" && group != "0"
}

func scheduledScriptOrDefinitionBroad(e scheduled.Entry) bool {
	return e.DefinitionPathPosture.BroadlyWritable || e.DefinitionDirectoryPosture.BroadlyWritable || e.ReferencedScriptPathPosture.BroadlyWritable || (isScriptLikePath(e.ActionExecutable) && e.ActionPath.BroadlyWritable)
}

func scheduledScriptOrDefinitionGroupWeak(e scheduled.Entry) bool {
	return pathGroupWeak(e.DefinitionPathPosture) || pathGroupWeak(e.DefinitionDirectoryPosture) || pathGroupWeak(e.ReferencedScriptPathPosture) || (isScriptLikePath(e.ActionExecutable) && pathGroupWeak(e.ActionPath))
}

func scheduledScriptOrDefinitionUnresolved(e scheduled.Entry) bool {
	if e.DefinitionPath != "" && pathUnresolved(e.DefinitionPathPosture) {
		return true
	}
	if e.ReferencedScriptPath != "" && pathUnresolved(e.ReferencedScriptPathPosture) {
		return true
	}
	return false
}

func scheduledExecutionDirectoryBroad(e scheduled.Entry) bool {
	return e.ActionDirectoryPosture.BroadlyWritable || e.WorkingDirectoryPosture.BroadlyWritable
}

func scheduledExecutionDirectoryGroupWeak(e scheduled.Entry) bool {
	return pathGroupWeak(e.ActionDirectoryPosture) || pathGroupWeak(e.WorkingDirectoryPosture)
}

func scheduledExecutionDirectoryUnresolved(e scheduled.Entry) bool {
	if e.ActionExecutable != "" && pathUnresolved(e.ActionDirectoryPosture) {
		return true
	}
	if e.WorkingDirectory != "" && pathUnresolved(e.WorkingDirectoryPosture) {
		return true
	}
	return false
}

func isScriptLikePath(path string) bool {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".js", ".ps1", ".cmd", ".bat", ".vbs":
		return true
	default:
		return false
	}
}

func observedValue(idx Index, key string) string {
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return ""
	}
	return fmt.Sprint(o.Value)
}

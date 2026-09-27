package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/persistence"
)

type persistenceEvidenceItem struct {
	Key   string
	Entry persistence.Entry
	Obs   evidence.Observation
}

// PersistencePathIntegrityRules implements the path-integrity checks,
// account/privilege correlation, and startup/login exposure
// rules. The checks consume only normalized local persistence/account metadata;
// they do not execute startup targets, inspect target contents, retrieve
// credentials, or mutate persistence.
func PersistencePathIntegrityRules() []Rule {
	rules := []Rule{
		{
			ID: "CHM-PER-001", Title: "Privileged persistence executable and script paths resist lower-privilege modification", Category: "persistence", Severity: SeverityHigh,
			AffectedObject: "persistence.path_integrity.executable", ExpectedState: "executables, referenced scripts, and their containing directories used by privileged persistence are not writable by lower-trust principals",
			Risk:        "A lower-privileged principal that can replace or modify an executable, script, or containing directory used by privileged startup can influence code that later runs with root, SYSTEM, or equivalent authority.",
			Remediation: "Move privileged persistence targets into administrator-controlled locations, restore trusted ownership, and remove broad or lower-trust write access from the executable/script and its containing directory. Reassess the persistence entry after correcting permissions.",
			Evaluate:    func(idx Index) Evaluation { return evaluatePersistenceExecutableIntegrity(idx) },
		},
		{
			ID: "CHM-PER-002", Title: "Privileged persistence definitions and configuration paths resist lower-privilege modification", Category: "persistence", Severity: SeverityHigh,
			AffectedObject: "persistence.path_integrity.definition", ExpectedState: "service/task/startup definitions and containing configuration directories used by privileged persistence are controlled by trusted administrators",
			Risk:        "Writable persistence definitions or configuration paths can let a lower-privileged principal redirect, replace, or alter what a privileged startup mechanism launches even when the target executable itself is protected.",
			Remediation: "Restore trusted ownership and restrictive permissions on privileged persistence definitions and their containing directories. Remove broad write grants and relocate mutable configuration away from privileged launch control paths.",
			Evaluate:    func(idx Index) Evaluation { return evaluatePersistenceDefinitionIntegrity(idx) },
		},
		{
			ID: "CHM-PER-003", Title: "Weak persistence paths are not executed by high-privilege identities", Category: "persistence", Severity: SeverityCritical,
			AffectedObject: "persistence.privilege_correlation", ExpectedState: "no lower-trust-writable persistence path is correlated to root, SYSTEM, local administrator, or equivalent high-privilege execution",
			Risk:        "A weak persistence path becomes materially more dangerous when the startup mechanism is proven to execute as root, SYSTEM, an administrator, or an equivalent privileged account because a lower-trust writer can influence code or configuration that later runs with elevated authority.",
			Remediation: "Treat the correlated path and execution identity as one boundary: remove lower-trust write access from the executable/script/definition and parent path, then reduce the persistence account privilege where the workload does not require administrative authority.",
			Evaluate:    func(idx Index) Evaluation { return evaluatePersistencePrivilegeCorrelation(idx) },
		},
		{
			ID: "CHM-PER-004", Title: "System-wide startup and login configuration is administrator-controlled", Category: "persistence", Severity: SeverityHigh,
			AffectedObject: "persistence.startup.system_control", ExpectedState: "enabled system-wide startup/login entries and their target/configuration boundaries are not modifiable by lower-trust principals",
			Risk:        "A lower-trust principal that can alter a system-wide startup or login entry can cause attacker-controlled code or configuration to be selected automatically for future sessions or boots, even when the mechanism itself does not execute as an administrator.",
			Remediation: "Restore administrator-controlled ownership and permissions on the affected system-wide startup definition, target, and containing directory. Remove broad write grants and relocate mutable launch material into a protected system location.",
			Evaluate:    func(idx Index) Evaluation { return evaluateSystemStartupControl(idx) },
		},
		{
			ID: "CHM-PER-005", Title: "User and login startup boundaries are not writable by unrelated principals", Category: "persistence", Severity: SeverityMedium,
			AffectedObject: "persistence.startup.user_boundary", ExpectedState: "enabled user/login startup entries may be controlled by their owning user but are not writable by unrelated groups, broad local principals, or everyone",
			Risk:        "Broad third-party write access to a user or login startup target or definition lets another local principal influence code that runs automatically in that user's session and can become a lateral or session-hijack boundary.",
			Remediation: "Keep user startup definitions and targets writable only by the owning user and trusted administrators. Remove group/everyone/authenticated-user write grants that are not explicitly required.",
			Evaluate:    func(idx Index) Evaluation { return evaluateUserStartupBoundary(idx) },
		},
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func persistenceItems(idx Index) ([]persistenceEvidenceItem, bool) {
	items := []persistenceEvidenceItem{}
	providerObserved := false
	for key, obs := range idx {
		if strings.HasPrefix(key, "persistence.source.") && obs.State == evidence.StateObserved {
			providerObserved = true
		}
		if !strings.HasPrefix(key, "persistence.entry.") || obs.State != evidence.StateObserved {
			continue
		}
		e, ok := obs.Value.(persistence.Entry)
		if !ok {
			continue
		}
		items = append(items, persistenceEvidenceItem{Key: key, Entry: e, Obs: obs})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Entry.Mechanism != items[j].Entry.Mechanism {
			return items[i].Entry.Mechanism < items[j].Entry.Mechanism
		}
		if strings.ToLower(items[i].Entry.Name) != strings.ToLower(items[j].Entry.Name) {
			return strings.ToLower(items[i].Entry.Name) < strings.ToLower(items[j].Entry.Name)
		}
		return items[i].Entry.ID < items[j].Entry.ID
	})
	return items, providerObserved
}

func privilegedPersistence(items []persistenceEvidenceItem) []persistenceEvidenceItem {
	out := []persistenceEvidenceItem{}
	for _, i := range items {
		if i.Entry.PathIntegrity.Privileged {
			out = append(out, i)
		}
	}
	return out
}

func evaluatePersistenceExecutableIntegrity(idx Index) Evaluation {
	items, observed := persistenceItems(idx)
	if len(items) == 0 {
		return persistenceEmpty(idx, observed, "persistence executable/script path")
	}
	privileged := privilegedPersistence(items)
	if len(privileged) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged persistence records were observed", Applicability: NotApplicable, EvidenceKeys: persistenceInventoryKeys(idx, items)}
	}
	weak := filterPersistence(privileged, func(e persistence.Entry) bool { return persistenceExecutableWeak(e) })
	if len(weak) > 0 {
		return Evaluation{Status: StatusFail, Confidence: persistenceConfidence(weak), ObservedState: fmt.Sprintf("%d privileged persistence record(s) have lower-trust-writable executable/script boundaries", len(weak)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(weak)}
	}
	unresolved := filterPersistence(privileged, func(e persistence.Entry) bool { return persistenceExecutableUnresolved(e) })
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("executable/script permission posture is unresolved for %d privileged persistence record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: persistenceConfidence(privileged), ObservedState: fmt.Sprintf("no lower-trust-writable executable/script boundary observed across %d privileged persistence record(s)", len(privileged)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(privileged)}
}

func evaluatePersistenceDefinitionIntegrity(idx Index) Evaluation {
	items, observed := persistenceItems(idx)
	if len(items) == 0 {
		return persistenceEmpty(idx, observed, "persistence definition/configuration path")
	}
	privileged := privilegedPersistence(items)
	if len(privileged) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged persistence records were observed", Applicability: NotApplicable, EvidenceKeys: persistenceInventoryKeys(idx, items)}
	}
	weak := filterPersistence(privileged, func(e persistence.Entry) bool { return persistenceDefinitionWeak(e) })
	if len(weak) > 0 {
		return Evaluation{Status: StatusFail, Confidence: persistenceConfidence(weak), ObservedState: fmt.Sprintf("%d privileged persistence record(s) have lower-trust-writable definition/configuration boundaries", len(weak)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(weak)}
	}
	unresolved := filterPersistence(privileged, func(e persistence.Entry) bool { return persistenceDefinitionUnresolved(e) })
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("definition/configuration permission posture is unresolved for %d privileged persistence record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: persistenceConfidence(privileged), ObservedState: fmt.Sprintf("no lower-trust-writable definition/configuration boundary observed across %d privileged persistence record(s)", len(privileged)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(privileged)}
}

func evaluatePersistencePrivilegeCorrelation(idx Index) Evaluation {
	items, observed := persistenceItems(idx)
	if len(items) == 0 {
		return persistenceEmpty(idx, observed, "persistence account/privilege correlation")
	}
	critical := filterPersistence(items, func(e persistence.Entry) bool {
		pc := e.PrivilegeCorrelation
		return pc.State == evidence.StateObserved && pc.HighPrivilege && pc.WeakPath
	})
	if len(critical) > 0 {
		return Evaluation{Status: StatusFail, Confidence: persistenceCorrelationConfidence(critical), ObservedState: fmt.Sprintf("%d persistence record(s) combine lower-trust-writable paths with proven high-privilege execution", len(critical)), Applicability: Applicable, EvidenceKeys: persistenceCorrelationEvidenceKeys(idx, critical)}
	}
	unresolved := filterPersistence(items, func(e persistence.Entry) bool {
		return e.PrivilegeCorrelation.WeakPath && e.PrivilegeCorrelation.State != evidence.StateObserved
	})
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("execution privilege is unresolved for %d persistence record(s) with weak path boundaries", len(unresolved)), Applicability: Applicable, EvidenceKeys: persistenceCorrelationEvidenceKeys(idx, unresolved)}
	}
	weakNonPrivileged := filterPersistence(items, func(e persistence.Entry) bool {
		pc := e.PrivilegeCorrelation
		return pc.State == evidence.StateObserved && pc.WeakPath && !pc.HighPrivilege
	})
	if len(weakNonPrivileged) > 0 {
		return Evaluation{Status: StatusPass, Confidence: persistenceCorrelationConfidence(weakNonPrivileged), ObservedState: fmt.Sprintf("%d weak persistence path record(s) were correlated to non-privileged execution; none were proven high privilege", len(weakNonPrivileged)), Applicability: Applicable, EvidenceKeys: persistenceCorrelationEvidenceKeys(idx, weakNonPrivileged)}
	}
	return Evaluation{Status: StatusPass, Confidence: persistenceCorrelationConfidence(items), ObservedState: "no weak persistence path was correlated to high-privilege execution", Applicability: Applicable, EvidenceKeys: persistenceCorrelationEvidenceKeys(idx, items)}
}

func persistenceCorrelationEvidenceKeys(idx Index, items []persistenceEvidenceItem) []string {
	keys := persistenceEvidenceKeys(items)
	for _, item := range items {
		key := "persistence.privilege." + strings.ToLower(strings.TrimSpace(item.Entry.ID))
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func persistenceCorrelationConfidence(items []persistenceEvidenceItem) evidence.Confidence {
	c := persistenceConfidence(items)
	for _, item := range items {
		pc := item.Entry.PrivilegeCorrelation
		switch pc.Confidence {
		case evidence.ConfidenceLow:
			return evidence.ConfidenceLow
		case evidence.ConfidenceMedium:
			if c == evidence.ConfidenceHigh || c == evidence.ConfidenceExact {
				c = evidence.ConfidenceMedium
			}
		case evidence.ConfidenceHigh:
			if c == evidence.ConfidenceExact {
				c = evidence.ConfidenceHigh
			}
		}
	}
	return c
}

func persistenceExecutableWeak(e persistence.Entry) bool {
	p := e.PathIntegrity
	return p.Executable.UntrustedWrite || p.ExecutableDirectory.UntrustedWrite || p.ReferencedScript.UntrustedWrite || p.ReferencedScriptDirectory.UntrustedWrite
}
func persistenceDefinitionWeak(e persistence.Entry) bool {
	p := e.PathIntegrity
	return p.Definition.UntrustedWrite || p.DefinitionDirectory.UntrustedWrite
}
func unresolvedPath(p persistence.PathPosture) bool {
	return p.State != evidence.StateObserved && p.State != evidence.StateNotApplicable
}
func persistenceExecutableUnresolved(e persistence.Entry) bool {
	p := e.PathIntegrity
	return unresolvedPath(p.Executable) || unresolvedPath(p.ExecutableDirectory) || unresolvedPath(p.ReferencedScript) || unresolvedPath(p.ReferencedScriptDirectory)
}
func persistenceDefinitionUnresolved(e persistence.Entry) bool {
	p := e.PathIntegrity
	return unresolvedPath(p.Definition) || unresolvedPath(p.DefinitionDirectory)
}
func filterPersistence(items []persistenceEvidenceItem, fn func(persistence.Entry) bool) []persistenceEvidenceItem {
	out := []persistenceEvidenceItem{}
	for _, i := range items {
		if fn(i.Entry) {
			out = append(out, i)
		}
	}
	return out
}
func persistenceEvidenceKeys(items []persistenceEvidenceItem) []string {
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, i.Key)
	}
	sort.Strings(out)
	return out
}
func persistenceInventoryKeys(idx Index, items []persistenceEvidenceItem) []string {
	keys := persistenceEvidenceKeys(items)
	if _, ok := idx["persistence.summary"]; ok {
		keys = append(keys, "persistence.summary")
	}
	sort.Strings(keys)
	return keys
}
func persistenceConfidence(items []persistenceEvidenceItem) evidence.Confidence {
	c := evidence.ConfidenceExact
	for _, i := range items {
		if i.Obs.Confidence == evidence.ConfidenceLow {
			return evidence.ConfidenceLow
		}
		if i.Obs.Confidence == evidence.ConfidenceMedium {
			c = evidence.ConfidenceMedium
		} else if i.Obs.Confidence == evidence.ConfidenceHigh && c == evidence.ConfidenceExact {
			c = evidence.ConfidenceHigh
		}
	}
	return c
}
func persistenceEmpty(idx Index, providerObserved bool, subject string) Evaluation {
	keys := []string{}
	if _, ok := idx["persistence.summary"]; ok {
		keys = append(keys, "persistence.summary")
	}
	if providerObserved {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no " + subject + " records were observed", Applicability: NotApplicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "persistence provider evidence is unavailable", Applicability: Undetermined, EvidenceKeys: keys}
}

func startupLoginItems(items []persistenceEvidenceItem) []persistenceEvidenceItem {
	out := []persistenceEvidenceItem{}
	for _, item := range items {
		if item.Entry.EnabledState == "DISABLED" || !isStartupLoginMechanism(item.Entry.Mechanism) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func isStartupLoginMechanism(mechanism string) bool {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "RUN_KEY", "RUN_ONCE_KEY", "STARTUP_FOLDER", "SYSTEMD_AUTOSTART", "XDG_AUTOSTART", "RC_LOCAL", "LOGIN_ITEM", "LAUNCHD":
		return true
	default:
		return false
	}
}

func systemStartupScope(e persistence.Entry) bool {
	switch strings.ToUpper(strings.TrimSpace(e.Scope)) {
	case "SYSTEM", "MACHINE":
		return true
	default:
		return false
	}
}

func userStartupScope(e persistence.Entry) bool {
	return strings.EqualFold(strings.TrimSpace(e.Scope), "USER")
}

func allPersistencePathPostures(e persistence.Entry) []persistence.PathPosture {
	p := e.PathIntegrity
	return []persistence.PathPosture{p.Executable, p.ExecutableDirectory, p.ReferencedScript, p.ReferencedScriptDirectory, p.Definition, p.DefinitionDirectory}
}

func systemStartupWeak(e persistence.Entry) bool {
	for _, p := range allPersistencePathPostures(e) {
		if p.State == evidence.StateObserved && p.UntrustedWrite {
			return true
		}
	}
	return false
}

func userStartupBroadWrite(e persistence.Entry) bool {
	for _, p := range allPersistencePathPostures(e) {
		if p.State != evidence.StateObserved {
			continue
		}
		if p.BroadlyWritable {
			return true
		}
		for _, principal := range p.WritePrincipals {
			n := strings.ToLower(strings.TrimSpace(principal))
			if strings.HasPrefix(n, "gid:") || n == "other" || strings.Contains(n, "everyone") || strings.Contains(n, "authenticated") || strings.Contains(n, "builtin\\users") || strings.Contains(n, "built-in users") {
				return true
			}
		}
	}
	return false
}

func startupPathUnresolved(e persistence.Entry) bool {
	useful := false
	for _, p := range allPersistencePathPostures(e) {
		if p.State == evidence.StateNotApplicable {
			continue
		}
		useful = true
		if p.State != evidence.StateObserved {
			return true
		}
	}
	return !useful
}

func evaluateSystemStartupControl(idx Index) Evaluation {
	items, observed := persistenceItems(idx)
	if len(items) == 0 {
		return persistenceEmpty(idx, observed, "startup/login")
	}
	startup := filterPersistence(startupLoginItems(items), systemStartupScope)
	if len(startup) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled system-wide startup/login records were observed", Applicability: NotApplicable, EvidenceKeys: persistenceInventoryKeys(idx, items)}
	}
	weak := filterPersistence(startup, systemStartupWeak)
	if len(weak) > 0 {
		return Evaluation{Status: StatusFail, Confidence: persistenceConfidence(weak), ObservedState: fmt.Sprintf("%d enabled system-wide startup/login record(s) have lower-trust-writable target or configuration boundaries", len(weak)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(weak)}
	}
	unresolved := filterPersistence(startup, startupPathUnresolved)
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("ownership/permission posture is unresolved for %d enabled system-wide startup/login record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: persistenceConfidence(startup), ObservedState: fmt.Sprintf("%d enabled system-wide startup/login record(s) have no observed lower-trust-writable boundary", len(startup)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(startup)}
}

func evaluateUserStartupBoundary(idx Index) Evaluation {
	items, observed := persistenceItems(idx)
	if len(items) == 0 {
		return persistenceEmpty(idx, observed, "user/login startup")
	}
	startup := filterPersistence(startupLoginItems(items), userStartupScope)
	if len(startup) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled user/login startup records were observed", Applicability: NotApplicable, EvidenceKeys: persistenceInventoryKeys(idx, items)}
	}
	weak := filterPersistence(startup, userStartupBroadWrite)
	if len(weak) > 0 {
		return Evaluation{Status: StatusFail, Confidence: persistenceConfidence(weak), ObservedState: fmt.Sprintf("%d enabled user/login startup record(s) are writable by unrelated or broad principals", len(weak)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(weak)}
	}
	unresolved := filterPersistence(startup, startupPathUnresolved)
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("ownership/permission posture is unresolved for %d enabled user/login startup record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: persistenceConfidence(startup), ObservedState: fmt.Sprintf("%d enabled user/login startup record(s) have no observed unrelated-principal write boundary", len(startup)), Applicability: Applicable, EvidenceKeys: persistenceEvidenceKeys(startup)}
}

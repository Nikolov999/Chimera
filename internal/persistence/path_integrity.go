package persistence

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
	"github.com/Nikolov999/chimera/internal/services"
)

// PathPosture is a bounded, metadata-only view of a filesystem path used by a
// persistence mechanism. UntrustedWrite is only asserted when local ownership,
// POSIX mode, or Windows DACL metadata proves that a lower-trust principal can
// modify the path. Unknown ACL/permission state never becomes a clean result.
type PathPosture struct {
	Path                    string              `json:"path,omitempty"`
	State                   evidence.State      `json:"state"`
	Exists                  bool                `json:"exists"`
	Directory               bool                `json:"directory"`
	OwnerID                 string              `json:"owner_id,omitempty"`
	OwnerPrincipal          string              `json:"owner_principal,omitempty"`
	OwnerTrust              string              `json:"owner_trust,omitempty"`
	GroupID                 string              `json:"group_id,omitempty"`
	Mode                    string              `json:"mode,omitempty"`
	PermissionModel         string              `json:"permission_model,omitempty"`
	DACLState               string              `json:"dacl_state,omitempty"`
	BroadlyWritable         bool                `json:"broadly_writable"`
	UntrustedWrite          bool                `json:"untrusted_write"`
	InheritedUntrustedWrite bool                `json:"inherited_untrusted_write"`
	WritePrincipals         []string            `json:"write_principals,omitempty"`
	ResolvedPath            string              `json:"resolved_path,omitempty"`
	CollectionSource        string              `json:"collection_source"`
	Confidence              evidence.Confidence `json:"confidence"`
	Reason                  string              `json:"reason,omitempty"`
}

// PathIntegrity joins a persistence record to executable/script/configuration
// path metadata. intentionally does not execute, open, or parse the
// target program/script content; it assesses only path ownership/permissions.
type PathIntegrity struct {
	State                     evidence.State `json:"state"`
	Privileged                bool           `json:"privileged"`
	PrivilegeBasis            string         `json:"privilege_basis"`
	Executable                PathPosture    `json:"executable"`
	ExecutableDirectory       PathPosture    `json:"executable_directory"`
	ReferencedScript          PathPosture    `json:"referenced_script"`
	ReferencedScriptDirectory PathPosture    `json:"referenced_script_directory"`
	Definition                PathPosture    `json:"definition"`
	DefinitionDirectory       PathPosture    `json:"definition_directory"`
	WeakRoles                 []string       `json:"weak_roles,omitempty"`
	Degraded                  []string       `json:"degraded,omitempty"`
}

func pathNotApplicable(source string) PathPosture {
	return PathPosture{State: evidence.StateNotApplicable, CollectionSource: source, Confidence: evidence.ConfidenceExact, Reason: "path is not represented by this persistence record"}
}

func privilegedContext(v string) (bool, string) {
	n := normalizeWord(v)
	switch n {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT", "ADMINISTRATOR":
		return true, n
	default:
		return false, n
	}
}

func composeServicePathIntegrity(s services.Service) PathIntegrity {
	privileged, basis := privilegedContext(s.PrivilegeContext)
	p := PathIntegrity{State: evidence.StateDegraded, Privileged: privileged, PrivilegeBasis: basis}
	if s.PathIntegrity == nil {
		p.Executable = unassessedPath(s.ExecutablePath, "service path-integrity metadata unavailable")
		p.ExecutableDirectory = unassessedContainingDirectory(s.ExecutablePath, "service path-integrity metadata unavailable")
		p.ReferencedScript = pathNotApplicable("service path-integrity metadata")
		p.ReferencedScriptDirectory = pathNotApplicable("service path-integrity metadata")
		p.Definition = unassessedPath(s.DefinitionPath, "service path-integrity metadata unavailable")
		p.DefinitionDirectory = unassessedContainingDirectory(s.DefinitionPath, "service path-integrity metadata unavailable")
		p.Degraded = []string{"service path-integrity metadata unavailable"}
		return normalizePathIntegrity(p)
	}
	sp := s.PathIntegrity
	p.Privileged = sp.Privileged
	p.PrivilegeBasis = fallback(sp.PrivilegeBasis, basis)
	p.Executable = servicePathPosture(sp.Executable, "service path-integrity metadata")
	p.ExecutableDirectory = servicePathPosture(sp.ExecutableDirectory, "service path-integrity metadata")
	p.ReferencedScript = pathNotApplicable("service path-integrity metadata")
	p.ReferencedScriptDirectory = pathNotApplicable("service path-integrity metadata")
	p.Definition = servicePathPosture(sp.Configuration, "service path-integrity metadata")
	p.DefinitionDirectory = servicePathPosture(sp.ConfigurationDirectory, "service path-integrity metadata")
	p.Degraded = append(p.Degraded, sp.Degraded...)
	return normalizePathIntegrity(p)
}

func servicePathPosture(in services.PathPosture, source string) PathPosture {
	st := persistenceState(in.State)
	p := PathPosture{Path: strings.TrimSpace(in.Path), State: st, OwnerID: strings.TrimSpace(in.Owner), GroupID: strings.TrimSpace(in.Group), Mode: strings.TrimSpace(in.Mode), PermissionModel: "service path-integrity provider", BroadlyWritable: in.LowerPrivilegeWritable, UntrustedWrite: in.LowerPrivilegeWritable, WritePrincipals: append([]string(nil), in.Principals...), CollectionSource: source, Confidence: evidence.ConfidenceHigh, Reason: strings.TrimSpace(in.Reason)}
	if st == evidence.StateObserved {
		p.Exists = true
	}
	if p.Path != "" && filepath.Ext(p.Path) == "" && strings.HasSuffix(strings.ToLower(in.Reason), "directory") {
		p.Directory = true
	}
	return normalizePathPosture(p)
}

func composeScheduledPathIntegrity(s scheduled.Entry) PathIntegrity {
	privileged, basis := privilegedContext(s.PrivilegeContext)
	p := PathIntegrity{
		State: evidence.StateObserved, Privileged: privileged, PrivilegeBasis: basis,
		Executable:                scheduledPathPosture(s.ActionPath, "scheduled-execution path metadata"),
		ExecutableDirectory:       scheduledPathPosture(s.ActionDirectoryPosture, "scheduled-execution path metadata"),
		ReferencedScript:          scheduledPathPosture(s.ReferencedScriptPathPosture, "scheduled-execution path metadata"),
		ReferencedScriptDirectory: pathNotApplicable("scheduled-execution path metadata"),
		Definition:                scheduledPathPosture(s.DefinitionPathPosture, "scheduled-execution path metadata"),
		DefinitionDirectory:       scheduledPathPosture(s.DefinitionDirectoryPosture, "scheduled-execution path metadata"),
	}
	if s.ReferencedScriptPath != "" {
		p.ReferencedScriptDirectory = derivedDirectoryPosture(p.ReferencedScript, "scheduled-execution path metadata")
	}
	return normalizePathIntegrity(p)
}

func scheduledPathPosture(in scheduled.PathPosture, source string) PathPosture {
	st := persistenceState(in.State)
	ownerID := strings.TrimSpace(in.OwnerSID)
	if ownerID == "" {
		ownerID = strings.TrimSpace(in.Owner)
	}
	reason := strings.TrimSpace(in.Reason)
	if st == evidence.StateObserved && in.UntrustedWritable && reason == "" {
		reason = "lower-trust principal can modify the persistence path"
		if len(in.WritePrincipals) > 0 {
			reason += ": " + strings.Join(uniqueSorted(in.WritePrincipals), ", ")
		}
	}
	return normalizePathPosture(PathPosture{
		Path: strings.TrimSpace(in.Path), State: st, Exists: in.Exists, Directory: in.IsDirectory,
		OwnerID: ownerID, OwnerPrincipal: strings.TrimSpace(in.Owner), OwnerTrust: strings.TrimSpace(in.OwnerTrust),
		GroupID: strings.TrimSpace(in.Group), Mode: strings.TrimSpace(in.Mode),
		PermissionModel: fallback(in.PermissionBasis, "scheduled-execution permission metadata"), DACLState: strings.TrimSpace(in.DACLState),
		BroadlyWritable: in.BroadlyWritable || in.OtherWritable, UntrustedWrite: in.UntrustedWritable,
		InheritedUntrustedWrite: in.InheritedUntrustedWrite, WritePrincipals: append([]string(nil), in.WritePrincipals...),
		CollectionSource: source, Confidence: evidence.ConfidenceHigh, Reason: reason,
	})
}

func derivedDirectoryPosture(file PathPosture, source string) PathPosture {
	if strings.TrimSpace(file.Path) == "" {
		return pathNotApplicable(source)
	}
	return PathPosture{Path: filepath.Dir(file.Path), State: evidence.StateUnavailable, CollectionSource: source, Confidence: evidence.ConfidenceMedium, Reason: "directory permission metadata was not included by the upstream scheduled-execution record"}
}

func unassessedPath(path, reason string) PathPosture {
	path = strings.TrimSpace(path)
	if path == "" {
		return pathNotApplicable("persistence path-integrity composition")
	}
	return PathPosture{Path: path, State: evidence.StateUnavailable, CollectionSource: "persistence path-integrity composition", Confidence: evidence.ConfidenceMedium, Reason: reason}
}

func unassessedContainingDirectory(path, reason string) PathPosture {
	path = strings.TrimSpace(path)
	if path == "" {
		return pathNotApplicable("persistence path-integrity composition")
	}
	return PathPosture{Path: filepath.Dir(path), State: evidence.StateUnavailable, Directory: true, CollectionSource: "persistence path-integrity composition", Confidence: evidence.ConfidenceMedium, Reason: reason}
}

func normalizeOptionalWord(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return normalizeWord(v)
}

func persistenceState(v string) evidence.State {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "OBSERVED", "COMPLETE":
		return evidence.StateObserved
	case "DEGRADED":
		return evidence.StateDegraded
	case "DENIED":
		return evidence.StateDenied
	case "UNSUPPORTED":
		return evidence.StateUnsupported
	case "NOT_APPLICABLE":
		return evidence.StateNotApplicable
	default:
		return evidence.StateUnavailable
	}
}

func normalizePathIntegrity(p PathIntegrity) PathIntegrity {
	if strings.TrimSpace(p.PrivilegeBasis) == "" {
		p.PrivilegeBasis = "UNKNOWN"
	}
	p.Executable = normalizePathPosture(p.Executable)
	p.ExecutableDirectory = normalizePathPosture(p.ExecutableDirectory)
	p.ReferencedScript = normalizePathPosture(p.ReferencedScript)
	p.ReferencedScriptDirectory = normalizePathPosture(p.ReferencedScriptDirectory)
	p.Definition = normalizePathPosture(p.Definition)
	p.DefinitionDirectory = normalizePathPosture(p.DefinitionDirectory)
	p.WeakRoles = nil
	roles := []struct {
		name string
		path PathPosture
	}{
		{"executable", p.Executable}, {"executable-directory", p.ExecutableDirectory}, {"referenced-script", p.ReferencedScript}, {"referenced-script-directory", p.ReferencedScriptDirectory}, {"definition", p.Definition}, {"definition-directory", p.DefinitionDirectory},
	}
	unresolved := 0
	applicable := 0
	for _, r := range roles {
		if r.path.State == evidence.StateNotApplicable {
			continue
		}
		applicable++
		if r.path.State == evidence.StateObserved && r.path.UntrustedWrite {
			p.WeakRoles = append(p.WeakRoles, r.name)
		}
		if r.path.State != evidence.StateObserved {
			unresolved++
			if r.path.Reason != "" {
				p.Degraded = append(p.Degraded, r.name+": "+r.path.Reason)
			}
		}
	}
	p.WeakRoles = uniqueSorted(p.WeakRoles)
	p.Degraded = uniqueSorted(p.Degraded)
	switch {
	case applicable == 0:
		p.State = evidence.StateNotApplicable
	case unresolved > 0:
		p.State = evidence.StateDegraded
	default:
		p.State = evidence.StateObserved
	}
	return p
}

func normalizePathPosture(p PathPosture) PathPosture {
	if p.State == "" {
		p.State = evidence.StateUnavailable
	}
	p.Path = strings.TrimSpace(p.Path)
	p.OwnerID = strings.TrimSpace(p.OwnerID)
	p.OwnerPrincipal = strings.TrimSpace(p.OwnerPrincipal)
	p.OwnerTrust = normalizeOptionalWord(p.OwnerTrust)
	if p.OwnerTrust == "" {
		if p.State == evidence.StateNotApplicable {
			p.OwnerTrust = "NOT_APPLICABLE"
		} else {
			p.OwnerTrust = "UNKNOWN"
		}
	}
	p.GroupID = strings.TrimSpace(p.GroupID)
	p.Mode = strings.TrimSpace(p.Mode)
	p.PermissionModel = strings.TrimSpace(p.PermissionModel)
	p.DACLState = normalizeOptionalWord(p.DACLState)
	if p.DACLState == "" {
		if strings.Contains(strings.ToUpper(p.PermissionModel), "WINDOWS") {
			p.DACLState = string(p.State)
		} else {
			p.DACLState = "NOT_APPLICABLE"
		}
	}
	p.ResolvedPath = strings.TrimSpace(p.ResolvedPath)
	p.CollectionSource = fallback(p.CollectionSource, "persistence path permission metadata")
	p.WritePrincipals = uniqueSorted(p.WritePrincipals)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Confidence == "" {
		p.Confidence = evidence.ConfidenceMedium
	}
	return p
}

func (p PathPosture) validate(label string) error {
	switch p.State {
	case evidence.StateObserved, evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateNotApplicable:
	default:
		return fmt.Errorf("%s has invalid path state %q", label, p.State)
	}
	if strings.TrimSpace(p.CollectionSource) == "" || p.Confidence == "" {
		return fmt.Errorf("%s path provenance is incomplete", label)
	}
	switch p.OwnerTrust {
	case "TRUSTED", "UNTRUSTED", "UNKNOWN", "NOT_APPLICABLE":
	default:
		return fmt.Errorf("%s has invalid owner-trust state %q", label, p.OwnerTrust)
	}
	switch p.DACLState {
	case "OBSERVED", "DEGRADED", "DENIED", "UNAVAILABLE", "UNSUPPORTED", "NOT_APPLICABLE":
	default:
		return fmt.Errorf("%s has invalid DACL state %q", label, p.DACLState)
	}
	if p.UntrustedWrite && p.State != evidence.StateObserved {
		return fmt.Errorf("%s cannot assert untrusted write without observed metadata", label)
	}
	if p.InheritedUntrustedWrite && !p.UntrustedWrite {
		return fmt.Errorf("%s inherited untrusted write requires an untrusted write assertion", label)
	}
	if !sort.StringsAreSorted(p.WritePrincipals) {
		return fmt.Errorf("%s write principals are not deterministically ordered", label)
	}
	return nil
}

func (p PathIntegrity) validate() error {
	for label, posture := range map[string]PathPosture{
		"executable": p.Executable, "executable_directory": p.ExecutableDirectory,
		"referenced_script": p.ReferencedScript, "referenced_script_directory": p.ReferencedScriptDirectory,
		"definition": p.Definition, "definition_directory": p.DefinitionDirectory,
	} {
		if err := posture.validate(label); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.PrivilegeBasis) == "" {
		return fmt.Errorf("persistence privilege basis is required")
	}
	if !sort.StringsAreSorted(p.WeakRoles) || !sort.StringsAreSorted(p.Degraded) {
		return fmt.Errorf("persistence path-integrity lists must be deterministically ordered")
	}
	return nil
}

func entryHasWeakExecutableBoundary(e Entry) bool {
	p := e.PathIntegrity
	return p.Executable.UntrustedWrite || p.ExecutableDirectory.UntrustedWrite || p.ReferencedScript.UntrustedWrite || p.ReferencedScriptDirectory.UntrustedWrite
}

func entryHasWeakDefinitionBoundary(e Entry) bool {
	p := e.PathIntegrity
	return p.Definition.UntrustedWrite || p.DefinitionDirectory.UntrustedWrite
}

func entryPathIntegrityUnresolved(e Entry) bool {
	if e.PathIntegrity.State == evidence.StateDegraded || e.PathIntegrity.State == evidence.StateDenied || e.PathIntegrity.State == evidence.StateUnavailable {
		return true
	}
	return false
}

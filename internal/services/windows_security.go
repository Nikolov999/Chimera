package services

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/windowsacl"
)

// WindowsACLPosture is a bounded normalized Windows ACL summary relevant to
// service execution and configuration integrity. Registry ACLs may additionally
// retain SID-first ACE metadata so unresolved account names do not erase rights
// evidence; file ACL providers continue to use the compact summary fields.
type WindowsACLPosture struct {
	State             string            `json:"state"`
	Stage             string            `json:"stage,omitempty"`
	AcquisitionMethod string            `json:"acquisition_method,omitempty"`
	BroadWriteGranted bool              `json:"broad_write_granted"`
	Principals        []string          `json:"principals,omitempty"`
	Rights            []string          `json:"rights,omitempty"`
	OwnerSID          string            `json:"owner_sid,omitempty"`
	InheritedWrite    bool              `json:"inherited_write"`
	Entries           []WindowsACLEntry `json:"entries,omitempty"`
	Reason            string            `json:"reason,omitempty"`
}

// WindowsACLEntry preserves one normalized Windows ACL rule without requiring
// principal-name resolution to succeed. Registry ACL collection uses SID-based
// enumeration so an unresolved account name cannot destroy authoritative SID
// and rights evidence.
type WindowsACLEntry struct {
	SID                       string   `json:"sid,omitempty"`
	Principal                 string   `json:"principal,omitempty"`
	PrincipalResolution       string   `json:"principal_resolution,omitempty"`
	PrincipalResolutionReason string   `json:"principal_resolution_reason,omitempty"`
	AccessType                string   `json:"access_type,omitempty"`
	Inherited                 bool     `json:"inherited"`
	Explicit                  bool     `json:"explicit"`
	InheritanceFlags          string   `json:"inheritance_flags,omitempty"`
	PropagationFlags          string   `json:"propagation_flags,omitempty"`
	Rights                    string   `json:"rights,omitempty"`
	RightsMask                int64    `json:"rights_mask"`
	AtomicMutatingRights      []string `json:"atomic_mutating_rights,omitempty"`
}

// WindowsServiceACLPosture summarizes the Service Control Manager object's
// DACL. The raw SDDL is parsed transiently and is not retained in output.
type WindowsServiceACLPosture struct {
	State       string   `json:"state"`
	Weak        bool     `json:"weak"`
	Dangerous   bool     `json:"dangerous"`
	ControlOnly bool     `json:"control_only"`
	Principals  []string `json:"principals,omitempty"`
	Rights      []string `json:"rights,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// WindowsSecurityComponents exposes independent enrichment coverage. Optional
// service-DLL and recovery dimensions are NOT_APPLICABLE when the service does
// not use them; one unavailable dimension does not erase evidence from others.
type WindowsSecurityComponents struct {
	ServiceObject            string `json:"service_object"`
	ExecutableACL            string `json:"executable_acl"`
	ExecutableDirectoryACL   string `json:"executable_directory_acl"`
	RegistryMetadata         string `json:"registry_metadata"`
	RegistryACL              string `json:"registry_acl"`
	ServiceDLLMetadata       string `json:"service_dll_metadata"`
	ServiceDLLACL            string `json:"service_dll_acl"`
	ServiceDLLDirectoryACL   string `json:"service_dll_directory_acl"`
	RecoveryConfiguration    string `json:"recovery_configuration"`
	RecoveryExecutableACL    string `json:"recovery_executable_acl"`
	RecoveryExecutableDirACL string `json:"recovery_executable_directory_acl"`
	Account                  string `json:"account"`
}

// WindowsSecurity is additive service security metadata. Command
// arguments and recovery-command values are intentionally discarded after
// extracting only the executable path and posture flags needed for assessment.
type WindowsSecurity struct {
	State                         string                    `json:"state"`
	UnquotedExecutablePath        bool                      `json:"unquoted_executable_path"`
	ExecutableResolution          string                    `json:"executable_resolution"`
	ExecutableACL                 WindowsACLPosture         `json:"executable_acl"`
	ExecutableDirectoryACL        WindowsACLPosture         `json:"executable_directory_acl"`
	ServiceDLLPath                string                    `json:"service_dll_path,omitempty"`
	ServiceDLLState               string                    `json:"service_dll_state"`
	ServiceDLLReason              string                    `json:"service_dll_reason,omitempty"`
	ServiceDLLACL                 WindowsACLPosture         `json:"service_dll_acl"`
	ServiceDLLDirectoryACL        WindowsACLPosture         `json:"service_dll_directory_acl"`
	ServiceACL                    WindowsServiceACLPosture  `json:"service_acl"`
	AccountAdminState             string                    `json:"account_admin_state"`
	AccountAdminReason            string                    `json:"account_admin_reason,omitempty"`
	RegistryState                 string                    `json:"registry_state"`
	RegistryReason                string                    `json:"registry_reason,omitempty"`
	RegistryACL                   WindowsACLPosture         `json:"registry_acl"`
	InteractiveProcess            bool                      `json:"interactive_process"`
	FailureCommandPresent         bool                      `json:"failure_command_present"`
	FailureCommandState           string                    `json:"failure_command_state"`
	FailureCommandReason          string                    `json:"failure_command_reason,omitempty"`
	FailureExecutablePath         string                    `json:"failure_executable_path,omitempty"`
	FailureExecutableUnquoted     bool                      `json:"failure_executable_unquoted"`
	FailureExecutableACL          WindowsACLPosture         `json:"failure_executable_acl"`
	FailureExecutableDirectoryACL WindowsACLPosture         `json:"failure_executable_directory_acl"`
	Components                    WindowsSecurityComponents `json:"components"`
	Degraded                      []string                  `json:"degraded,omitempty"`
}

type windowsPathACLRecord struct {
	State             string                  `json:"state"`
	Stage             string                  `json:"stage"`
	AcquisitionMethod string                  `json:"acquisition_method"`
	BroadWriteGranted bool                    `json:"broad_write_granted"`
	Principals        []string                `json:"principals"`
	Rights            []string                `json:"rights"`
	OwnerSID          string                  `json:"owner_sid"`
	InheritedWrite    bool                    `json:"inherited_write"`
	Entries           []windowsACLEntryRecord `json:"entries"`
	Reason            string                  `json:"reason"`
}

type windowsACLEntryRecord struct {
	SID                       string   `json:"sid"`
	Principal                 string   `json:"principal"`
	PrincipalResolution       string   `json:"principal_resolution"`
	PrincipalResolutionReason string   `json:"principal_resolution_reason"`
	AccessType                string   `json:"access_type"`
	Inherited                 bool     `json:"inherited"`
	Explicit                  bool     `json:"explicit"`
	InheritanceFlags          string   `json:"inheritance_flags"`
	PropagationFlags          string   `json:"propagation_flags"`
	Rights                    string   `json:"rights"`
	RightsMask                int64    `json:"rights_mask"`
	AtomicMutatingRights      []string `json:"atomic_mutating_rights"`
}

type windowsSecurityRecord struct {
	ServiceSDDL                   string               `json:"service_sddl"`
	ServiceACLState               string               `json:"service_acl_state"`
	ServiceACLReason              string               `json:"service_acl_reason"`
	AccountAdminState             string               `json:"account_admin_state"`
	AccountAdminReason            string               `json:"account_admin_reason"`
	RegistryState                 string               `json:"registry_state"`
	RegistryReason                string               `json:"registry_reason"`
	RegistryACL                   windowsPathACLRecord `json:"registry_acl"`
	InteractiveProcess            bool                 `json:"interactive_process"`
	ExecutableACL                 windowsPathACLRecord `json:"executable_acl"`
	ExecutableDirectoryACL        windowsPathACLRecord `json:"executable_directory_acl"`
	ServiceDLLPath                string               `json:"service_dll_path"`
	ServiceDLLState               string               `json:"service_dll_state"`
	ServiceDLLReason              string               `json:"service_dll_reason"`
	ServiceDLLACL                 windowsPathACLRecord `json:"service_dll_acl"`
	ServiceDLLDirectoryACL        windowsPathACLRecord `json:"service_dll_directory_acl"`
	FailureCommandPresent         bool                 `json:"failure_command_present"`
	FailureCommandState           string               `json:"failure_command_state"`
	FailureCommandReason          string               `json:"failure_command_reason"`
	FailureExecutablePath         string               `json:"failure_executable_path"`
	FailureExecutableUnquoted     bool                 `json:"failure_executable_unquoted"`
	FailureExecutableACL          windowsPathACLRecord `json:"failure_executable_acl"`
	FailureExecutableDirectoryACL windowsPathACLRecord `json:"failure_executable_directory_acl"`
	Errors                        []string             `json:"errors"`
}

func normalizeWindowsSecurity(raw windowsSecurityRecord, rawImagePath, executablePath string) *WindowsSecurity {
	serviceACL := parseWindowsServiceSDDL(raw.ServiceSDDL)
	if strings.TrimSpace(raw.ServiceSDDL) == "" {
		state := normalizeSecurityState(raw.ServiceACLState)
		if state == "" {
			state = "UNAVAILABLE"
		}
		serviceACL.State = state
		serviceACL.Reason = strings.TrimSpace(raw.ServiceACLReason)
		if serviceACL.Reason == "" && state != "OBSERVED" {
			serviceACL.Reason = "service object security descriptor unavailable"
		}
	}
	resolution := windowsExecutableResolution(rawImagePath, executablePath)
	sec := &WindowsSecurity{
		UnquotedExecutablePath:        resolution == "UNQUOTED",
		ExecutableResolution:          resolution,
		ExecutableACL:                 normalizeWindowsACL(raw.ExecutableACL),
		ExecutableDirectoryACL:        normalizeWindowsACL(raw.ExecutableDirectoryACL),
		ServiceDLLPath:                cleanWindowsSecurityPath(raw.ServiceDLLPath),
		ServiceDLLState:               normalizeOptionalSecurityMetadataState(raw.ServiceDLLState, strings.TrimSpace(raw.ServiceDLLPath) != ""),
		ServiceDLLReason:              strings.TrimSpace(raw.ServiceDLLReason),
		ServiceDLLACL:                 normalizeWindowsACL(raw.ServiceDLLACL),
		ServiceDLLDirectoryACL:        normalizeWindowsACL(raw.ServiceDLLDirectoryACL),
		ServiceACL:                    serviceACL,
		AccountAdminState:             normalizeTriState(raw.AccountAdminState),
		AccountAdminReason:            strings.TrimSpace(raw.AccountAdminReason),
		RegistryState:                 normalizeSecurityState(raw.RegistryState),
		RegistryReason:                strings.TrimSpace(raw.RegistryReason),
		RegistryACL:                   normalizeWindowsACL(raw.RegistryACL),
		InteractiveProcess:            raw.InteractiveProcess,
		FailureCommandPresent:         raw.FailureCommandPresent,
		FailureCommandState:           normalizeOptionalSecurityMetadataState(raw.FailureCommandState, raw.FailureCommandPresent),
		FailureCommandReason:          strings.TrimSpace(raw.FailureCommandReason),
		FailureExecutablePath:         cleanWindowsSecurityPath(raw.FailureExecutablePath),
		FailureExecutableUnquoted:     raw.FailureExecutableUnquoted,
		FailureExecutableACL:          normalizeWindowsACL(raw.FailureExecutableACL),
		FailureExecutableDirectoryACL: normalizeWindowsACL(raw.FailureExecutableDirectoryACL),
		Degraded:                      uniqueSorted(raw.Errors),
	}
	if sec.ServiceDLLState == "OBSERVED" && strings.TrimSpace(sec.ServiceDLLPath) == "" {
		sec.ServiceDLLState = "UNAVAILABLE"
		sec.ServiceDLLReason = fallback(sec.ServiceDLLReason, "ServiceDll is configured but its executable path could not be resolved")
	}
	if sec.FailureCommandState == "OBSERVED" && sec.FailureCommandPresent && strings.TrimSpace(sec.FailureExecutablePath) == "" {
		sec.FailureCommandState = "UNAVAILABLE"
		sec.FailureCommandReason = fallback(sec.FailureCommandReason, "recovery command is configured but its executable path could not be resolved")
	}
	sec.refreshComponents()
	sec.appendComponentDegradation()
	sec.Degraded = uniqueSorted(sec.Degraded)
	sec.State = "COMPLETE"
	for _, state := range sec.componentStates() {
		if state != "OBSERVED" && state != "NOT_APPLICABLE" {
			sec.State = "DEGRADED"
			break
		}
	}
	return sec
}

func unavailableWindowsSecurity(reason string) *WindowsSecurity {
	reason = fallback(strings.TrimSpace(reason), "Windows service security metadata unavailable")
	unavailable := WindowsACLPosture{State: "UNAVAILABLE", Reason: reason}
	sec := &WindowsSecurity{
		State:                         "DEGRADED",
		ExecutableResolution:          "UNAVAILABLE",
		ExecutableACL:                 unavailable,
		ExecutableDirectoryACL:        unavailable,
		ServiceDLLState:               "UNAVAILABLE",
		ServiceDLLReason:              reason,
		ServiceDLLACL:                 WindowsACLPosture{State: "UNAVAILABLE", Reason: reason},
		ServiceDLLDirectoryACL:        WindowsACLPosture{State: "UNAVAILABLE", Reason: reason},
		ServiceACL:                    WindowsServiceACLPosture{State: "UNAVAILABLE", Reason: reason},
		AccountAdminState:             "UNKNOWN",
		AccountAdminReason:            reason,
		RegistryState:                 "UNAVAILABLE",
		RegistryReason:                reason,
		RegistryACL:                   unavailable,
		FailureCommandState:           "UNAVAILABLE",
		FailureCommandReason:          reason,
		FailureExecutableACL:          WindowsACLPosture{State: "UNAVAILABLE", Reason: reason},
		FailureExecutableDirectoryACL: WindowsACLPosture{State: "UNAVAILABLE", Reason: reason},
		Degraded:                      []string{reason},
	}
	sec.refreshComponents()
	return sec
}

func (s *WindowsSecurity) refreshComponents() {
	if s == nil {
		return
	}
	s.ServiceDLLState = normalizeOptionalSecurityMetadataState(s.ServiceDLLState, strings.TrimSpace(s.ServiceDLLPath) != "")
	s.FailureCommandState = normalizeOptionalSecurityMetadataState(s.FailureCommandState, s.FailureCommandPresent)
	s.Components.ServiceObject = componentState(s.ServiceACL.State)
	s.Components.ExecutableACL = componentState(s.ExecutableACL.State)
	s.Components.ExecutableDirectoryACL = componentState(s.ExecutableDirectoryACL.State)
	s.Components.RegistryMetadata = componentState(s.RegistryState)
	s.Components.RegistryACL = componentState(s.RegistryACL.State)
	s.Components.ServiceDLLMetadata = componentState(s.ServiceDLLState)
	if s.Components.ServiceDLLMetadata == "NOT_APPLICABLE" {
		s.Components.ServiceDLLACL = "NOT_APPLICABLE"
		s.Components.ServiceDLLDirectoryACL = "NOT_APPLICABLE"
	} else if s.Components.ServiceDLLMetadata != "OBSERVED" {
		s.Components.ServiceDLLACL = s.Components.ServiceDLLMetadata
		s.Components.ServiceDLLDirectoryACL = s.Components.ServiceDLLMetadata
	} else {
		s.Components.ServiceDLLACL = componentState(s.ServiceDLLACL.State)
		s.Components.ServiceDLLDirectoryACL = componentState(s.ServiceDLLDirectoryACL.State)
	}
	s.Components.RecoveryConfiguration = componentState(s.FailureCommandState)
	if s.Components.RecoveryConfiguration == "NOT_APPLICABLE" {
		s.Components.RecoveryExecutableACL = "NOT_APPLICABLE"
		s.Components.RecoveryExecutableDirACL = "NOT_APPLICABLE"
	} else if s.Components.RecoveryConfiguration != "OBSERVED" {
		s.Components.RecoveryExecutableACL = s.Components.RecoveryConfiguration
		s.Components.RecoveryExecutableDirACL = s.Components.RecoveryConfiguration
	} else {
		s.Components.RecoveryExecutableACL = componentState(s.FailureExecutableACL.State)
		s.Components.RecoveryExecutableDirACL = componentState(s.FailureExecutableDirectoryACL.State)
	}
	if s.AccountAdminState == "YES" || s.AccountAdminState == "NO" {
		s.Components.Account = "OBSERVED"
	} else {
		s.Components.Account = "UNAVAILABLE"
	}
}

func (s WindowsSecurity) componentStates() []string {
	return []string{
		s.Components.ServiceObject,
		s.Components.ExecutableACL,
		s.Components.ExecutableDirectoryACL,
		s.Components.RegistryMetadata,
		s.Components.RegistryACL,
		s.Components.ServiceDLLMetadata,
		s.Components.ServiceDLLACL,
		s.Components.ServiceDLLDirectoryACL,
		s.Components.RecoveryConfiguration,
		s.Components.RecoveryExecutableACL,
		s.Components.RecoveryExecutableDirACL,
		s.Components.Account,
	}
}

func (s *WindowsSecurity) appendComponentDegradation() {
	if s == nil {
		return
	}
	appendACL := func(label string, acl WindowsACLPosture, applicable bool) {
		if !applicable || acl.State == "OBSERVED" || acl.State == "NOT_APPLICABLE" {
			return
		}
		s.Degraded = append(s.Degraded, label+": "+fallback(acl.Reason, strings.ToLower(acl.State)))
	}
	if s.ServiceACL.State != "OBSERVED" && s.ServiceACL.State != "NOT_APPLICABLE" {
		s.Degraded = append(s.Degraded, "service object ACL: "+fallback(s.ServiceACL.Reason, strings.ToLower(s.ServiceACL.State)))
	}
	appendACL("service executable ACL", s.ExecutableACL, true)
	appendACL("service executable directory ACL", s.ExecutableDirectoryACL, true)
	if s.RegistryState != "OBSERVED" && s.RegistryState != "NOT_APPLICABLE" {
		s.Degraded = append(s.Degraded, "service registry metadata: "+fallback(s.RegistryReason, strings.ToLower(s.RegistryState)))
	}
	appendACL("service registry ACL", s.RegistryACL, true)
	if s.ServiceDLLState != "OBSERVED" && s.ServiceDLLState != "NOT_APPLICABLE" {
		s.Degraded = append(s.Degraded, "service DLL metadata: "+fallback(s.ServiceDLLReason, strings.ToLower(s.ServiceDLLState)))
	}
	serviceDLLApplicable := s.ServiceDLLState == "OBSERVED"
	appendACL("service DLL ACL", s.ServiceDLLACL, serviceDLLApplicable)
	appendACL("service DLL directory ACL", s.ServiceDLLDirectoryACL, serviceDLLApplicable)
	if s.FailureCommandState != "OBSERVED" && s.FailureCommandState != "NOT_APPLICABLE" {
		s.Degraded = append(s.Degraded, "service recovery configuration: "+fallback(s.FailureCommandReason, strings.ToLower(s.FailureCommandState)))
	}
	recoveryApplicable := s.FailureCommandState == "OBSERVED"
	appendACL("service recovery executable ACL", s.FailureExecutableACL, recoveryApplicable)
	appendACL("service recovery executable directory ACL", s.FailureExecutableDirectoryACL, recoveryApplicable)
	if s.AccountAdminState == "UNKNOWN" {
		s.Degraded = append(s.Degraded, "account classification: "+fallback(s.AccountAdminReason, "local Administrators membership unresolved"))
	}
}

func componentState(state string) string {
	state = normalizeSecurityState(state)
	if state == "" {
		return "UNAVAILABLE"
	}
	return state
}

func combineSecurityComponentStates(states ...string) string {
	seenObserved := false
	allNotApplicable := true
	worst := ""
	for _, state := range states {
		state = componentState(state)
		switch state {
		case "OBSERVED":
			seenObserved = true
			allNotApplicable = false
		case "NOT_APPLICABLE":
		case "DENIED":
			allNotApplicable = false
			if worst == "" {
				worst = "DENIED"
			}
		case "DEGRADED":
			allNotApplicable = false
			worst = "DEGRADED"
		default:
			allNotApplicable = false
			if worst == "" || worst == "DENIED" {
				worst = "UNAVAILABLE"
			}
		}
	}
	if worst != "" {
		return worst
	}
	if allNotApplicable {
		return "NOT_APPLICABLE"
	}
	if seenObserved {
		return "OBSERVED"
	}
	return "UNAVAILABLE"
}

func aggregateSecurityStates(states ...string) string {
	seenObserved := false
	allNotApplicable := true
	for _, state := range states {
		state = componentState(state)
		switch state {
		case "OBSERVED":
			seenObserved = true
			allNotApplicable = false
		case "NOT_APPLICABLE":
		default:
			return "DEGRADED"
		}
	}
	if allNotApplicable {
		return "NOT_APPLICABLE"
	}
	if seenObserved {
		return "OBSERVED"
	}
	return "DEGRADED"
}

func normalizeWindowsACL(raw windowsPathACLRecord) WindowsACLPosture {
	state := normalizeSecurityState(raw.State)
	if state == "" {
		state = "UNAVAILABLE"
	}
	entries := normalizeWindowsACLEntries(raw.Entries)
	broadWrite := raw.BroadWriteGranted
	principals := uniqueSorted(raw.Principals)
	rights := uniqueSorted(raw.Rights)
	inheritedWrite := raw.InheritedWrite
	// Fix36 registry ACL records carry full SID-based ACE metadata. Recompute the
	// broad mutation summary from atomic RegistryRights in Go so the release
	// decision does not depend on PowerShell enum string formatting. File ACL
	// records currently have no Entries and retain their existing summary.
	if len(entries) > 0 {
		broadWrite, inheritedWrite = false, false
		principals, rights = nil, nil
		for i := range entries {
			entry := &entries[i]
			if len(entry.AtomicMutatingRights) == 0 {
				entry.AtomicMutatingRights = registryAtomicMutatingRights(entry.RightsMask)
			}
			if entry.AccessType != "ALLOW" || !broadWindowsRegistrySID(entry.SID) || !windowsacl.HasRegistryMutatingRights(entry.RightsMask) {
				continue
			}
			broadWrite = true
			inheritedWrite = inheritedWrite || entry.Inherited
			principals = append(principals, entry.SID)
			rights = append(rights, entry.AtomicMutatingRights...)
		}
		principals = uniqueSorted(principals)
		rights = uniqueSorted(rights)
	}
	return WindowsACLPosture{
		State:             state,
		Stage:             strings.ToUpper(strings.TrimSpace(raw.Stage)),
		AcquisitionMethod: strings.ToUpper(strings.TrimSpace(raw.AcquisitionMethod)),
		BroadWriteGranted: broadWrite,
		Principals:        principals,
		Rights:            rights,
		OwnerSID:          strings.TrimSpace(raw.OwnerSID),
		InheritedWrite:    inheritedWrite,
		Entries:           entries,
		Reason:            strings.TrimSpace(raw.Reason),
	}
}

func broadWindowsRegistrySID(sid string) bool {
	switch strings.TrimSpace(sid) {
	case "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-7", "S-1-5-4":
		return true
	default:
		return false
	}
}

func registryAtomicMutatingRights(mask int64) []string {
	var out []string
	for _, right := range []struct {
		name string
		mask int64
	}{
		{"SetValue", windowsacl.RegistrySetValue},
		{"CreateSubKey", windowsacl.RegistryCreateSubKey},
		{"CreateLink", windowsacl.RegistryCreateLink},
		{"Delete", windowsacl.RegistryDelete},
		{"ChangePermissions", windowsacl.RegistryChangePermissions},
		{"TakeOwnership", windowsacl.RegistryTakeOwnership},
	} {
		if mask&right.mask != 0 {
			out = append(out, right.name)
		}
	}
	return out
}

func normalizeWindowsACLEntries(raw []windowsACLEntryRecord) []WindowsACLEntry {
	out := make([]WindowsACLEntry, 0, len(raw))
	for _, entry := range raw {
		out = append(out, WindowsACLEntry{
			SID:                       strings.TrimSpace(entry.SID),
			Principal:                 strings.TrimSpace(entry.Principal),
			PrincipalResolution:       normalizeWord(entry.PrincipalResolution),
			PrincipalResolutionReason: strings.TrimSpace(entry.PrincipalResolutionReason),
			AccessType:                strings.ToUpper(strings.TrimSpace(entry.AccessType)),
			Inherited:                 entry.Inherited,
			Explicit:                  entry.Explicit,
			InheritanceFlags:          strings.TrimSpace(entry.InheritanceFlags),
			PropagationFlags:          strings.TrimSpace(entry.PropagationFlags),
			Rights:                    strings.TrimSpace(entry.Rights),
			RightsMask:                entry.RightsMask,
			AtomicMutatingRights:      uniqueSorted(entry.AtomicMutatingRights),
		})
	}
	return out
}

func normalizeExistingWindowsACLEntries(in []WindowsACLEntry) []WindowsACLEntry {
	for i := range in {
		in[i].SID = strings.TrimSpace(in[i].SID)
		in[i].Principal = strings.TrimSpace(in[i].Principal)
		in[i].PrincipalResolution = normalizeWord(in[i].PrincipalResolution)
		in[i].PrincipalResolutionReason = strings.TrimSpace(in[i].PrincipalResolutionReason)
		in[i].AccessType = strings.ToUpper(strings.TrimSpace(in[i].AccessType))
		in[i].InheritanceFlags = strings.TrimSpace(in[i].InheritanceFlags)
		in[i].PropagationFlags = strings.TrimSpace(in[i].PropagationFlags)
		in[i].Rights = strings.TrimSpace(in[i].Rights)
		in[i].AtomicMutatingRights = uniqueSorted(in[i].AtomicMutatingRights)
	}
	return in
}

func (s *WindowsSecurity) normalize() {
	if s == nil {
		return
	}
	s.State = normalizeSecurityState(s.State)
	if s.State == "" {
		s.State = "DEGRADED"
	}
	s.ExecutableResolution = normalizeWindowsExecutableResolution(s.ExecutableResolution)
	s.AccountAdminState = normalizeTriState(s.AccountAdminState)
	s.AccountAdminReason = strings.TrimSpace(s.AccountAdminReason)
	s.RegistryState = normalizeSecurityState(s.RegistryState)
	s.RegistryReason = strings.TrimSpace(s.RegistryReason)
	s.RegistryACL = normalizeExistingWindowsACL(s.RegistryACL)
	s.ServiceDLLPath = cleanWindowsSecurityPath(s.ServiceDLLPath)
	s.ServiceDLLState = normalizeOptionalSecurityMetadataState(s.ServiceDLLState, strings.TrimSpace(s.ServiceDLLPath) != "")
	s.ServiceDLLReason = strings.TrimSpace(s.ServiceDLLReason)
	s.FailureCommandState = normalizeOptionalSecurityMetadataState(s.FailureCommandState, s.FailureCommandPresent)
	s.FailureCommandReason = strings.TrimSpace(s.FailureCommandReason)
	s.FailureExecutablePath = cleanWindowsSecurityPath(s.FailureExecutablePath)
	s.ExecutableACL = normalizeExistingWindowsACL(s.ExecutableACL)
	s.ExecutableDirectoryACL = normalizeExistingWindowsACL(s.ExecutableDirectoryACL)
	s.ServiceDLLACL = normalizeExistingWindowsACL(s.ServiceDLLACL)
	s.ServiceDLLDirectoryACL = normalizeExistingWindowsACL(s.ServiceDLLDirectoryACL)
	s.FailureExecutableACL = normalizeExistingWindowsACL(s.FailureExecutableACL)
	s.FailureExecutableDirectoryACL = normalizeExistingWindowsACL(s.FailureExecutableDirectoryACL)
	s.ServiceACL.State = normalizeSecurityState(s.ServiceACL.State)
	if s.ServiceACL.State == "" {
		s.ServiceACL.State = "UNAVAILABLE"
	}
	s.ServiceACL.Principals = uniqueSorted(s.ServiceACL.Principals)
	s.ServiceACL.Rights = uniqueSorted(s.ServiceACL.Rights)
	s.ServiceACL.Reason = strings.TrimSpace(s.ServiceACL.Reason)
	s.refreshComponents()
	s.Degraded = uniqueSorted(s.Degraded)
}

func normalizeExistingWindowsACL(in WindowsACLPosture) WindowsACLPosture {
	in.State = normalizeSecurityState(in.State)
	if in.State == "" {
		in.State = "UNAVAILABLE"
	}
	in.Stage = strings.ToUpper(strings.TrimSpace(in.Stage))
	in.AcquisitionMethod = strings.ToUpper(strings.TrimSpace(in.AcquisitionMethod))
	in.Principals = uniqueSorted(in.Principals)
	in.Rights = uniqueSorted(in.Rights)
	in.OwnerSID = strings.TrimSpace(in.OwnerSID)
	in.Entries = normalizeExistingWindowsACLEntries(in.Entries)
	in.Reason = strings.TrimSpace(in.Reason)
	return in
}

func (s WindowsSecurity) Validate() error {
	if s.State != "COMPLETE" && s.State != "DEGRADED" {
		return fmt.Errorf("invalid Windows service security state %q", s.State)
	}
	for name, acl := range map[string]WindowsACLPosture{
		"executable":                   s.ExecutableACL,
		"executable_directory":         s.ExecutableDirectoryACL,
		"service_dll":                  s.ServiceDLLACL,
		"service_dll_directory":        s.ServiceDLLDirectoryACL,
		"failure_executable":           s.FailureExecutableACL,
		"failure_executable_directory": s.FailureExecutableDirectoryACL,
		"registry":                     s.RegistryACL,
	} {
		if err := validateWindowsACL(name, acl); err != nil {
			return err
		}
	}
	if !validSecurityState(s.ServiceACL.State) {
		return fmt.Errorf("invalid service-object ACL state %q", s.ServiceACL.State)
	}
	if s.ServiceACL.Dangerous && !s.ServiceACL.Weak {
		return fmt.Errorf("dangerous service-object ACL must also be weak")
	}
	if s.ServiceACL.ControlOnly && (s.ServiceACL.Weak || s.ServiceACL.Dangerous) {
		return fmt.Errorf("control-only service-object ACL must remain distinct from configuration-mutating weakness")
	}
	if !validSecurityState(s.RegistryState) {
		return fmt.Errorf("invalid service registry state %q", s.RegistryState)
	}
	if !validSecurityState(s.ServiceDLLState) {
		return fmt.Errorf("invalid service DLL metadata state %q", s.ServiceDLLState)
	}
	if !validSecurityState(s.FailureCommandState) {
		return fmt.Errorf("invalid service recovery configuration state %q", s.FailureCommandState)
	}
	if !validWindowsExecutableResolution(s.ExecutableResolution) {
		return fmt.Errorf("invalid Windows service executable resolution %q", s.ExecutableResolution)
	}
	if s.AccountAdminState != "YES" && s.AccountAdminState != "NO" && s.AccountAdminState != "UNKNOWN" {
		return fmt.Errorf("invalid account admin state %q", s.AccountAdminState)
	}
	for name, state := range map[string]string{
		"service_object":                    s.Components.ServiceObject,
		"executable_acl":                    s.Components.ExecutableACL,
		"executable_directory_acl":          s.Components.ExecutableDirectoryACL,
		"registry_metadata":                 s.Components.RegistryMetadata,
		"registry_acl":                      s.Components.RegistryACL,
		"service_dll_metadata":              s.Components.ServiceDLLMetadata,
		"service_dll_acl":                   s.Components.ServiceDLLACL,
		"service_dll_directory_acl":         s.Components.ServiceDLLDirectoryACL,
		"recovery_configuration":            s.Components.RecoveryConfiguration,
		"recovery_executable_acl":           s.Components.RecoveryExecutableACL,
		"recovery_executable_directory_acl": s.Components.RecoveryExecutableDirACL,
		"account":                           s.Components.Account,
	} {
		if !validComponentSecurityState(state) {
			return fmt.Errorf("invalid Windows service security component %s state %q", name, state)
		}
	}
	return nil
}

func validateWindowsACL(name string, acl WindowsACLPosture) error {
	if !validSecurityState(acl.State) {
		return fmt.Errorf("invalid %s ACL state %q", name, acl.State)
	}
	if acl.BroadWriteGranted && len(acl.Principals) == 0 {
		return fmt.Errorf("%s ACL broad write requires at least one principal", name)
	}
	return nil
}

func normalizeSecurityState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "OBSERVED", "UNAVAILABLE", "DENIED", "NOT_APPLICABLE", "DEGRADED":
		return v
	case "UNKNOWN", "":
		return "UNAVAILABLE"
	default:
		return v
	}
}

func validSecurityState(v string) bool {
	switch v {
	case "OBSERVED", "UNAVAILABLE", "DENIED", "NOT_APPLICABLE", "DEGRADED":
		return true
	default:
		return false
	}
}

func validComponentSecurityState(v string) bool {
	switch v {
	case "OBSERVED", "DEGRADED", "UNAVAILABLE", "DENIED", "NOT_APPLICABLE":
		return true
	default:
		return false
	}
}

func normalizeOptionalSecurityMetadataState(v string, configured bool) string {
	state := normalizeSecurityState(v)
	if strings.TrimSpace(v) == "" {
		if configured {
			return "OBSERVED"
		}
		return "NOT_APPLICABLE"
	}
	return state
}

func normalizeTriState(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "YES", "TRUE", "1":
		return "YES"
	case "NO", "FALSE", "0":
		return "NO"
	default:
		return "UNKNOWN"
	}
}

func cleanWindowsSecurityPath(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "\"'"))
	if v == "" {
		return ""
	}
	return v
}

func windowsExecutableResolution(rawCommand, executablePath string) string {
	if strings.TrimSpace(executablePath) == "" {
		return "UNAVAILABLE"
	}
	if windowsUnquotedExecutablePath(rawCommand, executablePath) {
		return "UNQUOTED"
	}
	return "QUOTED_OR_ABSOLUTE"
}

func normalizeWindowsExecutableResolution(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "UNQUOTED", "QUOTED_OR_ABSOLUTE", "UNAVAILABLE":
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return "UNAVAILABLE"
	}
}

func validWindowsExecutableResolution(v string) bool {
	switch v {
	case "UNQUOTED", "QUOTED_OR_ABSOLUTE", "UNAVAILABLE":
		return true
	default:
		return false
	}
}

func windowsUnquotedExecutablePath(rawCommand, executablePath string) bool {
	raw := strings.TrimSpace(rawCommand)
	exe := strings.TrimSpace(executablePath)
	if raw == "" || exe == "" || strings.HasPrefix(raw, `"`) {
		return false
	}
	return strings.ContainsAny(exe, " \t")
}

func parseWindowsServiceSDDL(sddl string) WindowsServiceACLPosture {
	sddl = strings.TrimSpace(sddl)
	if sddl == "" {
		return WindowsServiceACLPosture{State: "UNAVAILABLE", Reason: "service object security descriptor unavailable"}
	}
	result := WindowsServiceACLPosture{State: "OBSERVED"}
	broad := map[string]struct{}{
		"WD": {}, "S-1-1-0": {},
		"AU": {}, "S-1-5-11": {},
		"BU": {}, "S-1-5-32-545": {},
		"BG": {}, "S-1-5-32-546": {},
		"AN": {}, "S-1-5-7": {},
		"IU": {}, "S-1-5-4": {},
	}
	seenPrincipals := map[string]struct{}{}
	seenRights := map[string]struct{}{}
	dangerous := false
	control := false

	for _, ace := range splitSDDLAces(sddl) {
		fields := strings.Split(ace, ";")
		if len(fields) < 6 {
			continue
		}
		aceType := strings.ToUpper(strings.TrimSpace(fields[0]))
		if aceType != "A" && aceType != "OA" {
			continue
		}
		trustee := strings.ToUpper(strings.TrimSpace(fields[5]))
		if _, ok := broad[trustee]; !ok {
			continue
		}
		rights := strings.ToUpper(strings.TrimSpace(fields[2]))
		dangerRights, controlRights := classifyServiceRights(rights)
		if len(dangerRights) == 0 && len(controlRights) == 0 {
			continue
		}
		trustee = normalizeServiceTrusteeSID(trustee)
		seenPrincipals[trustee] = struct{}{}
		for _, r := range append(dangerRights, controlRights...) {
			seenRights[r] = struct{}{}
		}
		if len(dangerRights) > 0 {
			dangerous = true
		}
		if len(controlRights) > 0 {
			control = true
		}
	}

	// Keep operational start/stop/pause control visible, but do not collapse it
	// into configuration/security mutation. Only change-config, DACL/owner,
	// delete, generic-write/all style rights are classified as a weak service
	// object boundary. Control-only grants remain a separate WARN-grade signal.
	result.Weak = dangerous
	result.Dangerous = dangerous
	result.ControlOnly = control && !dangerous
	for p := range seenPrincipals {
		result.Principals = append(result.Principals, p)
	}
	for r := range seenRights {
		result.Rights = append(result.Rights, r)
	}
	sort.Strings(result.Principals)
	sort.Strings(result.Rights)
	return result
}

func normalizeServiceTrusteeSID(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "WD":
		return "S-1-1-0"
	case "AU":
		return "S-1-5-11"
	case "BU":
		return "S-1-5-32-545"
	case "BG":
		return "S-1-5-32-546"
	case "AN":
		return "S-1-5-7"
	case "IU":
		return "S-1-5-4"
	default:
		return strings.ToUpper(strings.TrimSpace(v))
	}
}

func splitSDDLAces(sddl string) []string {
	out := []string{}
	for i := 0; i < len(sddl); i++ {
		if sddl[i] != '(' {
			continue
		}
		end := strings.IndexByte(sddl[i+1:], ')')
		if end < 0 {
			break
		}
		out = append(out, sddl[i+1:i+1+end])
		i += end + 1
	}
	return out
}

func classifyServiceRights(rights string) (dangerous, control []string) {
	rights = strings.ToUpper(strings.TrimSpace(rights))
	if rights == "" {
		return nil, nil
	}
	if strings.HasPrefix(rights, "0X") {
		if n, err := strconv.ParseUint(strings.TrimPrefix(rights, "0X"), 16, 32); err == nil {
			// SERVICE_CHANGE_CONFIG=0x0002, SERVICE_START=0x0010,
			// SERVICE_STOP=0x0020, SERVICE_PAUSE_CONTINUE=0x0040,
			// SERVICE_INTERROGATE=0x0080, SERVICE_USER_DEFINED_CONTROL=0x0100,
			// DELETE=0x00010000, WRITE_DAC=0x00040000,
			// WRITE_OWNER=0x00080000, GENERIC_WRITE=0x40000000,
			// GENERIC_ALL=0x10000000.
			if n&(0x0002|0x00010000|0x00040000|0x00080000|0x40000000|0x10000000) != 0 {
				dangerous = append(dangerous, rights)
			}
			if n&(0x0010|0x0020|0x0040|0x0080|0x0100) != 0 {
				control = append(control, rights)
			}
			return dangerous, control
		}
	}
	for i := 0; i+1 < len(rights); i += 2 {
		code := rights[i : i+2]
		switch code {
		case "DC", "SD", "WD", "WO", "GW", "GA":
			dangerous = appendUniqueString(dangerous, code)
		case "RP", "WP", "DT", "LO", "CR":
			control = appendUniqueString(control, code)
		}
	}
	return dangerous, control
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func windowsBuiltinServiceAccount(account string) bool {
	a := strings.ToLower(strings.TrimSpace(account))
	a = strings.ReplaceAll(a, "/", `\`)
	switch a {
	case "localsystem", "system", `nt authority\system`, "localservice", `nt authority\localservice`, "networkservice", `nt authority\networkservice`:
		return true
	default:
		return false
	}
}

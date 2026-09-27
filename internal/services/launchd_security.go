package services

import (
	"fmt"
	"sort"
	"strings"
)

// LaunchdHardening is additive metadata describing launchd definition,
// executable, path, identity, and environment posture. Environment values are
// never retained; only variable names and security-relevant indicators are kept.
type LaunchdHardening struct {
	State                           string   `json:"state"`
	DefinitionOwner                 string   `json:"definition_owner"`
	DefinitionMode                  string   `json:"definition_mode,omitempty"`
	DefinitionBroadlyWritable       bool     `json:"definition_broadly_writable"`
	ExecutableState                 string   `json:"executable_state"`
	ExecutableOwner                 string   `json:"executable_owner,omitempty"`
	ExecutableMode                  string   `json:"executable_mode,omitempty"`
	ExecutableBroadlyWritable       bool     `json:"executable_broadly_writable"`
	ExecutableParentState           string   `json:"executable_parent_state"`
	ExecutableParentOwner           string   `json:"executable_parent_owner,omitempty"`
	ExecutableParentMode            string   `json:"executable_parent_mode,omitempty"`
	ExecutableParentBroadlyWritable bool     `json:"executable_parent_broadly_writable"`
	ProgramAbsolute                 bool     `json:"program_absolute"`
	PrivilegedWeakPath              bool     `json:"privileged_weak_path"`
	EnvironmentVariableNames        []string `json:"environment_variable_names,omitempty"`
	DangerousEnvironmentKeys        []string `json:"dangerous_environment_keys,omitempty"`
	EnvironmentValuesRedacted       bool     `json:"environment_values_redacted"`
	WorkingDirectory                string   `json:"working_directory,omitempty"`
	WorkingDirectoryBroadlyWritable bool     `json:"working_directory_broadly_writable"`
	RootDirectory                   string   `json:"root_directory,omitempty"`
	RootDirectoryBroadlyWritable    bool     `json:"root_directory_broadly_writable"`
	DangerousConfiguration          []string `json:"dangerous_configuration,omitempty"`
	Degraded                        []string `json:"degraded,omitempty"`
}

func (s *LaunchdHardening) normalize() {
	if s == nil {
		return
	}
	s.State = normalizeHardeningState(s.State)
	s.DefinitionOwner = fallback(strings.TrimSpace(s.DefinitionOwner), "UNKNOWN")
	s.DefinitionMode = strings.TrimSpace(s.DefinitionMode)
	s.ExecutableState = normalizePathState(s.ExecutableState)
	s.ExecutableOwner = strings.TrimSpace(s.ExecutableOwner)
	s.ExecutableMode = strings.TrimSpace(s.ExecutableMode)
	s.ExecutableParentState = normalizePathState(s.ExecutableParentState)
	s.ExecutableParentOwner = strings.TrimSpace(s.ExecutableParentOwner)
	s.ExecutableParentMode = strings.TrimSpace(s.ExecutableParentMode)
	s.EnvironmentVariableNames = normalizeCaseSensitiveTokens(s.EnvironmentVariableNames)
	s.DangerousEnvironmentKeys = normalizeCaseSensitiveTokens(s.DangerousEnvironmentKeys)
	s.WorkingDirectory = strings.TrimSpace(s.WorkingDirectory)
	s.RootDirectory = strings.TrimSpace(s.RootDirectory)
	s.DangerousConfiguration = normalizeCaseSensitiveTokens(s.DangerousConfiguration)
	s.Degraded = uniqueSorted(s.Degraded)
	if s.State == "" {
		s.State = "COMPLETE"
	}
	if len(s.Degraded) > 0 {
		s.State = "DEGRADED"
	}
}

func (s LaunchdHardening) Validate() error {
	if s.State != "COMPLETE" && s.State != "DEGRADED" {
		return fmt.Errorf("invalid launchd hardening state %q", s.State)
	}
	if strings.TrimSpace(s.DefinitionOwner) == "" {
		return fmt.Errorf("launchd definition ownership state is required")
	}
	if !validPathState(s.ExecutableState) || !validPathState(s.ExecutableParentState) {
		return fmt.Errorf("invalid launchd path metadata state")
	}
	return nil
}

func normalizePathState(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "OBSERVED", "DEGRADED", "UNAVAILABLE", "DENIED", "NOT_APPLICABLE", "UNKNOWN":
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return "UNKNOWN"
	}
}
func validPathState(v string) bool {
	switch v {
	case "OBSERVED", "DEGRADED", "UNAVAILABLE", "DENIED", "NOT_APPLICABLE", "UNKNOWN":
		return true
	default:
		return false
	}
}

func normalizeCaseSensitiveTokens(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

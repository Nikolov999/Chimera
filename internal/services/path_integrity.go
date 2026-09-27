package services

import (
	"fmt"
	"sort"
	"strings"
)

// PathPosture is a bounded summary of a service-controlled filesystem or
// configuration path. LowerPrivilegeWritable is true only when Chimera has
// concrete local metadata showing that a principal below the service's
// privileged execution boundary can modify the path.
type PathPosture struct {
	State                  string   `json:"state"`
	Path                   string   `json:"path,omitempty"`
	Owner                  string   `json:"owner,omitempty"`
	Group                  string   `json:"group,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	LowerPrivilegeWritable bool     `json:"lower_privilege_writable"`
	Principals             []string `json:"principals,omitempty"`
	Rights                 []string `json:"rights,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
}

// ServicePathIntegrity is correlation evidence. It does not change
// service state or permissions. It joins service privilege context to the
// integrity of executable, configuration, and search/resolution boundaries.
type ServicePathIntegrity struct {
	State                       string       `json:"state"`
	Privileged                  bool         `json:"privileged"`
	PrivilegeBasis              string       `json:"privilege_basis"`
	Executable                  PathPosture  `json:"executable"`
	ExecutableDirectory         PathPosture  `json:"executable_directory"`
	Configuration               PathPosture  `json:"configuration"`
	ConfigurationDirectory      PathPosture  `json:"configuration_directory"`
	ServiceDLL                  *PathPosture `json:"service_dll,omitempty"`
	ServiceDLLDirectory         *PathPosture `json:"service_dll_directory,omitempty"`
	RecoveryExecutable          *PathPosture `json:"recovery_executable,omitempty"`
	RecoveryExecutableDirectory *PathPosture `json:"recovery_executable_directory,omitempty"`
	SearchResolution            string       `json:"search_resolution"`
	SearchPathState             string       `json:"search_path_state"`
	SearchPathWritable          bool         `json:"search_path_writable"`
	SearchEvidence              []string     `json:"search_evidence,omitempty"`
	WeakRoles                   []string     `json:"weak_roles,omitempty"`
	Degraded                    []string     `json:"degraded,omitempty"`
}

func (p *ServicePathIntegrity) normalize() {
	if p == nil {
		return
	}
	p.State = strings.ToUpper(strings.TrimSpace(p.State))
	if p.State == "" {
		p.State = "COMPLETE"
	}
	p.PrivilegeBasis = fallback(strings.TrimSpace(p.PrivilegeBasis), "UNKNOWN")
	p.Executable = normalizePathPosture(p.Executable)
	p.ExecutableDirectory = normalizePathPosture(p.ExecutableDirectory)
	p.Configuration = normalizePathPosture(p.Configuration)
	p.ConfigurationDirectory = normalizePathPosture(p.ConfigurationDirectory)
	normalizeOptionalPathPosture(&p.ServiceDLL)
	normalizeOptionalPathPosture(&p.ServiceDLLDirectory)
	normalizeOptionalPathPosture(&p.RecoveryExecutable)
	normalizeOptionalPathPosture(&p.RecoveryExecutableDirectory)
	p.SearchResolution = normalizeSearchResolution(p.SearchResolution)
	p.SearchPathState = normalizePathState(p.SearchPathState)
	p.SearchEvidence = uniqueSorted(p.SearchEvidence)
	p.WeakRoles = uniqueSorted(p.WeakRoles)
	p.Degraded = uniqueSorted(p.Degraded)
	if p.SearchPathState == "" {
		p.SearchPathState = "UNKNOWN"
	}
	for _, posture := range []PathPosture{p.Executable, p.ExecutableDirectory, p.Configuration, p.ConfigurationDirectory} {
		if pathPostureDegrades(posture) {
			p.State = "DEGRADED"
		}
	}
	for _, posture := range []*PathPosture{p.ServiceDLL, p.ServiceDLLDirectory, p.RecoveryExecutable, p.RecoveryExecutableDirectory} {
		if posture != nil && pathPostureDegrades(*posture) {
			p.State = "DEGRADED"
		}
	}
	if p.SearchPathState == "DEGRADED" || p.SearchPathState == "DENIED" || p.SearchPathState == "UNAVAILABLE" || p.SearchPathState == "UNKNOWN" {
		if p.SearchResolution == "RELATIVE" || p.SearchResolution == "UNQUOTED" || p.SearchResolution == "UNKNOWN" {
			p.State = "DEGRADED"
		}
	}
	if len(p.Degraded) > 0 {
		p.State = "DEGRADED"
	}
}

func normalizeOptionalPathPosture(p **PathPosture) {
	if p == nil || *p == nil {
		return
	}
	normalized := normalizePathPosture(**p)
	*p = &normalized
}

func pathPostureDegrades(p PathPosture) bool {
	switch p.State {
	case "DEGRADED", "DENIED", "UNAVAILABLE", "UNKNOWN":
		return true
	default:
		return false
	}
}

func normalizePathPosture(p PathPosture) PathPosture {
	p.State = normalizePathState(p.State)
	if p.State == "" {
		p.State = "UNKNOWN"
	}
	p.Path = strings.TrimSpace(p.Path)
	p.Owner = strings.TrimSpace(p.Owner)
	p.Group = strings.TrimSpace(p.Group)
	p.Mode = strings.TrimSpace(p.Mode)
	p.Principals = uniqueSorted(p.Principals)
	p.Rights = uniqueSorted(p.Rights)
	p.Reason = strings.TrimSpace(p.Reason)
	return p
}

func normalizeSearchResolution(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "ABSOLUTE", "QUOTED_OR_ABSOLUTE", "RELATIVE", "UNQUOTED", "NOT_APPLICABLE", "UNKNOWN":
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return "UNKNOWN"
	}
}

func (p ServicePathIntegrity) Validate() error {
	if p.State != "COMPLETE" && p.State != "DEGRADED" {
		return fmt.Errorf("invalid service path-integrity state %q", p.State)
	}
	if strings.TrimSpace(p.PrivilegeBasis) == "" {
		return fmt.Errorf("service path-integrity privilege basis is required")
	}
	for name, posture := range map[string]PathPosture{
		"executable":              p.Executable,
		"executable_directory":    p.ExecutableDirectory,
		"configuration":           p.Configuration,
		"configuration_directory": p.ConfigurationDirectory,
	} {
		if !validPathState(posture.State) {
			return fmt.Errorf("invalid %s path state %q", name, posture.State)
		}
		if posture.LowerPrivilegeWritable && posture.State != "OBSERVED" {
			return fmt.Errorf("%s cannot be marked lower-privilege writable without observed metadata", name)
		}
	}
	for name, posture := range map[string]*PathPosture{
		"service_dll":                   p.ServiceDLL,
		"service_dll_directory":         p.ServiceDLLDirectory,
		"recovery_executable":           p.RecoveryExecutable,
		"recovery_executable_directory": p.RecoveryExecutableDirectory,
	} {
		if posture == nil {
			continue
		}
		if !validPathState(posture.State) {
			return fmt.Errorf("invalid %s path state %q", name, posture.State)
		}
		if posture.LowerPrivilegeWritable && posture.State != "OBSERVED" {
			return fmt.Errorf("%s cannot be marked lower-privilege writable without observed metadata", name)
		}
	}
	if normalizeSearchResolution(p.SearchResolution) != p.SearchResolution {
		return fmt.Errorf("invalid service search-resolution state %q", p.SearchResolution)
	}
	if !validPathState(p.SearchPathState) {
		return fmt.Errorf("invalid service search-path state %q", p.SearchPathState)
	}
	if p.SearchPathWritable && p.SearchPathState != "OBSERVED" {
		return fmt.Errorf("search path cannot be marked writable without observed metadata")
	}
	if !sort.StringsAreSorted(p.WeakRoles) || !sort.StringsAreSorted(p.SearchEvidence) || !sort.StringsAreSorted(p.Degraded) {
		return fmt.Errorf("service path-integrity lists must be deterministically ordered")
	}
	return nil
}

func serviceIsPrivileged(s Service) (bool, string) {
	switch strings.ToUpper(strings.TrimSpace(s.PrivilegeContext)) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT":
		return true, strings.ToUpper(strings.TrimSpace(s.PrivilegeContext))
	}
	if s.WindowsSecurity != nil && s.WindowsSecurity.AccountAdminState == "YES" {
		return true, "LOCAL_ADMIN_SERVICE_ACCOUNT"
	}
	return false, fallback(strings.ToUpper(strings.TrimSpace(s.PrivilegeContext)), "UNKNOWN")
}

func appendWeakRole(p *ServicePathIntegrity, role string, posture PathPosture) {
	if posture.State == "OBSERVED" && posture.LowerPrivilegeWritable {
		p.WeakRoles = append(p.WeakRoles, role)
	}
}

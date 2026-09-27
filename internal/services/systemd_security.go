package services

import (
	"fmt"
	"sort"
	"strings"
)

// SystemdHardening is additive metadata describing the effective
// service sandbox/privilege boundary reported by systemd. It contains only
// configuration posture; no service process is modified or probed.
type SystemdHardening struct {
	State                      string   `json:"state"`
	User                       string   `json:"user"`
	Group                      string   `json:"group"`
	UserConfigured             bool     `json:"user_configured"`
	GroupConfigured            bool     `json:"group_configured"`
	DynamicUser                string   `json:"dynamic_user"`
	NoNewPrivileges            string   `json:"no_new_privileges"`
	ProtectSystem              string   `json:"protect_system"`
	ProtectHome                string   `json:"protect_home"`
	PrivateTmp                 string   `json:"private_tmp"`
	PrivateDevices             string   `json:"private_devices"`
	PrivateNetwork             string   `json:"private_network"`
	CapabilityBoundingSetState string   `json:"capability_bounding_set_state"`
	CapabilityBoundingSet      []string `json:"capability_bounding_set,omitempty"`
	AmbientCapabilities        []string `json:"ambient_capabilities,omitempty"`
	RestrictNamespacesState    string   `json:"restrict_namespaces_state"`
	RestrictNamespaces         []string `json:"restrict_namespaces,omitempty"`
	ProtectKernelTunables      string   `json:"protect_kernel_tunables"`
	ProtectKernelModules       string   `json:"protect_kernel_modules"`
	ProtectControlGroups       string   `json:"protect_control_groups"`
	RestrictSUIDSGID           string   `json:"restrict_suid_sgid"`
	LockPersonality            string   `json:"lock_personality"`
	MemoryDenyWriteExecute     string   `json:"memory_deny_write_execute"`
	UMask                      string   `json:"umask,omitempty"`
	Degraded                   []string `json:"degraded,omitempty"`
}

func (s *SystemdHardening) normalize() {
	if s == nil {
		return
	}
	s.State = normalizeHardeningState(s.State)
	s.User = fallback(strings.TrimSpace(s.User), "root")
	s.Group = fallback(strings.TrimSpace(s.Group), "root")
	s.DynamicUser = normalizeBoolState(s.DynamicUser)
	s.NoNewPrivileges = normalizeBoolState(s.NoNewPrivileges)
	s.ProtectSystem = normalizeProtectSystem(s.ProtectSystem)
	s.ProtectHome = normalizeProtectHome(s.ProtectHome)
	s.PrivateTmp = normalizePrivateTmp(s.PrivateTmp)
	s.PrivateDevices = normalizeBoolState(s.PrivateDevices)
	s.PrivateNetwork = normalizeBoolState(s.PrivateNetwork)
	s.CapabilityBoundingSetState = normalizeSetState(s.CapabilityBoundingSetState)
	s.CapabilityBoundingSet = normalizeTokens(s.CapabilityBoundingSet)
	s.AmbientCapabilities = normalizeTokens(s.AmbientCapabilities)
	s.RestrictNamespacesState = normalizeNamespaceState(s.RestrictNamespacesState)
	s.RestrictNamespaces = normalizeTokens(s.RestrictNamespaces)
	s.ProtectKernelTunables = normalizeBoolState(s.ProtectKernelTunables)
	s.ProtectKernelModules = normalizeBoolState(s.ProtectKernelModules)
	s.ProtectControlGroups = normalizeBoolState(s.ProtectControlGroups)
	s.RestrictSUIDSGID = normalizeBoolState(s.RestrictSUIDSGID)
	s.LockPersonality = normalizeBoolState(s.LockPersonality)
	s.MemoryDenyWriteExecute = normalizeBoolState(s.MemoryDenyWriteExecute)
	s.UMask = strings.TrimSpace(s.UMask)
	s.Degraded = uniqueSorted(s.Degraded)
	if s.State == "" {
		s.State = "COMPLETE"
	}
	if len(s.Degraded) > 0 {
		s.State = "DEGRADED"
	}
}

func (s SystemdHardening) Validate() error {
	if s.State != "COMPLETE" && s.State != "DEGRADED" {
		return fmt.Errorf("invalid systemd hardening state %q", s.State)
	}
	for name, v := range map[string]string{
		"dynamic_user":              s.DynamicUser,
		"no_new_privileges":         s.NoNewPrivileges,
		"private_devices":           s.PrivateDevices,
		"private_network":           s.PrivateNetwork,
		"protect_kernel_tunables":   s.ProtectKernelTunables,
		"protect_kernel_modules":    s.ProtectKernelModules,
		"protect_control_groups":    s.ProtectControlGroups,
		"restrict_suid_sgid":        s.RestrictSUIDSGID,
		"lock_personality":          s.LockPersonality,
		"memory_deny_write_execute": s.MemoryDenyWriteExecute,
	} {
		if !validBoolState(v) {
			return fmt.Errorf("invalid systemd %s state %q", name, v)
		}
	}
	if !validProtectSystem(s.ProtectSystem) {
		return fmt.Errorf("invalid ProtectSystem state %q", s.ProtectSystem)
	}
	if !validProtectHome(s.ProtectHome) {
		return fmt.Errorf("invalid ProtectHome state %q", s.ProtectHome)
	}
	if !validPrivateTmp(s.PrivateTmp) {
		return fmt.Errorf("invalid PrivateTmp state %q", s.PrivateTmp)
	}
	if s.CapabilityBoundingSetState != "RESTRICTED" && s.CapabilityBoundingSetState != "UNRESTRICTED" && s.CapabilityBoundingSetState != "EMPTY" && s.CapabilityBoundingSetState != "UNKNOWN" {
		return fmt.Errorf("invalid capability bounding-set state %q", s.CapabilityBoundingSetState)
	}
	if s.RestrictNamespacesState != "RESTRICTED" && s.RestrictNamespacesState != "UNRESTRICTED" && s.RestrictNamespacesState != "UNKNOWN" {
		return fmt.Errorf("invalid namespace-restriction state %q", s.RestrictNamespacesState)
	}
	if strings.TrimSpace(s.User) == "" || strings.TrimSpace(s.Group) == "" {
		return fmt.Errorf("systemd hardening identity is incomplete")
	}
	return nil
}

func normalizeHardeningState(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "COMPLETE":
		return "COMPLETE"
	case "DEGRADED":
		return "DEGRADED"
	default:
		return ""
	}
}

func normalizeBoolState(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return "YES"
	case "no", "false", "0", "off":
		return "NO"
	default:
		return "UNKNOWN"
	}
}

func validBoolState(v string) bool { return v == "YES" || v == "NO" || v == "UNKNOWN" }

func normalizeProtectSystem(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return "STRICT"
	case "full":
		return "FULL"
	case "yes", "true":
		return "YES"
	case "no", "false":
		return "NO"
	default:
		return "UNKNOWN"
	}
}
func validProtectSystem(v string) bool {
	return v == "STRICT" || v == "FULL" || v == "YES" || v == "NO" || v == "UNKNOWN"
}

func normalizeProtectHome(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true":
		return "YES"
	case "read-only", "readonly", "read_only":
		return "READ_ONLY"
	case "tmpfs":
		return "TMPFS"
	case "no", "false":
		return "NO"
	default:
		return "UNKNOWN"
	}
}
func validProtectHome(v string) bool {
	return v == "YES" || v == "READ_ONLY" || v == "TMPFS" || v == "NO" || v == "UNKNOWN"
}

func normalizePrivateTmp(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true":
		return "YES"
	case "disconnected":
		return "DISCONNECTED"
	case "no", "false":
		return "NO"
	default:
		return "UNKNOWN"
	}
}
func validPrivateTmp(v string) bool {
	return v == "YES" || v == "DISCONNECTED" || v == "NO" || v == "UNKNOWN"
}

func normalizeSetState(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "RESTRICTED", "UNRESTRICTED", "EMPTY", "UNKNOWN":
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return "UNKNOWN"
	}
}

func normalizeNamespaceState(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "RESTRICTED", "UNRESTRICTED", "UNKNOWN":
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return "UNKNOWN"
	}
}

func normalizeTokens(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, token := range in {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func capabilitySetState(tokens []string, raw string) string {
	raw = strings.TrimSpace(raw)
	tokens = normalizeTokens(tokens)
	if raw == "" {
		return "EMPTY"
	}
	// A default systemd capability bounding set is broad and normally contains
	// all host-supported capabilities. Presence of multiple high-impact kernel
	// capabilities is a defensible signal that it is effectively unrestricted
	// for service hardening purposes, without relying on a kernel-version list.
	dangerous := 0
	for _, cap := range []string{"cap_sys_admin", "cap_sys_module", "cap_sys_ptrace", "cap_sys_rawio", "cap_dac_override"} {
		for _, got := range tokens {
			if got == cap {
				dangerous++
				break
			}
		}
	}
	if dangerous >= 4 && len(tokens) >= 20 {
		return "UNRESTRICTED"
	}
	return "RESTRICTED"
}

func namespaceRestrictionState(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", "no", "false", "0":
		return "UNRESTRICTED"
	case "yes", "true", "1":
		return "RESTRICTED"
	default:
		return "RESTRICTED"
	}
}

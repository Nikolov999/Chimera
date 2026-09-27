package processes

import (
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxPrivilegeListItems = 128

// RuntimePrivilegeContext is additive evidence for a live process.
// It records identity/integrity/privilege metadata only; it never contains
// credentials, process memory, token handles, or secret values.
type RuntimePrivilegeContext struct {
	ProcessID             string              `json:"process_id"`
	PID                   int                 `json:"pid"`
	Platform              string              `json:"platform"`
	State                 string              `json:"state"`
	AccountClass          string              `json:"account_class"`
	RealUserID            string              `json:"real_user_id,omitempty"`
	EffectiveUserID       string              `json:"effective_user_id,omitempty"`
	SavedUserID           string              `json:"saved_user_id,omitempty"`
	FileSystemUserID      string              `json:"filesystem_user_id,omitempty"`
	RealGroupID           string              `json:"real_group_id,omitempty"`
	EffectiveGroupID      string              `json:"effective_group_id,omitempty"`
	SavedGroupID          string              `json:"saved_group_id,omitempty"`
	FileSystemGroupID     string              `json:"filesystem_group_id,omitempty"`
	IdentityTransition    bool                `json:"identity_transition"`
	IntegrityLevel        string              `json:"integrity_level,omitempty"`
	TokenElevation        string              `json:"token_elevation,omitempty"`
	ElevationType         string              `json:"elevation_type,omitempty"`
	PrivilegeSetState     string              `json:"privilege_set_state"`
	EffectiveCapabilities []string            `json:"effective_capabilities,omitempty"`
	PermittedCapabilities []string            `json:"permitted_capabilities,omitempty"`
	AmbientCapabilities   []string            `json:"ambient_capabilities,omitempty"`
	EnabledPrivileges     []string            `json:"enabled_privileges,omitempty"`
	HighImpactPrivileges  []string            `json:"high_impact_privileges,omitempty"`
	ExcessSignals         []string            `json:"excess_signals,omitempty"`
	ElevatedUserContext   bool                `json:"elevated_user_context"`
	Source                string              `json:"source"`
	Confidence            evidence.Confidence `json:"confidence"`
	Reason                string              `json:"reason,omitempty"`
}

func normalizeRuntimePrivileges(processes []Process, in []RuntimePrivilegeContext, platform string) []RuntimePrivilegeContext {
	byPID := make(map[int]RuntimePrivilegeContext, len(in))
	for _, c := range in {
		if c.PID <= 0 {
			continue
		}
		c.Platform = fallback(strings.ToLower(strings.TrimSpace(c.Platform)), strings.ToLower(strings.TrimSpace(platform)))
		c.AccountClass = fallback(strings.ToUpper(strings.TrimSpace(c.AccountClass)), "UNKNOWN")
		c.State = fallback(strings.ToUpper(strings.TrimSpace(c.State)), "UNKNOWN")
		c.PrivilegeSetState = fallback(strings.ToUpper(strings.TrimSpace(c.PrivilegeSetState)), "UNKNOWN")
		c.TokenElevation = strings.ToUpper(strings.TrimSpace(c.TokenElevation))
		c.IntegrityLevel = strings.ToUpper(strings.TrimSpace(c.IntegrityLevel))
		c.ElevationType = strings.ToUpper(strings.TrimSpace(c.ElevationType))
		c.Source = fallback(strings.TrimSpace(c.Source), "platform runtime privilege metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceMedium
		}
		c.EffectiveCapabilities = normalizedList(c.EffectiveCapabilities)
		c.PermittedCapabilities = normalizedList(c.PermittedCapabilities)
		c.AmbientCapabilities = normalizedList(c.AmbientCapabilities)
		c.EnabledPrivileges = normalizedList(c.EnabledPrivileges)
		c.HighImpactPrivileges = normalizedList(c.HighImpactPrivileges)
		c.ExcessSignals = normalizedList(c.ExcessSignals)
		if old, ok := byPID[c.PID]; !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) {
			byPID[c.PID] = c
		}
	}

	out := make([]RuntimePrivilegeContext, 0, len(processes))
	for _, p := range processes {
		c, ok := byPID[p.PID]
		if !ok {
			c = RuntimePrivilegeContext{
				PID:               p.PID,
				Platform:          strings.ToLower(strings.TrimSpace(platform)),
				State:             "UNKNOWN",
				AccountClass:      "UNKNOWN",
				PrivilegeSetState: "UNKNOWN",
				Source:            "platform runtime privilege metadata",
				Confidence:        evidence.ConfidenceLow,
				Reason:            "runtime privilege metadata unavailable for observed process",
			}
		}
		c.ProcessID = p.ID
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ProcessID < out[j].ProcessID
	})
	return out
}

func normalizedList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > maxPrivilegeListItems {
		out = out[:maxPrivilegeListItems]
	}
	return out
}

func highImpactCapabilitySet(names ...[]string) []string {
	high := map[string]struct{}{
		"CAP_DAC_OVERRIDE": {}, "CAP_DAC_READ_SEARCH": {}, "CAP_SETGID": {}, "CAP_SETUID": {},
		"CAP_NET_ADMIN": {}, "CAP_SYS_MODULE": {}, "CAP_SYS_RAWIO": {}, "CAP_SYS_CHROOT": {},
		"CAP_SYS_PTRACE": {}, "CAP_SYS_ADMIN": {}, "CAP_SYS_BOOT": {}, "CAP_SYS_TIME": {},
		"CAP_AUDIT_CONTROL": {}, "CAP_MAC_OVERRIDE": {}, "CAP_MAC_ADMIN": {}, "CAP_BPF": {},
		"CAP_PERFMON": {}, "CAP_CHECKPOINT_RESTORE": {},
	}
	out := []string{}
	for _, list := range names {
		for _, name := range list {
			if _, ok := high[strings.ToUpper(strings.TrimSpace(name))]; ok {
				out = append(out, strings.ToUpper(strings.TrimSpace(name)))
			}
		}
	}
	return normalizedList(out)
}

func highImpactWindowsPrivileges(in []string) []string {
	high := map[string]struct{}{
		"SeAssignPrimaryTokenPrivilege": {}, "SeTcbPrivilege": {}, "SeBackupPrivilege": {},
		"SeRestorePrivilege": {}, "SeDebugPrivilege": {}, "SeImpersonatePrivilege": {},
		"SeCreateTokenPrivilege": {}, "SeLoadDriverPrivilege": {}, "SeTakeOwnershipPrivilege": {},
		"SeSecurityPrivilege": {}, "SeRelabelPrivilege": {}, "SeTrustedCredManAccessPrivilege": {},
		"SeDelegateSessionUserImpersonatePrivilege": {},
	}
	out := []string{}
	for _, name := range in {
		if _, ok := high[strings.TrimSpace(name)]; ok {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return normalizedList(out)
}

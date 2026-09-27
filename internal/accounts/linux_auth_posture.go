package accounts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxLinuxAuthFiles = 256
	maxLinuxPAMRules  = 8192
)

// LinuxAuthConfigPath captures metadata for PAM/login policy configuration
// consumed by the assessment. Only ownership/mode and parser state
// are retained; no credentials or authentication tokens are collected.
type LinuxAuthConfigPath struct {
	ID            string              `json:"id"`
	Path          string              `json:"path"`
	Kind          string              `json:"kind"`
	State         evidence.State      `json:"state"`
	Mode          string              `json:"mode,omitempty"`
	UID           uint32              `json:"uid,omitempty"`
	GID           uint32              `json:"gid,omitempty"`
	Parsed        bool                `json:"parsed"`
	Insecure      bool                `json:"insecure"`
	InsecureBasis []string            `json:"insecure_basis,omitempty"`
	Source        string              `json:"source"`
	Confidence    evidence.Confidence `json:"confidence"`
	Reason        string              `json:"reason,omitempty"`
}

// LinuxPAMRule is a normalized PAM configuration statement. Arguments are not
// copied verbatim; only security-relevant boolean/numeric posture fields are
// retained to avoid leaking configuration values that are not needed by rules.
type LinuxPAMRule struct {
	ID         string `json:"id"`
	Service    string `json:"service"`
	Type       string `json:"type"`
	Control    string `json:"control"`
	Module     string `json:"module"`
	Source     string `json:"source"`
	Line       int    `json:"line"`
	NullOK     bool   `json:"nullok"`
	NoPassExp  bool   `json:"no_pass_expiry"`
	EvenRoot   bool   `json:"even_deny_root"`
	LocalUsers bool   `json:"local_users_only"`
	Deny       int    `json:"deny,omitempty"`
	UnlockTime int    `json:"unlock_time,omitempty"`
	Retry      int    `json:"retry,omitempty"`
	MinLen     int    `json:"min_length,omitempty"`
	Remember   int    `json:"remember,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

// LinuxLoginPolicy is the non-secret subset of /etc/login.defs that affects
// password ageing and default password hashing.
type LinuxLoginPolicy struct {
	State         evidence.State      `json:"state"`
	Source        string              `json:"source"`
	MaxDays       int                 `json:"pass_max_days,omitempty"`
	MinDays       int                 `json:"pass_min_days,omitempty"`
	WarnAge       int                 `json:"pass_warn_age,omitempty"`
	MinLength     int                 `json:"pass_min_len,omitempty"`
	EncryptMethod string              `json:"encrypt_method,omitempty"`
	Confidence    evidence.Confidence `json:"confidence"`
	Reason        string              `json:"reason,omitempty"`
}

// LinuxAuthTuning contains selected safe-to-report values from faillock,
// pwquality, and pwhistory configuration files.
type LinuxAuthTuning struct {
	FaillockDeny       int  `json:"faillock_deny,omitempty"`
	FaillockUnlockTime int  `json:"faillock_unlock_time,omitempty"`
	EvenDenyRoot       bool `json:"even_deny_root"`
	PwqualityMinLen    int  `json:"pwquality_min_length,omitempty"`
	PwqualityMinClass  int  `json:"pwquality_min_class,omitempty"`
	PwqualityRetry     int  `json:"pwquality_retry,omitempty"`
	PasswordRemember   int  `json:"password_remember,omitempty"`
}

type LinuxAuthSummary struct {
	ParsedFiles         int `json:"parsed_files"`
	PAMRules            int `json:"pam_rules"`
	AuthRules           int `json:"auth_rules"`
	PasswordRules       int `json:"password_rules"`
	LockoutRules        int `json:"lockout_rules"`
	QualityRules        int `json:"quality_rules"`
	HistoryRules        int `json:"history_rules"`
	NullOKRules         int `json:"nullok_rules"`
	PermitRules         int `json:"permit_rules"`
	InsecureConfigPaths int `json:"insecure_config_paths"`
}

// LinuxAuthPosture is the PAM/login.defs assessment surface.
type LinuxAuthPosture struct {
	State       evidence.State        `json:"state"`
	Source      string                `json:"source"`
	Reason      string                `json:"reason,omitempty"`
	ConfigPaths []LinuxAuthConfigPath `json:"config_paths,omitempty"`
	PAMRules    []LinuxPAMRule        `json:"pam_rules,omitempty"`
	LoginPolicy LinuxLoginPolicy      `json:"login_policy"`
	Tuning      LinuxAuthTuning       `json:"tuning"`
	Summary     LinuxAuthSummary      `json:"summary"`
}

func stableLinuxAuthID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return prefix + "-" + hex.EncodeToString(sum[:10])
}

func normalizeLinuxAuthPosture(platform string, p LinuxAuthPosture) LinuxAuthPosture {
	p.Source = strings.TrimSpace(p.Source)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Source == "" {
		p.Source = "Linux PAM/login policy provider"
	}
	if p.State == "" {
		if strings.EqualFold(platform, "linux") {
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "Linux PAM/login policy provider returned no state")
		} else {
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "Linux PAM/login policy assessment is not applicable on this platform")
		}
	}

	seenPaths := map[string]struct{}{}
	paths := make([]LinuxAuthConfigPath, 0, len(p.ConfigPaths))
	for _, item := range p.ConfigPaths {
		item.Path = strings.TrimSpace(item.Path)
		item.Kind = strings.ToUpper(strings.TrimSpace(item.Kind))
		item.Source = strings.TrimSpace(item.Source)
		item.Reason = strings.TrimSpace(item.Reason)
		item.InsecureBasis = uniqueSorted(item.InsecureBasis)
		if item.ID == "" && item.Path != "" {
			item.ID = stableLinuxAuthID("auth-config", item.Path, item.Kind)
		}
		if item.ID == "" || item.Path == "" || item.Kind == "" {
			continue
		}
		if item.State == "" {
			item.State = evidence.StateUnavailable
		}
		if item.Source == "" {
			item.Source = item.Path
		}
		if item.Confidence == "" {
			item.Confidence = evidence.ConfidenceHigh
		}
		if item.State != evidence.StateObserved && item.Reason == "" {
			item.Reason = "authentication configuration path metadata was not observable"
		}
		if _, ok := seenPaths[item.ID]; ok {
			continue
		}
		seenPaths[item.ID] = struct{}{}
		paths = append(paths, item)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Path != paths[j].Path {
			return paths[i].Path < paths[j].Path
		}
		return paths[i].ID < paths[j].ID
	})
	p.ConfigPaths = paths

	seenRules := map[string]struct{}{}
	rules := make([]LinuxPAMRule, 0, len(p.PAMRules))
	for _, r := range p.PAMRules {
		r.Service = strings.TrimSpace(r.Service)
		r.Type = strings.ToLower(strings.TrimSpace(r.Type))
		r.Control = strings.TrimSpace(r.Control)
		r.Module = strings.ToLower(strings.TrimSpace(r.Module))
		r.Source = strings.TrimSpace(r.Source)
		r.Hash = strings.ToUpper(strings.TrimSpace(r.Hash))
		if r.ID == "" {
			r.ID = stableLinuxAuthID("pam-rule", r.Source, fmt.Sprint(r.Line), r.Service, r.Type, r.Control, r.Module)
		}
		if r.ID == "" || r.Service == "" || r.Type == "" || r.Control == "" || r.Module == "" || r.Source == "" || r.Line <= 0 {
			continue
		}
		if _, ok := seenRules[r.ID]; ok {
			continue
		}
		seenRules[r.ID] = struct{}{}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Source != rules[j].Source {
			return rules[i].Source < rules[j].Source
		}
		if rules[i].Line != rules[j].Line {
			return rules[i].Line < rules[j].Line
		}
		return rules[i].ID < rules[j].ID
	})
	p.PAMRules = rules

	p.LoginPolicy.Source = strings.TrimSpace(p.LoginPolicy.Source)
	p.LoginPolicy.Reason = strings.TrimSpace(p.LoginPolicy.Reason)
	p.LoginPolicy.EncryptMethod = strings.ToUpper(strings.TrimSpace(p.LoginPolicy.EncryptMethod))
	if p.LoginPolicy.Source == "" {
		p.LoginPolicy.Source = "/etc/login.defs"
	}
	if p.LoginPolicy.State == "" {
		p.LoginPolicy.State = evidence.StateUnavailable
		p.LoginPolicy.Reason = fallback(p.LoginPolicy.Reason, "login.defs policy was not observable")
	}
	if p.LoginPolicy.Confidence == "" {
		p.LoginPolicy.Confidence = evidence.ConfidenceHigh
	}
	p.Summary = summarizeLinuxAuthPosture(p)
	return p
}

func summarizeLinuxAuthPosture(p LinuxAuthPosture) LinuxAuthSummary {
	s := LinuxAuthSummary{}
	for _, cfg := range p.ConfigPaths {
		if cfg.Parsed {
			s.ParsedFiles++
		}
		if cfg.Insecure {
			s.InsecureConfigPaths++
		}
	}
	s.PAMRules = len(p.PAMRules)
	for _, r := range p.PAMRules {
		switch r.Type {
		case "auth":
			s.AuthRules++
		case "password":
			s.PasswordRules++
		}
		switch r.Module {
		case "pam_faillock.so", "pam_tally2.so", "pam_tally.so":
			s.LockoutRules++
		case "pam_pwquality.so", "pam_passwdqc.so", "pam_cracklib.so":
			s.QualityRules++
		case "pam_pwhistory.so":
			s.HistoryRules++
		case "pam_permit.so":
			s.PermitRules++
		}
		if r.NullOK {
			s.NullOKRules++
		}
		if r.Module == "pam_unix.so" && r.Remember > 0 {
			s.HistoryRules++
		}
	}
	return s
}

func validateLinuxAuthPosture(platform string, p LinuxAuthPosture) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("Linux authentication posture state/source is incomplete")
	}
	if !strings.EqualFold(platform, "linux") && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("non-Linux authentication posture must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && p.State != evidence.StateDegraded && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed Linux authentication posture requires a reason")
	}
	if len(p.ConfigPaths) > maxLinuxAuthFiles || len(p.PAMRules) > maxLinuxPAMRules {
		return fmt.Errorf("Linux authentication posture exceeds bounded record limits")
	}
	last := ""
	seen := map[string]struct{}{}
	for i, cfg := range p.ConfigPaths {
		if cfg.ID == "" || cfg.Path == "" || cfg.Kind == "" || cfg.State == "" || cfg.Source == "" || cfg.Confidence == "" {
			return fmt.Errorf("Linux auth config path %d is incomplete", i)
		}
		if cfg.State != evidence.StateObserved && cfg.Reason == "" {
			return fmt.Errorf("Linux auth config path %q non-observed without reason", cfg.ID)
		}
		if _, ok := seen[cfg.ID]; ok {
			return fmt.Errorf("duplicate Linux auth config path id %q", cfg.ID)
		}
		seen[cfg.ID] = struct{}{}
		key := cfg.Path + "\x00" + cfg.ID
		if last != "" && key < last {
			return fmt.Errorf("Linux auth config paths are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, r := range p.PAMRules {
		if r.ID == "" || r.Service == "" || r.Type == "" || r.Control == "" || r.Module == "" || r.Source == "" || r.Line <= 0 {
			return fmt.Errorf("Linux PAM rule %d is incomplete", i)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate Linux PAM rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		key := r.Source + "\x00" + fmt.Sprintf("%09d", r.Line) + "\x00" + r.ID
		if last != "" && key < last {
			return fmt.Errorf("Linux PAM rules are not deterministically ordered")
		}
		last = key
	}
	if p.LoginPolicy.State == "" || p.LoginPolicy.Source == "" || p.LoginPolicy.Confidence == "" {
		return fmt.Errorf("Linux login policy is incomplete")
	}
	if p.LoginPolicy.State != evidence.StateObserved && p.LoginPolicy.Reason == "" {
		return fmt.Errorf("non-observed Linux login policy requires a reason")
	}
	if p.Summary != summarizeLinuxAuthPosture(p) {
		return fmt.Errorf("Linux authentication posture summary does not match records")
	}
	return nil
}

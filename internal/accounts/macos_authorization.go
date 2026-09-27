package accounts

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxMacOSAuthorizationIdentities = 4096
	maxMacOSAuthorizationRights     = 128
)

// MacOSIdentityAuthorization links a local OpenDirectory principal to the
// non-secret SecureToken/FileVault authorization metadata that macOS exposes.
// Chimera never reads passwords, private keys, recovery keys, or token secrets.
type MacOSIdentityAuthorization struct {
	ID                       string              `json:"id"`
	Principal                string              `json:"principal"`
	UID                      string              `json:"uid,omitempty"`
	Privileged               bool                `json:"privileged"`
	EnabledState             string              `json:"enabled_state"`
	LoginCapability          string              `json:"login_capability"`
	SecureToken              string              `json:"secure_token"`
	SecureTokenEvidenceState evidence.State      `json:"secure_token_evidence_state"`
	FileVaultAuthorized      string              `json:"filevault_authorized"`
	FileVaultEvidenceState   evidence.State      `json:"filevault_evidence_state"`
	Source                   string              `json:"source"`
	Confidence               evidence.Confidence `json:"confidence"`
	Reason                   string              `json:"reason,omitempty"`
}

// MacOSAuthorizationRight retains only the security-relevant class/rule names
// from an authorizationdb right. Arbitrary plist values are intentionally not
// emitted.
type MacOSAuthorizationRight struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	State      evidence.State      `json:"state"`
	Class      string              `json:"class,omitempty"`
	Rules      []string            `json:"rules,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Reason     string              `json:"reason,omitempty"`
}

type MacOSAuthorizationSummary struct {
	IdentityRecords             int `json:"identity_records"`
	PrivilegedIdentities        int `json:"privileged_identities"`
	EnabledPrivilegedIdentities int `json:"enabled_privileged_identities"`
	SecureTokenEnabled          int `json:"secure_token_enabled"`
	SecureTokenDisabled         int `json:"secure_token_disabled"`
	SecureTokenUnknown          int `json:"secure_token_unknown"`
	FileVaultAuthorized         int `json:"filevault_authorized"`
	FileVaultUnknown            int `json:"filevault_unknown"`
	AuthorizationRights         int `json:"authorization_rights"`
	AllowClassRights            int `json:"allow_class_rights"`
}

// MacOSAuthorizationPosture is the macOS local-authorization surface.
type MacOSAuthorizationPosture struct {
	State         evidence.State               `json:"state"`
	Source        string                       `json:"source"`
	Reason        string                       `json:"reason,omitempty"`
	FileVault     SecurityControl              `json:"filevault"`
	LoginControls []SecurityControl            `json:"login_controls,omitempty"`
	Rights        []MacOSAuthorizationRight    `json:"authorization_rights,omitempty"`
	Identities    []MacOSIdentityAuthorization `json:"identities,omitempty"`
	Summary       MacOSAuthorizationSummary    `json:"summary"`
}

func normalizeMacOSAuthorizationPosture(platform string, p MacOSAuthorizationPosture) MacOSAuthorizationPosture {
	p.Source = strings.TrimSpace(p.Source)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Source == "" {
		p.Source = "macOS local authorization provider"
	}
	if p.State == "" {
		if strings.EqualFold(platform, "darwin") {
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "macOS local authorization provider returned no state")
		} else {
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "macOS local authorization assessment is not applicable on this platform")
		}
	}

	p.FileVault = normalizeMacControl(p.FileVault, "filevault", "FileVault disk encryption", "fdesetup status")

	seenControls := map[string]struct{}{}
	controls := make([]SecurityControl, 0, len(p.LoginControls))
	for _, c := range p.LoginControls {
		c = normalizeMacControl(c, c.ID, c.Name, c.Source)
		if c.ID == "" || c.Name == "" || c.Source == "" {
			continue
		}
		if _, ok := seenControls[c.ID]; ok {
			continue
		}
		seenControls[c.ID] = struct{}{}
		controls = append(controls, c)
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].ID < controls[j].ID })
	p.LoginControls = controls

	seenRights := map[string]struct{}{}
	rights := make([]MacOSAuthorizationRight, 0, len(p.Rights))
	for _, r := range p.Rights {
		r.ID = slug(r.ID)
		r.Name = strings.TrimSpace(r.Name)
		r.Class = strings.ToUpper(strings.TrimSpace(r.Class))
		r.Source = strings.TrimSpace(r.Source)
		r.Reason = strings.TrimSpace(r.Reason)
		r.Rules = uniqueSorted(r.Rules)
		if r.ID == "" && r.Name != "" {
			r.ID = slug(r.Name)
		}
		if r.State == "" {
			r.State = evidence.StateUnavailable
		}
		if r.Source == "" {
			r.Source = "security authorizationdb read " + r.Name
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceHigh
		}
		if r.State != evidence.StateObserved && r.Reason == "" {
			r.Reason = "authorization right was not observable"
		}
		if r.ID == "" || r.Name == "" {
			continue
		}
		if _, ok := seenRights[r.ID]; ok {
			continue
		}
		seenRights[r.ID] = struct{}{}
		rights = append(rights, r)
	}
	sort.Slice(rights, func(i, j int) bool { return rights[i].ID < rights[j].ID })
	if len(rights) > maxMacOSAuthorizationRights {
		rights = rights[:maxMacOSAuthorizationRights]
	}
	p.Rights = rights

	seenIDs := map[string]struct{}{}
	ids := make([]MacOSIdentityAuthorization, 0, len(p.Identities))
	for _, item := range p.Identities {
		item.Principal = strings.TrimSpace(item.Principal)
		item.UID = strings.TrimSpace(item.UID)
		item.EnabledState = upperDefault(item.EnabledState, "UNKNOWN")
		item.LoginCapability = upperDefault(item.LoginCapability, "UNKNOWN")
		item.SecureToken = upperDefault(item.SecureToken, "UNKNOWN")
		item.FileVaultAuthorized = upperDefault(item.FileVaultAuthorized, "UNKNOWN")
		item.Source = strings.TrimSpace(item.Source)
		item.Reason = strings.TrimSpace(item.Reason)
		if item.ID == "" && item.Principal != "" {
			item.ID = stableLinuxAuthID("macos-auth", item.Principal, item.UID)
		}
		if item.SecureTokenEvidenceState == "" {
			item.SecureTokenEvidenceState = evidence.StateUnavailable
		}
		if item.FileVaultEvidenceState == "" {
			item.FileVaultEvidenceState = evidence.StateUnavailable
		}
		if item.Source == "" {
			item.Source = "macOS local authorization metadata"
		}
		if item.Confidence == "" {
			item.Confidence = evidence.ConfidenceHigh
		}
		if item.ID == "" || item.Principal == "" {
			continue
		}
		if _, ok := seenIDs[item.ID]; ok {
			continue
		}
		seenIDs[item.ID] = struct{}{}
		ids = append(ids, item)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Principal != ids[j].Principal {
			return ids[i].Principal < ids[j].Principal
		}
		return ids[i].ID < ids[j].ID
	})
	if len(ids) > maxMacOSAuthorizationIdentities {
		ids = ids[:maxMacOSAuthorizationIdentities]
	}
	p.Identities = ids
	p.Summary = summarizeMacOSAuthorizationPosture(p)
	return p
}

func normalizeMacControl(c SecurityControl, id, name, source string) SecurityControl {
	c.ID = slug(fallback(c.ID, id))
	c.Name = fallback(strings.TrimSpace(c.Name), name)
	c.Value = strings.ToUpper(strings.TrimSpace(c.Value))
	c.Source = fallback(strings.TrimSpace(c.Source), source)
	c.Reason = strings.TrimSpace(c.Reason)
	if c.State == "" {
		c.State = evidence.StateUnavailable
	}
	if c.Confidence == "" {
		c.Confidence = evidence.ConfidenceHigh
	}
	if c.State != evidence.StateObserved {
		c.Value = ""
		if c.Reason == "" {
			c.Reason = "macOS authorization control was not observable"
		}
	}
	return c
}

func summarizeMacOSAuthorizationPosture(p MacOSAuthorizationPosture) MacOSAuthorizationSummary {
	s := MacOSAuthorizationSummary{IdentityRecords: len(p.Identities), AuthorizationRights: len(p.Rights)}
	for _, item := range p.Identities {
		if item.Privileged {
			s.PrivilegedIdentities++
			if item.EnabledState == "ENABLED" {
				s.EnabledPrivilegedIdentities++
			}
		}
		if item.SecureTokenEvidenceState == evidence.StateObserved {
			switch item.SecureToken {
			case "ENABLED":
				s.SecureTokenEnabled++
			case "DISABLED":
				s.SecureTokenDisabled++
			default:
				s.SecureTokenUnknown++
			}
		} else {
			s.SecureTokenUnknown++
		}
		if item.FileVaultEvidenceState == evidence.StateObserved {
			if item.FileVaultAuthorized == "AUTHORIZED" {
				s.FileVaultAuthorized++
			}
		} else {
			s.FileVaultUnknown++
		}
	}
	for _, r := range p.Rights {
		if r.State == evidence.StateObserved && r.Class == "ALLOW" {
			s.AllowClassRights++
		}
	}
	return s
}

func validateMacOSAuthorizationPosture(platform string, p MacOSAuthorizationPosture) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("macOS authorization posture state/source is incomplete")
	}
	if !strings.EqualFold(platform, "darwin") && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("non-macOS authorization posture must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && p.State != evidence.StateDegraded && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed macOS authorization posture requires a reason")
	}
	if err := validateMacControl(p.FileVault); err != nil {
		return fmt.Errorf("FileVault control: %w", err)
	}
	last := ""
	seen := map[string]struct{}{}
	for i, c := range p.LoginControls {
		if err := validateMacControl(c); err != nil {
			return fmt.Errorf("macOS login control %d: %w", i, err)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate macOS login control %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && c.ID < last {
			return fmt.Errorf("macOS login controls are not deterministically ordered")
		}
		last = c.ID
	}
	last = ""
	seen = map[string]struct{}{}
	for i, r := range p.Rights {
		if r.ID == "" || r.Name == "" || r.State == "" || r.Source == "" || r.Confidence == "" {
			return fmt.Errorf("macOS authorization right %d is incomplete", i)
		}
		if r.State != evidence.StateObserved && r.Reason == "" {
			return fmt.Errorf("macOS authorization right %q non-observed without reason", r.ID)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate macOS authorization right %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if last != "" && r.ID < last {
			return fmt.Errorf("macOS authorization rights are not deterministically ordered")
		}
		last = r.ID
	}
	last = ""
	seen = map[string]struct{}{}
	for i, item := range p.Identities {
		if item.ID == "" || item.Principal == "" || item.EnabledState == "" || item.LoginCapability == "" || item.SecureToken == "" || item.SecureTokenEvidenceState == "" || item.FileVaultAuthorized == "" || item.FileVaultEvidenceState == "" || item.Source == "" || item.Confidence == "" {
			return fmt.Errorf("macOS authorization identity %d is incomplete", i)
		}
		if _, ok := seen[item.ID]; ok {
			return fmt.Errorf("duplicate macOS authorization identity %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		key := item.Principal + "\x00" + item.ID
		if last != "" && key < last {
			return fmt.Errorf("macOS authorization identities are not deterministically ordered")
		}
		last = key
	}
	if p.Summary != summarizeMacOSAuthorizationPosture(p) {
		return fmt.Errorf("macOS authorization posture summary does not match records")
	}
	return nil
}

func validateMacControl(c SecurityControl) error {
	if c.ID == "" || c.Name == "" || c.State == "" || c.Source == "" || c.Confidence == "" {
		return fmt.Errorf("control is incomplete")
	}
	if c.State == evidence.StateObserved && strings.TrimSpace(c.Value) == "" {
		return fmt.Errorf("observed control %q has no normalized value", c.ID)
	}
	if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
		return fmt.Errorf("non-observed control %q requires a reason", c.ID)
	}
	return nil
}

func parseFileVaultStatus(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "filevault is on"):
		return "ENABLED", true
	case strings.Contains(s, "filevault is off"):
		return "DISABLED", true
	case strings.Contains(s, "encryption in progress"):
		return "ENCRYPTING", true
	case strings.Contains(s, "decryption in progress"):
		return "DECRYPTING", true
	default:
		return "", false
	}
}

func parseSecureTokenStatus(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "secure token is enabled"):
		return "ENABLED", true
	case strings.Contains(s, "secure token is disabled"):
		return "DISABLED", true
	default:
		return "", false
	}
}

func parseBooleanPosture(raw string) (bool, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.Trim(s, "\"'")
	switch s {
	case "1", "yes", "true", "enabled":
		return true, true
	case "0", "no", "false", "disabled":
		return false, true
	default:
		return false, false
	}
}

func parseFdesetupUsers(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "username") {
			continue
		}
		name := line
		if i := strings.Index(name, ","); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name != "" && !strings.ContainsAny(name, " \t") {
			out[name] = struct{}{}
		}
	}
	return out
}

var plistStringRE = regexp.MustCompile(`(?is)<string>\s*([^<]+?)\s*</string>`)

func parseAuthorizationDBRight(name, raw string) MacOSAuthorizationRight {
	right := MacOSAuthorizationRight{ID: slug(name), Name: name, State: evidence.StateUnavailable, Source: "security authorizationdb read " + name, Confidence: evidence.ConfidenceHigh, Reason: "authorization right output could not be normalized"}
	lower := strings.ToLower(raw)
	class := plistValueAfterKey(lower, raw, "class")
	if class == "" {
		return right
	}
	right.State = evidence.StateObserved
	right.Class = strings.ToUpper(strings.TrimSpace(class))
	right.Reason = ""
	if body := plistArrayAfterKey(lower, raw, "rule"); body != "" {
		for _, m := range plistStringRE.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				v := strings.TrimSpace(m[1])
				if v != "" {
					right.Rules = append(right.Rules, v)
				}
			}
		}
		right.Rules = uniqueSorted(right.Rules)
	}
	return right
}

func plistValueAfterKey(lower, raw, key string) string {
	needle := "<key>" + strings.ToLower(key) + "</key>"
	i := strings.Index(lower, needle)
	if i < 0 {
		return ""
	}
	tailLower := lower[i+len(needle):]
	j := strings.Index(tailLower, "<string>")
	if j < 0 {
		return ""
	}
	start := i + len(needle) + j + len("<string>")
	endRel := strings.Index(strings.ToLower(raw[start:]), "</string>")
	if endRel < 0 {
		return ""
	}
	return strings.TrimSpace(raw[start : start+endRel])
}

func plistArrayAfterKey(lower, raw, key string) string {
	needle := "<key>" + strings.ToLower(key) + "</key>"
	i := strings.Index(lower, needle)
	if i < 0 {
		return ""
	}
	tailLower := lower[i+len(needle):]
	j := strings.Index(tailLower, "<array>")
	if j < 0 {
		return ""
	}
	start := i + len(needle) + j + len("<array>")
	endRel := strings.Index(strings.ToLower(raw[start:]), "</array>")
	if endRel < 0 {
		return ""
	}
	return raw[start : start+endRel]
}

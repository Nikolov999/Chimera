//go:build darwin

package accounts

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMacOSAuthorizationPosture(ctx context.Context, inv *Inventory) {
	p := MacOSAuthorizationPosture{Source: "macOS fdesetup/sysadminctl/defaults/authorizationdb metadata"}
	var problems []string

	p.FileVault = collectMacFileVault(ctx)
	if p.FileVault.State != evidence.StateObserved {
		problems = append(problems, "FileVault state: "+fallback(p.FileVault.Reason, "unavailable"))
	}

	fvUsers, fvState, fvReason := collectMacFileVaultUsers(ctx, p.FileVault)
	if fvState != evidence.StateObserved && p.FileVault.Value != "DISABLED" {
		problems = append(problems, "FileVault authorized-user metadata: "+fallback(fvReason, "unavailable"))
	}

	p.LoginControls = []SecurityControl{
		collectMacDefaultsBool(ctx, "automatic-login", "Automatic login", "autoLoginUser", true),
		collectMacDefaultsBool(ctx, "guest-login", "Guest login", "GuestEnabled", false),
		collectMacDefaultsBool(ctx, "disable-fde-auto-login", "Disable FileVault preboot automatic login", "DisableFDEAutoLogin", false),
	}
	for _, c := range p.LoginControls {
		if c.State != evidence.StateObserved {
			problems = append(problems, c.Name+": "+fallback(c.Reason, "unavailable"))
		}
	}

	for _, rightName := range []string{"system.preferences", "system.preferences.accounts"} {
		r := collectMacAuthorizationRight(ctx, rightName)
		p.Rights = append(p.Rights, r)
		if r.State != evidence.StateObserved {
			problems = append(problems, rightName+": "+fallback(r.Reason, "unavailable"))
		}
	}

	sysadminctl, sysadminErr := exec.LookPath("sysadminctl")
	seenLocal := map[string]struct{}{}
	for _, a := range inv.Accounts {
		if ctx.Err() != nil {
			break
		}
		// SecureToken/FileVault relationships are relevant to human and
		// privileged local accounts; skip service/system noise.
		if a.AccountType != "HUMAN" && !a.Privileged {
			continue
		}
		seenLocal[a.Name] = struct{}{}
		item := MacOSIdentityAuthorization{
			Principal: a.Principal, UID: a.UID, Privileged: a.Privileged,
			EnabledState: a.EnabledState, LoginCapability: a.LoginCapability,
			SecureToken: "UNKNOWN", SecureTokenEvidenceState: evidence.StateUnavailable,
			FileVaultAuthorized: "UNKNOWN", FileVaultEvidenceState: fvState,
			Source:     "OpenDirectory + sysadminctl/fdesetup authorization metadata",
			Confidence: evidence.ConfidenceHigh,
		}
		if sysadminErr != nil {
			item.Reason = "sysadminctl not found"
		} else {
			raw, err := exec.CommandContext(ctx, sysadminctl, "-secureTokenStatus", a.Name).CombinedOutput()
			if token, ok := parseSecureTokenStatus(string(raw)); ok {
				item.SecureToken = token
				item.SecureTokenEvidenceState = evidence.StateObserved
			} else if err != nil {
				item.Reason = "SecureToken status unavailable: " + compactExecReason(string(raw), err)
			} else {
				item.Reason = "SecureToken status output was not recognized"
			}
		}
		if fvState == evidence.StateObserved {
			if p.FileVault.Value == "DISABLED" {
				item.FileVaultAuthorized = "NOT_APPLICABLE"
				item.FileVaultEvidenceState = evidence.StateNotApplicable
			} else {
				if _, ok := fvUsers[a.Name]; ok {
					item.FileVaultAuthorized = "AUTHORIZED"
				} else {
					item.FileVaultAuthorized = "NOT_AUTHORIZED"
				}
				item.FileVaultEvidenceState = evidence.StateObserved
			}
		}
		p.Identities = append(p.Identities, item)
	}
	// Preserve FileVault-authorized principals that no longer map to a local
	// account as explicit relationship evidence instead of silently dropping
	// them from the assessment.
	if fvState == evidence.StateObserved && p.FileVault.Value != "DISABLED" {
		for name := range fvUsers {
			if _, ok := seenLocal[name]; ok {
				continue
			}
			p.Identities = append(p.Identities, MacOSIdentityAuthorization{
				Principal: name, EnabledState: "UNKNOWN", LoginCapability: "UNKNOWN",
				SecureToken: "UNKNOWN", SecureTokenEvidenceState: evidence.StateUnavailable,
				FileVaultAuthorized: "AUTHORIZED", FileVaultEvidenceState: evidence.StateObserved,
				Source:     "fdesetup authorized-user metadata; no matching local OpenDirectory account",
				Confidence: evidence.ConfidenceHigh, Reason: "FileVault-authorized identity did not map to the collected local account inventory",
			})
		}
	}

	switch {
	case ctx.Err() != nil:
		p.State = evidence.StateUnavailable
		p.Reason = "macOS authorization collection cancelled or timed out: " + ctx.Err().Error()
	case p.FileVault.State == evidence.StateObserved || len(p.Identities) > 0 || anyMacObservedControl(p.LoginControls) || anyMacObservedRight(p.Rights):
		if len(problems) > 0 {
			p.State = evidence.StateDegraded
			p.Reason = strings.Join(uniqueSorted(problems), "; ")
		} else {
			p.State = evidence.StateObserved
		}
	default:
		p.State = evidence.StateUnavailable
		p.Reason = "no supported macOS local authorization provider returned usable metadata"
	}
	inv.MacOSAuthorizationPosture = normalizeMacOSAuthorizationPosture("darwin", p)
}

func collectMacFileVault(ctx context.Context) SecurityControl {
	c := SecurityControl{ID: "filevault", Name: "FileVault disk encryption", Source: "fdesetup status", Confidence: evidence.ConfidenceHigh}
	path, err := exec.LookPath("fdesetup")
	if err != nil {
		c.State = evidence.StateUnavailable
		c.Reason = "fdesetup not found"
		return c
	}
	raw, err := exec.CommandContext(ctx, path, "status").CombinedOutput()
	if v, ok := parseFileVaultStatus(string(raw)); ok {
		c.State = evidence.StateObserved
		c.Value = v
		c.Confidence = evidence.ConfidenceExact
		return c
	}
	c.State = evidence.StateUnavailable
	c.Reason = compactExecReason(string(raw), err)
	return c
}

func collectMacFileVaultUsers(ctx context.Context, fv SecurityControl) (map[string]struct{}, evidence.State, string) {
	if fv.State == evidence.StateObserved && fv.Value == "DISABLED" {
		return map[string]struct{}{}, evidence.StateObserved, ""
	}
	path, err := exec.LookPath("fdesetup")
	if err != nil {
		return nil, evidence.StateUnavailable, "fdesetup not found"
	}
	raw, err := exec.CommandContext(ctx, path, "list", "-extended").CombinedOutput()
	if err != nil {
		reason := compactExecReason(string(raw), err)
		low := strings.ToLower(reason)
		if strings.Contains(low, "must be root") || strings.Contains(low, "not permitted") || strings.Contains(low, "permission") {
			return nil, evidence.StateDenied, reason
		}
		return nil, evidence.StateUnavailable, reason
	}
	return parseFdesetupUsers(string(raw)), evidence.StateObserved, ""
}

func collectMacDefaultsBool(ctx context.Context, id, name, key string, stringPresence bool) SecurityControl {
	source := "defaults read /Library/Preferences/com.apple.loginwindow " + key
	c := SecurityControl{ID: id, Name: name, Source: source, Confidence: evidence.ConfidenceHigh}
	path, err := exec.LookPath("defaults")
	if err != nil {
		c.State = evidence.StateUnavailable
		c.Reason = "defaults not found"
		return c
	}
	raw, err := exec.CommandContext(ctx, path, "read", "/Library/Preferences/com.apple.loginwindow", key).CombinedOutput()
	if err != nil {
		c.State = evidence.StateUnavailable
		c.Reason = compactExecReason(string(raw), err)
		return c
	}
	text := strings.TrimSpace(string(raw))
	if stringPresence {
		if text == "" {
			c.State = evidence.StateUnavailable
			c.Reason = "empty loginwindow value"
			return c
		}
		c.State = evidence.StateObserved
		c.Value = "ENABLED"
		c.Confidence = evidence.ConfidenceExact
		return c
	}
	if b, ok := parseBooleanPosture(text); ok {
		c.State = evidence.StateObserved
		if b {
			c.Value = "ENABLED"
		} else {
			c.Value = "DISABLED"
		}
		c.Confidence = evidence.ConfidenceExact
		return c
	}
	c.State = evidence.StateUnavailable
	c.Reason = "loginwindow boolean value could not be normalized"
	return c
}

func collectMacAuthorizationRight(ctx context.Context, name string) MacOSAuthorizationRight {
	source := "security authorizationdb read " + name
	right := MacOSAuthorizationRight{ID: slug(name), Name: name, State: evidence.StateUnavailable, Source: source, Confidence: evidence.ConfidenceHigh}
	path, err := exec.LookPath("security")
	if err != nil {
		right.Reason = "security tool not found"
		return right
	}
	raw, err := exec.CommandContext(ctx, path, "authorizationdb", "read", name).CombinedOutput()
	if err != nil {
		right.Reason = compactExecReason(string(raw), err)
		return right
	}
	parsed := parseAuthorizationDBRight(name, string(raw))
	parsed.Source = source
	return parsed
}

func compactExecReason(raw string, err error) string {
	text := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	if len(text) > 240 {
		text = text[:240] + "..."
	}
	if text != "" {
		return text
	}
	if err != nil {
		return err.Error()
	}
	return "provider returned no usable output"
}

func anyMacObservedControl(in []SecurityControl) bool {
	for _, c := range in {
		if c.State == evidence.StateObserved {
			return true
		}
	}
	return false
}

func anyMacObservedRight(in []MacOSAuthorizationRight) bool {
	for _, r := range in {
		if r.State == evidence.StateObserved {
			return true
		}
	}
	return false
}

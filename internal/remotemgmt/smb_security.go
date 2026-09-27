package remotemgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

const smbSecuritySchemaVersion = "chimera.smb-security/v1"

const (
	smbStateComplete      = "COMPLETE"
	smbStateDegraded      = "DEGRADED"
	smbStateNotApplicable = "NOT_APPLICABLE"
)

type SMBSetting struct {
	Name       string              `json:"name"`
	Scope      string              `json:"scope"`
	State      evidence.State      `json:"state"`
	Value      string              `json:"value,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Explicit   bool                `json:"explicit"`
	Reason     string              `json:"reason,omitempty"`
}

type SMBShareGrant struct {
	Principal string `json:"principal"`
	Access    string `json:"access"`
	Type      string `json:"type,omitempty"`
}

type SMBShare struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Path               string              `json:"path,omitempty"`
	State              evidence.State      `json:"state"`
	Special            bool                `json:"special"`
	Hidden             bool                `json:"hidden"`
	GuestAllowed       bool                `json:"guest_allowed"`
	Writable           bool                `json:"writable"`
	WritableKnown      bool                `json:"writable_known"`
	EncryptionRequired bool                `json:"encryption_required"`
	BroadRead          bool                `json:"broad_read"`
	BroadWrite         bool                `json:"broad_write"`
	AccessKnown        bool                `json:"access_known"`
	SensitivePath      bool                `json:"sensitive_path"`
	Grants             []SMBShareGrant     `json:"grants,omitempty"`
	RiskTags           []string            `json:"risk_tags,omitempty"`
	Source             string              `json:"source"`
	Confidence         evidence.Confidence `json:"confidence"`
	Reason             string              `json:"reason,omitempty"`
}

type SMBSecuritySummary struct {
	Applicable          bool `json:"applicable"`
	SettingsObserved    int  `json:"settings_observed"`
	SettingsUnavailable int  `json:"settings_unavailable"`
	Shares              int  `json:"shares"`
	GuestShares         int  `json:"guest_shares"`
	WritableGuestShares int  `json:"writable_guest_shares"`
	BroadWriteShares    int  `json:"broad_write_shares"`
	AccessUnavailable   int  `json:"access_unavailable_shares"`
	EncryptedShares     int  `json:"encrypted_shares"`
	SensitiveShares     int  `json:"sensitive_shares"`
	RiskTaggedShares    int  `json:"risk_tagged_shares"`
}

type SMBSecurity struct {
	Schema               string             `json:"schema"`
	State                string             `json:"state"`
	Platform             string             `json:"platform"`
	EvaluationSource     string             `json:"evaluation_source,omitempty"`
	ShareInventoryState  evidence.State     `json:"share_inventory_state"`
	ShareInventorySource string             `json:"share_inventory_source"`
	ShareInventoryReason string             `json:"share_inventory_reason,omitempty"`
	Settings             []SMBSetting       `json:"settings"`
	Shares               []SMBShare         `json:"shares"`
	Summary              SMBSecuritySummary `json:"summary"`
	Degraded             []string           `json:"degraded,omitempty"`
}

type smbPlatformResult struct {
	Detected             bool
	EvaluationSource     string
	ShareInventoryState  evidence.State
	ShareInventorySource string
	ShareInventoryReason string
	Settings             []SMBSetting
	Shares               []SMBShare
	Degraded             []string
}

func collectSMBSecurity(ctx context.Context, svc services.Inventory, net netinv.Inventory) SMBSecurity {
	platform := collectPlatformSMBSecurity(ctx)
	detected := platform.Detected || hasSMBPresence(svc, net)
	out := SMBSecurity{
		Schema:               smbSecuritySchemaVersion,
		State:                smbStateNotApplicable,
		Platform:             runtime.GOOS,
		EvaluationSource:     strings.TrimSpace(platform.EvaluationSource),
		ShareInventoryState:  evidence.StateNotApplicable,
		ShareInventorySource: "local SMB/file-sharing provider",
		Settings:             []SMBSetting{},
		Shares:               []SMBShare{},
	}
	if !detected {
		out.Summary = summarizeSMB(out)
		return out
	}
	out.State = smbStateComplete
	out.Settings = append(out.Settings, platform.Settings...)
	out.Shares = append(out.Shares, platform.Shares...)
	out.Degraded = append(out.Degraded, platform.Degraded...)
	out.ShareInventoryState = platform.ShareInventoryState
	out.ShareInventorySource = strings.TrimSpace(platform.ShareInventorySource)
	out.ShareInventoryReason = strings.TrimSpace(platform.ShareInventoryReason)
	if out.ShareInventorySource == "" {
		out.ShareInventorySource = "local SMB/file-sharing provider"
	}
	if out.ShareInventoryState == "" {
		out.ShareInventoryState = evidence.StateUnavailable
		out.ShareInventoryReason = "share inventory provider did not report collection state"
	}
	if out.ShareInventoryState != evidence.StateObserved && out.ShareInventoryState != evidence.StateNotApplicable {
		if out.ShareInventoryReason == "" {
			out.ShareInventoryReason = string(out.ShareInventoryState)
		}
		out.Degraded = append(out.Degraded, "SMB share inventory: "+out.ShareInventoryReason)
	}
	for _, s := range out.Settings {
		if s.State != evidence.StateObserved && s.State != evidence.StateNotApplicable {
			reason := strings.TrimSpace(s.Reason)
			if reason == "" {
				reason = string(s.State)
			}
			out.Degraded = append(out.Degraded, "SMB setting "+s.Name+": "+reason)
		}
	}
	for _, sh := range out.Shares {
		if sh.State != evidence.StateObserved && sh.State != evidence.StateNotApplicable {
			reason := strings.TrimSpace(sh.Reason)
			if reason == "" {
				reason = string(sh.State)
			}
			out.Degraded = append(out.Degraded, "SMB share "+sh.Name+": "+reason)
		}
	}
	out = normalizeSMBSecurity(out)
	if len(out.Degraded) > 0 {
		out.State = smbStateDegraded
	}
	return out
}

func hasSMBPresence(svc services.Inventory, net netinv.Inventory) bool {
	for _, s := range svc.Services {
		if s.Exposure != nil && strings.EqualFold(s.Exposure.State, "CLASSIFIED") && strings.EqualFold(s.Exposure.Family, "SMB") {
			return true
		}
		text := strings.ToLower(strings.Join([]string{s.Name, s.DisplayName, s.Executable, s.ExecutablePath}, " "))
		if strings.Contains(text, "smbd") || strings.Contains(text, "samba") || strings.Contains(text, "lanmanserver") || strings.Contains(text, "filesharing") {
			return true
		}
	}
	for _, ep := range net.Endpoints {
		if ep.LocalPort == 445 || ep.LocalPort == 139 {
			return true
		}
		text := strings.ToLower(strings.Join([]string{ep.Owner.ServiceName, ep.Owner.ProcessName, ep.Owner.Executable}, " "))
		if strings.Contains(text, "smbd") || strings.Contains(text, "samba") || strings.Contains(text, "lanmanserver") {
			return true
		}
	}
	return false
}

func normalizeSMBSecurity(in SMBSecurity) SMBSecurity {
	for i := range in.Settings {
		in.Settings[i].Name = strings.ToLower(strings.TrimSpace(in.Settings[i].Name))
		in.Settings[i].Scope = strings.ToLower(strings.TrimSpace(in.Settings[i].Scope))
		in.Settings[i].Value = strings.TrimSpace(in.Settings[i].Value)
		in.Settings[i].Source = strings.TrimSpace(in.Settings[i].Source)
		in.Settings[i].Reason = strings.TrimSpace(in.Settings[i].Reason)
		if in.Settings[i].Scope == "" {
			in.Settings[i].Scope = "server"
		}
		if in.Settings[i].Confidence == "" {
			in.Settings[i].Confidence = evidence.ConfidenceLow
		}
	}
	sort.Slice(in.Settings, func(i, j int) bool {
		if in.Settings[i].Scope == in.Settings[j].Scope {
			return in.Settings[i].Name < in.Settings[j].Name
		}
		return in.Settings[i].Scope < in.Settings[j].Scope
	})
	for i := range in.Shares {
		in.Shares[i].Name = strings.TrimSpace(in.Shares[i].Name)
		in.Shares[i].Path = strings.TrimSpace(in.Shares[i].Path)
		in.Shares[i].Source = strings.TrimSpace(in.Shares[i].Source)
		in.Shares[i].Reason = strings.TrimSpace(in.Shares[i].Reason)
		in.Shares[i].RiskTags = uniqueStrings(in.Shares[i].RiskTags)
		sort.Slice(in.Shares[i].Grants, func(a, b int) bool {
			if in.Shares[i].Grants[a].Principal == in.Shares[i].Grants[b].Principal {
				return in.Shares[i].Grants[a].Access < in.Shares[i].Grants[b].Access
			}
			return in.Shares[i].Grants[a].Principal < in.Shares[i].Grants[b].Principal
		})
		if in.Shares[i].ID == "" {
			in.Shares[i].ID = smbShareID(in.Shares[i].Name, in.Shares[i].Path)
		}
		if in.Shares[i].Confidence == "" {
			in.Shares[i].Confidence = evidence.ConfidenceLow
		}
	}
	sort.Slice(in.Shares, func(i, j int) bool { return in.Shares[i].ID < in.Shares[j].ID })
	in.Degraded = uniqueStrings(in.Degraded)
	in.Summary = summarizeSMB(in)
	return in
}

func summarizeSMB(in SMBSecurity) SMBSecuritySummary {
	s := SMBSecuritySummary{Applicable: in.State != smbStateNotApplicable, Shares: len(in.Shares)}
	for _, setting := range in.Settings {
		if setting.State == evidence.StateObserved {
			s.SettingsObserved++
		} else if setting.State != evidence.StateNotApplicable {
			s.SettingsUnavailable++
		}
	}
	for _, sh := range in.Shares {
		if sh.State != evidence.StateObserved {
			continue
		}
		if sh.GuestAllowed {
			s.GuestShares++
			if sh.WritableKnown && sh.Writable {
				s.WritableGuestShares++
			}
		}
		if sh.BroadWrite {
			s.BroadWriteShares++
		}
		if !sh.AccessKnown {
			s.AccessUnavailable++
		}
		if sh.EncryptionRequired {
			s.EncryptedShares++
		}
		if sh.SensitivePath {
			s.SensitiveShares++
		}
		if len(sh.RiskTags) > 0 {
			s.RiskTaggedShares++
		}
	}
	return s
}

func validateSMBSecurity(s SMBSecurity) error {
	if s.Schema != smbSecuritySchemaVersion {
		return fmt.Errorf("unexpected SMB security schema %q", s.Schema)
	}
	if s.Platform == "" {
		return fmt.Errorf("SMB security platform is required")
	}
	switch s.State {
	case smbStateComplete, smbStateDegraded, smbStateNotApplicable:
	default:
		return fmt.Errorf("invalid SMB security state %q", s.State)
	}
	if s.State == smbStateNotApplicable {
		return nil
	}
	if s.ShareInventoryState == "" || s.ShareInventorySource == "" {
		return fmt.Errorf("SMB share inventory state/source are required")
	}
	if s.ShareInventoryState != evidence.StateObserved && s.ShareInventoryState != evidence.StateNotApplicable && strings.TrimSpace(s.ShareInventoryReason) == "" {
		return fmt.Errorf("SMB share inventory requires degradation reason")
	}
	last := ""
	for i, setting := range s.Settings {
		if setting.Name == "" || setting.Scope == "" || setting.State == "" || setting.Source == "" || setting.Confidence == "" {
			return fmt.Errorf("SMB setting %d is incomplete", i)
		}
		if setting.State != evidence.StateObserved && setting.State != evidence.StateNotApplicable && setting.Reason == "" {
			return fmt.Errorf("SMB setting %q requires degradation reason", setting.Name)
		}
		key := setting.Scope + "." + setting.Name
		if last != "" && key < last {
			return fmt.Errorf("SMB settings are not deterministically ordered")
		}
		last = key
	}
	last = ""
	for i, sh := range s.Shares {
		if sh.ID == "" || sh.Name == "" || sh.State == "" || sh.Source == "" || sh.Confidence == "" {
			return fmt.Errorf("SMB share %d is incomplete", i)
		}
		if sh.State != evidence.StateObserved && sh.State != evidence.StateNotApplicable && sh.Reason == "" {
			return fmt.Errorf("SMB share %q requires degradation reason", sh.Name)
		}
		if last != "" && sh.ID < last {
			return fmt.Errorf("SMB shares are not deterministically ordered")
		}
		last = sh.ID
	}
	if s.Summary != summarizeSMB(s) {
		return fmt.Errorf("SMB security summary does not match records")
	}
	return nil
}

func buildSMBEvidence(s SMBSecurity, at time.Time) []evidence.Observation {
	source := "local SMB/file-sharing security assessment"
	if s.State == smbStateNotApplicable {
		return []evidence.Observation{evidence.NewState("smb_security.applicability", evidence.StateNotApplicable, source, at, evidence.ConfidenceHigh, "local SMB/file-sharing server configuration or surface was not detected")}
	}
	out := []evidence.Observation{
		evidence.NewObserved("smb_security.applicability", "APPLICABLE", source, at, evidence.ConfidenceHigh),
		evidence.NewObserved("smb_security.summary", s.Summary, source, at, evidence.ConfidenceHigh),
	}
	if s.ShareInventoryState == evidence.StateObserved {
		out = append(out, evidence.NewObserved("smb_security.shares_inventory", map[string]any{"state": "OBSERVED", "count": len(s.Shares)}, s.ShareInventorySource, at, evidence.ConfidenceHigh))
	} else if s.ShareInventoryState == evidence.StateNotApplicable {
		out = append(out, evidence.NewState("smb_security.shares_inventory", evidence.StateNotApplicable, s.ShareInventorySource, at, evidence.ConfidenceHigh, "SMB share inventory is not applicable"))
	} else {
		out = append(out, evidence.NewState("smb_security.shares_inventory", s.ShareInventoryState, s.ShareInventorySource, at, evidence.ConfidenceLow, s.ShareInventoryReason))
	}
	for _, setting := range s.Settings {
		key := "smb_security.setting." + setting.Scope + "." + smbEvidenceToken(setting.Name)
		if setting.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, setting, setting.Source, at, setting.Confidence))
		} else if setting.State == evidence.StateNotApplicable {
			out = append(out, evidence.NewState(key, evidence.StateNotApplicable, setting.Source, at, setting.Confidence, setting.Reason))
		} else {
			out = append(out, evidence.NewState(key, setting.State, setting.Source, at, setting.Confidence, setting.Reason))
		}
	}
	for _, sh := range s.Shares {
		key := "smb_security.share." + sh.ID
		if sh.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, sh, sh.Source, at, sh.Confidence))
		} else if sh.State == evidence.StateNotApplicable {
			out = append(out, evidence.NewState(key, evidence.StateNotApplicable, sh.Source, at, sh.Confidence, sh.Reason))
		} else {
			out = append(out, evidence.NewState(key, sh.State, sh.Source, at, sh.Confidence, sh.Reason))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func smbEvidenceToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer(" ", "_", "-", "_", "/", "_", "\\", "_", ".", "_")
	return repl.Replace(s)
}

func smbShareID(name, path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name)) + "\x00" + strings.ToLower(filepath.Clean(strings.TrimSpace(path)))))
	return "smbs-" + hex.EncodeToString(sum[:8])
}

func smbSensitivePath(path string) bool {
	p := strings.TrimSpace(path)
	if p == "" {
		return false
	}
	if runtime.GOOS == "windows" || strings.Contains(p, `:\`) {
		q := strings.ToLower(strings.ReplaceAll(filepath.Clean(p), "/", `\`))
		if len(q) == 3 && q[1:] == `:\` {
			return true
		}
		roots := []string{`c:\windows`, `c:\program files`, `c:\program files (x86)`, `c:\programdata`, `c:\users\default`}
		for _, root := range roots {
			if q == root || strings.HasPrefix(q, root+`\`) {
				return true
			}
		}
		return false
	}
	q := filepath.Clean(p)
	if q == "/" {
		return true
	}
	roots := []string{"/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/private/etc", "/System", "/Library", "/var/lib", "/var/run", "/run/secrets"}
	for _, root := range roots {
		if q == root || strings.HasPrefix(q, root+"/") {
			return true
		}
	}
	return false
}

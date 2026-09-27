package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.accounts/v1"
	CollectorName    = "accounts"
	CollectorVersion = "accounts/phase072-v1"
	maxAccounts      = 16384
	maxGroups        = 16384
)

type AuthenticationMetadata struct {
	State              string `json:"state"`
	PasswordState      string `json:"password_state"`
	PasswordRequired   string `json:"password_required"`
	PasswordExpires    string `json:"password_expires"`
	PasswordChangeable string `json:"password_changeable"`
	LastLogin          string `json:"last_login,omitempty"`
	LastPasswordChange string `json:"last_password_change,omitempty"`
	Source             string `json:"source"`
	Reason             string `json:"reason,omitempty"`
}

type Account struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Principal        string                 `json:"principal"`
	UID              string                 `json:"uid,omitempty"`
	GID              string                 `json:"gid,omitempty"`
	SID              string                 `json:"sid,omitempty"`
	Home             string                 `json:"home,omitempty"`
	Shell            string                 `json:"shell,omitempty"`
	Description      string                 `json:"description,omitempty"`
	AccountType      string                 `json:"account_type"`
	EnabledState     string                 `json:"enabled_state"`
	LoginCapability  string                 `json:"login_capability"`
	Privileged       bool                   `json:"privileged"`
	PrivilegeBasis   []string               `json:"privilege_basis,omitempty"`
	ServiceAccount   bool                   `json:"service_account"`
	ServiceBasis     []string               `json:"service_basis,omitempty"`
	Groups           []string               `json:"groups,omitempty"`
	Authentication   AuthenticationMetadata `json:"authentication"`
	CollectionSource string                 `json:"collection_source"`
	Confidence       evidence.Confidence    `json:"confidence"`
}

type Group struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	GID              string              `json:"gid,omitempty"`
	SID              string              `json:"sid,omitempty"`
	Privileged       bool                `json:"privileged"`
	Members          []string            `json:"members,omitempty"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

// SecurityControl is a normalized, non-secret Windows security-control fact.
// Value contains only a posture label derived from policy/runtime metadata;
// raw credential values are never required or retained by downstream rules.
type SecurityControl struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	State      evidence.State      `json:"state"`
	Value      string              `json:"value,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Reason     string              `json:"reason,omitempty"`
}

// SecurityPolicy represents host-local account/UAC policy evidence. // populates it on Windows and marks it NOT_APPLICABLE elsewhere.
type SecurityPolicy struct {
	State    evidence.State    `json:"state"`
	Source   string            `json:"source"`
	Reason   string            `json:"reason,omitempty"`
	Controls []SecurityControl `json:"controls,omitempty"`
}

// CredentialProtection represents non-secret Windows credential-defense posture.
// populates it from registry policy and Device Guard runtime metadata
// and marks it NOT_APPLICABLE on non-Windows hosts.
type CredentialProtection struct {
	State    evidence.State    `json:"state"`
	Source   string            `json:"source"`
	Reason   string            `json:"reason,omitempty"`
	Controls []SecurityControl `json:"controls,omitempty"`
}

type Summary struct {
	Accounts                   int `json:"accounts"`
	Groups                     int `json:"groups"`
	Enabled                    int `json:"enabled"`
	Disabled                   int `json:"disabled"`
	EnabledUnknown             int `json:"enabled_unknown"`
	LoginCapable               int `json:"login_capable"`
	LoginDisabled              int `json:"login_disabled"`
	LoginUnknown               int `json:"login_unknown"`
	Privileged                 int `json:"privileged"`
	ServiceAccounts            int `json:"service_accounts"`
	HumanAccounts              int `json:"human_accounts"`
	SystemAccounts             int `json:"system_accounts"`
	AuthObserved               int `json:"auth_observed"`
	AuthDegraded               int `json:"auth_degraded"`
	PasswordStateKnown         int `json:"password_state_known"`
	EmptyPasswordObserved      int `json:"empty_password_observed"`
	PasswordNotRequired        int `json:"password_not_required"`
	PasswordStateUnknown       int `json:"password_state_unknown"`
	PasswordRequirementUnknown int `json:"password_requirement_unknown"`
}

type Inventory struct {
	Schema                    string                    `json:"schema"`
	EvidenceSchema            string                    `json:"evidence_schema"`
	Collector                 string                    `json:"collector"`
	CollectorVersion          string                    `json:"collector_version"`
	Platform                  string                    `json:"platform"`
	Architecture              string                    `json:"architecture"`
	CollectedAt               time.Time                 `json:"collected_at"`
	Accounts                  []Account                 `json:"accounts"`
	Groups                    []Group                   `json:"groups"`
	Sources                   []SourceStatus            `json:"sources"`
	Summary                   Summary                   `json:"summary"`
	SecurityPolicy            SecurityPolicy            `json:"security_policy"`
	CredentialProtection      CredentialProtection      `json:"credential_protection"`
	SudoPosture               SudoPosture               `json:"sudo_posture"`
	LinuxAuthPosture          LinuxAuthPosture          `json:"linux_auth_posture"`
	MacOSAuthorizationPosture MacOSAuthorizationPosture `json:"macos_authorization_posture"`
	SSHKeyPosture             SSHKeyPosture             `json:"ssh_key_posture"`
	Evidence                  []evidence.Observation    `json:"evidence"`
	Degraded                  []string                  `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at}
	collectPlatform(ctx, &inv)
	collectSecurityPolicy(ctx, &inv)
	collectCredentialProtection(ctx, &inv)
	collectSudoPosture(ctx, &inv)
	collectLinuxAuthPosture(ctx, &inv)
	collectMacOSAuthorizationPosture(ctx, &inv)
	inv.Groups = normalizeGroups(inv.Groups)
	inv.Accounts = normalizeAccounts(inv.Accounts, inv.Groups)
	inv.Sources = normalizeSources(inv.Sources)
	inv.SecurityPolicy = normalizeSecurityPolicy(inv.Platform, inv.SecurityPolicy)
	inv.CredentialProtection = normalizeCredentialProtection(inv.Platform, inv.CredentialProtection)
	inv.SudoPosture = normalizeSudoPosture(inv.Platform, inv.SudoPosture)
	inv.LinuxAuthPosture = normalizeLinuxAuthPosture(inv.Platform, inv.LinuxAuthPosture)
	inv.MacOSAuthorizationPosture = normalizeMacOSAuthorizationPosture(inv.Platform, inv.MacOSAuthorizationPosture)
	collectSSHKeyPosture(ctx, &inv)
	inv.SSHKeyPosture = normalizeSSHKeyPosture(inv.Platform, inv.SSHKeyPosture)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Accounts, inv.Groups)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected account collector contract")
	}
	if strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" || inv.CollectedAt.IsZero() {
		return fmt.Errorf("account inventory identity is incomplete")
	}
	if len(inv.Accounts) > maxAccounts || len(inv.Groups) > maxGroups {
		return fmt.Errorf("account inventory exceeds record limits")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, a := range inv.Accounts {
		if a.ID == "" || strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Principal) == "" || strings.TrimSpace(a.AccountType) == "" || strings.TrimSpace(a.EnabledState) == "" || strings.TrimSpace(a.LoginCapability) == "" || strings.TrimSpace(a.Authentication.State) == "" || strings.TrimSpace(a.Authentication.PasswordState) == "" || strings.TrimSpace(a.Authentication.Source) == "" || strings.TrimSpace(a.CollectionSource) == "" || a.Confidence == "" {
			return fmt.Errorf("account record %d is incomplete", i)
		}
		if _, ok := seen[a.ID]; ok {
			return fmt.Errorf("duplicate account id %q", a.ID)
		}
		seen[a.ID] = struct{}{}
		k := accountSortKey(a)
		if last != "" && k < last {
			return fmt.Errorf("account records are not deterministically ordered")
		}
		last = k
	}
	seen = map[string]struct{}{}
	last = ""
	for i, g := range inv.Groups {
		if g.ID == "" || strings.TrimSpace(g.Name) == "" || strings.TrimSpace(g.CollectionSource) == "" || g.Confidence == "" {
			return fmt.Errorf("group record %d is incomplete", i)
		}
		if _, ok := seen[g.ID]; ok {
			return fmt.Errorf("duplicate group id %q", g.ID)
		}
		seen[g.ID] = struct{}{}
		k := groupSortKey(g)
		if last != "" && k < last {
			return fmt.Errorf("group records are not deterministically ordered")
		}
		last = k
	}

	if err := validateSecurityPolicy(inv.Platform, inv.SecurityPolicy); err != nil {
		return err
	}
	if err := validateCredentialProtection(inv.Platform, inv.CredentialProtection); err != nil {
		return err
	}
	if err := validateSudoPosture(inv.Platform, inv.SudoPosture); err != nil {
		return err
	}
	if err := validateLinuxAuthPosture(inv.Platform, inv.LinuxAuthPosture); err != nil {
		return err
	}
	if err := validateMacOSAuthorizationPosture(inv.Platform, inv.MacOSAuthorizationPosture); err != nil {
		return err
	}
	if err := validateSSHKeyPosture(inv.Platform, inv.SSHKeyPosture); err != nil {
		return err
	}
	if inv.Summary != summarize(inv.Accounts, inv.Groups) {
		return fmt.Errorf("account summary does not match records")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func normalizeAccounts(in []Account, groups []Group) []Account {
	groupPriv := map[string]bool{}
	for _, g := range groups {
		groupPriv[strings.ToLower(g.Name)] = g.Privileged
	}
	seen := map[string]struct{}{}
	out := make([]Account, 0, len(in))
	for _, a := range in {
		a.Name = strings.TrimSpace(a.Name)
		if a.Name == "" {
			continue
		}
		a.Principal = strings.TrimSpace(a.Principal)
		if a.Principal == "" {
			a.Principal = a.Name
		}
		a.AccountType = upperDefault(a.AccountType, "UNKNOWN")
		a.EnabledState = upperDefault(a.EnabledState, "UNKNOWN")
		a.LoginCapability = upperDefault(a.LoginCapability, "UNKNOWN")
		a.Authentication.State = upperDefault(a.Authentication.State, "UNKNOWN")
		a.Authentication.PasswordState = upperDefault(a.Authentication.PasswordState, "UNKNOWN")
		a.Authentication.PasswordRequired = upperDefault(a.Authentication.PasswordRequired, "UNKNOWN")
		a.Authentication.PasswordExpires = upperDefault(a.Authentication.PasswordExpires, "UNKNOWN")
		a.Authentication.PasswordChangeable = upperDefault(a.Authentication.PasswordChangeable, "UNKNOWN")
		if strings.TrimSpace(a.Authentication.Source) == "" {
			a.Authentication.Source = a.CollectionSource
		}
		a.Groups = uniqueSorted(a.Groups)
		a.PrivilegeBasis = uniqueSorted(a.PrivilegeBasis)
		a.ServiceBasis = uniqueSorted(a.ServiceBasis)
		for _, g := range a.Groups {
			if groupPriv[strings.ToLower(g)] {
				a.Privileged = true
				a.PrivilegeBasis = appendUnique(a.PrivilegeBasis, "member of privileged group "+g)
			}
		}
		a.PrivilegeBasis = uniqueSorted(a.PrivilegeBasis)
		if a.CollectionSource == "" {
			a.CollectionSource = "platform local account provider"
		}
		if a.Confidence == "" {
			a.Confidence = evidence.ConfidenceHigh
		}
		a.ID = stableAccountID(a)
		if _, ok := seen[a.ID]; ok {
			continue
		}
		seen[a.ID] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return accountSortKey(out[i]) < accountSortKey(out[j]) })
	if len(out) > maxAccounts {
		out = out[:maxAccounts]
	}
	return out
}

func normalizeGroups(in []Group) []Group {
	seen := map[string]struct{}{}
	out := make([]Group, 0, len(in))
	for _, g := range in {
		g.Name = strings.TrimSpace(g.Name)
		if g.Name == "" {
			continue
		}
		g.Members = uniqueSorted(g.Members)
		if g.CollectionSource == "" {
			g.CollectionSource = "platform local group provider"
		}
		if g.Confidence == "" {
			g.Confidence = evidence.ConfidenceHigh
		}
		g.ID = stableGroupID(g)
		if _, ok := seen[g.ID]; ok {
			continue
		}
		seen[g.ID] = struct{}{}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return groupSortKey(out[i]) < groupSortKey(out[j]) })
	if len(out) > maxGroups {
		out = out[:maxGroups]
	}
	return out
}

func summarize(accounts []Account, groups []Group) Summary {
	s := Summary{Accounts: len(accounts), Groups: len(groups)}
	for _, a := range accounts {
		switch a.EnabledState {
		case "ENABLED":
			s.Enabled++
		case "DISABLED":
			s.Disabled++
		default:
			s.EnabledUnknown++
		}
		switch a.LoginCapability {
		case "LOGIN_CAPABLE":
			s.LoginCapable++
		case "LOGIN_DISABLED":
			s.LoginDisabled++
		default:
			s.LoginUnknown++
		}
		if a.Privileged {
			s.Privileged++
		}
		if a.ServiceAccount {
			s.ServiceAccounts++
		}
		switch a.AccountType {
		case "HUMAN":
			s.HumanAccounts++
		case "SYSTEM", "SERVICE":
			s.SystemAccounts++
		}
		switch a.Authentication.State {
		case "OBSERVED":
			s.AuthObserved++
		case "DEGRADED", "DENIED", "UNAVAILABLE":
			s.AuthDegraded++
		}
		if a.Authentication.PasswordState != "UNKNOWN" {
			s.PasswordStateKnown++
		} else {
			s.PasswordStateUnknown++
		}
		if a.Authentication.PasswordState == "EMPTY" {
			s.EmptyPasswordObserved++
		}
		switch a.Authentication.PasswordRequired {
		case "NO":
			s.PasswordNotRequired++
		case "UNKNOWN":
			s.PasswordRequirementUnknown++
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("account.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.count", len(inv.Accounts), "normalized local account inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.group.count", len(inv.Groups), "normalized local group inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.summary", inv.Summary, "normalized local account inventory", at, evidence.ConfidenceHigh),
	}
	if len(inv.Sources) == 0 {
		out = append(out, evidence.NewState("account.inventory.provider", evidence.StateUnavailable, "platform local account provider", at, evidence.ConfidenceLow, "no supported local account provider returned a status"))
	}
	for _, src := range inv.Sources {
		key := "account.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			st := src.State
			if st == "" {
				st = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, st, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "account provider did not return usable metadata")))
		}
	}
	for _, a := range inv.Accounts {
		out = append(out, evidence.NewObserved("account.item."+a.ID, a, a.CollectionSource, at, a.Confidence))
	}
	for _, g := range inv.Groups {
		out = append(out, evidence.NewObserved("account.group."+g.ID, g, g.CollectionSource, at, g.Confidence))
	}
	policySource := fallback(inv.SecurityPolicy.Source, "local security policy provider")
	switch inv.SecurityPolicy.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.policy.provider", map[string]any{"state": string(inv.SecurityPolicy.State), "control_count": len(inv.SecurityPolicy.Controls)}, policySource, at, evidence.ConfidenceHigh))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.policy.provider", evidence.StateNotApplicable, policySource, at, evidence.ConfidenceExact, fallback(inv.SecurityPolicy.Reason, "local security policy assessment is not applicable on this platform")))
	default:
		st := inv.SecurityPolicy.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.policy.provider", st, policySource, at, evidence.ConfidenceLow, fallback(inv.SecurityPolicy.Reason, "local security policy provider did not return usable metadata")))
	}
	for _, c := range inv.SecurityPolicy.Controls {
		key := "account.policy." + slug(c.ID)
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c.Value, c.Source, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.Source, at, c.Confidence, fallback(c.Reason, "policy value was not observable")))
		}
	}
	credentialSource := fallback(inv.CredentialProtection.Source, "Windows credential-protection provider")
	switch inv.CredentialProtection.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.credential_protection.provider", map[string]any{"state": string(inv.CredentialProtection.State), "control_count": len(inv.CredentialProtection.Controls)}, credentialSource, at, evidence.ConfidenceHigh))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.credential_protection.provider", evidence.StateNotApplicable, credentialSource, at, evidence.ConfidenceExact, fallback(inv.CredentialProtection.Reason, "Windows credential-protection assessment is not applicable on this platform")))
	default:
		st := inv.CredentialProtection.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.credential_protection.provider", st, credentialSource, at, evidence.ConfidenceLow, fallback(inv.CredentialProtection.Reason, "Windows credential-protection provider did not return usable metadata")))
	}
	for _, c := range inv.CredentialProtection.Controls {
		key := "account.credential_protection." + slug(c.ID)
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c.Value, c.Source, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.Source, at, c.Confidence, fallback(c.Reason, "credential-protection value was not observable")))
		}
	}
	sudoSource := fallback(inv.SudoPosture.Source, "Linux sudoers posture provider")
	switch inv.SudoPosture.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.sudo.provider", map[string]any{"state": string(inv.SudoPosture.State), "parsed_files": inv.SudoPosture.Summary.ParsedFiles}, sudoSource, at, evidence.ConfidenceHigh))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.sudo.provider", evidence.StateNotApplicable, sudoSource, at, evidence.ConfidenceExact, fallback(inv.SudoPosture.Reason, "Linux sudo/sudoers assessment is not applicable on this platform")))
	default:
		st := inv.SudoPosture.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.sudo.provider", st, sudoSource, at, evidence.ConfidenceLow, fallback(inv.SudoPosture.Reason, "Linux sudoers provider did not return complete usable metadata")))
	}
	if inv.SudoPosture.Summary.ParsedFiles > 0 {
		confidence := evidence.ConfidenceHigh
		if inv.SudoPosture.State == evidence.StateDegraded {
			confidence = evidence.ConfidenceMedium
		}
		out = append(out, evidence.NewObserved("account.sudo.summary", inv.SudoPosture.Summary, sudoSource, at, confidence))
	}
	for _, cfg := range inv.SudoPosture.ConfigPaths {
		key := "account.sudo.config." + cfg.ID
		if cfg.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, cfg, cfg.Source, at, cfg.Confidence))
		} else {
			out = append(out, evidence.NewState(key, cfg.State, cfg.Source, at, cfg.Confidence, fallback(cfg.Reason, "sudo configuration path metadata was not observable")))
		}
	}
	for _, grant := range inv.SudoPosture.Grants {
		out = append(out, evidence.NewObserved("account.sudo.grant."+grant.ID, grant, grant.Source, at, evidence.ConfidenceHigh))
	}
	for _, issue := range inv.SudoPosture.EnvironmentIssues {
		out = append(out, evidence.NewObserved("account.sudo.environment."+issue.ID, issue, issue.Source, at, evidence.ConfidenceHigh))
	}
	for _, issue := range inv.SudoPosture.PathIssues {
		out = append(out, evidence.NewObserved("account.sudo.path."+issue.ID, issue, issue.Source, at, evidence.ConfidenceHigh))
	}
	authSource := fallback(inv.LinuxAuthPosture.Source, "Linux PAM/login policy provider")
	switch inv.LinuxAuthPosture.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.linux_auth.provider", map[string]any{"state": string(inv.LinuxAuthPosture.State), "parsed_files": inv.LinuxAuthPosture.Summary.ParsedFiles, "pam_rules": inv.LinuxAuthPosture.Summary.PAMRules}, authSource, at, evidence.ConfidenceHigh))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.linux_auth.provider", evidence.StateNotApplicable, authSource, at, evidence.ConfidenceExact, fallback(inv.LinuxAuthPosture.Reason, "Linux PAM/login policy assessment is not applicable on this platform")))
	default:
		st := inv.LinuxAuthPosture.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.linux_auth.provider", st, authSource, at, evidence.ConfidenceLow, fallback(inv.LinuxAuthPosture.Reason, "Linux PAM/login policy provider did not return complete usable metadata")))
	}
	if inv.LinuxAuthPosture.Summary.ParsedFiles > 0 || inv.LinuxAuthPosture.Summary.PAMRules > 0 {
		conf := evidence.ConfidenceHigh
		if inv.LinuxAuthPosture.State == evidence.StateDegraded {
			conf = evidence.ConfidenceMedium
		}
		out = append(out, evidence.NewObserved("account.linux_auth.summary", inv.LinuxAuthPosture.Summary, authSource, at, conf))
	}
	for _, cfg := range inv.LinuxAuthPosture.ConfigPaths {
		key := "account.linux_auth.config." + cfg.ID
		if cfg.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, cfg, cfg.Source, at, cfg.Confidence))
		} else {
			out = append(out, evidence.NewState(key, cfg.State, cfg.Source, at, cfg.Confidence, fallback(cfg.Reason, "Linux authentication configuration path metadata was not observable")))
		}
	}
	for _, rule := range inv.LinuxAuthPosture.PAMRules {
		out = append(out, evidence.NewObserved("account.linux_auth.pam."+rule.ID, rule, rule.Source, at, evidence.ConfidenceHigh))
	}
	if inv.LinuxAuthPosture.LoginPolicy.State == evidence.StateObserved {
		out = append(out, evidence.NewObserved("account.linux_auth.login_policy", inv.LinuxAuthPosture.LoginPolicy, inv.LinuxAuthPosture.LoginPolicy.Source, at, inv.LinuxAuthPosture.LoginPolicy.Confidence))
	} else {
		out = append(out, evidence.NewState("account.linux_auth.login_policy", inv.LinuxAuthPosture.LoginPolicy.State, inv.LinuxAuthPosture.LoginPolicy.Source, at, inv.LinuxAuthPosture.LoginPolicy.Confidence, fallback(inv.LinuxAuthPosture.LoginPolicy.Reason, "Linux login policy was not observable")))
	}
	if inv.LinuxAuthPosture.State == evidence.StateObserved || inv.LinuxAuthPosture.State == evidence.StateDegraded {
		out = append(out, evidence.NewObserved("account.linux_auth.tuning", inv.LinuxAuthPosture.Tuning, authSource, at, evidence.ConfidenceHigh))
	}
	macSource := fallback(inv.MacOSAuthorizationPosture.Source, "macOS local authorization provider")
	switch inv.MacOSAuthorizationPosture.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.macos_authorization.provider", map[string]any{"state": string(inv.MacOSAuthorizationPosture.State), "identity_records": inv.MacOSAuthorizationPosture.Summary.IdentityRecords, "authorization_rights": inv.MacOSAuthorizationPosture.Summary.AuthorizationRights}, macSource, at, evidence.ConfidenceHigh))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.macos_authorization.provider", evidence.StateNotApplicable, macSource, at, evidence.ConfidenceExact, fallback(inv.MacOSAuthorizationPosture.Reason, "macOS local authorization assessment is not applicable on this platform")))
	default:
		st := inv.MacOSAuthorizationPosture.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.macos_authorization.provider", st, macSource, at, evidence.ConfidenceLow, fallback(inv.MacOSAuthorizationPosture.Reason, "macOS local authorization provider did not return complete usable metadata")))
	}
	if inv.MacOSAuthorizationPosture.FileVault.State == evidence.StateObserved {
		out = append(out, evidence.NewObserved("account.macos_authorization.filevault", inv.MacOSAuthorizationPosture.FileVault.Value, inv.MacOSAuthorizationPosture.FileVault.Source, at, inv.MacOSAuthorizationPosture.FileVault.Confidence))
	} else {
		out = append(out, evidence.NewState("account.macos_authorization.filevault", inv.MacOSAuthorizationPosture.FileVault.State, inv.MacOSAuthorizationPosture.FileVault.Source, at, inv.MacOSAuthorizationPosture.FileVault.Confidence, fallback(inv.MacOSAuthorizationPosture.FileVault.Reason, "FileVault state was not observable")))
	}
	for _, c := range inv.MacOSAuthorizationPosture.LoginControls {
		key := "account.macos_authorization.login." + slug(c.ID)
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c.Value, c.Source, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.Source, at, c.Confidence, fallback(c.Reason, "macOS login control was not observable")))
		}
	}
	for _, r := range inv.MacOSAuthorizationPosture.Rights {
		key := "account.macos_authorization.right." + slug(r.ID)
		if r.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, r, r.Source, at, r.Confidence))
		} else {
			out = append(out, evidence.NewState(key, r.State, r.Source, at, r.Confidence, fallback(r.Reason, "macOS authorization right was not observable")))
		}
	}
	for _, item := range inv.MacOSAuthorizationPosture.Identities {
		out = append(out, evidence.NewObserved("account.macos_authorization.identity."+item.ID, item, item.Source, at, item.Confidence))
	}
	if inv.MacOSAuthorizationPosture.State == evidence.StateObserved || inv.MacOSAuthorizationPosture.State == evidence.StateDegraded {
		out = append(out, evidence.NewObserved("account.macos_authorization.summary", inv.MacOSAuthorizationPosture.Summary, macSource, at, evidence.ConfidenceHigh))
	}
	sshSource := fallback(inv.SSHKeyPosture.Source, "local SSH key/authorized_keys metadata provider")
	switch inv.SSHKeyPosture.State {
	case evidence.StateObserved:
		out = append(out, evidence.NewObserved("account.ssh_key.provider", map[string]any{"state": string(inv.SSHKeyPosture.State), "records": len(inv.SSHKeyPosture.Records)}, sshSource, at, evidence.ConfidenceHigh))
	case evidence.StateDegraded:
		out = append(out, evidence.NewObserved("account.ssh_key.provider", map[string]any{"state": string(inv.SSHKeyPosture.State), "records": len(inv.SSHKeyPosture.Records), "reason": inv.SSHKeyPosture.Reason}, sshSource, at, evidence.ConfidenceMedium))
	case evidence.StateNotApplicable:
		out = append(out, evidence.NewState("account.ssh_key.provider", evidence.StateNotApplicable, sshSource, at, evidence.ConfidenceExact, fallback(inv.SSHKeyPosture.Reason, "SSH key/authorized_keys assessment is not applicable on this platform")))
	default:
		st := inv.SSHKeyPosture.State
		if st == "" {
			st = evidence.StateUnavailable
		}
		out = append(out, evidence.NewState("account.ssh_key.provider", st, sshSource, at, evidence.ConfidenceLow, fallback(inv.SSHKeyPosture.Reason, "SSH key/authorized_keys provider did not return usable metadata")))
	}
	if inv.SSHKeyPosture.State == evidence.StateObserved || inv.SSHKeyPosture.State == evidence.StateDegraded {
		conf := evidence.ConfidenceHigh
		if inv.SSHKeyPosture.State == evidence.StateDegraded {
			conf = evidence.ConfidenceMedium
		}
		out = append(out, evidence.NewObserved("account.ssh_key.summary", inv.SSHKeyPosture.Summary, sshSource, at, conf))
	}
	for _, r := range inv.SSHKeyPosture.Records {
		key := "account.ssh_key.path." + r.ID
		if r.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, r, r.Source, at, r.Confidence))
		} else {
			out = append(out, evidence.NewState(key, r.State, r.Source, at, r.Confidence, fallback(r.Reason, "SSH path metadata was not observable")))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func normalizeSecurityPolicy(platform string, p SecurityPolicy) SecurityPolicy {
	if strings.TrimSpace(p.Source) == "" {
		p.Source = "platform local security policy provider"
	}
	if p.State == "" {
		if strings.EqualFold(platform, "windows") {
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "Windows local security policy provider returned no state")
		} else {
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "Windows UAC/local-security-policy assessment is not applicable on this platform")
		}
	}
	seen := map[string]struct{}{}
	out := make([]SecurityControl, 0, len(p.Controls))
	for _, c := range p.Controls {
		c.ID = slug(c.ID)
		c.Name = strings.TrimSpace(c.Name)
		c.Value = strings.ToUpper(strings.TrimSpace(c.Value))
		c.Source = strings.TrimSpace(c.Source)
		c.Reason = strings.TrimSpace(c.Reason)
		if c.ID == "" || c.Name == "" || c.Source == "" {
			continue
		}
		if c.State == "" {
			c.State = evidence.StateUnavailable
		}
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		if c.State != evidence.StateObserved {
			c.Value = ""
		}
		if _, ok := seen[c.ID]; ok {
			continue
		}
		seen[c.ID] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	p.Controls = out
	return p
}

func validateSecurityPolicy(platform string, p SecurityPolicy) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("local security policy state/source is incomplete")
	}
	if !strings.EqualFold(platform, "windows") && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("non-Windows security policy must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed local security policy requires a reason")
	}
	last := ""
	seen := map[string]struct{}{}
	for i, c := range p.Controls {
		if c.ID == "" || c.Name == "" || c.Source == "" || c.State == "" || c.Confidence == "" {
			return fmt.Errorf("security policy control %d is incomplete", i)
		}
		if c.State == evidence.StateObserved && strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("security policy control %q observed without a normalized value", c.ID)
		}
		if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("security policy control %q non-observed without a reason", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate security policy control %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && c.ID < last {
			return fmt.Errorf("security policy controls are not deterministically ordered")
		}
		last = c.ID
	}
	return nil
}

func normalizeCredentialProtection(platform string, p CredentialProtection) CredentialProtection {
	if strings.TrimSpace(p.Source) == "" {
		p.Source = "Windows credential-protection provider"
	}
	if p.State == "" {
		if strings.EqualFold(platform, "windows") {
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "Windows credential-protection provider returned no state")
		} else {
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "Windows credential-protection assessment is not applicable on this platform")
		}
	}
	seen := map[string]struct{}{}
	out := make([]SecurityControl, 0, len(p.Controls))
	for _, c := range p.Controls {
		c.ID = slug(c.ID)
		c.Name = strings.TrimSpace(c.Name)
		c.Value = strings.ToUpper(strings.TrimSpace(c.Value))
		c.Source = strings.TrimSpace(c.Source)
		c.Reason = strings.TrimSpace(c.Reason)
		if c.ID == "" || c.Name == "" || c.Source == "" {
			continue
		}
		if c.State == "" {
			c.State = evidence.StateUnavailable
		}
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		if c.State != evidence.StateObserved {
			c.Value = ""
		}
		if _, ok := seen[c.ID]; ok {
			continue
		}
		seen[c.ID] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	p.Controls = out
	return p
}

func validateCredentialProtection(platform string, p CredentialProtection) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("credential-protection state/source is incomplete")
	}
	if !strings.EqualFold(platform, "windows") && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("non-Windows credential-protection state must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed credential-protection provider requires a reason")
	}
	last := ""
	seen := map[string]struct{}{}
	for i, c := range p.Controls {
		if c.ID == "" || c.Name == "" || c.Source == "" || c.State == "" || c.Confidence == "" {
			return fmt.Errorf("credential-protection control %d is incomplete", i)
		}
		if c.State == evidence.StateObserved && strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("credential-protection control %q observed without a normalized value", c.ID)
		}
		if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("credential-protection control %q non-observed without a reason", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate credential-protection control %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && c.ID < last {
			return fmt.Errorf("credential-protection controls are not deterministically ordered")
		}
		last = c.ID
	}
	return nil
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	inv.Sources = append(inv.Sources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)})
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && strings.TrimSpace(reason) != "" {
		inv.Degraded = append(inv.Degraded, id+": "+strings.TrimSpace(reason))
	}
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func stableAccountID(a Account) string {
	basis := strings.Join([]string{runtime.GOOS, strings.ToLower(a.Principal), a.UID, a.SID}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return "acct-" + hex.EncodeToString(sum[:10])
}
func stableGroupID(g Group) string {
	basis := strings.Join([]string{runtime.GOOS, strings.ToLower(g.Name), g.GID, g.SID}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return "grp-" + hex.EncodeToString(sum[:10])
}
func accountSortKey(a Account) string {
	return strings.ToLower(a.Principal) + "\x00" + a.UID + "\x00" + a.SID + "\x00" + a.ID
}
func groupSortKey(g Group) string {
	return strings.ToLower(g.Name) + "\x00" + g.GID + "\x00" + g.SID + "\x00" + g.ID
}
func upperDefault(v, d string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return d
	}
	return v
}
func uniqueSorted(in []string) []string {
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
func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}
func intString(v int) string {
	if v < 0 {
		return ""
	}
	return strconv.Itoa(v)
}

package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

// MacOSAuthorizationRules implements using only normalized,
// read-only local authorization evidence. No authentication is attempted and
// no recovery/token secret material is collected.
func MacOSAuthorizationRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-032", Title: "FileVault protects the system volume", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "macos.filevault.state", ExpectedState: "FileVault is enabled or actively completing encryption",
			Risk:        "A macOS system volume without FileVault can expose local account data and other at-rest host information if the device or storage is accessed offline.",
			Remediation: "Enable FileVault through the approved macOS management workflow, escrow recovery material according to organizational policy, and verify encryption completes successfully.",
			Evaluate:    evaluateMacFileVault,
		},
		{
			ID: "CHM-ID-033", Title: "Automatic macOS login is disabled", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "macos.loginwindow.automatic_login", ExpectedState: "automatic login is disabled",
			Risk:        "Automatic login bypasses the normal interactive authentication boundary after boot and can expose the logged-in user's local access to anyone with physical access to the host.",
			Remediation: "Disable automatic login in macOS login settings or the managed loginwindow preference and require normal user authentication at sign-in.",
			Evaluate:    func(idx Index) Evaluation { return evaluateMacLoginControl(idx, "automatic-login", false) },
		},
		{
			ID: "CHM-ID-034", Title: "Guest macOS login is disabled", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "macos.loginwindow.guest_login", ExpectedState: "guest login is disabled unless explicitly required and managed",
			Risk:        "An enabled local Guest login expands unauthenticated physical-access paths and can provide an unnecessary interactive account surface.",
			Remediation: "Disable Guest login unless there is a documented requirement and compensating controls; manage the setting centrally where applicable.",
			Evaluate:    func(idx Index) Evaluation { return evaluateMacLoginControl(idx, "guest-login", false) },
		},
		{
			ID: "CHM-ID-035", Title: "FileVault preboot unlock does not automatically log in a user", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "macos.loginwindow.disable_fde_auto_login", ExpectedState: "DisableFDEAutoLogin is enabled when FileVault is enabled",
			Risk:        "Allowing FileVault preboot authentication to automatically complete the user login reduces separation between disk-unlock and interactive session authentication.",
			Remediation: "Enable the managed DisableFDEAutoLogin loginwindow preference so the user must authenticate again at the macOS login window after FileVault unlock when organizational policy requires that separation.",
			Evaluate:    evaluateMacFDEAutoLogin,
		},
		{
			ID: "CHM-ID-036", Title: "Sensitive macOS authorization rights do not use unconditional allow", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "macos.authorizationdb.sensitive_rights", ExpectedState: "observed sensitive authorizationdb rights require a rule/user decision and are not class=allow",
			Risk:        "A sensitive authorization right configured as unconditional allow can remove the expected authentication or authorization decision for protected system operations.",
			Remediation: "Restore the affected authorization right to the Apple or enterprise-approved rule set and investigate unmanaged changes to the local authorization database before reassessment.",
			Evaluate:    evaluateMacAuthorizationRights,
		},
		{
			ID: "CHM-ID-037", Title: "FileVault-authorized identities map to active local accounts", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "macos.filevault.identity_relationship", ExpectedState: "every locally observable FileVault-authorized identity maps to an enabled local account",
			Risk:        "A stale, deleted, disabled, or otherwise unresolved FileVault-authorized identity can leave preboot authorization relationships that no longer match intended local account ownership.",
			Remediation: "Review FileVault-enabled users, remove stale authorization through the approved FileVault/user-management workflow, and confirm each remaining identity maps to an intended active local account.",
			Evaluate:    evaluateMacFileVaultIdentityMapping,
		},
		{
			ID: "CHM-ID-038", Title: "Enabled local administrators have an observable SecureToken relationship", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "macos.admin.securetoken_relationship", ExpectedState: "enabled login-capable local administrators have SecureToken enabled or an explicitly reviewed exception",
			Risk:        "An administrator account with an unexpected SecureToken relationship can create inconsistent local authorization and FileVault administration behavior and may indicate unmanaged account provisioning.",
			Remediation: "Review local administrator ownership and provisioning. Grant or remove SecureToken only through the approved macOS account-management workflow so administrative and FileVault authorization relationships match policy.",
			Evaluate:    evaluateMacAdminSecureToken,
		},
	}
}

func macAuthorizationApplicability(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "darwin" {
		keys := macAuthorizationProviderKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "macOS local authorization assessment is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	if o, ok := idx["account.macos_authorization.provider"]; ok && o.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: NotApplicable, EvidenceKeys: []string{o.Key}}, true
	}
	return Evaluation{}, false
}

func evaluateMacFileVault(idx Index) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	o, ok := idx["account.macos_authorization.filevault"]
	if !ok || o.State != evidence.StateObserved {
		return macUnknownFromObservation(idx, o, ok, "FileVault state is unavailable")
	}
	v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	switch v {
	case "ENABLED":
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "FileVault is enabled", Applicability: Applicable, EvidenceKeys: []string{o.Key}}
	case "ENCRYPTING":
		return Evaluation{Status: StatusWarn, Confidence: o.Confidence, ObservedState: "FileVault encryption is still in progress", Applicability: Applicable, EvidenceKeys: []string{o.Key}}
	case "DISABLED", "DECRYPTING":
		return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: "FileVault state is " + v, Applicability: Applicable, EvidenceKeys: []string{o.Key}}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "unrecognized FileVault state: " + v, Applicability: Applicable, EvidenceKeys: []string{o.Key}}
	}
}

func evaluateMacLoginControl(idx Index, id string, wantedEnabled bool) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	key := "account.macos_authorization.login." + id
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return macUnknownFromObservation(idx, o, ok, id+" loginwindow control is unavailable")
	}
	v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	want := "DISABLED"
	if wantedEnabled {
		want = "ENABLED"
	}
	if v == want {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: id + " is " + strings.ToLower(v), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if v == "ENABLED" || v == "DISABLED" {
		return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: id + " is " + strings.ToLower(v), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: id + " has unrecognized state " + v, Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluateMacFDEAutoLogin(idx Index) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	fv, ok := idx["account.macos_authorization.filevault"]
	if !ok || fv.State != evidence.StateObserved {
		return macUnknownFromObservation(idx, fv, ok, "FileVault state is unavailable")
	}
	fvState := strings.ToUpper(strings.TrimSpace(fmt.Sprint(fv.Value)))
	if fvState == "DISABLED" || fvState == "DECRYPTING" {
		return Evaluation{Status: StatusPass, Confidence: fv.Confidence, ObservedState: "FileVault preboot auto-login control is not applicable while FileVault is " + strings.ToLower(fvState), Applicability: NotApplicable, EvidenceKeys: []string{fv.Key}}
	}
	key := "account.macos_authorization.login.disable-fde-auto-login"
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return macUnknownFromObservation(idx, o, ok, "DisableFDEAutoLogin setting is unavailable")
	}
	v := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	if v == "ENABLED" {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "DisableFDEAutoLogin is enabled", Applicability: Applicable, EvidenceKeys: []string{fv.Key, key}}
	}
	if v == "DISABLED" {
		return Evaluation{Status: StatusWarn, Confidence: o.Confidence, ObservedState: "DisableFDEAutoLogin is disabled while FileVault is active", Applicability: Applicable, EvidenceKeys: []string{fv.Key, key}}
	}
	return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "DisableFDEAutoLogin has unrecognized state " + v, Applicability: Applicable, EvidenceKeys: []string{fv.Key, key}}
}

func evaluateMacAuthorizationRights(idx Index) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	var observed, bad []string
	var keys []string
	for key, o := range idx {
		if !strings.HasPrefix(key, "account.macos_authorization.right.") || o.State != evidence.StateObserved {
			continue
		}
		r, ok := o.Value.(accounts.MacOSAuthorizationRight)
		if !ok {
			continue
		}
		observed = append(observed, r.Name+"="+r.Class)
		keys = append(keys, key)
		if r.Class == "ALLOW" {
			bad = append(bad, r.Name)
		}
	}
	sort.Strings(observed)
	sort.Strings(bad)
	sort.Strings(keys)
	if len(bad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "authorizationdb rights using unconditional allow: " + strings.Join(bad, ", "), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(observed) == 0 {
		return macAuthorizationProviderUnknown(idx, "no sensitive authorizationdb rights were observable")
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "observed sensitive authorizationdb rights are not class=allow: " + strings.Join(observed, ", "), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateMacFileVaultIdentityMapping(idx Index) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	fv, ok := idx["account.macos_authorization.filevault"]
	if !ok || fv.State != evidence.StateObserved {
		return macUnknownFromObservation(idx, fv, ok, "FileVault state is unavailable")
	}
	if strings.EqualFold(strings.TrimSpace(fmt.Sprint(fv.Value)), "DISABLED") {
		return Evaluation{Status: StatusPass, Confidence: fv.Confidence, ObservedState: "FileVault identity mapping is not applicable while FileVault is disabled", Applicability: NotApplicable, EvidenceKeys: []string{fv.Key}}
	}
	items := macAuthorizationIdentities(idx)
	if len(items) == 0 {
		return macAuthorizationProviderUnknown(idx, "no macOS identity relationship evidence was available")
	}
	var bad, unresolved []macIdentityEvidence
	for _, item := range items {
		v := item.Identity
		if v.FileVaultEvidenceState != evidence.StateObserved || v.FileVaultAuthorized == "UNKNOWN" {
			unresolved = append(unresolved, item)
			continue
		}
		if v.FileVaultAuthorized != "AUTHORIZED" {
			continue
		}
		if v.EnabledState != "ENABLED" || v.LoginCapability == "LOGIN_DISABLED" || v.UID == "" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "FileVault-authorized identities with stale/unresolved local-account mapping: " + describeMacIdentities(bad), Applicability: Applicable, EvidenceKeys: macIdentityKeys(bad)}
	}
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no stale FileVault authorization proven, but relationship state is unresolved for %d identity record(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: macIdentityKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "all observed FileVault-authorized identities map to enabled local accounts", Applicability: Applicable, EvidenceKeys: macIdentityKeys(items)}
}

func evaluateMacAdminSecureToken(idx Index) Evaluation {
	if e, ok := macAuthorizationApplicability(idx); ok {
		return e
	}
	items := macAuthorizationIdentities(idx)
	var eligible, disabled, unresolved []macIdentityEvidence
	for _, item := range items {
		v := item.Identity
		if !v.Privileged || v.EnabledState != "ENABLED" || v.LoginCapability != "LOGIN_CAPABLE" {
			continue
		}
		eligible = append(eligible, item)
		if v.SecureTokenEvidenceState != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if v.SecureToken == "DISABLED" {
			disabled = append(disabled, item)
		}
	}
	if len(eligible) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled login-capable local administrator identity required SecureToken relationship assessment", Applicability: Applicable, EvidenceKeys: macAuthorizationProviderKeys(idx)}
	}
	if len(disabled) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "enabled local administrators with SecureToken disabled: " + describeMacIdentities(disabled), Applicability: Applicable, EvidenceKeys: macIdentityKeys(disabled)}
	}
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("SecureToken relationship is unresolved for %d of %d enabled local administrator(s)", len(unresolved), len(eligible)), Applicability: Applicable, EvidenceKeys: macIdentityKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled login-capable local administrator(s) have SecureToken enabled", len(eligible)), Applicability: Applicable, EvidenceKeys: macIdentityKeys(eligible)}
}

type macIdentityEvidence struct {
	Key      string
	Identity accounts.MacOSIdentityAuthorization
}

func macAuthorizationIdentities(idx Index) []macIdentityEvidence {
	var out []macIdentityEvidence
	for key, o := range idx {
		if !strings.HasPrefix(key, "account.macos_authorization.identity.") || o.State != evidence.StateObserved {
			continue
		}
		item, ok := o.Value.(accounts.MacOSIdentityAuthorization)
		if !ok {
			continue
		}
		out = append(out, macIdentityEvidence{Key: key, Identity: item})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func describeMacIdentities(items []macIdentityEvidence) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		v := item.Identity
		detail := v.Principal
		if v.UID != "" {
			detail += "(uid=" + v.UID + ")"
		}
		parts = append(parts, detail)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func macIdentityKeys(items []macIdentityEvidence) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
	}
	sort.Strings(keys)
	return keys
}

func macAuthorizationProviderKeys(idx Index) []string {
	var keys []string
	for _, key := range []string{"account.platform", "account.macos_authorization.provider", "account.macos_authorization.summary", "account.macos_authorization.filevault"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func macAuthorizationProviderUnknown(idx Index, text string) Evaluation {
	if o, ok := idx["account.macos_authorization.provider"]; ok {
		if o.State != evidence.StateObserved {
			return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: macAuthorizationProviderKeys(idx)}
		}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: text, Applicability: Applicable, EvidenceKeys: macAuthorizationProviderKeys(idx)}
}

func macUnknownFromObservation(idx Index, o evidence.Observation, ok bool, missing string) Evaluation {
	if ok {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{o.Key}}
	}
	return macAuthorizationProviderUnknown(idx, missing)
}

package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// WindowsLocalSecurityRules implements . It evaluates read-only,
// normalized UAC and local-security-option metadata plus the local account
// inventory. No rule changes policy or attempts authentication.
func WindowsLocalSecurityRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-007", Title: "Windows User Account Control is enabled", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.uac.enabled", ExpectedState: "User Account Control is enabled",
			Risk:        "Disabling User Account Control removes an important privilege-separation and elevation-consent boundary for local administrative activity.",
			Remediation: "Enable User Account Control through approved Windows policy management and verify application compatibility before deployment.",
			Evaluate:    func(idx Index) Evaluation { return evaluateWindowsPolicyEquals(idx, "uac-enabled", "ENABLED") },
		},
		{
			ID: "CHM-ID-008", Title: "Administrator elevation requires an explicit prompt", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.uac.admin_consent_prompt", ExpectedState: "administrator elevation does not use ELEVATE_WITHOUT_PROMPTING",
			Risk:        "Silent elevation for administrators weakens the boundary between ordinary administrative sessions and elevated execution.",
			Remediation: "Configure the UAC administrator elevation prompt to require consent or credentials rather than elevating without prompting.",
			Evaluate:    evaluateWindowsAdminConsentPrompt,
		},
		{
			ID: "CHM-ID-009", Title: "UAC elevation prompts use the secure desktop", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.uac.secure_desktop", ExpectedState: "UAC elevation prompts use the secure desktop",
			Risk:        "Prompting outside the secure desktop increases the opportunity for same-session processes to interfere with or imitate elevation prompts.",
			Remediation: "Enable secure-desktop prompting for UAC elevation through approved Windows policy management.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateWindowsPolicyEquals(idx, "secure-desktop-prompt", "ENABLED")
			},
		},
		{
			ID: "CHM-ID-010", Title: "Built-in Administrator uses Admin Approval Mode when active", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.uac.builtin_administrator_approval_mode", ExpectedState: "the built-in Administrator is disabled or Admin Approval Mode is enabled",
			Risk:        "An active built-in Administrator account outside Admin Approval Mode receives a weaker elevation boundary than other administrative identities.",
			Remediation: "Keep the built-in Administrator disabled where possible. If it must remain enabled, configure Admin Approval Mode for that account.",
			Evaluate:    evaluateBuiltinAdministratorApprovalMode,
		},
		{
			ID: "CHM-ID-011", Title: "Remote UAC token filtering is enabled", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.uac.remote_token_filtering", ExpectedState: "remote UAC token filtering remains enabled for local administrator accounts",
			Risk:        "Disabling remote UAC token filtering can grant local administrator credentials a full elevated token during remote administrative access, increasing lateral-movement impact.",
			Remediation: "Remove policy that disables remote UAC token filtering unless a documented management requirement justifies it and compensating controls exist.",
			Evaluate:    func(idx Index) Evaluation { return evaluateWindowsPolicyEquals(idx, "remote-uac-filtering", "ENABLED") },
		},
		{
			ID: "CHM-ID-012", Title: "Built-in Guest account is disabled", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.accounts.builtin_guest", ExpectedState: "the built-in Guest account is disabled",
			Risk:        "An enabled Guest account introduces an additional low-assurance local authentication path and can interact with permissive sharing policy.",
			Remediation: "Disable the built-in Guest account unless a documented legacy requirement exists, and constrain any exceptional guest-access design with explicit network and share policy.",
			Evaluate:    evaluateWindowsGuestAccount,
		},
		{
			ID: "CHM-ID-013", Title: "Blank local passwords are restricted to console logon", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.security.limit_blank_password_use", ExpectedState: "remote use of blank local passwords is restricted",
			Risk:        "Allowing blank-password local accounts to authenticate remotely turns a weak local credential state into a network-reachable authentication risk.",
			Remediation: "Enable the Windows security option that limits blank-password local accounts to console logon and separately remediate any blank-password accounts reported by Chimera.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateWindowsPolicyEquals(idx, "limit-blank-password-use", "ENABLED")
			},
		},
		{
			ID: "CHM-ID-014", Title: "Anonymous local account and SAM access is restricted", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.security.anonymous_access", ExpectedState: "Everyone does not include anonymous users, anonymous SAM enumeration is restricted, and anonymous access is not unrestricted",
			Risk:        "Permissive anonymous access can expose account or security-boundary information without an authenticated principal and can weaken downstream share/service authorization assumptions.",
			Remediation: "Restrict anonymous SAM/account access and ensure anonymous users are not implicitly included in Everyone permissions unless a documented compatibility requirement exists.",
			Evaluate:    evaluateWindowsAnonymousAccess,
		},
		{
			ID: "CHM-ID-015", Title: "Network access does not force local users to Guest", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.security.force_guest", ExpectedState: "ForceGuest is disabled",
			Risk:        "Forcing local network users into the Guest security context can create ambiguous authorization behavior and weaken per-user accountability for local sharing access.",
			Remediation: "Use the classic local-user authentication model unless a documented legacy sharing requirement explicitly needs Guest-only behavior.",
			Evaluate:    func(idx Index) Evaluation { return evaluateWindowsPolicyEquals(idx, "force-guest", "DISABLED") },
		},
	}
}

func evaluateWindowsPolicyEquals(idx Index, id, expected string) Evaluation {
	if e, ok := windowsPolicyApplicability(idx); ok {
		return e
	}
	key := "account.policy." + id
	o, ok := idx[key]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Windows local security policy evidence key is missing: " + key, Applicability: Undetermined, EvidenceKeys: windowsPolicyProviderKeys(idx)}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	if value == expected {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: id + "=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: id + "=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluateWindowsAdminConsentPrompt(idx Index) Evaluation {
	if e, ok := windowsPolicyApplicability(idx); ok {
		return e
	}
	key := "account.policy.admin-consent-prompt"
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		if !ok {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "administrator consent-prompt policy is unavailable", Applicability: Undetermined, EvidenceKeys: windowsPolicyProviderKeys(idx)}
		}
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	if value == "ELEVATE_WITHOUT_PROMPTING" {
		return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: "administrator consent prompt=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if strings.HasPrefix(value, "VALUE_") || value == "" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized administrator consent-prompt value=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "administrator consent prompt=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluateBuiltinAdministratorApprovalMode(idx Index) Evaluation {
	if e, ok := windowsPolicyApplicability(idx); ok {
		return e
	}
	items, usable := accountEvidenceItems(idx)
	var admin *accountEvidenceItem
	for i := range items {
		if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(items[i].Account.SID)), "-500") {
			admin = &items[i]
			break
		}
	}
	if admin == nil {
		if !usable || accountSourcesDegraded(idx) {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "built-in Administrator account state is unavailable", Applicability: Undetermined, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "built-in Administrator SID (-500) was not present in the local account inventory", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
	}
	if admin.Account.EnabledState == "DISABLED" {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "built-in Administrator account is disabled", Applicability: Applicable, EvidenceKeys: []string{admin.Key}}
	}
	if admin.Account.EnabledState != "ENABLED" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "built-in Administrator enabled state is unresolved", Applicability: Applicable, EvidenceKeys: []string{admin.Key}}
	}
	e := evaluateWindowsPolicyEquals(idx, "builtin-admin-approval-mode", "ENABLED")
	e.EvidenceKeys = appendUnique(e.EvidenceKeys, admin.Key)
	sort.Strings(e.EvidenceKeys)
	return e
}

func evaluateWindowsGuestAccount(idx Index) Evaluation {
	if e, ok := windowsPolicyApplicability(idx); ok {
		return e
	}
	items, usable := accountEvidenceItems(idx)
	for _, item := range items {
		if !strings.HasSuffix(strings.ToUpper(strings.TrimSpace(item.Account.SID)), "-501") {
			continue
		}
		switch item.Account.EnabledState {
		case "DISABLED":
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "built-in Guest account is disabled", Applicability: Applicable, EvidenceKeys: []string{item.Key}}
		case "ENABLED":
			return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: "built-in Guest account is enabled: " + item.Account.Principal, Applicability: Applicable, EvidenceKeys: []string{item.Key}}
		default:
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "built-in Guest account enabled state is unresolved", Applicability: Applicable, EvidenceKeys: []string{item.Key}}
		}
	}
	if !usable || accountSourcesDegraded(idx) {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "built-in Guest account state is unavailable", Applicability: Undetermined, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "built-in Guest SID (-501) was not present in the local account inventory", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
}

func evaluateWindowsAnonymousAccess(idx Index) Evaluation {
	if e, ok := windowsPolicyApplicability(idx); ok {
		return e
	}
	checks := []struct{ key, insecure string }{
		{"account.policy.everyone-includes-anonymous", "ENABLED"},
		{"account.policy.restrict-anonymous-sam", "DISABLED"},
		{"account.policy.restrict-anonymous", "NONE"},
	}
	keys := make([]string, 0, len(checks))
	bad := make([]string, 0)
	unknown := make([]string, 0)
	conf := evidence.ConfidenceExact
	for _, c := range checks {
		o, ok := idx[c.key]
		if !ok {
			unknown = append(unknown, c.key+"=MISSING")
			continue
		}
		keys = append(keys, c.key)
		if o.Confidence != evidence.ConfidenceExact {
			conf = evidence.ConfidenceHigh
		}
		if o.State != evidence.StateObserved {
			unknown = append(unknown, c.key+"="+string(o.State))
			continue
		}
		value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
		if value == c.insecure {
			bad = append(bad, c.key+"="+value)
		}
	}
	sort.Strings(keys)
	sort.Strings(bad)
	sort.Strings(unknown)
	if len(bad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: conf, ObservedState: "insecure anonymous-access policy: " + strings.Join(bad, ", "), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "no insecure anonymous-access state proven; unresolved controls: " + strings.Join(unknown, ", "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: conf, ObservedState: "anonymous Everyone/SAM/access restrictions are enabled", Applicability: Applicable, EvidenceKeys: keys}
}

func windowsPolicyApplicability(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "windows" {
		keys := windowsPolicyProviderKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Windows UAC/local-security-policy assessment is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	return Evaluation{}, false
}

func windowsPolicyProviderKeys(idx Index) []string {
	keys := make([]string, 0, 2)
	for _, key := range []string{"account.platform", "account.policy.provider"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

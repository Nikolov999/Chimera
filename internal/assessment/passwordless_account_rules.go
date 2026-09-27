package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

// PasswordlessAccountRules implements . The rules consume only
// normalized local account metadata. They never attempt authentication, read
// plaintext passwords, or attach password hashes to evidence/findings.
func PasswordlessAccountRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-005", Title: "Enabled local accounts do not have empty passwords", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "accounts.authentication.empty_password",
			ExpectedState:  "no enabled login-capable local account has an observed EMPTY password state",
			Risk:           "An enabled local account with no password materially weakens the host authentication boundary, especially when the account can sign in interactively or holds elevated authority.",
			Remediation:    "Set a strong managed password or disable interactive sign-in for the affected local account. If the identity is no longer required, disable or remove it through the approved account-management process.",
			Evaluate:       evaluateEmptyPasswordAccounts,
		},
		{
			ID: "CHM-ID-006", Title: "Windows local accounts require passwords", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "accounts.authentication.password_required",
			ExpectedState:  "enabled login-capable Windows local accounts have PasswordRequired enabled",
			Risk:           "A local account configured so that a password is not required permits a weaker authentication posture even when Chimera cannot safely determine the account's current password value.",
			Remediation:    "Require passwords for affected Windows local accounts and review the account's sign-in rights. Set or rotate credentials through approved administrative tooling rather than through Chimera.",
			Evaluate:       evaluatePasswordRequiredPolicy,
		},
	}
}

func evaluateEmptyPasswordAccounts(idx Index) Evaluation {
	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}

	eligible := make([]accountEvidenceItem, 0)
	empty := make([]accountEvidenceItem, 0)
	unresolved := make([]accountEvidenceItem, 0)
	for _, item := range items {
		a := item.Account
		if a.EnabledState == "DISABLED" || a.LoginCapability == "LOGIN_DISABLED" {
			continue
		}
		if a.EnabledState != "ENABLED" || a.LoginCapability != "LOGIN_CAPABLE" {
			continue
		}
		eligible = append(eligible, item)
		switch strings.ToUpper(strings.TrimSpace(a.Authentication.PasswordState)) {
		case "EMPTY":
			empty = append(empty, item)
		case "PASSWORD_SET":
			// Defensible positive evidence that the account is not empty-password.
		case "LOCKED", "DISABLED":
			// Contradictory with an enabled/login-capable account, but it still does
			// not prove an empty password. Preserve uncertainty rather than pass.
			unresolved = append(unresolved, item)
		default:
			unresolved = append(unresolved, item)
		}
	}

	if len(empty) > 0 {
		return Evaluation{
			Status: StatusFail, Confidence: evidence.ConfidenceExact,
			ObservedState: "enabled login-capable accounts with observed empty password state: " + describeAccountItems(empty, passwordlessAccountDescription),
			Applicability: Applicable, EvidenceKeys: accountItemKeys(empty),
		}
	}
	if len(eligible) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled login-capable local accounts require empty-password assessment", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
	}
	if len(unresolved) > 0 {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceMedium,
			ObservedState: fmt.Sprintf("no empty password proven; password state is not safely observable for %d of %d enabled login-capable account(s)", len(unresolved), len(eligible)),
			Applicability: Applicable, EvidenceKeys: accountItemKeys(unresolved),
		}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled login-capable local account(s) have a non-empty password state", len(eligible)), Applicability: Applicable, EvidenceKeys: accountItemKeys(eligible)}
}

func evaluatePasswordRequiredPolicy(idx Index) Evaluation {
	platform := accountPlatform(idx)
	if platform != "windows" {
		keys := accountInventoryEvidenceKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{
			Status: StatusPass, Confidence: evidence.ConfidenceExact,
			ObservedState: "PasswordRequired account-flag assessment is not applicable to the current " + fallbackAccountPlatform(platform) + " provider",
			Applicability: NotApplicable, EvidenceKeys: keys,
		}
	}

	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}
	eligible := make([]accountEvidenceItem, 0)
	bad := make([]accountEvidenceItem, 0)
	unknown := make([]accountEvidenceItem, 0)
	for _, item := range items {
		a := item.Account
		if a.EnabledState == "DISABLED" || a.LoginCapability == "LOGIN_DISABLED" {
			continue
		}
		if a.EnabledState != "ENABLED" || a.LoginCapability != "LOGIN_CAPABLE" {
			continue
		}
		eligible = append(eligible, item)
		switch strings.ToUpper(strings.TrimSpace(a.Authentication.PasswordRequired)) {
		case "NO":
			bad = append(bad, item)
		case "YES":
			// Expected state.
		default:
			unknown = append(unknown, item)
		}
	}
	if len(bad) > 0 {
		return Evaluation{
			Status: StatusFail, Confidence: evidence.ConfidenceHigh,
			ObservedState: "enabled login-capable Windows accounts with PasswordRequired=NO: " + describeAccountItems(bad, passwordRequiredDescription),
			Applicability: Applicable, EvidenceKeys: accountItemKeys(bad),
		}
	}
	if len(eligible) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled login-capable Windows local accounts require PasswordRequired assessment", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
	}
	if len(unknown) > 0 {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceMedium,
			ObservedState: fmt.Sprintf("no PasswordRequired=NO account proven; password-requirement metadata is unresolved for %d of %d eligible account(s)", len(unknown), len(eligible)),
			Applicability: Applicable, EvidenceKeys: accountItemKeys(unknown),
		}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled login-capable Windows local account(s) require a password", len(eligible)), Applicability: Applicable, EvidenceKeys: accountItemKeys(eligible)}
}

func passwordlessAccountDescription(a accounts.Account) string {
	flags := []string{"password=EMPTY"}
	if a.Privileged {
		flags = append(flags, "privileged")
	}
	if a.ServiceAccount {
		flags = append(flags, "service-account")
	}
	return a.Principal + " [" + strings.Join(flags, ",") + "]"
}

func passwordRequiredDescription(a accounts.Account) string {
	parts := []string{a.Principal, "PasswordRequired=NO"}
	if a.Privileged {
		parts = append(parts, "privileged")
	}
	if a.ServiceAccount {
		parts = append(parts, "service-account")
	}
	if len(parts) == 2 {
		return parts[0] + " [" + parts[1] + "]"
	}
	return parts[0] + " [" + strings.Join(parts[1:], ",") + "]"
}

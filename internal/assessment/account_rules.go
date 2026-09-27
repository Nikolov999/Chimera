package assessment

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

const dormantPrivilegedThreshold = 90 * 24 * time.Hour

type accountEvidenceItem struct {
	Key     string
	Account accounts.Account
}

// PrivilegedAccountRules implements using only the normalized,
// read-only account/group metadata introduced in . The rules do not
// authenticate, inspect password material, modify membership, or infer missing
// privilege data as safe.
func PrivilegedAccountRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-001", Title: "Unexpected privileged service or system memberships are absent", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "accounts.privileged.unexpected_membership",
			ExpectedState:  "no enabled service/system principal has unexpected administrator/root-equivalent membership and no alternate UID 0 principal exists",
			Risk:           "A service or system principal with administrator/root-equivalent authority can turn compromise of that principal or its service into broad host control. Alternate UID 0 identities are especially difficult to distinguish from root during incident response and access review.",
			Remediation:    "Remove unnecessary administrator/root-equivalent membership from service and system principals, eliminate unintended alternate UID 0 accounts, and assign only the minimum local rights required for the workload.",
			Evaluate:       evaluateUnexpectedPrivilegedMembership,
		},
		{
			ID: "CHM-ID-002", Title: "Enabled privileged accounts are not dormant", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "accounts.privileged.dormancy",
			ExpectedState:  "enabled login-capable privileged accounts with observable last-logon metadata have activity within 90 days",
			Risk:           "Dormant privileged accounts preserve high-impact credentials and authorization paths that may escape routine ownership review or credential hygiene.",
			Remediation:    "Validate ownership and business need for dormant privileged accounts, disable or remove accounts that are no longer required, and rotate credentials or re-establish access through the approved administrative process before reuse.",
			Evaluate:       evaluateDormantPrivilegedAccounts,
		},
		{
			ID: "CHM-ID-003", Title: "Service accounts are non-interactive", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "accounts.service.interactive_login",
			ExpectedState:  "enabled local service accounts do not expose an interactive login path at the account level",
			Risk:           "An interactive login-capable service identity expands the ways a service credential can be abused and weakens separation between workload and human sign-in contexts.",
			Remediation:    "Use a non-interactive shell or platform service identity, deny interactive sign-in where appropriate, and keep the account enabled only for the service functions that require it.",
			Evaluate:       evaluateInteractiveServiceAccounts,
		},
		{
			ID: "CHM-ID-004", Title: "High-impact delegated local privilege groups are tightly scoped", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "accounts.privileged.delegated_scope",
			ExpectedState:  "enabled local principals are not assigned high-impact delegated groups unless that authority is explicitly required",
			Risk:           "Membership in groups such as Windows operator roles, Linux container/raw-disk groups, or macOS wheel can provide capabilities materially beyond ordinary user access and may create practical host-compromise paths.",
			Remediation:    "Review each reported group membership, remove unnecessary delegated authority, and use narrower task-specific permissions or approved administrative elevation instead of persistent broad group membership.",
			Evaluate:       evaluateDangerousPrivilegeScope,
		},
	}
}

func evaluateUnexpectedPrivilegedMembership(idx Index) Evaluation {
	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}
	bad := make([]accountEvidenceItem, 0)
	unknown := make([]accountEvidenceItem, 0)
	for _, item := range items {
		a := item.Account
		if a.EnabledState == "DISABLED" || !a.Privileged {
			continue
		}
		if a.EnabledState == "UNKNOWN" {
			unknown = append(unknown, item)
			continue
		}
		if isAlternateUIDZero(a) {
			bad = append(bad, item)
			continue
		}
		if isCorePrivilegedAccount(a) {
			continue
		}
		if a.ServiceAccount || a.AccountType == "SERVICE" {
			bad = append(bad, item)
			continue
		}
		if a.AccountType == "SYSTEM" && a.LoginCapability == "LOGIN_CAPABLE" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "unexpected privileged principals: " + describeAccountItems(bad, privilegeDescription), Applicability: Applicable, EvidenceKeys: accountItemKeys(bad)}
	}
	if len(unknown) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no unexpected privileged membership proven; enabled state is unknown for %d privileged principal(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: accountItemKeys(unknown)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no unexpected privileged service/system membership or alternate UID 0 principal observed", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
}

func evaluateDormantPrivilegedAccounts(idx Index) Evaluation {
	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}
	platform := accountPlatform(idx)
	// supplies a normalized LastLogin field on every platform, but its
	// current provider has reliable timestamp semantics only on Windows. Do not
	// manufacture a dormancy conclusion on platforms where that evidence is not
	// yet collected.
	if platform != "windows" {
		keys := accountInventoryEvidenceKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "last-logon dormancy assessment is not applicable to the current " + fallbackAccountPlatform(platform) + " account provider", Applicability: NotApplicable, EvidenceKeys: keys}
	}

	eligible := make([]accountEvidenceItem, 0)
	stale := make([]accountEvidenceItem, 0)
	unresolved := make([]accountEvidenceItem, 0)
	var newestEvidence time.Time
	for _, item := range items {
		if item.Account.Privileged && item.Account.EnabledState == "ENABLED" && item.Account.LoginCapability == "LOGIN_CAPABLE" && !item.Account.ServiceAccount {
			eligible = append(eligible, item)
			if o, ok := idx[item.Key]; ok && o.CollectedAt.After(newestEvidence) {
				newestEvidence = o.CollectedAt
			}
		}
	}
	if len(eligible) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled login-capable privileged non-service accounts require dormancy assessment", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
	}
	if newestEvidence.IsZero() {
		newestEvidence = time.Now().UTC()
	}
	for _, item := range eligible {
		last, ok := parseAccountTimestamp(item.Account.Authentication.LastLogin)
		if !ok || last.After(newestEvidence.Add(5*time.Minute)) {
			unresolved = append(unresolved, item)
			continue
		}
		if newestEvidence.Sub(last) > dormantPrivilegedThreshold {
			stale = append(stale, item)
		}
	}
	if len(stale) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "privileged accounts with last logon older than 90 days: " + describeAccountItems(stale, func(a accounts.Account) string {
			return fmt.Sprintf("%s (last=%s)", a.Principal, a.Authentication.LastLogin)
		}), Applicability: Applicable, EvidenceKeys: accountItemKeys(stale)}
	}
	if len(unresolved) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no dormant privileged account proven, but %d of %d eligible account(s) lack a reliable last-logon timestamp", len(unresolved), len(eligible)), Applicability: Applicable, EvidenceKeys: accountItemKeys(unresolved)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d enabled privileged account(s) have observed last-logon activity within 90 days", len(eligible)), Applicability: Applicable, EvidenceKeys: accountItemKeys(eligible)}
}

func evaluateInteractiveServiceAccounts(idx Index) Evaluation {
	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}
	bad := make([]accountEvidenceItem, 0)
	unknown := make([]accountEvidenceItem, 0)
	serviceCount := 0
	for _, item := range items {
		a := item.Account
		if !a.ServiceAccount && a.AccountType != "SERVICE" {
			continue
		}
		serviceCount++
		if a.EnabledState == "DISABLED" || a.LoginCapability == "LOGIN_DISABLED" {
			continue
		}
		if a.EnabledState == "ENABLED" && a.LoginCapability == "LOGIN_CAPABLE" {
			bad = append(bad, item)
			continue
		}
		unknown = append(unknown, item)
	}
	if len(bad) > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "interactive login-capable service accounts: " + describeAccountItems(bad, func(a accounts.Account) string { return a.Principal }), Applicability: Applicable, EvidenceKeys: accountItemKeys(bad)}
	}
	if len(unknown) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no interactive service account proven; login or enabled state is unresolved for %d service account(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: accountItemKeys(unknown)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d service account(s) observed; none are enabled with an interactive account-level login path", serviceCount), Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
}

func evaluateDangerousPrivilegeScope(idx Index) Evaluation {
	items, usable := accountEvidenceItems(idx)
	if len(items) == 0 {
		return accountInventoryEmptyEvaluation(idx, usable)
	}
	platform := accountPlatform(idx)
	bad := make([]accountEvidenceItem, 0)
	for _, item := range items {
		a := item.Account
		if a.EnabledState == "DISABLED" {
			continue
		}
		if isAlternateUIDZero(a) || hasDangerousDelegatedGroup(platform, a.Groups) {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "high-impact delegated privilege observed: " + describeAccountItems(bad, func(a accounts.Account) string {
			return a.Principal + " [" + strings.Join(dangerousGroups(platform, a.Groups), ",") + "]"
		}), Applicability: Applicable, EvidenceKeys: accountItemKeys(bad)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no enabled principal has a high-impact delegated group assignment", Applicability: Applicable, EvidenceKeys: accountInventoryEvidenceKeys(idx)}
}

func accountEvidenceItems(idx Index) ([]accountEvidenceItem, bool) {
	out := make([]accountEvidenceItem, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.item.") || obs.State != evidence.StateObserved {
			continue
		}
		a, ok := obs.Value.(accounts.Account)
		if !ok {
			continue
		}
		out = append(out, accountEvidenceItem{Key: key, Account: a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	usable := false
	if count, ok := idx["account.inventory.count"]; ok && count.State == evidence.StateObserved {
		usable = true
	}
	return out, usable
}

func accountInventoryEmptyEvaluation(idx Index, usable bool) Evaluation {
	keys := accountInventoryEvidenceKeys(idx)
	if usable && !accountSourcesDegraded(idx) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local account records require assessment", Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "local account inventory is unavailable or degraded", Applicability: Undetermined, EvidenceKeys: keys}
}

func accountInventoryEvidenceKeys(idx Index) []string {
	keys := make([]string, 0)
	for key := range idx {
		if key == "account.inventory.count" || key == "account.inventory.summary" || strings.HasPrefix(key, "account.source.") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func accountSourcesDegraded(idx Index) bool {
	for key, obs := range idx {
		if strings.HasPrefix(key, "account.source.") && obs.State != evidence.StateObserved && obs.State != evidence.StateNotApplicable {
			return true
		}
	}
	return false
}

func accountPlatform(idx Index) string {
	if o, ok := idx["account.platform"]; ok && o.State == evidence.StateObserved {
		return strings.ToLower(strings.TrimSpace(fmt.Sprint(o.Value)))
	}
	return ""
}

func fallbackAccountPlatform(platform string) string {
	if strings.TrimSpace(platform) == "" {
		return "unknown-platform"
	}
	return platform
}

func isCorePrivilegedAccount(a accounts.Account) bool {
	if a.UID == "0" && strings.EqualFold(a.Name, "root") {
		return true
	}
	return strings.HasSuffix(strings.ToUpper(strings.TrimSpace(a.SID)), "-500")
}

func isAlternateUIDZero(a accounts.Account) bool {
	return strings.TrimSpace(a.UID) == "0" && !strings.EqualFold(strings.TrimSpace(a.Name), "root")
}

func privilegeDescription(a accounts.Account) string {
	basis := strings.Join(a.PrivilegeBasis, ",")
	if basis == "" {
		basis = "privileged=true"
	}
	return a.Principal + " [" + basis + "]"
}

func dangerousPrivilegeDescription(platform string, a accounts.Account) string {
	if isAlternateUIDZero(a) {
		return a.Principal + " [alternate UID 0]"
	}
	groups := dangerousGroups(platform, a.Groups)
	if len(groups) == 0 {
		return a.Principal + " [high-impact delegated privilege]"
	}
	return a.Principal + " [" + strings.Join(groups, ",") + "]"
}

func dangerousGroups(platform string, groups []string) []string {
	var set map[string]struct{}
	switch strings.ToLower(platform) {
	case "windows":
		set = stringSet("backup operators", "account operators", "server operators", "print operators", "hyper-v administrators")
	case "linux":
		set = stringSet("docker", "lxd", "disk", "shadow")
	case "darwin":
		set = stringSet("wheel")
	default:
		set = map[string]struct{}{}
	}
	out := make([]string, 0)
	for _, g := range groups {
		if _, ok := set[strings.ToLower(strings.TrimSpace(g))]; ok {
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

func hasDangerousDelegatedGroup(platform string, groups []string) bool {
	return len(dangerousGroups(platform, groups)) > 0
}

func stringSet(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}

func accountItemKeys(items []accountEvidenceItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
	}
	sort.Strings(keys)
	return keys
}

func describeAccountItems(items []accountEvidenceItem, render func(accounts.Account) string) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, render(item.Account))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func parseAccountTimestamp(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05Z07:00", "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

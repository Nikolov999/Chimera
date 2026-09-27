package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

// LinuxAuthenticationRules implements over normalized, read-only
// PAM/login.defs evidence. The rules never authenticate, inspect password
// hashes, change PAM configuration, or infer an unreadable policy as secure.
func LinuxAuthenticationRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-026", Title: "PAM authentication chains avoid permissive bypasses", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "linux.authentication.pam_chain", ExpectedState: "active PAM authentication/password/account chains do not use pam_permit and do not allow null passwords through pam_unix",
			Risk:        "Permissive PAM modules or null-password options can weaken the local authentication boundary and allow accounts to bypass expected password checks.",
			Remediation: "Remove unintended pam_permit entries and nullok/nullok_secure options from security-sensitive PAM stacks, then validate the distribution-supported authentication profile before deployment.",
			Evaluate:    evaluatePAMBypass,
		},
		{
			ID: "CHM-ID-027", Title: "PAM authentication includes bounded failure lockout", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "linux.authentication.lockout", ExpectedState: "local PAM authentication uses pam_faillock/pam_tally-style failure tracking with a bounded deny threshold",
			Risk:        "Without local authentication failure throttling or lockout, repeated password guessing against local PAM-backed services can proceed without an account-level rate-control boundary.",
			Remediation: "Configure the distribution-supported pam_faillock or equivalent failure-control mechanism with an appropriate deny threshold and unlock policy, accounting for service and availability requirements.",
			Evaluate:    evaluatePAMLockout,
		},
		{
			ID: "CHM-ID-028", Title: "PAM password changes enforce quality controls", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "linux.authentication.password_quality", ExpectedState: "local password changes use a supported quality module and a defensible minimum password length",
			Risk:        "Weak local password composition and length controls increase the likelihood that account credentials can be guessed or recovered after credential material is exposed elsewhere.",
			Remediation: "Enable pam_pwquality, pam_passwdqc, or the distribution-supported equivalent and enforce a minimum length appropriate to enterprise password policy.",
			Evaluate:    evaluatePAMPasswordQuality,
		},
		{
			ID: "CHM-ID-029", Title: "Local password ageing policy is bounded", Category: "identity", Severity: SeverityLow,
			AffectedObject: "linux.authentication.password_ageing", ExpectedState: "login.defs provides a non-zero minimum password age, bounded maximum age, and warning period where local password ageing is used",
			Risk:        "Unbounded or immediately reusable local passwords can weaken credential lifecycle controls and permit rapid password cycling around history requirements.",
			Remediation: "Set PASS_MIN_DAYS, PASS_MAX_DAYS, and PASS_WARN_AGE to values aligned with the organization's authentication policy, or document why lifecycle is managed by a different identity provider.",
			Evaluate:    evaluateLoginPasswordAgeing,
		},
		{
			ID: "CHM-ID-030", Title: "Local password hashing policy avoids legacy algorithms", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "linux.authentication.password_hashing", ExpectedState: "local password hashing explicitly uses a modern supported algorithm and avoids DES/MD5/bigcrypt or other legacy selections",
			Risk:        "Legacy password hashing algorithms materially reduce the work required to recover passwords from exposed password hashes.",
			Remediation: "Use the distribution-supported modern password hashing default such as yescrypt or another approved adaptive/strong scheme, and migrate legacy password hashes through the normal password-change process.",
			Evaluate:    evaluatePasswordHashing,
		},
		{
			ID: "CHM-ID-031", Title: "PAM and login-policy configuration is protected from weak writes", Category: "identity", Severity: SeverityCritical,
			AffectedObject: "linux.authentication.configuration_integrity", ExpectedState: "PAM and login-policy files/directories are root-owned and not group/world writable",
			Risk:        "A weakly writable PAM or login-policy path can allow local authentication policy tampering, including authentication bypass or credential-policy weakening.",
			Remediation: "Restore root ownership and restrictive write permissions on PAM, login.defs, faillock, pwquality, and password-history configuration paths using the operating system's package/profile management workflow.",
			Evaluate:    evaluateLinuxAuthConfigIntegrity,
		},
	}
}

type linuxPAMEvidence struct {
	Key  string
	Rule accounts.LinuxPAMRule
}
type linuxAuthConfigEvidence struct {
	Key  string
	Path accounts.LinuxAuthConfigPath
}

func evaluatePAMBypass(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	items := linuxPAMEvidenceItems(idx)
	authCount := map[string]int{}
	authHasDeny := map[string]bool{}
	for _, item := range items {
		if item.Rule.Type != "auth" {
			continue
		}
		authCount[item.Rule.Service]++
		if item.Rule.Module == "pam_deny.so" {
			authHasDeny[item.Rule.Service] = true
		}
	}
	var bad []string
	var keys []string
	for _, item := range items {
		r := item.Rule
		unsafePermit := r.Type == "auth" && r.Module == "pam_permit.so" && (strings.EqualFold(r.Control, "sufficient") || (authCount[r.Service] == 1 && !authHasDeny[r.Service]))
		unsafeNull := r.Type == "auth" && r.Module == "pam_unix.so" && r.NullOK
		if unsafePermit || unsafeNull {
			bad = append(bad, fmt.Sprintf("%s %s:%d %s/%s", r.Service, r.Source, r.Line, r.Type, r.Module))
			keys = appendUnique(keys, item.Key)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "permissive PAM authentication constructs: " + strings.Join(bad, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return linuxAuthCleanOrUnknown(idx, "no standalone/sufficient pam_permit authentication bypass or pam_unix null-password option was observed in parsed auth rules")
}

func evaluatePAMLockout(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	rules := linuxPAMEvidenceItems(idx)
	var lockout []linuxPAMEvidence
	for _, item := range rules {
		if item.Rule.Type != "auth" {
			continue
		}
		switch item.Rule.Module {
		case "pam_faillock.so", "pam_tally2.so", "pam_tally.so":
			lockout = append(lockout, item)
		}
	}
	if len(lockout) == 0 {
		if !linuxAuthProviderObserved(idx) {
			return linuxAuthCleanOrUnknown(idx, "")
		}
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "no pam_faillock/pam_tally-style authentication failure-control module was observed in parsed PAM auth rules", Applicability: Applicable, EvidenceKeys: linuxAuthProviderEvidenceKeys(idx)}
	}
	tuning, tuningKey := linuxAuthTuning(idx)
	keys := make([]string, 0, len(lockout)+1)
	for _, item := range lockout {
		keys = appendUnique(keys, item.Key)
	}
	if tuningKey != "" {
		keys = appendUnique(keys, tuningKey)
	}
	sort.Strings(keys)
	if tuning.FaillockDeny > 5 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("failure-control module present but deny threshold is %d (>5)", tuning.FaillockDeny), Applicability: Applicable, EvidenceKeys: keys}
	}
	if tuning.FaillockDeny > 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("failure-control module observed with deny threshold %d", tuning.FaillockDeny), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceMedium, ObservedState: "failure-control module is present; explicit deny threshold was not observed and module/distribution defaults may apply", Applicability: Applicable, EvidenceKeys: keys}
}

func evaluatePAMPasswordQuality(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	var quality []linuxPAMEvidence
	for _, item := range linuxPAMEvidenceItems(idx) {
		if item.Rule.Type != "password" {
			continue
		}
		switch item.Rule.Module {
		case "pam_pwquality.so", "pam_passwdqc.so", "pam_cracklib.so":
			quality = append(quality, item)
		}
	}
	if len(quality) == 0 {
		if !linuxAuthProviderObserved(idx) {
			return linuxAuthCleanOrUnknown(idx, "")
		}
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "no supported PAM password-quality module was observed in parsed password rules", Applicability: Applicable, EvidenceKeys: linuxAuthProviderEvidenceKeys(idx)}
	}
	tuning, tuningKey := linuxAuthTuning(idx)
	keys := []string{}
	for _, item := range quality {
		keys = appendUnique(keys, item.Key)
	}
	if tuningKey != "" {
		keys = appendUnique(keys, tuningKey)
	}
	sort.Strings(keys)
	if tuning.PwqualityMinLen > 0 && tuning.PwqualityMinLen < 12 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("password-quality module is present but minimum length is %d (<12)", tuning.PwqualityMinLen), Applicability: Applicable, EvidenceKeys: keys}
	}
	if tuning.PwqualityMinLen >= 12 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("password-quality module is present with minimum length %d", tuning.PwqualityMinLen), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceMedium, ObservedState: "password-quality module is present; an explicit minimum length was not observable and provider defaults may apply", Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateLoginPasswordAgeing(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	obs, ok := idx["account.linux_auth.login_policy"]
	if !ok || obs.State != evidence.StateObserved {
		if ok {
			return Evaluation{Status: StatusUnknown, Confidence: obs.Confidence, ObservedState: observedText(obs), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "login.defs password ageing evidence is missing", Applicability: Undetermined, EvidenceKeys: linuxAuthProviderEvidenceKeys(idx)}
	}
	lp, ok := obs.Value.(accounts.LinuxLoginPolicy)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "login.defs evidence type is unavailable", Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
	}
	var weak []string
	if lp.MinDays == 0 {
		weak = append(weak, "PASS_MIN_DAYS=0 or unset")
	}
	if lp.MaxDays == 0 || lp.MaxDays > 365 {
		weak = append(weak, fmt.Sprintf("PASS_MAX_DAYS=%d", lp.MaxDays))
	}
	if lp.WarnAge == 0 {
		weak = append(weak, "PASS_WARN_AGE=0 or unset")
	}
	if len(weak) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceExact, ObservedState: "weak or unbounded login.defs password ageing: " + strings.Join(weak, ", "), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("PASS_MIN_DAYS=%d PASS_MAX_DAYS=%d PASS_WARN_AGE=%d", lp.MinDays, lp.MaxDays, lp.WarnAge), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
}

func evaluatePasswordHashing(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	algs := map[string]struct{}{}
	var keys []string
	for _, item := range linuxPAMEvidenceItems(idx) {
		if item.Rule.Type == "password" && item.Rule.Module == "pam_unix.so" && item.Rule.Hash != "" {
			algs[item.Rule.Hash] = struct{}{}
			keys = appendUnique(keys, item.Key)
		}
	}
	if obs, ok := idx["account.linux_auth.login_policy"]; ok && obs.State == evidence.StateObserved {
		if lp, ok := obs.Value.(accounts.LinuxLoginPolicy); ok && lp.EncryptMethod != "" {
			algs[lp.EncryptMethod] = struct{}{}
			keys = appendUnique(keys, obs.Key)
		}
	}
	sort.Strings(keys)
	for _, weak := range []string{"DES", "MD5", "BIGCRYPT"} {
		if _, ok := algs[weak]; ok {
			return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: "legacy local password hash algorithm explicitly configured: " + weak, Applicability: Applicable, EvidenceKeys: keys}
		}
	}
	if _, ok := algs["SHA256"]; ok {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceExact, ObservedState: "SHA256 crypt is explicitly configured; prefer the current distribution-approved stronger password hashing scheme", Applicability: Applicable, EvidenceKeys: keys}
	}
	for _, strong := range []string{"YESCRYPT", "SHA512", "BLOWFISH"} {
		if _, ok := algs[strong]; ok {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "non-legacy local password hash algorithm observed: " + strong, Applicability: Applicable, EvidenceKeys: keys}
		}
	}
	if !linuxAuthProviderObserved(idx) {
		return linuxAuthCleanOrUnknown(idx, "")
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "no explicit password hashing algorithm was observed in PAM/login.defs; distribution defaults may apply", Applicability: Applicable, EvidenceKeys: linuxAuthProviderEvidenceKeys(idx)}
}

func evaluateLinuxAuthConfigIntegrity(idx Index) Evaluation {
	if e, ok := linuxAuthNotApplicable(idx); ok {
		return e
	}
	var bad []linuxAuthConfigEvidence
	for _, item := range linuxAuthConfigEvidenceItems(idx) {
		if item.Path.State == evidence.StateObserved && item.Path.Insecure {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		var parts, keys []string
		for _, item := range bad {
			parts = append(parts, item.Path.Path+" ["+strings.Join(item.Path.InsecureBasis, ", ")+"]")
			keys = append(keys, item.Key)
		}
		sort.Strings(parts)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: "insecure authentication configuration path metadata: " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return linuxAuthCleanOrUnknown(idx, "all observed PAM/login-policy configuration paths are root-owned and not group/world-writable")
}

func linuxAuthNotApplicable(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "linux" {
		keys := linuxAuthProviderEvidenceKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Linux PAM/login policy assessment is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	if provider, ok := idx["account.linux_auth.provider"]; ok && provider.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: provider.Confidence, ObservedState: observedText(provider), Applicability: NotApplicable, EvidenceKeys: []string{provider.Key}}, true
	}
	return Evaluation{}, false
}

func linuxAuthCleanOrUnknown(idx Index, passText string) Evaluation {
	provider, ok := idx["account.linux_auth.provider"]
	keys := linuxAuthProviderEvidenceKeys(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Linux PAM/login policy provider evidence is missing", Applicability: Undetermined, EvidenceKeys: keys}
	}
	if provider.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: provider.Confidence, ObservedState: observedText(provider), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: passText, Applicability: Applicable, EvidenceKeys: keys}
}

func linuxAuthProviderObserved(idx Index) bool {
	o, ok := idx["account.linux_auth.provider"]
	return ok && o.State == evidence.StateObserved
}

func linuxAuthProviderEvidenceKeys(idx Index) []string {
	var keys []string
	for _, key := range []string{"account.platform", "account.linux_auth.provider", "account.linux_auth.summary", "account.linux_auth.tuning"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func linuxPAMEvidenceItems(idx Index) []linuxPAMEvidence {
	var out []linuxPAMEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.linux_auth.pam.") || obs.State != evidence.StateObserved {
			continue
		}
		if r, ok := obs.Value.(accounts.LinuxPAMRule); ok {
			out = append(out, linuxPAMEvidence{Key: key, Rule: r})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func linuxAuthConfigEvidenceItems(idx Index) []linuxAuthConfigEvidence {
	var out []linuxAuthConfigEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.linux_auth.config.") || obs.State != evidence.StateObserved {
			continue
		}
		if p, ok := obs.Value.(accounts.LinuxAuthConfigPath); ok {
			out = append(out, linuxAuthConfigEvidence{Key: key, Path: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func linuxAuthTuning(idx Index) (accounts.LinuxAuthTuning, string) {
	if obs, ok := idx["account.linux_auth.tuning"]; ok && obs.State == evidence.StateObserved {
		if t, ok := obs.Value.(accounts.LinuxAuthTuning); ok {
			return t, obs.Key
		}
	}
	return accounts.LinuxAuthTuning{}, ""
}

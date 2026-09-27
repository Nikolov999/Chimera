package assessment

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	microsoftLSAProtectionURL   = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
	microsoftCredentialGuardURL = "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure"
	microsoftWindowsBaselineURL = "https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows"
	microsoftCachedLogonsURL    = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available"
	microsoftNoLMHashURL        = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password"
)

// WindowsCredentialProtectionRules implements . The rules consume
// normalized registry/CIM posture only; they never read LSASS memory, retrieve
// credentials, authenticate, or modify credential-protection settings.
func WindowsCredentialProtectionRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-016", Title: "LSA protected-process protection is configured", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.credentials.lsa_protection", ExpectedState: "LSA protection is explicitly enabled with or without UEFI lock",
			Risk:        "Without added LSA protected-process protection, untrusted code has a weaker boundary against injecting into or reading the Local Security Authority process that manages sensitive authentication material.",
			Remediation: "Enable added LSA protection through approved Windows policy management, validate LSA plug-in compatibility, and reboot according to the Microsoft deployment guidance.",
			References:  []Reference{{Title: "Microsoft: Configure added LSA protection", URL: microsoftLSAProtectionURL}},
			Evaluate:    evaluateWindowsLSAProtection,
		},
		{
			ID: "CHM-ID-017", Title: "Windows Credential Guard is running", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.credentials.credential_guard", ExpectedState: "Credential Guard is running on a supported 64-bit Windows host",
			Risk:        "When Credential Guard is not running, supported domain credential material is not isolated behind the virtualization-based security boundary provided by Credential Guard.",
			Remediation: "Enable Credential Guard using approved policy on supported hardware and verify the Win32_DeviceGuard runtime state after reboot.",
			References:  []Reference{{Title: "Microsoft: Configure Credential Guard", URL: microsoftCredentialGuardURL}},
			Evaluate:    evaluateWindowsCredentialGuard,
		},
		{
			ID: "CHM-ID-018", Title: "WDigest plaintext credential caching is disabled", Category: "identity", Severity: SeverityCritical,
			AffectedObject: "windows.credentials.wdigest", ExpectedState: "WDigest UseLogonCredential is disabled",
			Risk:        "Enabling WDigest credential caching can cause LSASS to retain reusable plaintext password material for interactive logons, materially increasing credential-theft impact.",
			Remediation: "Disable WDigest UseLogonCredential through approved Windows policy management and validate any legacy application dependency before deployment.",
			References:  []Reference{{Title: "Microsoft Windows security baseline: WDigest Authentication", URL: microsoftWindowsBaselineURL}},
			Evaluate: func(idx Index) Evaluation {
				return evaluateWindowsCredentialEquals(idx, "wdigest-credential-caching", "DISABLED")
			},
		},
		{
			ID: "CHM-ID-019", Title: "Cached domain logons are tightly bounded", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "windows.credentials.cached_domain_logons", ExpectedState: "domain logon caching is disabled or limited to at most two users",
			Risk:        "Caching more domain logons leaves additional offline verifier material on the host and expands credential exposure if the device is lost or its local security boundary is compromised.",
			Remediation: "Set the cached domain logon count to the lowest value compatible with offline-access requirements; Microsoft documents zero as the strongest setting and notes two as an operational option for mobile systems.",
			References:  []Reference{{Title: "Microsoft: Interactive logon cached-logon policy", URL: microsoftCachedLogonsURL}},
			Evaluate:    evaluateWindowsCachedLogons,
		},
		{
			ID: "CHM-ID-020", Title: "Legacy LAN Manager password hash storage is disabled", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "windows.credentials.lm_hash_storage", ExpectedState: "Windows is configured not to store legacy LM password hashes on password change",
			Risk:        "LAN Manager password hashes are substantially weaker than modern Windows password representations and increase password-recovery risk if the local account database is compromised.",
			Remediation: "Enable the Windows policy that prevents storage of LAN Manager password hashes on the next password change, then follow organizational password-rotation procedures where appropriate.",
			References:  []Reference{{Title: "Microsoft: Prevent Windows from storing LM hashes", URL: microsoftNoLMHashURL}},
			Evaluate:    func(idx Index) Evaluation { return evaluateWindowsCredentialEquals(idx, "lm-hash-storage", "DISABLED") },
		},
	}
}

func evaluateWindowsCredentialEquals(idx Index, id, expected string) Evaluation {
	if e, ok := windowsCredentialProtectionApplicability(idx); ok {
		return e
	}
	key := "account.credential_protection." + id
	o, ok := idx[key]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Windows credential-protection evidence key is missing: " + key, Applicability: Undetermined, EvidenceKeys: credentialProtectionProviderKeys(idx)}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	if value == expected {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: id + "=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if strings.HasPrefix(value, "VALUE_") || value == "" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized " + id + " value=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: id + "=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluateWindowsLSAProtection(idx Index) Evaluation {
	if e, ok := windowsCredentialProtectionApplicability(idx); ok {
		return e
	}
	key := "account.credential_protection.lsa-protection-config"
	o, ok := idx[key]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "LSA protection configuration evidence is unavailable; Windows 11 can enable LSA protection automatically without an explicit RunAsPPL value", Applicability: Undetermined, EvidenceKeys: credentialProtectionProviderKeys(idx)}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	switch value {
	case "ENABLED_UEFI_LOCK", "ENABLED_WITHOUT_UEFI_LOCK":
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "LSA protection configuration=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	case "DISABLED":
		return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: "LSA protection is explicitly disabled", Applicability: Applicable, EvidenceKeys: []string{key}}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized LSA protection configuration=" + value, Applicability: Applicable, EvidenceKeys: []string{key}}
	}
}

func evaluateWindowsCredentialGuard(idx Index) Evaluation {
	if e, ok := windowsCredentialProtectionApplicability(idx); ok {
		return e
	}
	keys := credentialProtectionProviderKeys(idx)
	if arch, ok := idx["account.architecture"]; ok && arch.State == evidence.StateObserved {
		keys = appendUnique(keys, "account.architecture")
		v := strings.ToLower(strings.TrimSpace(fmt.Sprint(arch.Value)))
		if v != "amd64" && v != "arm64" {
			sort.Strings(keys)
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Credential Guard requires supported 64-bit Windows hardware; architecture=" + v, Applicability: NotApplicable, EvidenceKeys: keys}
		}
	}
	key := "account.credential_protection.credential-guard-runtime"
	o, ok := idx[key]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Credential Guard runtime evidence is unavailable", Applicability: Undetermined, EvidenceKeys: keys}
	}
	keys = appendUnique(keys, key)
	for _, supporting := range []string{
		"account.credential_protection.credential-guard-configured",
		"account.credential_protection.credential-guard-lsa-config",
		"account.credential_protection.virtualization-based-security",
	} {
		if _, ok := idx[supporting]; ok {
			keys = appendUnique(keys, supporting)
		}
	}
	sort.Strings(keys)
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: keys}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(o.Value)))
	switch value {
	case "RUNNING":
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "Credential Guard is running", Applicability: Applicable, EvidenceKeys: keys}
	case "NOT_RUNNING":
		return Evaluation{Status: StatusFail, Confidence: o.Confidence, ObservedState: "Credential Guard is not running", Applicability: Applicable, EvidenceKeys: keys}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized Credential Guard runtime state=" + value, Applicability: Applicable, EvidenceKeys: keys}
	}
}

func evaluateWindowsCachedLogons(idx Index) Evaluation {
	if e, ok := windowsCredentialProtectionApplicability(idx); ok {
		return e
	}
	domainKey := "account.credential_protection.domain-membership"
	domain, ok := idx[domainKey]
	if !ok || domain.State != evidence.StateObserved {
		keys := credentialProtectionProviderKeys(idx)
		if ok {
			keys = appendUnique(keys, domainKey)
		}
		sort.Strings(keys)
		if !ok {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Windows domain-membership evidence is unavailable", Applicability: Undetermined, EvidenceKeys: keys}
		}
		return Evaluation{Status: StatusUnknown, Confidence: domain.Confidence, ObservedState: observedText(domain), Applicability: Undetermined, EvidenceKeys: keys}
	}
	domainValue := strings.ToUpper(strings.TrimSpace(fmt.Sprint(domain.Value)))
	if domainValue == "WORKGROUP" {
		return Evaluation{Status: StatusPass, Confidence: domain.Confidence, ObservedState: "cached domain logon policy is not applicable to a workgroup host", Applicability: NotApplicable, EvidenceKeys: []string{domainKey}}
	}
	if domainValue != "DOMAIN_JOINED" {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized domain-membership state=" + domainValue, Applicability: Undetermined, EvidenceKeys: []string{domainKey}}
	}

	countKey := "account.credential_protection.cached-logons-count"
	countObs, ok := idx[countKey]
	keys := []string{domainKey}
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "CachedLogonsCount evidence is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	keys = append(keys, countKey)
	if countObs.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: countObs.Confidence, ObservedState: observedText(countObs), Applicability: Applicable, EvidenceKeys: keys}
	}
	value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(countObs.Value)))
	if !strings.HasPrefix(value, "COUNT_") {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "unrecognized cached-logon count=" + value, Applicability: Applicable, EvidenceKeys: keys}
	}
	count, err := strconv.Atoi(strings.TrimPrefix(value, "COUNT_"))
	if err != nil || count < 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "invalid cached-logon count=" + value, Applicability: Applicable, EvidenceKeys: keys}
	}
	switch {
	case count <= 2:
		return Evaluation{Status: StatusPass, Confidence: countObs.Confidence, ObservedState: fmt.Sprintf("CachedLogonsCount=%d", count), Applicability: Applicable, EvidenceKeys: keys}
	case count <= 10:
		return Evaluation{Status: StatusWarn, Confidence: countObs.Confidence, ObservedState: fmt.Sprintf("CachedLogonsCount=%d; operationally common but broader than the hardened 0-2 target", count), Applicability: Applicable, EvidenceKeys: keys}
	default:
		return Evaluation{Status: StatusFail, Confidence: countObs.Confidence, ObservedState: fmt.Sprintf("CachedLogonsCount=%d", count), Applicability: Applicable, EvidenceKeys: keys}
	}
}

func windowsCredentialProtectionApplicability(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "windows" {
		keys := credentialProtectionProviderKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Windows credential-protection assessment is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	return Evaluation{}, false
}

func credentialProtectionProviderKeys(idx Index) []string {
	keys := make([]string, 0, 3)
	for _, key := range []string{"account.platform", "account.architecture", "account.credential_protection.provider"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

package accounts

import "github.com/Nikolov999/chimera/internal/evidence"

// windowsSecurityPolicyDefault returns only defaults that are deterministic for
// the Windows 11 local policy represented by these registry values. Controls
// whose effective state can be enabled by hardware/OS policy outside the value
// itself must not be inferred here.
func windowsSecurityPolicyDefault(id string) (int64, bool) {
	switch id {
	case "uac-enabled":
		return 1, true
	case "admin-consent-prompt":
		return 5, true
	case "secure-desktop-prompt":
		return 1, true
	case "builtin-admin-approval-mode":
		return 0, true
	case "remote-uac-filtering":
		return 0, true
	case "limit-blank-password-use":
		return 1, true
	case "everyone-includes-anonymous":
		return 0, true
	case "restrict-anonymous":
		return 0, true
	case "restrict-anonymous-sam":
		return 1, true
	case "force-guest":
		return 0, true
	default:
		return 0, false
	}
}

func windowsCredentialProtectionDefault(id string) (int64, bool) {
	switch id {
	case "wdigest-credential-caching":
		return 0, true
	case "cached-logons-count":
		return 10, true
	case "lm-hash-storage":
		return 1, true
	// Do not infer RunAsPPL or Credential Guard LsaCfgFlags from absence on
	// current Windows 11: their effective state can be established by modern
	// platform defaults/policy outside these registry values and is separately
	// corroborated by Device Guard runtime/configuration metadata.
	default:
		return 0, false
	}
}

func makeDefaultSecurityControl(id, name, source string, raw int64) SecurityControl {
	return SecurityControl{ID: id, Name: name, State: evidence.StateObserved, Value: normalizeDWORDPolicy(id, raw), Source: source + " (documented Windows default; registry value absent)", Confidence: evidence.ConfidenceHigh, Reason: "registry value absent; deterministic Windows default applied"}
}

func makeDefaultCredentialControl(id, name, source string, raw int64) SecurityControl {
	return SecurityControl{ID: id, Name: name, State: evidence.StateObserved, Value: normalizeCredentialProtectionValue(id, raw), Source: source + " (documented Windows default; registry value absent)", Confidence: evidence.ConfidenceHigh, Reason: "registry value absent; deterministic Windows default applied"}
}

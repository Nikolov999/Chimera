package accounts

import (
	"fmt"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func normalizeCredentialProtectionValue(id string, raw int64) string {
	switch id {
	case "lsa-protection-config", "credential-guard-lsa-config":
		switch raw {
		case 0:
			return "DISABLED"
		case 1:
			return "ENABLED_UEFI_LOCK"
		case 2:
			return "ENABLED_WITHOUT_UEFI_LOCK"
		}
	case "credential-guard-runtime":
		if raw == 0 {
			return "NOT_RUNNING"
		}
		if raw == 1 {
			return "RUNNING"
		}
	case "credential-guard-configured":
		if raw == 0 {
			return "NOT_CONFIGURED"
		}
		if raw == 1 {
			return "CONFIGURED"
		}
	case "virtualization-based-security":
		switch raw {
		case 0:
			return "DISABLED"
		case 1:
			return "ENABLED_NOT_RUNNING"
		case 2:
			return "RUNNING"
		}
	case "wdigest-credential-caching":
		if raw == 0 {
			return "DISABLED"
		}
		if raw == 1 {
			return "ENABLED"
		}
	case "lm-hash-storage":
		// NoLMHash=1 means Windows does not create/store the legacy LM hash on
		// the next password change. The normalized value describes the risky
		// behavior rather than the registry value itself.
		if raw == 1 {
			return "DISABLED"
		}
		if raw == 0 {
			return "ENABLED"
		}
	case "domain-membership":
		if raw == 1 {
			return "DOMAIN_JOINED"
		}
		if raw == 0 {
			return "WORKGROUP"
		}
	case "cached-logons-count":
		if raw >= 0 {
			return fmt.Sprintf("COUNT_%d", raw)
		}
	}
	return fmt.Sprintf("VALUE_%d", raw)
}

func makeObservedCredentialControl(id, name, source string, raw int64) SecurityControl {
	return SecurityControl{
		ID:         id,
		Name:       name,
		State:      evidence.StateObserved,
		Value:      normalizeCredentialProtectionValue(id, raw),
		Source:     source,
		Confidence: evidence.ConfidenceExact,
	}
}

func makeUnavailableCredentialControl(id, name, source, reason string, state evidence.State) SecurityControl {
	if state == "" || state == evidence.StateObserved {
		state = evidence.StateUnavailable
	}
	return SecurityControl{
		ID:         id,
		Name:       name,
		State:      state,
		Source:     source,
		Confidence: evidence.ConfidenceLow,
		Reason:     strings.TrimSpace(reason),
	}
}

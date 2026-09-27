package accounts

import (
	"fmt"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func normalizeDWORDPolicy(id string, raw int64) string {
	switch id {
	case "uac-enabled", "secure-desktop-prompt", "builtin-admin-approval-mode", "limit-blank-password-use", "restrict-anonymous-sam", "force-guest":
		if raw == 0 {
			return "DISABLED"
		}
		if raw == 1 {
			return "ENABLED"
		}
	case "remote-uac-filtering":
		// LocalAccountTokenFilterPolicy=1 disables the normal remote UAC token
		// filtering behavior for local administrator accounts.
		if raw == 0 {
			return "ENABLED"
		}
		if raw == 1 {
			return "DISABLED"
		}
	case "everyone-includes-anonymous":
		if raw == 0 {
			return "DISABLED"
		}
		if raw == 1 {
			return "ENABLED"
		}
	case "admin-consent-prompt":
		switch raw {
		case 0:
			return "ELEVATE_WITHOUT_PROMPTING"
		case 1:
			return "PROMPT_CREDENTIALS_SECURE_DESKTOP"
		case 2:
			return "PROMPT_CONSENT_SECURE_DESKTOP"
		case 3:
			return "PROMPT_CREDENTIALS"
		case 4:
			return "PROMPT_CONSENT"
		case 5:
			return "PROMPT_CONSENT_NON_WINDOWS_BINARIES"
		}
	case "restrict-anonymous":
		switch raw {
		case 0:
			return "NONE"
		case 1:
			return "NO_SAM_ACCOUNT_ENUMERATION"
		case 2:
			return "NO_ACCESS_WITHOUT_EXPLICIT_ANONYMOUS_PERMISSIONS"
		}
	}
	return fmt.Sprintf("VALUE_%d", raw)
}

func makeObservedSecurityControl(id, name, source string, raw int64) SecurityControl {
	return SecurityControl{
		ID:         id,
		Name:       name,
		State:      evidence.StateObserved,
		Value:      normalizeDWORDPolicy(id, raw),
		Source:     source,
		Confidence: evidence.ConfidenceExact,
	}
}

func makeUnavailableSecurityControl(id, name, source, reason string, state evidence.State) SecurityControl {
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

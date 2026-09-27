package kernel

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SecureBootEnabled  = "ENABLED"
	SecureBootDisabled = "DISABLED"
	SecureBootUnknown  = "UNKNOWN"
)

func observedSecureBoot(enabled bool, mode, provider, source string, confidence evidence.Confidence) SecureBootAssessment {
	state := SecureBootDisabled
	if enabled {
		state = SecureBootEnabled
	}
	v := enabled
	return SecureBootAssessment{
		CollectionState: evidence.StateObserved,
		State:           state,
		Enabled:         &v,
		Mode:            strings.TrimSpace(mode),
		Provider:        strings.TrimSpace(provider),
		Source:          strings.TrimSpace(source),
		Confidence:      confidence,
	}
}

func unavailableSecureBoot(state evidence.State, provider, source, reason string, confidence evidence.Confidence) SecureBootAssessment {
	return SecureBootAssessment{
		CollectionState: state,
		State:           string(state),
		Provider:        strings.TrimSpace(provider),
		Source:          strings.TrimSpace(source),
		Confidence:      confidence,
		Reason:          strings.TrimSpace(reason),
	}
}

func boolFromSecureBootText(text string) (bool, bool) {
	v := strings.ToLower(strings.TrimSpace(text))
	switch {
	case v == "1", v == "true", v == "enabled", strings.Contains(v, "secureboot enabled"), strings.Contains(v, "secure boot enabled"):
		return true, true
	case v == "0", v == "false", v == "disabled", strings.Contains(v, "secureboot disabled"), strings.Contains(v, "secure boot disabled"):
		return false, true
	default:
		return false, false
	}
}

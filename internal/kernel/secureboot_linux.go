//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSecureBoot(ctx context.Context, k Inventory) SecureBootAssessment {
	const provider = "Linux UEFI SecureBoot variable"
	if strings.EqualFold(k.BootMode, "legacy-or-unreported") || !pathExists("/sys/firmware/efi") {
		return unavailableSecureBoot(evidence.StateNotApplicable, provider, "/sys/firmware/efi", "host is not exposing a UEFI boot environment; UEFI Secure Boot is not applicable to the observed boot mode", evidence.ConfidenceHigh)
	}

	matches, err := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if err != nil {
		return unavailableSecureBoot(evidence.StateDegraded, provider, "/sys/firmware/efi/efivars", "could not enumerate the UEFI SecureBoot variable: "+err.Error(), evidence.ConfidenceLow)
	}
	for _, path := range matches {
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			if errors.Is(readErr, os.ErrPermission) {
				if viaMok, ok := secureBootViaMokutil(ctx); ok {
					return viaMok
				}
				return unavailableSecureBoot(evidence.StateDenied, provider, path, "permission denied while reading the UEFI SecureBoot variable", evidence.ConfidenceHigh)
			}
			continue
		}
		// Linux efivarfs prepends the four-byte UEFI variable attributes field;
		// the SecureBoot payload is the following UINT8 value.
		if len(b) < 5 {
			return unavailableSecureBoot(evidence.StateDegraded, provider, path, fmt.Sprintf("UEFI SecureBoot variable had unexpected length %d", len(b)), evidence.ConfidenceLow)
		}
		switch b[4] {
		case 0:
			return observedSecureBoot(false, "UEFI", provider, path, evidence.ConfidenceExact)
		case 1:
			return observedSecureBoot(true, "UEFI", provider, path, evidence.ConfidenceExact)
		default:
			return unavailableSecureBoot(evidence.StateDegraded, provider, path, fmt.Sprintf("UEFI SecureBoot variable contained unexpected value %d", b[4]), evidence.ConfidenceLow)
		}
	}

	if viaMok, ok := secureBootViaMokutil(ctx); ok {
		return viaMok
	}
	if !pathExists("/sys/firmware/efi/efivars") {
		return unavailableSecureBoot(evidence.StateUnavailable, provider, "/sys/firmware/efi/efivars", "UEFI boot was observed but efivarfs is not available, so Secure Boot state cannot be read locally", evidence.ConfidenceMedium)
	}
	return unavailableSecureBoot(evidence.StateUnavailable, provider, "/sys/firmware/efi/efivars/SecureBoot-*", "UEFI boot was observed but no readable SecureBoot variable was found", evidence.ConfidenceMedium)
}

func secureBootViaMokutil(ctx context.Context) (SecureBootAssessment, bool) {
	if !commandAvailable("mokutil") {
		return SecureBootAssessment{}, false
	}
	out, err := run(ctx, "mokutil", "--sb-state")
	if err != nil {
		return SecureBootAssessment{}, false
	}
	if enabled, ok := boolFromSecureBootText(out); ok {
		return observedSecureBoot(enabled, "UEFI", "mokutil", "mokutil --sb-state", evidence.ConfidenceHigh), true
	}
	return unavailableSecureBoot(evidence.StateDegraded, "mokutil", "mokutil --sb-state", "provider returned an unrecognized Secure Boot state", evidence.ConfidenceLow), true
}

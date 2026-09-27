//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMemoryMitigations(ctx context.Context, _ Inventory) []MitigationAssessment {
	_ = ctx
	out := []MitigationAssessment{
		collectLinuxASLR(),
		collectLinuxMmapMinAddr(),
	}
	if m := collectLinuxEntropyBits("linux.mmap_rnd_bits", "Linux mmap ASLR entropy", "/proc/sys/vm/mmap_rnd_bits"); m.ID != "" {
		out = append(out, m)
	}
	if m := collectLinuxEntropyBits("linux.mmap_rnd_compat_bits", "Linux compat mmap ASLR entropy", "/proc/sys/vm/mmap_rnd_compat_bits"); m.ID != "" {
		out = append(out, m)
	}
	return out
}

func collectLinuxASLR() MitigationAssessment {
	const id = "linux.aslr"
	const name = "Linux address-space layout randomization"
	const provider = "Linux kernel randomize_va_space policy"
	const source = "/proc/sys/kernel/randomize_va_space"
	b, err := os.ReadFile(source)
	if err != nil {
		return linuxMitigationReadFailure(id, name, provider, source, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return unavailableMitigation(id, name, evidence.StateDegraded, provider, source, "ASLR provider returned a non-numeric value", evidence.ConfidenceLow)
	}
	switch v {
	case 0:
		return observedMitigation(id, name, "DISABLED", "randomize_va_space=0", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 1:
		return observedMitigation(id, name, "PARTIAL", "randomize_va_space=1 (conservative randomization)", provider, source, boolPtr(true), evidence.ConfidenceExact)
	case 2:
		return observedMitigation(id, name, "FULL", "randomize_va_space=2 (full randomization)", provider, source, boolPtr(true), evidence.ConfidenceExact)
	default:
		return unavailableMitigation(id, name, evidence.StateDegraded, provider, source, fmt.Sprintf("ASLR provider returned unrecognized value %d", v), evidence.ConfidenceLow)
	}
}

func collectLinuxMmapMinAddr() MitigationAssessment {
	const id = "linux.mmap_min_addr"
	const name = "Linux low-address mmap protection"
	const provider = "Linux vm.mmap_min_addr policy"
	const source = "/proc/sys/vm/mmap_min_addr"
	b, err := os.ReadFile(source)
	if err != nil {
		return linuxMitigationReadFailure(id, name, provider, source, err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return unavailableMitigation(id, name, evidence.StateDegraded, provider, source, "mmap_min_addr provider returned a non-numeric value", evidence.ConfidenceLow)
	}
	if v == 0 {
		return observedMitigation(id, name, "DISABLED", "mmap_min_addr=0", provider, source, boolPtr(false), evidence.ConfidenceExact)
	}
	return observedMitigation(id, name, "ENABLED", fmt.Sprintf("mmap_min_addr=%d bytes", v), provider, source, boolPtr(true), evidence.ConfidenceExact)
}

func collectLinuxEntropyBits(id, name, source string) MitigationAssessment {
	const provider = "Linux mmap ASLR entropy policy"
	b, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unavailableMitigation(id, name, evidence.StateNotApplicable, provider, source, "this architecture/kernel does not expose the entropy control", evidence.ConfidenceHigh)
		}
		return linuxMitigationReadFailure(id, name, provider, source, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < 0 {
		return unavailableMitigation(id, name, evidence.StateDegraded, provider, source, "ASLR entropy provider returned an invalid value", evidence.ConfidenceLow)
	}
	return observedMitigation(id, name, "CONFIGURED", fmt.Sprintf("%d bits", v), provider, source, nil, evidence.ConfidenceExact)
}

func linuxMitigationReadFailure(id, name, provider, source string, err error) MitigationAssessment {
	if errors.Is(err, os.ErrPermission) {
		return unavailableMitigation(id, name, evidence.StateDenied, provider, source, "permission denied while reading mitigation state", evidence.ConfidenceHigh)
	}
	if errors.Is(err, os.ErrNotExist) {
		return unavailableMitigation(id, name, evidence.StateUnsupported, provider, source, "running kernel does not expose this mitigation provider", evidence.ConfidenceHigh)
	}
	return unavailableMitigation(id, name, evidence.StateUnavailable, provider, source, "mitigation state could not be read: "+err.Error(), evidence.ConfidenceLow)
}

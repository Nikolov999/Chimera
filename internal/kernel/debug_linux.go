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

func collectDebugExposure(ctx context.Context, _ Inventory) []DebugExposureAssessment {
	_ = ctx
	return []DebugExposureAssessment{
		collectLinuxKptrRestrict(),
		collectLinuxDmesgRestrict(),
		collectLinuxPtraceScope(),
	}
}

func collectLinuxKptrRestrict() DebugExposureAssessment {
	const id = "linux.kptr_restrict"
	const name = "Linux kernel pointer exposure"
	const provider = "Linux kernel.kptr_restrict policy"
	const source = "/proc/sys/kernel/kptr_restrict"
	v, err := readLinuxDebugInteger(source)
	if err != nil {
		return linuxDebugReadFailure(id, name, provider, source, err)
	}
	switch v {
	case 0:
		return observedDebugExposure(id, name, "EXPOSED", "kptr_restrict=0 (kernel pointers broadly available subject to file permissions)", provider, source, boolPtr(true), evidence.ConfidenceExact)
	case 1:
		return observedDebugExposure(id, name, "RESTRICTED", "kptr_restrict=1 (pointer formatting restricted by privilege/context)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 2:
		return observedDebugExposure(id, name, "HIDDEN", "kptr_restrict=2 (kernel pointers hidden regardless of privilege for affected interfaces)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	default:
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, fmt.Sprintf("kernel.kptr_restrict returned unrecognized value %d", v), evidence.ConfidenceLow)
	}
}

func collectLinuxDmesgRestrict() DebugExposureAssessment {
	const id = "linux.dmesg_restrict"
	const name = "Linux kernel log access"
	const provider = "Linux kernel.dmesg_restrict policy"
	const source = "/proc/sys/kernel/dmesg_restrict"
	v, err := readLinuxDebugInteger(source)
	if err != nil {
		return linuxDebugReadFailure(id, name, provider, source, err)
	}
	switch v {
	case 0:
		return observedDebugExposure(id, name, "UNRESTRICTED", "dmesg_restrict=0 (kernel log access is not gated by this sysctl)", provider, source, boolPtr(true), evidence.ConfidenceExact)
	case 1:
		return observedDebugExposure(id, name, "RESTRICTED", "dmesg_restrict=1 (kernel log access requires the relevant privilege)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	default:
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, fmt.Sprintf("kernel.dmesg_restrict returned unrecognized value %d", v), evidence.ConfidenceLow)
	}
}

func collectLinuxPtraceScope() DebugExposureAssessment {
	const id = "linux.ptrace_scope"
	const name = "Linux ptrace process-debugging scope"
	const provider = "Yama ptrace_scope policy"
	const source = "/proc/sys/kernel/yama/ptrace_scope"
	v, err := readLinuxDebugInteger(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unavailableDebugExposure(id, name, evidence.StateNotApplicable, provider, source, "Yama ptrace_scope is not exposed by this running kernel", evidence.ConfidenceHigh)
		}
		return linuxDebugReadFailure(id, name, provider, source, err)
	}
	switch v {
	case 0:
		return observedDebugExposure(id, name, "CLASSIC", "ptrace_scope=0 (same-UID attach follows classic ptrace permissions)", provider, source, boolPtr(true), evidence.ConfidenceExact)
	case 1:
		return observedDebugExposure(id, name, "RESTRICTED", "ptrace_scope=1 (attach restricted to descendants or explicitly permitted tracers)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 2:
		return observedDebugExposure(id, name, "ADMIN_ONLY", "ptrace_scope=2 (attach requires administrative ptrace privilege)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 3:
		return observedDebugExposure(id, name, "NO_ATTACH", "ptrace_scope=3 (ptrace attach disabled)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	default:
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, fmt.Sprintf("Yama ptrace_scope returned unrecognized value %d", v), evidence.ConfidenceLow)
	}
}

func readLinuxDebugInteger(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func linuxDebugReadFailure(id, name, provider, source string, err error) DebugExposureAssessment {
	if errors.Is(err, os.ErrPermission) {
		return unavailableDebugExposure(id, name, evidence.StateDenied, provider, source, "permission denied while reading debug-exposure policy", evidence.ConfidenceHigh)
	}
	if errors.Is(err, os.ErrNotExist) {
		return unavailableDebugExposure(id, name, evidence.StateUnsupported, provider, source, "running kernel does not expose this debug-exposure provider", evidence.ConfidenceHigh)
	}
	if _, ok := err.(*strconv.NumError); ok {
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, "debug-exposure provider returned a non-numeric value", evidence.ConfidenceLow)
	}
	return unavailableDebugExposure(id, name, evidence.StateUnavailable, provider, source, "debug-exposure policy could not be read: "+err.Error(), evidence.ConfidenceLow)
}

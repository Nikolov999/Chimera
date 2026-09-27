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

func collectUnprivilegedFeatures(ctx context.Context, _ Inventory) []UnprivilegedFeatureAssessment {
	_ = ctx
	return []UnprivilegedFeatureAssessment{
		collectLinuxUnprivilegedBPF(),
		collectLinuxUnprivilegedUserNamespaces(),
		collectLinuxUserNamespaceLimit(),
		collectLinuxPerfEventPolicy(),
		collectLinuxUnprivilegedUserfaultfd(),
	}
}

func collectLinuxUnprivilegedBPF() UnprivilegedFeatureAssessment {
	const id = "linux.unprivileged_bpf"
	const name = "Linux unprivileged BPF"
	const provider = "Linux kernel.unprivileged_bpf_disabled policy"
	const source = "/proc/sys/kernel/unprivileged_bpf_disabled"
	v, err := readLinuxUnprivilegedInteger(source)
	if err != nil {
		return linuxUnprivilegedReadFailure(id, name, provider, source, err, false)
	}
	state, mode, exposed, ok := interpretUnprivilegedBPF(v)
	if !ok {
		return unavailableUnprivilegedFeature(id, name, evidence.StateDegraded, provider, source, "unprivileged BPF policy returned an unrecognized value: "+mode, evidence.ConfidenceLow)
	}
	return observedUnprivilegedFeature(id, name, state, mode, provider, source, exposed, evidence.ConfidenceExact)
}

func collectLinuxUnprivilegedUserNamespaces() UnprivilegedFeatureAssessment {
	const id = "linux.unprivileged_userns_clone"
	const name = "Linux unprivileged user-namespace creation"
	const provider = "Linux kernel.unprivileged_userns_clone policy"
	const source = "/proc/sys/kernel/unprivileged_userns_clone"
	v, err := readLinuxUnprivilegedInteger(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unavailableUnprivilegedFeature(id, name, evidence.StateNotApplicable, provider, source, "this running kernel does not expose the distribution-specific unprivileged_userns_clone policy; max_user_namespaces is reported separately", evidence.ConfidenceHigh)
		}
		return linuxUnprivilegedReadFailure(id, name, provider, source, err, true)
	}
	state, mode, exposed, ok := interpretBinaryExposure("unprivileged_userns_clone", v)
	if !ok {
		return unavailableUnprivilegedFeature(id, name, evidence.StateDegraded, provider, source, "unprivileged user-namespace policy returned an unrecognized value: "+mode, evidence.ConfidenceLow)
	}
	return observedUnprivilegedFeature(id, name, state, mode, provider, source, exposed, evidence.ConfidenceExact)
}

func collectLinuxUserNamespaceLimit() UnprivilegedFeatureAssessment {
	const id = "linux.user_namespace_limit"
	const name = "Linux user-namespace capacity"
	const provider = "Linux user.max_user_namespaces policy"
	const source = "/proc/sys/user/max_user_namespaces"
	v, err := readLinuxUnprivilegedInteger(source)
	if err != nil {
		return linuxUnprivilegedReadFailure(id, name, provider, source, err, false)
	}
	state, mode, exposed := interpretNamespaceLimit(v)
	return observedUnprivilegedFeature(id, name, state, mode, provider, source, exposed, evidence.ConfidenceExact)
}

func collectLinuxPerfEventPolicy() UnprivilegedFeatureAssessment {
	const id = "linux.perf_event_paranoid"
	const name = "Linux unprivileged performance-event access"
	const provider = "Linux kernel.perf_event_paranoid policy"
	const source = "/proc/sys/kernel/perf_event_paranoid"
	v, err := readLinuxUnprivilegedInteger(source)
	if err != nil {
		return linuxUnprivilegedReadFailure(id, name, provider, source, err, false)
	}
	state, mode, exposed := interpretPerfEventParanoid(v)
	return observedUnprivilegedFeature(id, name, state, mode, provider, source, exposed, evidence.ConfidenceExact)
}

func collectLinuxUnprivilegedUserfaultfd() UnprivilegedFeatureAssessment {
	const id = "linux.unprivileged_userfaultfd"
	const name = "Linux unprivileged userfaultfd kernel-fault handling"
	const provider = "Linux vm.unprivileged_userfaultfd policy"
	const source = "/proc/sys/vm/unprivileged_userfaultfd"
	v, err := readLinuxUnprivilegedInteger(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unavailableUnprivilegedFeature(id, name, evidence.StateUnsupported, provider, source, "running kernel does not expose vm.unprivileged_userfaultfd", evidence.ConfidenceHigh)
		}
		return linuxUnprivilegedReadFailure(id, name, provider, source, err, true)
	}
	switch v {
	case 0:
		return observedUnprivilegedFeature(id, name, "KERNEL_FAULTS_RESTRICTED", "unprivileged_userfaultfd=0 (unprivileged kernel-fault handling is restricted; user-mode-only userfaultfd may still be available)", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 1:
		return observedUnprivilegedFeature(id, name, "UNPRIVILEGED_KERNEL_FAULTS_ALLOWED", "unprivileged_userfaultfd=1", provider, source, boolPtr(true), evidence.ConfidenceExact)
	default:
		return unavailableUnprivilegedFeature(id, name, evidence.StateDegraded, provider, source, fmt.Sprintf("vm.unprivileged_userfaultfd returned unrecognized value %d", v), evidence.ConfidenceLow)
	}
}

func readLinuxUnprivilegedInteger(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func linuxUnprivilegedReadFailure(id, name, provider, source string, err error, missingNotApplicable bool) UnprivilegedFeatureAssessment {
	if errors.Is(err, os.ErrPermission) {
		return unavailableUnprivilegedFeature(id, name, evidence.StateDenied, provider, source, "permission denied while reading unprivileged-kernel-feature policy", evidence.ConfidenceHigh)
	}
	if errors.Is(err, os.ErrNotExist) {
		state := evidence.StateUnsupported
		reason := "running kernel does not expose this unprivileged-kernel-feature provider"
		if missingNotApplicable {
			state = evidence.StateNotApplicable
			reason = "this optional kernel/distribution policy interface is not present"
		}
		return unavailableUnprivilegedFeature(id, name, state, provider, source, reason, evidence.ConfidenceHigh)
	}
	if _, ok := err.(*strconv.NumError); ok {
		return unavailableUnprivilegedFeature(id, name, evidence.StateDegraded, provider, source, "unprivileged-kernel-feature provider returned a non-numeric value", evidence.ConfidenceLow)
	}
	return unavailableUnprivilegedFeature(id, name, evidence.StateUnavailable, provider, source, "unprivileged-kernel-feature policy could not be read: "+err.Error(), evidence.ConfidenceLow)
}

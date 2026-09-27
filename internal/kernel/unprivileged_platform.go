package kernel

import "github.com/Nikolov999/chimera/internal/evidence"

func phase015PlatformNotApplicable(platform string) []UnprivilegedFeatureAssessment {
	defs := []struct {
		id, name, source string
	}{
		{"linux.unprivileged_bpf", "Linux unprivileged BPF", "/proc/sys/kernel/unprivileged_bpf_disabled"},
		{"linux.unprivileged_userns_clone", "Linux unprivileged user-namespace creation", "/proc/sys/kernel/unprivileged_userns_clone"},
		{"linux.user_namespace_limit", "Linux user-namespace capacity", "/proc/sys/user/max_user_namespaces"},
		{"linux.perf_event_paranoid", "Linux unprivileged performance-event access", "/proc/sys/kernel/perf_event_paranoid"},
		{"linux.unprivileged_userfaultfd", "Linux unprivileged userfaultfd kernel-fault handling", "/proc/sys/vm/unprivileged_userfaultfd"},
	}
	out := make([]UnprivilegedFeatureAssessment, 0, len(defs))
	for _, d := range defs {
		out = append(out, unavailableUnprivilegedFeature(d.id, d.name, evidence.StateNotApplicable, "platform applicability", d.source, "Linux kernel feature is not applicable on "+platform+"; Chimera does not invent a platform equivalent", evidence.ConfidenceExact))
	}
	return out
}

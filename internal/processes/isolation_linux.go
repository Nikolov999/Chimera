//go:build linux

package processes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

var linuxIsolationNamespaces = []string{"pid", "mnt", "net", "user", "uts", "ipc", "cgroup", "time"}

func collectIsolationPlatform(ctx context.Context, items []Process) ([]IsolationContext, isolationProviderStats) {
	stats := isolationProviderStats{ID: "linux-process-isolation", State: evidence.StateObserved, Source: "/proc/<pid> namespace/status/cgroup/LSM metadata"}
	baseline := linuxNamespaceLinks("/proc/1/ns")
	if len(baseline) == 0 {
		baseline = linuxNamespaceLinks("/proc/self/ns")
	}
	out := make([]IsolationContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c, err := readLinuxIsolationContext(p.PID, baseline)
		if err != nil {
			c = IsolationContext{PID: p.PID, Platform: "linux", State: "UNKNOWN", IsolationState: "UNKNOWN", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "/proc/<pid> isolation metadata", Confidence: evidence.ConfidenceLow, Reason: err.Error()}
			if linuxProcessLifecycleGone(err) {
				// The base process snapshot is intentionally point-in-time while this
				// secondary view is collected concurrently. A PID that exits before its
				// namespace/status/cgroup metadata is read remains explicit UNKNOWN
				// evidence, but is not a provider-health failure.
				c.Source = "Linux procfs lifecycle-aware isolation metadata"
				c.Confidence = evidence.ConfidenceExact
				c.Reason = "process exited before isolation enrichment completed"
				stats.Count++
			} else if errors.Is(err, os.ErrPermission) {
				c.State = "DENIED"
				stats.Denied++
			} else {
				stats.Missing++
			}
		} else {
			stats.Count++
		}
		out = append(out, c)
	}
	if stats.Count == 0 && stats.Denied > 0 {
		stats.State = evidence.StateDenied
	} else if stats.Count == 0 && stats.Missing > 0 {
		stats.State = evidence.StateUnavailable
	} else if stats.Denied > 0 || stats.Missing > 0 {
		stats.State = evidence.StateDegraded
	}
	return out, stats
}

func readLinuxIsolationContext(pid int, baseline map[string]string) (IsolationContext, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	st, statusErr := readLinuxStatus(filepath.Join(base, "status"))
	cur := linuxNamespaceLinks(filepath.Join(base, "ns"))
	if statusErr != nil && len(cur) == 0 {
		return IsolationContext{}, statusErr
	}

	c := IsolationContext{PID: pid, Platform: "linux", State: "OBSERVED", IsolationState: "HOST", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "/proc/<pid> namespace/status/cgroup/LSM metadata", Confidence: evidence.ConfidenceHigh}
	c.PIDNamespace = linuxNamespaceDiffers(cur, baseline, "pid")
	c.MountNamespace = linuxNamespaceDiffers(cur, baseline, "mnt")
	c.NetworkNamespace = linuxNamespaceDiffers(cur, baseline, "net")
	c.UserNamespace = linuxNamespaceDiffers(cur, baseline, "user")
	c.UTSNamespace = linuxNamespaceDiffers(cur, baseline, "uts")
	c.IPCNamespace = linuxNamespaceDiffers(cur, baseline, "ipc")
	c.CgroupNamespace = linuxNamespaceDiffers(cur, baseline, "cgroup")
	c.TimeNamespace = linuxNamespaceDiffers(cur, baseline, "time")
	c.NamespaceCount = countIsolationNamespaces(c)
	c.NestedPIDNamespace = len(st.nspid) > 1
	c.Seccomp = seccompName(st.seccomp)
	c.NoNewPrivileges = st.noNewPrivs

	cgroup, scoped, runtimeName, containerHint, cgroupErr := linuxCgroupIsolation(filepath.Join(base, "cgroup"))
	c.Cgroup, c.CgroupScoped, c.ContainerRuntime, c.ContainerHint = cgroup, scoped, runtimeName, containerHint

	lsm, sandbox, sandboxBasis, lsmErr := linuxLSMIsolation(filepath.Join(base, "attr", "current"))
	c.LSMProfile, c.Sandbox, c.SandboxBasis = lsm, sandbox, sandboxBasis

	signals := []string{}
	if c.PIDNamespace {
		signals = append(signals, "pid-namespace")
	}
	if c.MountNamespace {
		signals = append(signals, "mount-namespace")
	}
	if c.NetworkNamespace {
		signals = append(signals, "network-namespace")
	}
	if c.UserNamespace {
		signals = append(signals, "user-namespace")
	}
	if c.UTSNamespace {
		signals = append(signals, "uts-namespace")
	}
	if c.IPCNamespace {
		signals = append(signals, "ipc-namespace")
	}
	if c.CgroupNamespace {
		signals = append(signals, "cgroup-namespace")
	}
	if c.TimeNamespace {
		signals = append(signals, "time-namespace")
	}
	if c.NestedPIDNamespace {
		signals = append(signals, "nested-pid-namespace")
	}
	if c.Seccomp == "FILTER" || c.Seccomp == "STRICT" {
		signals = append(signals, "seccomp-"+strings.ToLower(c.Seccomp))
	}
	if c.NoNewPrivileges {
		signals = append(signals, "no-new-privileges")
	}
	if c.CgroupScoped {
		signals = append(signals, "cgroup-scoped")
	}
	if c.ContainerHint {
		signals = append(signals, "container-context")
	}
	if c.Sandbox == "PROFILED" || c.Sandbox == "ENFORCED" {
		signals = append(signals, "lsm-profiled")
	}
	c.Signals = normalizedList(signals)

	switch {
	case c.ContainerHint || c.NestedPIDNamespace || c.NamespaceCount >= 2:
		c.IsolationState = "ISOLATED"
	case c.NamespaceCount == 1 || c.NoNewPrivileges || c.Seccomp == "FILTER" || c.Seccomp == "STRICT" || c.Sandbox == "PROFILED" || c.Sandbox == "ENFORCED":
		c.IsolationState = "PARTIAL"
	default:
		c.IsolationState = "HOST"
	}

	reasons := []string{}
	if statusErr != nil {
		reasons = append(reasons, "status metadata: "+statusErr.Error())
	}
	if cgroupErr != nil {
		reasons = append(reasons, "cgroup metadata: "+cgroupErr.Error())
	}
	if lsmErr != nil && !errors.Is(lsmErr, os.ErrNotExist) {
		reasons = append(reasons, "LSM profile metadata: "+lsmErr.Error())
	}
	if len(cur) == 0 {
		reasons = append(reasons, "namespace links unavailable")
	}
	if len(reasons) > 0 {
		c.State = "DEGRADED"
		c.Confidence = evidence.ConfidenceMedium
		c.Reason = strings.Join(reasons, "; ")
	}
	return c, nil
}

func linuxNamespaceLinks(dir string) map[string]string {
	out := map[string]string{}
	for _, name := range linuxIsolationNamespaces {
		if v, err := os.Readlink(filepath.Join(dir, name)); err == nil {
			out[name] = v
		}
	}
	return out
}

func linuxNamespaceDiffers(cur, baseline map[string]string, name string) bool {
	return cur[name] != "" && baseline[name] != "" && cur[name] != baseline[name]
}

func linuxCgroupIsolation(path string) (raw string, scoped bool, runtimeName string, containerHint bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false, "", false, err
	}
	text := strings.TrimSpace(string(b))
	if len(text) > 8192 {
		text = text[:8192]
	}
	paths := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		p := strings.TrimSpace(parts[2])
		if p != "" {
			paths = append(paths, p)
		}
	}
	paths = normalizedList(paths)
	sort.Strings(paths)
	raw = strings.Join(paths, ";")
	low := strings.ToLower(raw)
	markers := []struct{ needle, runtime string }{
		{"kubepods", "kubernetes"}, {"docker", "docker"}, {"containerd", "containerd"}, {"libpod", "podman"}, {"podman", "podman"}, {"lxc", "lxc"}, {"machine.slice", "systemd-machine"},
	}
	for _, m := range markers {
		if strings.Contains(low, m.needle) {
			containerHint = true
			runtimeName = m.runtime
			break
		}
	}
	scoped = raw != "" && raw != "/"
	return raw, scoped, runtimeName, containerHint, nil
}

func linuxLSMIsolation(path string) (profile, sandbox, basis string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "UNKNOWN", "", err
	}
	profile = strings.TrimSpace(string(b))
	if len(profile) > 512 {
		profile = profile[:512]
	}
	low := strings.ToLower(profile)
	switch {
	case profile == "":
		return "", "UNKNOWN", "LSM profile metadata was empty", nil
	case strings.Contains(low, "unconfined"):
		return profile, "NONE", "LSM profile reports an unconfined process", nil
	case strings.Contains(low, "(enforce)") || strings.Contains(low, "docker-default") || strings.Contains(low, "lxc-"):
		return profile, "ENFORCED", "LSM profile metadata indicates an enforced confinement profile", nil
	default:
		return profile, "PROFILED", "LSM security context/profile is present; exact confinement semantics are provider-specific", nil
	}
}

package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const securityInspectBatch = 24

var dangerousCapabilitySet = map[string]struct{}{
	"ALL": {}, "SYS_ADMIN": {}, "SYS_MODULE": {}, "SYS_RAWIO": {},
	"SYS_PTRACE": {}, "SYS_BOOT": {}, "SYS_TIME": {}, "NET_ADMIN": {},
	"DAC_READ_SEARCH": {}, "SYSLOG": {}, "BPF": {}, "PERFMON": {},
	"CHECKPOINT_RESTORE": {}, "MAC_ADMIN": {}, "MAC_OVERRIDE": {},
	"AUDIT_CONTROL": {},
}

func runtimeRootlessState(ctx context.Context, r Runtime) string {
	switch r.Name {
	case "docker":
		if strings.HasPrefix(r.Endpoint, "/run/user/") {
			return "TRUE"
		}
		if r.Endpoint != "" {
			return "FALSE"
		}
	case "podman":
		if strings.HasPrefix(r.Endpoint, "/run/user/") {
			return "TRUE"
		}
		if state := podmanRootlessState(ctx, r); state != "UNKNOWN" {
			return state
		}
	}
	if strings.TrimSpace(r.RootlessState) != "" {
		return r.RootlessState
	}
	return "UNKNOWN"
}

// collectSecurityPosture performs metadata-only inspection through an already
// observed local runtime provider. It deliberately does not inspect a
// container filesystem, environment-variable values, mounted secret content,
// or any configured remote endpoint.
func collectSecurityPosture(ctx context.Context, r Runtime, instances []Container) ([]SecurityPosture, evidence.State, string) {
	if len(instances) == 0 {
		return nil, evidence.StateObserved, ""
	}
	items := append([]Container(nil), instances...)
	sort.Slice(items, func(i, j int) bool {
		return containerSortKey(items[i]) < containerSortKey(items[j])
	})
	truncated := false
	if len(items) > maxSecurity {
		items = items[:maxSecurity]
		truncated = true
	}

	switch r.Name {
	case "docker":
		return collectDockerSecurity(ctx, r, items, truncated)
	case "podman":
		return collectPodmanSecurity(ctx, r, items, truncated)
	case "containerd":
		return nil, evidence.StateUnavailable, "containerd instance metadata is observable, but the local ctr provider does not expose a stable OCI execution specification for existing containers"
	default:
		return nil, evidence.StateNotApplicable, "no security provider exists for runtime " + r.Name
	}
}

func collectDockerSecurity(ctx context.Context, r Runtime, items []Container, truncated bool) ([]SecurityPosture, evidence.State, string) {
	if r.BinaryPath == "" || r.Endpoint == "" {
		return nil, evidence.StateUnavailable, "Docker security inspection requires the observed local Docker CLI and engine endpoint"
	}
	defaultUserns := dockerDefaultUserNamespace(ctx, r)
	return collectInspectBatches(ctx, r, items, truncated, defaultUserns, func(batch []string) (string, error) {
		args := []string{"-H", dockerEndpoint(r.Endpoint, r.EndpointKind), "inspect"}
		args = append(args, batch...)
		return localCommand(ctx, 4500*time.Millisecond, r.BinaryPath, args...)
	})
}

func collectPodmanSecurity(ctx context.Context, r Runtime, items []Container, truncated bool) ([]SecurityPosture, evidence.State, string) {
	if r.BinaryPath == "" {
		return nil, evidence.StateUnavailable, "Podman security inspection requires the local Podman CLI"
	}
	if r.RootlessState == "UNKNOWN" {
		r.RootlessState = podmanRootlessState(ctx, r)
	}
	defaultUserns := "UNKNOWN"
	if r.RootlessState == "TRUE" {
		defaultUserns = "REMAPPED"
	} else if r.RootlessState == "FALSE" {
		defaultUserns = "HOST"
	}
	return collectInspectBatches(ctx, r, items, truncated, defaultUserns, func(batch []string) (string, error) {
		args := []string{"--remote=false", "container", "inspect"}
		args = append(args, batch...)
		return localCommandEnv(ctx, 4500*time.Millisecond, sanitizedContainerEnv(), r.BinaryPath, args...)
	})
}

func collectInspectBatches(ctx context.Context, r Runtime, items []Container, truncated bool, defaultUserns string, run func([]string) (string, error)) ([]SecurityPosture, evidence.State, string) {
	byID := make(map[string]Container, len(items))
	for _, c := range items {
		byID[c.RuntimeContainerID] = c
	}

	var out []SecurityPosture
	var reasons []string
	denied := false
	for start := 0; start < len(items); start += securityInspectBatch {
		end := start + securityInspectBatch
		if end > len(items) {
			end = len(items)
		}
		ids := make([]string, 0, end-start)
		for _, c := range items[start:end] {
			ids = append(ids, c.RuntimeContainerID)
		}
		raw, err := run(ids)
		if err != nil {
			reasons = append(reasons, shortErr(err))
			if classifyAccess(err) == "DENIED" {
				denied = true
				break
			}
			continue
		}
		recs, err := parseRuntimeInspect(r.Name, raw, defaultUserns)
		if err != nil {
			reasons = append(reasons, shortErr(err))
			continue
		}
		if len(recs) != len(ids) {
			reasons = append(reasons, fmt.Sprintf("runtime returned %d security records for %d requested containers", len(recs), len(ids)))
		}
		for i := range recs {
			if src, ok := byID[recs[i].RuntimeContainerID]; ok {
				recs[i].Namespace = src.Namespace
				if recs[i].Name == "" {
					recs[i].Name = src.Name
				}
			}
		}
		out = append(out, recs...)
	}
	if truncated {
		reasons = append(reasons, fmt.Sprintf("security inspection bounded to %d of %d-or-more local containers", maxSecurity, maxSecurity+1))
	}
	if len(reasons) == 0 {
		return out, evidence.StateObserved, ""
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if denied && len(out) == 0 {
		return out, evidence.StateDenied, reason
	}
	return out, evidence.StateUnavailable, reason
}

func parseRuntimeInspect(runtimeName, raw, defaultUserns string) ([]SecurityPosture, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty %s inspect output", runtimeName)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		var one map[string]any
		if oneErr := json.Unmarshal([]byte(raw), &one); oneErr != nil {
			return nil, fmt.Errorf("parse %s inspect output: %w", runtimeName, err)
		}
		arr = []map[string]any{one}
	}
	out := make([]SecurityPosture, 0, len(arr))
	for _, m := range arr {
		id := firstString(m, "Id", "ID", "id")
		if id == "" {
			continue
		}
		host := nestedMap(m, "HostConfig")
		cfg := nestedMap(m, "Config")
		privileged, privilegedOK := boolField(host, "Privileged", "privileged")
		privilegedState := "UNKNOWN"
		if privilegedOK {
			if privileged {
				privilegedState = "TRUE"
			} else {
				privilegedState = "FALSE"
			}
		}
		user, userOK := stringField(cfg, "User", "user")
		rootState := configuredRootState(user, userOK)
		pidMode, pidOK := stringField(host, "PidMode", "PIDMode", "pid_mode")
		netMode, netOK := stringField(host, "NetworkMode", "network_mode")
		usernsMode, usernsOK := stringField(host, "UsernsMode", "UserNSMode", "userns_mode")
		pidNS := namespaceMode(pidMode, pidOK, "PRIVATE")
		netNS := networkNamespaceMode(netMode, netOK)
		userNS := userNamespaceMode(usernsMode, usernsOK, defaultUserns)

		capAdd, capOK := stringSliceField(host, "CapAdd", "cap_add")
		capDrop, capDropOK := stringSliceField(host, "CapDrop", "cap_drop")
		capAdd = normalizeStringSet(capAdd)
		capDrop = normalizeStringSet(capDrop)
		capState := "UNKNOWN"
		if capOK || capDropOK {
			capState = "OBSERVED"
		}
		dangerous := dangerousCapabilities(capAdd)
		capBounding := capabilityBoundingState(privilegedState, capAdd, capOK, capDrop, capDropOK)

		securityOpt, securityOptOK := stringSliceField(host, "SecurityOpt", "security_opt", "SecurityOpts", "security_opts")
		seccompState, seccompProfile := seccompPosture(runtimeName, securityOpt, securityOptOK)
		appArmorProfile, appArmorOK := stringField(m, "AppArmorProfile", "apparmor_profile")
		processLabel, processLabelOK := stringField(m, "ProcessLabel", "process_label")
		macState := mandatoryAccessControlPosture(runtimeName, securityOpt, securityOptOK, appArmorProfile, appArmorOK, processLabel, processLabelOK)
		readOnlyRootFS, readOnlyRootFSOK := boolField(host, "ReadonlyRootfs", "ReadonlyRootFS", "read_only_rootfs")
		readOnlyRootFSState := triStateBool(readOnlyRootFS, readOnlyRootFSOK)
		noNewPrivilegesState := noNewPrivilegesPosture(host, securityOpt, securityOptOK)

		devices, devicesOK := sliceField(host, "Devices", "devices")
		deviceRules, deviceRulesOK := stringSliceField(host, "DeviceCgroupRules", "device_cgroup_rules")
		unrestricted := "UNKNOWN"
		if privilegedOK && privileged {
			unrestricted = "TRUE"
		} else if hasUnrestrictedDeviceRule(deviceRules) {
			unrestricted = "TRUE"
		} else if privilegedOK && (devicesOK || deviceRulesOK) {
			unrestricted = "FALSE"
		}

		mounts, mountCount, mountsTruncated, mountsObserved, mountRisks := runtimeMountPosture(m, host)
		mountState := "UNKNOWN"
		if mountsObserved {
			mountState = "OBSERVED"
		}
		hostRootMount := mountRiskState(mountsObserved, mountRisks, "HOST_ROOT")
		runtimeSocketMount := mountRiskState(mountsObserved, mountRisks, "RUNTIME_SOCKET")
		credentialMount := mountRiskState(mountsObserved, mountRisks, "CREDENTIAL_PATH")
		deviceMount := mountRiskState(mountsObserved, mountRisks, "DEVICE_PATH")
		sensitiveHostMount := mountRiskState(mountsObserved, mountRisks, "SENSITIVE_HOST_PATH")

		out = append(out, SecurityPosture{
			Runtime: runtimeName, RuntimeContainerID: id, Name: strings.TrimPrefix(firstString(m, "Name", "name"), "/"),
			State: evidence.StateObserved, PrivilegedState: privilegedState, ConfiguredUser: strings.TrimSpace(user), RootExecutionState: rootState,
			PIDNamespace: pidNS, NetworkNamespace: netNS, UserNamespace: userNS, CapabilityAssessmentState: capState,
			AddedCapabilities: capAdd, DroppedCapabilities: capDrop, DangerousCapabilities: dangerous, CapabilityBoundingState: capBounding,
			SeccompState: seccompState, SeccompProfile: seccompProfile, MandatoryAccessControlState: macState, AppArmorProfile: strings.TrimSpace(appArmorProfile), SELinuxProcessLabel: strings.TrimSpace(processLabel),
			ReadOnlyRootFSState: readOnlyRootFSState, NoNewPrivilegesState: noNewPrivilegesState, DeviceCount: len(devices), DeviceCgroupRuleCount: len(deviceRules),
			UnrestrictedDeviceAccessState: unrestricted, MountAssessmentState: mountState, MountCount: mountCount, MountsTruncated: mountsTruncated, Mounts: mounts,
			HostRootMountState: hostRootMount, RuntimeSocketMountState: runtimeSocketMount, CredentialMountState: credentialMount, DeviceMountState: deviceMount, SensitiveHostPathMountState: sensitiveHostMount,
			CollectionSource: runtimeName + " inspect over explicit local runtime provider", Confidence: evidence.ConfidenceHigh,
		})
	}
	return out, nil
}

func runtimeMountPosture(record, host map[string]any) ([]MountPosture, int, bool, bool, map[string]bool) {
	raw, observed := sliceField(record, "Mounts", "mounts")
	var mounts []MountPosture
	if observed {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			typeName, _ := stringField(m, "Type", "type")
			source, _ := stringField(m, "Source", "source")
			dest, _ := stringField(m, "Destination", "destination", "Target", "target")
			prop, _ := stringField(m, "Propagation", "propagation")
			rw, rwOK := boolField(m, "RW", "rw")
			mode, modeOK := stringField(m, "Mode", "mode", "Options", "options")
			access := mountAccess(rw, rwOK, mode, modeOK)
			mounts = append(mounts, newMountPosture(typeName, source, dest, access, prop))
		}
	} else if binds, ok := stringSliceField(host, "Binds", "binds"); ok {
		observed = true
		for _, bind := range binds {
			if m, ok := parseBindMount(bind); ok {
				mounts = append(mounts, m)
			}
		}
	}
	// Risk states are computed before detail truncation so a bounded evidence
	// payload cannot hide an observed dangerous mount.
	total := len(mounts)
	risks := map[string]bool{}
	for _, m := range mounts {
		for _, tag := range m.RiskTags {
			risks[tag] = true
		}
	}
	sort.SliceStable(mounts, func(i, j int) bool {
		iDanger := len(mounts[i].RiskTags) > 0
		jDanger := len(mounts[j].RiskTags) > 0
		if iDanger != jDanger {
			return iDanger
		}
		a := strings.ToLower(mounts[i].Source + "\x00" + mounts[i].Destination)
		b := strings.ToLower(mounts[j].Source + "\x00" + mounts[j].Destination)
		return a < b
	})
	truncated := total > maxMountsPerContainer
	if truncated {
		mounts = mounts[:maxMountsPerContainer]
	}
	return mounts, total, truncated, observed, risks
}

func newMountPosture(typeName, source, dest, access, propagation string) MountPosture {
	t := strings.ToLower(strings.TrimSpace(typeName))
	src := strings.TrimSpace(source)
	dst := strings.TrimSpace(dest)
	risks := classifyHostMountRisks(t, src)
	return MountPosture{Type: t, Source: src, Destination: dst, Access: access, Propagation: strings.TrimSpace(propagation), RiskTags: risks}
}

func mountAccess(rw bool, rwObserved bool, mode string, modeObserved bool) string {
	if rwObserved {
		if rw {
			return "READ_WRITE"
		}
		return "READ_ONLY"
	}
	if modeObserved {
		m := strings.ToLower(strings.TrimSpace(mode))
		for _, part := range strings.Split(m, ",") {
			switch strings.TrimSpace(part) {
			case "ro":
				return "READ_ONLY"
			case "rw":
				return "READ_WRITE"
			}
		}
	}
	return "UNKNOWN"
}

func parseBindMount(bind string) (MountPosture, bool) {
	b := strings.TrimSpace(bind)
	if b == "" {
		return MountPosture{}, false
	}
	// This fallback is used only when a runtime omits structured Mounts. Split
	// from the right so ordinary Unix paths remain deterministic. Windows
	// runtimes normally expose the structured representation.
	parts := strings.Split(b, ":")
	if len(parts) < 2 {
		return MountPosture{}, false
	}
	source, dest := parts[0], parts[1]
	mode := ""
	if len(parts) > 2 {
		mode = parts[len(parts)-1]
	}
	return newMountPosture("bind", source, dest, mountAccess(false, false, mode, mode != ""), ""), true
}

func classifyHostMountRisks(typeName, source string) []string {
	t := strings.ToLower(strings.TrimSpace(typeName))
	src := normalizeHostMountPath(source)
	if src == "" {
		return nil
	}
	// Named volumes are runtime-managed storage, not direct host-path exposure.
	if t != "" && t != "bind" && t != "npipe" {
		return nil
	}
	var tags []string
	if isHostRootPath(src) {
		tags = append(tags, "HOST_ROOT")
	}
	if isRuntimeControlSocketPath(src) {
		tags = append(tags, "RUNTIME_SOCKET")
	}
	if isCredentialPath(src) {
		tags = append(tags, "CREDENTIAL_PATH")
	}
	if isDevicePath(src) {
		tags = append(tags, "DEVICE_PATH")
	}
	if isSensitiveHostPath(src) {
		tags = append(tags, "SENSITIVE_HOST_PATH")
	}
	return uniqueSortedUpper(tags)
}

func normalizeHostMountPath(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, `\`, "/"))
	for strings.Contains(v, "//") && !strings.HasPrefix(v, "//./pipe/") {
		v = strings.ReplaceAll(v, "//", "/")
	}
	if len(v) > 1 {
		v = strings.TrimSuffix(v, "/")
	}
	return strings.ToLower(v)
}

func isHostRootPath(p string) bool {
	if p == "/" {
		return true
	}
	if len(p) == 2 && p[1] == ':' && p[0] >= 'a' && p[0] <= 'z' {
		return true
	}
	return false
}

func isRuntimeControlSocketPath(p string) bool {
	if strings.Contains(p, "/docker.sock") || strings.Contains(p, "/podman.sock") || strings.Contains(p, "/containerd.sock") {
		return true
	}
	return strings.Contains(p, "//./pipe/docker_engine") || strings.Contains(p, "//./pipe/containerd-containerd") || strings.Contains(p, "//./pipe/podman")
}

func isCredentialPath(p string) bool {
	markers := []string{"/.ssh", "/.aws", "/.azure", "/.kube", "/.gnupg", "/.config/gcloud", "/.docker"}
	for _, marker := range markers {
		if p == marker || strings.Contains(p, marker+"/") || strings.HasSuffix(p, marker) {
			return true
		}
	}
	return false
}

func isDevicePath(p string) bool {
	return p == "/dev" || strings.HasPrefix(p, "/dev/")
}

func isSensitiveHostPath(p string) bool {
	prefixes := []string{
		"/etc", "/proc", "/sys", "/boot", "/run/secrets", "/etc/kubernetes",
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet", "/var/lib/containers",
		"c:/windows", "c:/programdata/docker", "c:/programdata/containerd", "c:/programdata/kubernetes",
	}
	for _, prefix := range prefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func mountRiskState(observed bool, risks map[string]bool, tag string) string {
	if !observed {
		return "UNKNOWN"
	}
	if risks[tag] {
		return "TRUE"
	}
	return "FALSE"
}

func dockerDefaultUserNamespace(ctx context.Context, r Runtime) string {
	if r.RootlessState == "TRUE" {
		return "REMAPPED"
	}
	if r.BinaryPath == "" || r.Endpoint == "" {
		return "UNKNOWN"
	}
	out, err := localCommand(ctx, 2500*time.Millisecond, r.BinaryPath, "-H", dockerEndpoint(r.Endpoint, r.EndpointKind), "info", "--format", "{{json .SecurityOptions}}")
	if err == nil {
		var options []string
		if json.Unmarshal([]byte(strings.TrimSpace(out)), &options) == nil {
			for _, option := range options {
				if strings.Contains(strings.ToLower(option), "name=userns") || strings.Contains(strings.ToLower(option), "userns") {
					return "REMAPPED"
				}
			}
			if r.RootlessState == "FALSE" {
				return "HOST"
			}
		}
	}
	return "UNKNOWN"
}

func podmanRootlessState(ctx context.Context, r Runtime) string {
	if r.BinaryPath == "" {
		return "UNKNOWN"
	}
	out, err := localCommandEnv(ctx, 2500*time.Millisecond, sanitizedContainerEnv(), r.BinaryPath, "--remote=false", "info", "--format", "json")
	if err != nil {
		return "UNKNOWN"
	}
	var m map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &m) != nil {
		return "UNKNOWN"
	}
	if v, ok := nestedBoolPath(m, []string{"host", "security", "rootless"}); ok {
		if v {
			return "TRUE"
		}
		return "FALSE"
	}
	return "UNKNOWN"
}

func capabilityBoundingState(privilegedState string, capAdd []string, capAddObserved bool, capDrop []string, capDropObserved bool) string {
	if privilegedState == "TRUE" || containsNormalized(capAdd, "ALL") {
		return "UNBOUNDED"
	}
	if containsNormalized(capDrop, "ALL") {
		return "REDUCED"
	}
	if privilegedState == "FALSE" && (capAddObserved || capDropObserved) {
		return "BOUNDED"
	}
	return "UNKNOWN"
}

func seccompPosture(runtimeName string, options []string, observed bool) (string, string) {
	if observed {
		for _, raw := range options {
			opt := strings.ToLower(strings.TrimSpace(raw))
			if !strings.Contains(opt, "seccomp") {
				continue
			}
			if strings.Contains(opt, "unconfined") || strings.Contains(opt, "disable") {
				return "UNCONFINED", strings.TrimSpace(raw)
			}
			if strings.Contains(opt, "builtin") || strings.Contains(opt, "default") {
				return "DEFAULT", strings.TrimSpace(raw)
			}
			return "CUSTOM", strings.TrimSpace(raw)
		}
		// Docker and Podman use their runtime default when SecurityOpt is present
		// but no explicit seccomp override is configured. This is metadata-only;
		// Chimera does not load or execute the profile.
		if runtimeName == "docker" || runtimeName == "podman" {
			return "DEFAULT", "runtime default"
		}
	}
	return "UNKNOWN", ""
}

func mandatoryAccessControlPosture(runtimeName string, options []string, optionsObserved bool, appArmor string, appArmorObserved bool, processLabel string, processLabelObserved bool) string {
	for _, raw := range options {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(opt, "apparmor") && strings.Contains(opt, "unconfined") {
			return "UNCONFINED"
		}
		if strings.Contains(opt, "label=disable") || strings.Contains(opt, "label:disable") || strings.Contains(opt, "selinux=disable") {
			return "UNCONFINED"
		}
	}
	if strings.EqualFold(strings.TrimSpace(appArmor), "unconfined") {
		return "UNCONFINED"
	}
	if strings.TrimSpace(appArmor) != "" {
		return "ENFORCED"
	}
	if strings.EqualFold(strings.TrimSpace(processLabel), "unconfined") || strings.EqualFold(strings.TrimSpace(processLabel), "disable") {
		return "UNCONFINED"
	}
	if strings.TrimSpace(processLabel) != "" {
		return "ENFORCED"
	}
	if (appArmorObserved || processLabelObserved) && optionsObserved && (runtimeName == "docker" || runtimeName == "podman") {
		// Empty profiles do not prove the host has a mandatory-access-control
		// provider available, so retain uncertainty rather than claiming clean or
		// unconfined state.
		return "UNKNOWN"
	}
	return "UNKNOWN"
}

func noNewPrivilegesPosture(host map[string]any, options []string, optionsObserved bool) string {
	if v, ok := boolField(host, "NoNewPrivileges", "no_new_privileges"); ok {
		return triStateBool(v, true)
	}
	if optionsObserved {
		for _, raw := range options {
			opt := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "_", "-"))
			if strings.Contains(opt, "no-new-privileges") {
				if strings.Contains(opt, "=false") || strings.Contains(opt, ":false") {
					return "FALSE"
				}
				return "TRUE"
			}
		}
		return "FALSE"
	}
	return "UNKNOWN"
}

func triStateBool(v bool, observed bool) string {
	if !observed {
		return "UNKNOWN"
	}
	if v {
		return "TRUE"
	}
	return "FALSE"
}

func containsNormalized(values []string, want string) bool {
	want = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(want, "CAP_")))
	for _, v := range normalizeStringSet(values) {
		if v == want {
			return true
		}
	}
	return false
}

func dangerousCapabilities(caps []string) []string {
	var out []string
	for _, cap := range normalizeStringSet(caps) {
		if _, ok := dangerousCapabilitySet[cap]; ok {
			out = append(out, cap)
		}
	}
	return out
}

func configuredRootState(user string, observed bool) string {
	if !observed {
		return "UNKNOWN"
	}
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
		return "TRUE"
	}
	return "FALSE"
}

func namespaceMode(mode string, observed bool, emptyDefault string) string {
	if !observed {
		return "UNKNOWN"
	}
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return emptyDefault
	}
	if m == "host" {
		return "HOST"
	}
	if strings.HasPrefix(m, "container:") {
		return "SHARED_CONTAINER"
	}
	return "PRIVATE"
}

func networkNamespaceMode(mode string, observed bool) string {
	return namespaceMode(mode, observed, "PRIVATE")
}

func userNamespaceMode(mode string, observed bool, emptyDefault string) string {
	if !observed {
		return "UNKNOWN"
	}
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return normalizeNamespaceState(emptyDefault)
	}
	if m == "host" {
		return "HOST"
	}
	if strings.HasPrefix(m, "container:") {
		return "SHARED_CONTAINER"
	}
	return "REMAPPED"
}

func hasUnrestrictedDeviceRule(rules []string) bool {
	for _, rule := range rules {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(rule)))
		if len(fields) < 3 || fields[0] != "a" || fields[1] != "*:*" {
			continue
		}
		perms := fields[2]
		if strings.Contains(perms, "r") && strings.Contains(perms, "w") && strings.Contains(perms, "m") {
			return true
		}
	}
	return false
}

func nestedMap(m map[string]any, key string) map[string]any {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			if child, ok := v.(map[string]any); ok {
				return child
			}
		}
	}
	return map[string]any{}
}

func stringField(m map[string]any, keys ...string) (string, bool) {
	for _, want := range keys {
		for k, v := range m {
			if !strings.EqualFold(k, want) {
				continue
			}
			if v == nil {
				return "", true
			}
			s, ok := v.(string)
			if !ok {
				return strings.TrimSpace(fmt.Sprint(v)), true
			}
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

func boolField(m map[string]any, keys ...string) (bool, bool) {
	for _, want := range keys {
		for k, v := range m {
			if !strings.EqualFold(k, want) {
				continue
			}
			b, ok := v.(bool)
			return b, ok
		}
	}
	return false, false
}

func stringSliceField(m map[string]any, keys ...string) ([]string, bool) {
	for _, want := range keys {
		for k, v := range m {
			if !strings.EqualFold(k, want) {
				continue
			}
			if v == nil {
				return nil, true
			}
			arr, ok := v.([]any)
			if !ok {
				if direct, ok := v.([]string); ok {
					return direct, true
				}
				return nil, false
			}
			out := make([]string, 0, len(arr))
			for _, item := range arr {
				if item != nil {
					out = append(out, strings.TrimSpace(fmt.Sprint(item)))
				}
			}
			return out, true
		}
	}
	return nil, false
}

func sliceField(m map[string]any, keys ...string) ([]any, bool) {
	for _, want := range keys {
		for k, v := range m {
			if !strings.EqualFold(k, want) {
				continue
			}
			if v == nil {
				return nil, true
			}
			arr, ok := v.([]any)
			return arr, ok
		}
	}
	return nil, false
}

func nestedBoolPath(m map[string]any, path []string) (bool, bool) {
	cur := m
	for i, part := range path {
		if i == len(path)-1 {
			return boolField(cur, part)
		}
		cur = nestedMap(cur, part)
		if len(cur) == 0 {
			return false, false
		}
	}
	return false, false
}

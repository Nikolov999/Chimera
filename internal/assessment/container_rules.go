package assessment

import (
	"fmt"
	"sort"
	"strings"

	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
)

// ContainerSecurityRules implements the privileged-container checks,
// dangerous host-mount checks, isolation-control checks, local runtime endpoint/network API exposure checks, Kubernetes/orchestration local-posture checks, and profile-aware developer-surface checks. The rules consume metadata-only
// local runtime inspection and
// never enter containers, read environment values, inspect mounted secret
// content, or contact remote runtime endpoints.
func ContainerSecurityRules() []Rule {
	rules := []Rule{
		{
			ID: "CHM-CTR-001", Title: "Containers do not run in privileged mode", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.privileged", ExpectedState: "no observed container is configured with privileged mode enabled",
			Risk:        "Privileged containers substantially weaken the runtime isolation boundary and can grant broad host device, capability, and kernel access relative to an ordinary container.",
			Remediation: "Remove privileged mode and grant only the narrowly required capabilities, devices, namespaces, and filesystem access. Recreate or redeploy the container using the hardened runtime configuration.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "privileged mode", StatusFail, func(c containerinv.SecurityPosture) (string, bool) {
					return c.PrivilegedState, c.PrivilegedState == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-002", Title: "Containers do not share the host PID namespace", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.pid_namespace", ExpectedState: "no observed container uses the host PID namespace",
			Risk:        "Host PID namespace sharing exposes host process metadata and can materially weaken process-isolation boundaries, especially when combined with elevated capabilities or writable host mounts.",
			Remediation: "Use the runtime's private PID namespace unless host PID visibility is explicitly required and separately controlled. Remove host-PID mode from the container specification and redeploy.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "host PID namespace", StatusFail, func(c containerinv.SecurityPosture) (string, bool) {
					return boolWord(c.PIDNamespace == "HOST"), c.PIDNamespace == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-003", Title: "Containers do not share the host network namespace", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.network_namespace", ExpectedState: "no observed container uses the host network namespace",
			Risk:        "Host network namespace sharing removes an important network-isolation boundary and can expose host interfaces and listening context directly to container workloads.",
			Remediation: "Use a dedicated bridge, user-defined, or otherwise isolated container network unless host networking is explicitly required. Remove host-network mode and redeploy the workload.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "host network namespace", StatusFail, func(c containerinv.SecurityPosture) (string, bool) {
					return boolWord(c.NetworkNamespace == "HOST"), c.NetworkNamespace == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-004", Title: "Containers avoid the host user namespace", Category: "containers", Severity: SeverityMedium,
			AffectedObject: "container.security.user_namespace", ExpectedState: "container user identities are remapped/rootless where the runtime and workload support it",
			Risk:        "Using the host user namespace preserves a closer relationship between container and host user identities; when a workload also runs as container root or receives powerful capabilities, the impact of another isolation failure can increase.",
			Remediation: "Use rootless containers or supported user-namespace remapping for workloads that do not require host user-namespace semantics. Validate application UID/GID and volume ownership requirements before redeployment.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "host user namespace", StatusWarn, func(c containerinv.SecurityPosture) (string, bool) {
					return boolWord(c.UserNamespace == "HOST"), c.UserNamespace == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-005", Title: "Containers do not add high-risk Linux capabilities", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.capabilities", ExpectedState: "no observed container explicitly adds a high-risk capability or ALL capabilities",
			Risk:        "Powerful added capabilities such as SYS_ADMIN, SYS_MODULE, SYS_PTRACE, NET_ADMIN, BPF, or ALL can bypass important container restrictions and materially expand access to host kernel or network surfaces.",
			Remediation: "Remove unnecessary capability additions and use a least-privilege allowlist. Prefer dropping capabilities by default and adding only those required by the workload after testing.",
			Evaluate:    evaluateDangerousContainerCapabilities,
		},
		{
			ID: "CHM-CTR-006", Title: "Containers are configured to run as non-root", Category: "containers", Severity: SeverityMedium,
			AffectedObject: "container.security.root_execution", ExpectedState: "workloads use an explicit non-root runtime user when application requirements permit",
			Risk:        "Running as UID 0 inside a container increases the consequence of runtime, kernel, mount, device, or capability misconfiguration and weakens defense in depth even when namespaces remain intact.",
			Remediation: "Configure an explicit non-root USER/UID for the workload and grant only the filesystem and capability access it requires. Preserve root execution only where a documented workload requirement justifies it.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "container root execution", StatusWarn, func(c containerinv.SecurityPosture) (string, bool) {
					return c.RootExecutionState, c.RootExecutionState == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-007", Title: "Containers do not receive unrestricted host-device access", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.devices", ExpectedState: "no observed container has unrestricted all-device read/write/mknod access",
			Risk:        "Unrestricted device access can expose sensitive host kernel interfaces and physical or virtual devices directly to a container, substantially weakening the isolation boundary.",
			Remediation: "Remove privileged/all-device access and map only explicitly required devices with the minimum read/write permissions. Avoid wildcard device-cgroup grants.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerSecurityState(idx, "unrestricted device access", StatusFail, func(c containerinv.SecurityPosture) (string, bool) {
					return c.UnrestrictedDeviceAccessState, c.UnrestrictedDeviceAccessState == "UNKNOWN"
				})
			},
		},
		{
			ID: "CHM-CTR-008", Title: "Containers do not mount the host filesystem root", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.mounts.host_root", ExpectedState: "no observed container bind-mounts a host filesystem root",
			Risk:        "Mounting the host filesystem root gives a container broad visibility into host files and, when writable, can collapse important host/container integrity boundaries.",
			Remediation: "Remove host-root mounts. Bind only the minimum required host directory or file, prefer read-only access where possible, and keep host administrative paths outside the container.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerMountRisk(idx, "HOST_ROOT", "host filesystem root mount", StatusFail, func(c containerinv.SecurityPosture) string { return c.HostRootMountState })
			},
		},
		{
			ID: "CHM-CTR-009", Title: "Containers do not mount container-runtime control sockets", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.mounts.runtime_socket", ExpectedState: "no observed container mounts Docker, Podman, or containerd control sockets/pipes",
			Risk:        "A workload with access to a container-runtime control socket can often create or control other workloads and materially affect the host runtime boundary, independent of ordinary filesystem mount permissions.",
			Remediation: "Do not expose runtime control sockets to application containers. Use a narrowly scoped broker or purpose-built API if runtime automation is required.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerMountRisk(idx, "RUNTIME_SOCKET", "container-runtime control socket mount", StatusFail, func(c containerinv.SecurityPosture) string { return c.RuntimeSocketMountState })
			},
		},
		{
			ID: "CHM-CTR-010", Title: "Containers do not mount host credential directories", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.mounts.credentials", ExpectedState: "no observed container mounts host SSH, cloud, Kubernetes, GPG, or runtime credential/config directories",
			Risk:        "Host credential-directory mounts can expose authentication material and trusted client configuration to a compromised or overly broad container workload.",
			Remediation: "Remove broad credential-directory mounts. Provide only the exact non-secret configuration or short-lived workload credential required, with read-only and least-privilege access where supported.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerMountRisk(idx, "CREDENTIAL_PATH", "host credential-directory mount", StatusFail, func(c containerinv.SecurityPosture) string { return c.CredentialMountState })
			},
		},
		{
			ID: "CHM-CTR-011", Title: "Containers avoid host device-path mounts", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.mounts.devices", ExpectedState: "no observed container bind-mounts broad or sensitive host device paths",
			Risk:        "Direct host device-path mounts can expose kernel-backed interfaces or physical/virtual devices outside the normal container filesystem boundary.",
			Remediation: "Remove broad /dev or device-file bind mounts unless the workload has a documented hardware requirement. Expose only the specific device required and combine it with the minimum device-cgroup permissions.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerMountRisk(idx, "DEVICE_PATH", "host device-path mount", StatusFail, func(c containerinv.SecurityPosture) string { return c.DeviceMountState })
			},
		},
		{
			ID: "CHM-CTR-012", Title: "Containers avoid sensitive host-path mounts", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.mounts.sensitive_host_path", ExpectedState: "no observed container mounts high-impact host system, kernel, boot, orchestration, or runtime-state paths",
			Risk:        "Mounts of host system configuration, proc/sys, boot, orchestration state, or runtime data expose high-impact host metadata and can become host-integrity paths when writable.",
			Remediation: "Remove sensitive host-path mounts or narrow them to the exact file/directory required. Prefer read-only access and isolate administrative/runtime state from application workloads.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerMountRisk(idx, "SENSITIVE_HOST_PATH", "sensitive host-path mount", StatusFail, func(c containerinv.SecurityPosture) string { return c.SensitiveHostPathMountState })
			},
		},

		{
			ID: "CHM-CTR-013", Title: "Containers keep seccomp confinement enabled", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.seccomp", ExpectedState: "observed Linux container workloads use the runtime default or a custom seccomp profile rather than unconfined mode",
			Risk:        "Disabling seccomp removes a syscall-filtering layer that reduces container access to sensitive kernel interfaces and increases the consequence of a workload compromise.",
			Remediation: "Remove seccomp=unconfined or equivalent settings. Use the runtime default seccomp profile or a tested least-privilege custom profile when the workload requires additional syscalls.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerIsolationControl(idx, "seccomp confinement", StatusFail, func(c containerinv.SecurityPosture) string { return c.SeccompState }, []string{"UNCONFINED"}, []string{"DEFAULT", "CUSTOM"}, []string{"NOT_APPLICABLE"})
			},
		},
		{
			ID: "CHM-CTR-014", Title: "Containers retain mandatory access-control confinement", Category: "containers", Severity: SeverityMedium,
			AffectedObject: "container.security.mandatory_access_control", ExpectedState: "AppArmor or SELinux confinement remains enabled where the runtime exposes an applicable mandatory-access-control provider",
			Risk:        "Explicitly disabling AppArmor or SELinux removes an independent policy boundary around container processes and can increase host impact when another runtime control fails.",
			Remediation: "Remove apparmor=unconfined, label=disable, or equivalent overrides. Use the runtime's default confinement profile or a reviewed workload-specific AppArmor/SELinux policy.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerIsolationControl(idx, "mandatory access-control confinement", StatusWarn, func(c containerinv.SecurityPosture) string { return c.MandatoryAccessControlState }, []string{"UNCONFINED"}, []string{"ENFORCED"}, []string{"NOT_APPLICABLE"})
			},
		},
		{
			ID: "CHM-CTR-015", Title: "Containers retain bounded Linux capabilities", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.security.capability_bounding", ExpectedState: "container capability sets remain bounded or are explicitly reduced",
			Risk:        "An unbounded capability set materially weakens the kernel privilege boundary and can grant container processes broad host-facing powers even without a separate exploit.",
			Remediation: "Avoid privileged mode and CAP_ALL-style grants. Keep the runtime default bounding set or drop ALL capabilities and add back only the minimum capabilities required by the workload.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerIsolationControl(idx, "capability bounding", StatusFail, func(c containerinv.SecurityPosture) string { return c.CapabilityBoundingState }, []string{"UNBOUNDED"}, []string{"BOUNDED", "REDUCED"}, []string{"NOT_APPLICABLE"})
			},
		},
		{
			ID: "CHM-CTR-016", Title: "Containers prefer a read-only root filesystem", Category: "containers", Severity: SeverityMedium,
			AffectedObject: "container.security.read_only_rootfs", ExpectedState: "workloads use a read-only root filesystem when application write requirements can be isolated to explicit writable mounts",
			Risk:        "A writable container root filesystem gives compromised processes more persistence and tampering opportunities inside the workload and weakens immutability as a defensive control.",
			Remediation: "Enable the runtime's read-only root filesystem option and provide narrowly scoped writable tmpfs/volume mounts only for paths that require writes. Validate application behavior before redeployment.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerIsolationControl(idx, "read-only root filesystem", StatusWarn, func(c containerinv.SecurityPosture) string {
					if c.ReadOnlyRootFSState == "TRUE" {
						return "ENABLED"
					}
					if c.ReadOnlyRootFSState == "FALSE" {
						return "DISABLED"
					}
					return "UNKNOWN"
				}, []string{"DISABLED"}, []string{"ENABLED"}, nil)
			},
		},
		{
			ID: "CHM-CTR-017", Title: "Containers prevent gaining additional privileges", Category: "containers", Severity: SeverityMedium,
			AffectedObject: "container.security.no_new_privileges", ExpectedState: "no-new-privileges is enabled for workloads unless a documented requirement depends on setuid/setgid or file-capability privilege transitions",
			Risk:        "Without no-new-privileges, a process may gain additional privilege through setuid/setgid binaries or file capabilities inside the container, increasing the impact of application compromise.",
			Remediation: "Enable no-new-privileges for the container and validate workload behavior. Remove unnecessary setuid/setgid or file-capability dependencies rather than disabling the control globally.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateContainerIsolationControl(idx, "no-new-privileges", StatusWarn, func(c containerinv.SecurityPosture) string {
					if c.NoNewPrivilegesState == "TRUE" {
						return "ENABLED"
					}
					if c.NoNewPrivilegesState == "FALSE" {
						return "DISABLED"
					}
					return "UNKNOWN"
				}, []string{"DISABLED"}, []string{"ENABLED"}, nil)
			},
		},
		{
			ID: "CHM-CTR-018", Title: "Container runtime control sockets are not broadly writable", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.runtime_endpoint.permissions", ExpectedState: "local container-runtime control sockets are not world-writable and permission metadata is observable",
			Risk:        "A broadly writable Docker, Podman, or containerd control socket can allow an untrusted local principal to control workloads and may provide a path to host-level administrative impact.",
			Remediation: "Restrict the runtime control socket to the runtime service owner and a deliberately managed administrative group. Remove world-write access and review membership of any group that can write to the socket.",
			Evaluate:    evaluateRuntimeEndpointPermissions,
		},
		{
			ID: "CHM-CTR-019", Title: "Container runtime APIs are not exposed on non-loopback interfaces", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.runtime_endpoint.network_exposure", ExpectedState: "container-runtime API listeners are absent or bound only to loopback interfaces unless an explicitly hardened remote-management design exists",
			Risk:        "A container-runtime API reachable from non-loopback interfaces expands a high-impact administrative control plane to the network. Weak authentication, TLS, firewall, or authorization around that listener can lead to direct workload or host compromise.",
			Remediation: "Prefer local Unix sockets or named pipes for runtime administration. If remote runtime management is required, bind it to a dedicated management interface, require strong mutual authentication and encryption, and enforce narrow firewall source restrictions.",
			Evaluate:    evaluateRuntimeNetworkExposure,
		},
		{
			ID: "CHM-CTR-020", Title: "Kubernetes configuration files are not broadly accessible", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.orchestration.kubeconfig.permissions", ExpectedState: "local kubeconfig files are restricted to the intended principal or tightly controlled administrative group",
			Risk:        "Kubeconfig files can contain embedded client keys, bearer tokens, or references to privileged credential material. Broad read or write access can expose cluster identity material or allow an untrusted principal to alter the client/control-plane configuration used by local administrators and services.",
			Remediation: "Restrict kubeconfig ownership and permissions to the intended user or service account. Remove world access, remove unnecessary group write access, and treat group-readable kubeconfigs containing credentials as an explicit administrative exception rather than a default.",
			Evaluate:    evaluateKubeconfigPermissions,
		},
		{
			ID: "CHM-CTR-021", Title: "Kubernetes referenced credential files are protected", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.orchestration.credential_path.permissions", ExpectedState: "local client-key and token files referenced by kubeconfig are not broadly readable or writable",
			Risk:        "A kubeconfig may reference external client keys or token files. Broad local access to those files can expose reusable cluster authentication material even when the kubeconfig itself is appropriately protected.",
			Remediation: "Restrict referenced client-key and token files to the intended principal or narrowly managed service account. Remove world access and unnecessary group read/write grants, then verify the referencing kubeconfig still functions with least privilege.",
			Evaluate:    evaluateKubernetesCredentialPathPermissions,
		},
		{
			ID: "CHM-CTR-022", Title: "Kubernetes API exposure matches the host role", Category: "containers", Severity: SeverityHigh,
			AffectedObject: "container.orchestration.api.network_exposure", ExpectedState: "workstations do not expose a Kubernetes API beyond loopback; server/control-plane listeners are intentionally exposed only on approved interfaces and constrained by authentication and firewall policy",
			Risk:        "The Kubernetes API is a high-impact administrative control plane. Unexpected non-loopback exposure on a workstation materially expands attack surface, while server-side wildcard exposure requires deliberate network, authentication, and authorization controls.",
			Remediation: "On workstations, bind local Kubernetes APIs to loopback unless remote access is explicitly required. On servers, bind to intended management/control-plane interfaces and enforce strong authentication, authorization, TLS, and narrow firewall source policy.",
			Evaluate:    evaluateKubernetesAPIExposure,
		},
	}
	rules = append(rules, DeveloperSurfaceRules()...)
	return rules
}

type kubeconfigEvidence struct {
	Key    string
	Record containerinv.KubeconfigPosture
}

type kubernetesCredentialEvidence struct {
	Key    string
	Record containerinv.KubernetesCredentialPathPosture
}

func evaluateKubeconfigPermissions(idx Index) Evaluation {
	items := make([]kubeconfigEvidence, 0)
	unknown := make([]kubeconfigEvidence, 0)
	warn := make([]kubeconfigEvidence, 0)
	fail := make([]kubeconfigEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.orchestration.kubeconfig.") {
			continue
		}
		rec, ok := obs.Value.(containerinv.KubeconfigPosture)
		if obs.State != evidence.StateObserved || !ok {
			unknown = append(unknown, kubeconfigEvidence{Key: key, Record: rec})
			continue
		}
		item := kubeconfigEvidence{Key: key, Record: rec}
		items = append(items, item)
		if rec.PermissionAssessmentState != "OBSERVED" || rec.WorldReadableState == "UNKNOWN" || rec.WorldWritableState == "UNKNOWN" || rec.GroupReadableState == "UNKNOWN" || rec.GroupWritableState == "UNKNOWN" {
			unknown = append(unknown, item)
			continue
		}
		if rec.WorldReadableState == "TRUE" || rec.WorldWritableState == "TRUE" || rec.GroupWritableState == "TRUE" {
			fail = append(fail, item)
			continue
		}
		if rec.GroupReadableState == "TRUE" {
			warn = append(warn, item)
		}
	}
	sortKubeconfigEvidence(items)
	sortKubeconfigEvidence(unknown)
	sortKubeconfigEvidence(warn)
	sortKubeconfigEvidence(fail)
	if len(fail) > 0 {
		desc, keys := kubeconfigDescriptions(fail)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d kubeconfig file(s) have world access or group-write access: %s", len(fail), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(warn) > 0 {
		desc, keys := kubeconfigDescriptions(warn)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d kubeconfig file(s) are group-readable and require group-membership review: %s", len(warn), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := kubeconfigDescriptions(unknown)
		keys = append(keys, kubernetesSourceKeys(idx, "container.source.kubernetes-kubeconfig", false)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("kubeconfig permissions could not be fully resolved for %d file(s): %s", len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(items) == 0 {
		return noKubernetesFileEvaluation(idx, "no local kubeconfig file was observed", "container.source.kubernetes-kubeconfig")
	}
	_, keys := kubeconfigDescriptions(items)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d observed kubeconfig file(s) have no world access, group-write access, or unresolved permission metadata", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateKubernetesCredentialPathPermissions(idx Index) Evaluation {
	items := make([]kubernetesCredentialEvidence, 0)
	unknown := make([]kubernetesCredentialEvidence, 0)
	warn := make([]kubernetesCredentialEvidence, 0)
	fail := make([]kubernetesCredentialEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.orchestration.credential_path.") {
			continue
		}
		rec, ok := obs.Value.(containerinv.KubernetesCredentialPathPosture)
		if obs.State != evidence.StateObserved || !ok {
			unknown = append(unknown, kubernetesCredentialEvidence{Key: key, Record: rec})
			continue
		}
		item := kubernetesCredentialEvidence{Key: key, Record: rec}
		items = append(items, item)
		if rec.PermissionAssessmentState != "OBSERVED" || rec.WorldReadableState == "UNKNOWN" || rec.WorldWritableState == "UNKNOWN" || rec.GroupReadableState == "UNKNOWN" || rec.GroupWritableState == "UNKNOWN" {
			unknown = append(unknown, item)
			continue
		}
		if rec.WorldReadableState == "TRUE" || rec.WorldWritableState == "TRUE" || rec.GroupWritableState == "TRUE" {
			fail = append(fail, item)
			continue
		}
		if rec.GroupReadableState == "TRUE" {
			warn = append(warn, item)
		}
	}
	sortKubernetesCredentialEvidence(items)
	sortKubernetesCredentialEvidence(unknown)
	sortKubernetesCredentialEvidence(warn)
	sortKubernetesCredentialEvidence(fail)
	if len(fail) > 0 {
		desc, keys := kubernetesCredentialDescriptions(fail)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d referenced Kubernetes credential file(s) have world access or group-write access: %s", len(fail), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(warn) > 0 {
		desc, keys := kubernetesCredentialDescriptions(warn)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d referenced Kubernetes credential file(s) are group-readable and require group-membership review: %s", len(warn), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := kubernetesCredentialDescriptions(unknown)
		keys = append(keys, kubernetesSourceKeys(idx, "container.source.kubernetes-credential-paths", false)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("referenced Kubernetes credential-file permissions could not be fully resolved for %d path(s): %s", len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(items) == 0 {
		return noKubernetesFileEvaluation(idx, "no external client-key or token-file reference was observed in local kubeconfig metadata", "container.source.kubernetes-credential-paths")
	}
	_, keys := kubernetesCredentialDescriptions(items)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d referenced Kubernetes credential file(s) have no world access, group-write access, or unresolved permission metadata", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func noKubernetesFileEvaluation(idx Index, message, sourceKey string) Evaluation {
	if obs, ok := idx[sourceKey]; ok {
		if obs.State == evidence.StateNotApplicable {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: message, Applicability: NotApplicable, EvidenceKeys: []string{sourceKey}}
		}
		if obs.State != evidence.StateObserved {
			return Evaluation{Status: StatusUnknown, Confidence: obs.Confidence, ObservedState: observedText(obs), Applicability: Undetermined, EvidenceKeys: []string{sourceKey}}
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: message, Applicability: NotApplicable, EvidenceKeys: []string{sourceKey}}
	}
	if obs, ok := idx["container.orchestration.kubernetes"]; ok && obs.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: message, Applicability: NotApplicable, EvidenceKeys: []string{"container.orchestration.kubernetes"}}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Kubernetes local-posture evidence is unavailable", Applicability: Undetermined, EvidenceKeys: []string{sourceKey}}
}

func kubeconfigDescriptions(items []kubeconfigEvidence) ([]string, []string) {
	desc := make([]string, 0, minInt(len(items), 12))
	keys := make([]string, 0, minInt(len(items), 64))
	for i, item := range items {
		if i < 12 {
			mode := item.Record.Mode
			if mode == "" {
				mode = "mode unknown"
			} else {
				mode = "mode " + mode
			}
			extra := ""
			if item.Record.EmbeddedCredentialState == "TRUE" {
				extra = ", embedded-credentials=" + strings.Join(item.Record.EmbeddedCredentialKinds, ",")
			}
			desc = append(desc, item.Record.Path+" ["+mode+extra+"]")
		}
		if i < 64 {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > 12 {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-12))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func kubernetesCredentialDescriptions(items []kubernetesCredentialEvidence) ([]string, []string) {
	desc := make([]string, 0, minInt(len(items), 12))
	keys := make([]string, 0, minInt(len(items), 64))
	for i, item := range items {
		if i < 12 {
			mode := item.Record.Mode
			if mode == "" {
				mode = "mode unknown"
			} else {
				mode = "mode " + mode
			}
			desc = append(desc, item.Record.Kind+" "+item.Record.Path+" ["+mode+"]")
		}
		if i < 64 {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > 12 {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-12))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func sortKubeconfigEvidence(items []kubeconfigEvidence) {
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Record.Path) < strings.ToLower(items[j].Record.Path)
	})
}

func sortKubernetesCredentialEvidence(items []kubernetesCredentialEvidence) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Record.Kind != items[j].Record.Kind {
			return items[i].Record.Kind < items[j].Record.Kind
		}
		return strings.ToLower(items[i].Record.Path) < strings.ToLower(items[j].Record.Path)
	})
}

func kubernetesSourceKeys(idx Index, exact string, includeNotApplicable bool) []string {
	keys := make([]string, 0)
	for key, obs := range idx {
		if key != exact {
			continue
		}
		if obs.State != evidence.StateObserved && (includeNotApplicable || obs.State != evidence.StateNotApplicable) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

type kubernetesNetworkEvidence struct {
	Key        string
	Endpoint   netinv.Endpoint
	Confidence evidence.Confidence
}

func evaluateKubernetesAPIExposure(idx Index) Evaluation {
	role := "NOT_APPLICABLE"
	kubeKey := "container.orchestration.kubernetes"
	if obs, ok := idx[kubeKey]; ok && obs.State == evidence.StateObserved {
		if p, ok := obs.Value.(containerinv.KubernetesPosture); ok {
			role = p.Applicability
		}
	}
	items := kubernetesAPIItems(idx)
	if role == "NOT_APPLICABLE" {
		ownerProven := make([]kubernetesNetworkEvidence, 0, len(items))
		for _, item := range items {
			if item.Confidence == evidence.ConfidenceHigh || item.Confidence == evidence.ConfidenceExact {
				ownerProven = append(ownerProven, item)
			}
		}
		items = ownerProven
		if len(items) > 0 {
			role = "UNKNOWN"
		}
	}
	bad := make([]kubernetesNetworkEvidence, 0)
	for _, item := range items {
		b := item.Endpoint.InterfaceBinding
		if b.IsWildcard || b.Class == "ALL_INTERFACES" || b.Class == "NON_LOOPBACK" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc := make([]string, 0, minInt(len(bad), 12))
		keys := make([]string, 0, minInt(len(bad)+1, 64))
		confidence := evidence.ConfidenceMedium
		status := StatusWarn
		for i, item := range bad {
			if item.Confidence == evidence.ConfidenceHigh || item.Confidence == evidence.ConfidenceExact {
				confidence = evidence.ConfidenceHigh
				if role == "WORKSTATION" {
					status = StatusFail
				}
			}
			if i < 12 {
				desc = append(desc, fmt.Sprintf("%s:%d [%s]", item.Endpoint.LocalAddress, item.Endpoint.LocalPort, item.Endpoint.InterfaceBinding.Class))
			}
			if i < 63 {
				keys = append(keys, item.Key)
			}
		}
		if _, ok := idx[kubeKey]; ok {
			keys = append(keys, kubeKey)
		}
		if len(bad) > 12 {
			desc = append(desc, fmt.Sprintf("+%d more", len(bad)-12))
		}
		return Evaluation{Status: status, Confidence: confidence, ObservedState: fmt.Sprintf("%d Kubernetes API listener(s) are reachable beyond loopback on a %s posture: %s", len(bad), role, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(items) > 0 {
		keys := make([]string, 0, len(items)+1)
		for _, item := range items {
			keys = append(keys, item.Key)
		}
		if _, ok := idx[kubeKey]; ok {
			keys = append(keys, kubeKey)
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed Kubernetes API listener(s) are limited to loopback", len(items)), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if obs, ok := idx[kubeKey]; ok && obs.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "Kubernetes was not observed locally and no Kubernetes API listener was identified", Applicability: NotApplicable, EvidenceKeys: []string{kubeKey}}
	}
	if networkProviderUsable(idx) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local Kubernetes API listener was observed", Applicability: Applicable, EvidenceKeys: existingKeys(idx, "network.inventory.count", kubeKey)}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "local network listener inventory is unavailable, so Kubernetes API exposure cannot be resolved", Applicability: Undetermined, EvidenceKeys: existingKeys(idx, "network.inventory.count", kubeKey)}
}

func kubernetesAPIItems(idx Index) []kubernetesNetworkEvidence {
	out := make([]kubernetesNetworkEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "network.endpoint.") || obs.State != evidence.StateObserved {
			continue
		}
		ep, ok := obs.Value.(netinv.Endpoint)
		if !ok || ep.Protocol != "TCP" || ep.TransportState != "LISTEN" {
			continue
		}
		confidence, ok := identifyKubernetesAPIEndpoint(ep)
		if !ok {
			continue
		}
		out = append(out, kubernetesNetworkEvidence{Key: key, Endpoint: ep, Confidence: confidence})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Endpoint.LocalAddress != out[j].Endpoint.LocalAddress {
			return out[i].Endpoint.LocalAddress < out[j].Endpoint.LocalAddress
		}
		if out[i].Endpoint.LocalPort != out[j].Endpoint.LocalPort {
			return out[i].Endpoint.LocalPort < out[j].Endpoint.LocalPort
		}
		return out[i].Endpoint.ID < out[j].Endpoint.ID
	})
	return out
}

func identifyKubernetesAPIEndpoint(ep netinv.Endpoint) (evidence.Confidence, bool) {
	owner := strings.ToLower(strings.Join([]string{ep.Owner.ProcessName, ep.Owner.Executable, ep.Owner.ServiceName}, " "))
	for _, token := range []string{"kube-apiserver", "kube apiserver", "k3s", "rke2", "microk8s", "k0s"} {
		if strings.Contains(owner, token) {
			return evidence.ConfidenceHigh, true
		}
	}
	switch ep.LocalPort {
	case 6443, 16443, 8080:
		return evidence.ConfidenceMedium, true
	default:
		return "", false
	}
}

type runtimeEndpointEvidence struct {
	Key    string
	Record containerinv.RuntimeEndpointPosture
}

func evaluateRuntimeEndpointPermissions(idx Index) Evaluation {
	items := make([]runtimeEndpointEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.runtime_endpoint.") || obs.State != evidence.StateObserved {
			continue
		}
		rec, ok := obs.Value.(containerinv.RuntimeEndpointPosture)
		if ok {
			items = append(items, runtimeEndpointEvidence{Key: key, Record: rec})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Record.Runtime != items[j].Record.Runtime {
			return items[i].Record.Runtime < items[j].Record.Runtime
		}
		return items[i].Record.Endpoint < items[j].Record.Endpoint
	})
	bad := make([]runtimeEndpointEvidence, 0)
	unknown := make([]runtimeEndpointEvidence, 0)
	for _, item := range items {
		if item.Record.PermissionAssessmentState != "OBSERVED" || item.Record.WorldWritableState == "UNKNOWN" {
			unknown = append(unknown, item)
			continue
		}
		if item.Record.WorldWritableState == "TRUE" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := runtimeEndpointDescriptions(bad)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d local runtime control endpoint(s) are world-writable: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := runtimeEndpointDescriptions(unknown)
		keys = append(keys, degradedRuntimeEndpointSources(idx)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("runtime endpoint permissions could not be fully resolved for %d endpoint(s): %s", len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if degraded := degradedRuntimeEndpointSources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime endpoint permission assessment is incomplete because local socket/pipe metadata is unavailable", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if len(items) == 0 {
		if runtimeEndpointSourceNotApplicable(idx) {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local container-runtime control socket or pipe was observed", Applicability: NotApplicable, EvidenceKeys: []string{"container.source.runtime-endpoint-permissions"}}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "runtime endpoint permission evidence is unavailable", Applicability: Undetermined, EvidenceKeys: []string{"container.source.runtime-endpoint-permissions"}}
	}
	_, keys := runtimeEndpointDescriptions(items)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: fmt.Sprintf("%d observed local runtime control endpoint(s) are not world-writable", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func runtimeEndpointDescriptions(items []runtimeEndpointEvidence) ([]string, []string) {
	desc := make([]string, 0, minInt(len(items), 12))
	keys := make([]string, 0, minInt(len(items), 64))
	for i, item := range items {
		if i < 12 {
			mode := item.Record.Mode
			if mode == "" {
				mode = "mode unknown"
			} else {
				mode = "mode " + mode
			}
			desc = append(desc, item.Record.Runtime+" "+item.Record.Endpoint+" ["+mode+"]")
		}
		if i < 64 {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > 12 {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-12))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func degradedRuntimeEndpointSources(idx Index) []string {
	keys := make([]string, 0)
	for key, obs := range idx {
		if key == "container.source.runtime-endpoint-permissions" && obs.State != evidence.StateObserved && obs.State != evidence.StateNotApplicable {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func runtimeEndpointSourceNotApplicable(idx Index) bool {
	obs, ok := idx["container.source.runtime-endpoint-permissions"]
	return ok && obs.State == evidence.StateNotApplicable
}

type runtimeNetworkEvidence struct {
	Key        string
	Endpoint   netinv.Endpoint
	Runtime    string
	Confidence evidence.Confidence
}

func evaluateRuntimeNetworkExposure(idx Index) Evaluation {
	items := runtimeNetworkAPIItems(idx)
	bad := make([]runtimeNetworkEvidence, 0)
	for _, item := range items {
		b := item.Endpoint.InterfaceBinding
		if b.IsWildcard || b.Class == "ALL_INTERFACES" || b.Class == "NON_LOOPBACK" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc := make([]string, 0, minInt(len(bad), 12))
		keys := make([]string, 0, minInt(len(bad), 64))
		confidence := evidence.ConfidenceMedium
		status := StatusWarn
		for i, item := range bad {
			if item.Confidence == evidence.ConfidenceHigh || item.Confidence == evidence.ConfidenceExact {
				confidence = evidence.ConfidenceHigh
				status = StatusFail
			}
			if i < 12 {
				desc = append(desc, fmt.Sprintf("%s %s:%d [%s]", item.Runtime, item.Endpoint.LocalAddress, item.Endpoint.LocalPort, item.Endpoint.InterfaceBinding.Class))
			}
			if i < 64 {
				keys = append(keys, item.Key)
			}
		}
		if len(bad) > 12 {
			desc = append(desc, fmt.Sprintf("+%d more", len(bad)-12))
		}
		return Evaluation{Status: status, Confidence: confidence, ObservedState: fmt.Sprintf("%d container-runtime API listener(s) are exposed beyond loopback: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(items) > 0 {
		keys := make([]string, 0, len(items))
		for _, item := range items {
			keys = append(keys, item.Key)
		}
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed container-runtime API listener(s) are limited to loopback", len(items)), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if networkProviderUsable(idx) {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no container-runtime API network listener was observed", Applicability: Applicable, EvidenceKeys: []string{"network.inventory.count"}}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "local network listener inventory is unavailable, so runtime API network exposure cannot be resolved", Applicability: Undetermined, EvidenceKeys: []string{"network.inventory.count"}}
}

func runtimeNetworkAPIItems(idx Index) []runtimeNetworkEvidence {
	out := make([]runtimeNetworkEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "network.endpoint.") || obs.State != evidence.StateObserved {
			continue
		}
		ep, ok := obs.Value.(netinv.Endpoint)
		if !ok || ep.Protocol != "TCP" || ep.TransportState != "LISTEN" {
			continue
		}
		runtimeName, conf, ok := identifyRuntimeAPIEndpoint(ep)
		if !ok {
			continue
		}
		out = append(out, runtimeNetworkEvidence{Key: key, Endpoint: ep, Runtime: runtimeName, Confidence: conf})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Runtime != out[j].Runtime {
			return out[i].Runtime < out[j].Runtime
		}
		if out[i].Endpoint.LocalAddress != out[j].Endpoint.LocalAddress {
			return out[i].Endpoint.LocalAddress < out[j].Endpoint.LocalAddress
		}
		if out[i].Endpoint.LocalPort != out[j].Endpoint.LocalPort {
			return out[i].Endpoint.LocalPort < out[j].Endpoint.LocalPort
		}
		return out[i].Endpoint.ID < out[j].Endpoint.ID
	})
	return out
}

func identifyRuntimeAPIEndpoint(ep netinv.Endpoint) (string, evidence.Confidence, bool) {
	owner := strings.ToLower(strings.Join([]string{ep.Owner.ProcessName, ep.Owner.Executable, ep.Owner.ServiceName}, " "))
	for _, pair := range []struct {
		name   string
		tokens []string
	}{
		{"docker", []string{"dockerd", "docker daemon", "com.docker.backend", "cri-dockerd"}},
		{"podman", []string{"podman", "libpod"}},
		{"containerd", []string{"containerd"}},
	} {
		for _, token := range pair.tokens {
			if strings.Contains(owner, token) {
				return pair.name, evidence.ConfidenceHigh, true
			}
		}
	}
	switch ep.LocalPort {
	case 2375, 2376, 4243:
		return "docker-compatible", evidence.ConfidenceMedium, true
	default:
		return "", "", false
	}
}

type containerIsolationSelector func(containerinv.SecurityPosture) string

func evaluateContainerIsolationControl(idx Index, label string, badStatus Status, selector containerIsolationSelector, badValues, goodValues, notApplicableValues []string) Evaluation {
	items := containerSecurityItems(idx)
	badSet := assessmentStringSet(badValues)
	goodSet := assessmentStringSet(goodValues)
	naSet := assessmentStringSet(notApplicableValues)
	bad := make([]containerSecurityEvidence, 0)
	unknown := make([]containerSecurityEvidence, 0)
	na := make([]containerSecurityEvidence, 0)
	good := make([]containerSecurityEvidence, 0)
	for _, item := range items {
		state := strings.ToUpper(strings.TrimSpace(selector(item.Record)))
		if _, ok := badSet[state]; ok {
			bad = append(bad, item)
			continue
		}
		if _, ok := goodSet[state]; ok {
			good = append(good, item)
			continue
		}
		if _, ok := naSet[state]; ok {
			na = append(na, item)
			continue
		}
		unknown = append(unknown, item)
	}
	if len(bad) > 0 {
		desc, keys := containerSecurityDescriptions(bad, label+" weakened")
		return Evaluation{Status: badStatus, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d container(s) have weakened %s: %s", len(bad), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := containerSecurityDescriptions(unknown, label+" unresolved")
		keys = append(keys, degradedContainerSecuritySources(idx)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%s could not be resolved for %d observed container(s): %s", label, len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if degraded := degradedContainerSecuritySources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: label + " assessment is incomplete because one or more local runtime security providers are unavailable", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if len(items) == 0 {
		return noContainerSecurityEvaluation(idx, label)
	}
	if len(good) == 0 && len(na) > 0 {
		_, keys := containerSecurityDescriptions(na, label+" not applicable")
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%s is not applicable to %d observed container(s)", label, len(na)), Applicability: NotApplicable, EvidenceKeys: keys}
	}
	all := append(append([]containerSecurityEvidence{}, good...), na...)
	_, keys := containerSecurityDescriptions(all, label)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed container(s) retain acceptable %s posture", len(items), label), Applicability: Applicable, EvidenceKeys: keys}
}

func assessmentStringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

type containerSecurityEvidence struct {
	Key    string
	Record containerinv.SecurityPosture
}

type containerStateSelector func(containerinv.SecurityPosture) (value string, unknown bool)

func evaluateContainerSecurityState(idx Index, label string, badStatus Status, selector containerStateSelector) Evaluation {
	items := containerSecurityItems(idx)
	bad := make([]containerSecurityEvidence, 0)
	unknown := make([]containerSecurityEvidence, 0)
	for _, item := range items {
		value, unresolved := selector(item.Record)
		if unresolved {
			unknown = append(unknown, item)
			continue
		}
		if strings.EqualFold(value, "TRUE") {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := containerSecurityDescriptions(bad, label)
		return Evaluation{Status: badStatus, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d container(s) have %s: %s", len(bad), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := containerSecurityDescriptions(unknown, label+" unresolved")
		keys = append(keys, degradedContainerSecuritySources(idx)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%s could not be resolved for %d observed container(s): %s", label, len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if degraded := degradedContainerSecuritySources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: label + " assessment is incomplete because one or more local runtime security providers are unavailable", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if len(items) == 0 {
		return noContainerSecurityEvaluation(idx, label)
	}
	_, keys := containerSecurityDescriptions(items, label)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed container(s) do not have %s", len(items), label), Applicability: Applicable, EvidenceKeys: keys}
}

type containerMountStateSelector func(containerinv.SecurityPosture) string

func evaluateContainerMountRisk(idx Index, tag, label string, badStatus Status, selector containerMountStateSelector) Evaluation {
	items := containerSecurityItems(idx)
	bad := make([]containerSecurityEvidence, 0)
	unknown := make([]containerSecurityEvidence, 0)
	for _, item := range items {
		state := selector(item.Record)
		if item.Record.MountAssessmentState != "OBSERVED" || state == "UNKNOWN" {
			unknown = append(unknown, item)
			continue
		}
		if state == "TRUE" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc := make([]string, 0, minInt(len(bad), 12))
		keys := make([]string, 0, minInt(len(bad), 64))
		for i, item := range bad {
			if i < 12 {
				desc = append(desc, containerMountDescription(item.Record, tag, label))
			}
			if i < 64 {
				keys = append(keys, item.Key)
			}
		}
		if len(bad) > 12 {
			desc = append(desc, fmt.Sprintf("+%d more", len(bad)-12))
		}
		return Evaluation{Status: badStatus, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d container(s) have %s: %s", len(bad), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(unknown) > 0 {
		desc, keys := containerSecurityDescriptions(unknown, label+" unresolved")
		keys = append(keys, degradedContainerSecuritySources(idx)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%s could not be resolved for %d observed container(s): %s", label, len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if degraded := degradedContainerSecuritySources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: label + " assessment is incomplete because one or more local runtime security providers are unavailable", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if len(items) == 0 {
		return noContainerSecurityEvaluation(idx, label)
	}
	_, keys := containerSecurityDescriptions(items, label)
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed container(s) do not have %s", len(items), label), Applicability: Applicable, EvidenceKeys: keys}
}

func containerMountDescription(c containerinv.SecurityPosture, tag, label string) string {
	parts := make([]string, 0, 4)
	for _, m := range c.Mounts {
		match := false
		for _, risk := range m.RiskTags {
			if risk == tag {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		access := strings.ToLower(strings.ReplaceAll(m.Access, "_", "-"))
		parts = append(parts, m.Source+" -> "+m.Destination+" ["+access+"]")
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return containerSecurityLabel(c) + " [" + label + "]"
	}
	return containerSecurityLabel(c) + " [" + strings.Join(parts, ", ") + "]"
}

func evaluateDangerousContainerCapabilities(idx Index) Evaluation {
	items := containerSecurityItems(idx)
	bad := make([]containerSecurityEvidence, 0)
	unknown := make([]containerSecurityEvidence, 0)
	for _, item := range items {
		if item.Record.CapabilityAssessmentState != "OBSERVED" {
			unknown = append(unknown, item)
			continue
		}
		if len(item.Record.DangerousCapabilities) > 0 {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc := make([]string, 0, minInt(len(bad), 12))
		keys := make([]string, 0, minInt(len(bad), 64))
		for i, item := range bad {
			if i < 12 {
				desc = append(desc, containerSecurityLabel(item.Record)+" ["+strings.Join(item.Record.DangerousCapabilities, ",")+"]")
			}
			if i < 64 {
				keys = append(keys, item.Key)
			}
		}
		if len(bad) > 12 {
			desc = append(desc, fmt.Sprintf("+%d more", len(bad)-12))
		}
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d container(s) explicitly add high-risk capabilities: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(unknown) > 0 {
		desc, keys := containerSecurityDescriptions(unknown, "capability additions unresolved")
		keys = append(keys, degradedContainerSecuritySources(idx)...)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("capability additions could not be resolved for %d observed container(s): %s", len(unknown), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if degraded := degradedContainerSecuritySources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "dangerous capability assessment is incomplete because one or more local runtime security providers are unavailable", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if len(items) == 0 {
		return noContainerSecurityEvaluation(idx, "dangerous capability additions")
	}
	_, keys := containerSecurityDescriptions(items, "capabilities")
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed container(s) do not explicitly add a capability in the high-risk set", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func containerSecurityItems(idx Index) []containerSecurityEvidence {
	out := make([]containerSecurityEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.security.") || obs.State != evidence.StateObserved {
			continue
		}
		rec, ok := obs.Value.(containerinv.SecurityPosture)
		if !ok {
			continue
		}
		out = append(out, containerSecurityEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Runtime != out[j].Record.Runtime {
			return out[i].Record.Runtime < out[j].Record.Runtime
		}
		if out[i].Record.Name != out[j].Record.Name {
			return out[i].Record.Name < out[j].Record.Name
		}
		return out[i].Record.RuntimeContainerID < out[j].Record.RuntimeContainerID
	})
	return out
}

func degradedContainerSecuritySources(idx Index) []string {
	keys := make([]string, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "container.source.") || !strings.HasSuffix(key, "-security") {
			continue
		}
		switch obs.State {
		case evidence.StateObserved, evidence.StateNotApplicable:
			continue
		default:
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func noContainerSecurityEvaluation(idx Index, label string) Evaluation {
	if degraded := degradedContainerSecuritySources(idx); len(degraded) > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: label + " cannot be assessed because local container security inventory is incomplete", Applicability: Applicable, EvidenceKeys: degraded}
	}
	if obs, ok := idx["container.summary"]; ok && obs.State == evidence.StateObserved {
		if summary, ok := obs.Value.(containerinv.Summary); ok && summary.Containers == 0 {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local container instances were observed", Applicability: NotApplicable, EvidenceKeys: []string{"container.summary"}}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "container instances were observed but no normalized security posture records are available", Applicability: Applicable, EvidenceKeys: []string{"container.summary"}}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "container security inventory is missing", Applicability: Undetermined}
}

func containerSecurityDescriptions(items []containerSecurityEvidence, label string) ([]string, []string) {
	const maxDescriptions = 12
	const maxKeys = 64
	desc := make([]string, 0, minInt(len(items), maxDescriptions)+1)
	keys := make([]string, 0, minInt(len(items), maxKeys))
	for i, item := range items {
		if i < maxDescriptions {
			desc = append(desc, containerSecurityLabel(item.Record)+" ["+label+"]")
		}
		if i < maxKeys {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > maxDescriptions {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-maxDescriptions))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func containerSecurityLabel(c containerinv.SecurityPosture) string {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = c.RuntimeContainerID
		if len(name) > 16 {
			name = name[:16]
		}
	}
	if c.Namespace != "" {
		return c.Runtime + "/" + c.Namespace + "/" + name
	}
	return c.Runtime + "/" + name
}

func boolWord(v bool) string {
	if v {
		return "TRUE"
	}
	return "FALSE"
}

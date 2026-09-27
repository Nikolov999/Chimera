package containers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	networkinv "github.com/Nikolov999/chimera/internal/network"
)

const (
	SchemaVersion         = "chimera.containers/v1"
	CollectorName         = "container-runtime"
	CollectorVersion      = "containers/phase095-v1"
	maxRuntimes           = 16
	maxContainers         = 4096
	maxConfigs            = 128
	maxSecurity           = 512
	maxRuntimeEndpoints   = 64
	maxMountsPerContainer = 128
)

type Runtime struct {
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	BinaryPath        string              `json:"binary_path,omitempty"`
	Version           string              `json:"version,omitempty"`
	InstallationState string              `json:"installation_state"`
	RuntimeState      string              `json:"runtime_state"`
	Accessibility     string              `json:"accessibility"`
	Endpoint          string              `json:"endpoint,omitempty"`
	EndpointKind      string              `json:"endpoint_kind,omitempty"`
	RootlessState     string              `json:"rootless_state"`
	CollectionSource  string              `json:"collection_source"`
	Confidence        evidence.Confidence `json:"confidence"`
	Reason            string              `json:"reason,omitempty"`
}

type Container struct {
	ID                 string              `json:"id"`
	Runtime            string              `json:"runtime"`
	RuntimeContainerID string              `json:"runtime_container_id"`
	Namespace          string              `json:"namespace,omitempty"`
	Name               string              `json:"name,omitempty"`
	Image              string              `json:"image,omitempty"`
	State              string              `json:"state"`
	Status             string              `json:"status,omitempty"`
	PID                int                 `json:"pid,omitempty"`
	CollectionSource   string              `json:"collection_source"`
	Confidence         evidence.Confidence `json:"confidence"`
}

// MountPosture contains host-path mount metadata only. Chimera never reads mounted
// content. RiskTags are deterministic path/category classifications used by the
// /090 rules.
type MountPosture struct {
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Access      string   `json:"access"`
	Propagation string   `json:"propagation,omitempty"`
	RiskTags    []string `json:"risk_tags,omitempty"`
}

// SecurityPosture contains only non-secret container execution-boundary metadata.
// It is collected from explicit local runtime inspection and never from container
// filesystems, environment-variable values, mounted secret material, or remote
// runtime endpoints.
type SecurityPosture struct {
	ID                            string              `json:"id"`
	Runtime                       string              `json:"runtime"`
	RuntimeContainerID            string              `json:"runtime_container_id"`
	Namespace                     string              `json:"namespace,omitempty"`
	Name                          string              `json:"name,omitempty"`
	State                         evidence.State      `json:"state"`
	PrivilegedState               string              `json:"privileged_state"`
	ConfiguredUser                string              `json:"configured_user,omitempty"`
	RootExecutionState            string              `json:"root_execution_state"`
	PIDNamespace                  string              `json:"pid_namespace"`
	NetworkNamespace              string              `json:"network_namespace"`
	UserNamespace                 string              `json:"user_namespace"`
	CapabilityAssessmentState     string              `json:"capability_assessment_state"`
	AddedCapabilities             []string            `json:"added_capabilities,omitempty"`
	DroppedCapabilities           []string            `json:"dropped_capabilities,omitempty"`
	DangerousCapabilities         []string            `json:"dangerous_capabilities,omitempty"`
	CapabilityBoundingState       string              `json:"capability_bounding_state"`
	SeccompState                  string              `json:"seccomp_state"`
	SeccompProfile                string              `json:"seccomp_profile,omitempty"`
	MandatoryAccessControlState   string              `json:"mandatory_access_control_state"`
	AppArmorProfile               string              `json:"apparmor_profile,omitempty"`
	SELinuxProcessLabel           string              `json:"selinux_process_label,omitempty"`
	ReadOnlyRootFSState           string              `json:"read_only_rootfs_state"`
	NoNewPrivilegesState          string              `json:"no_new_privileges_state"`
	DeviceCount                   int                 `json:"device_count"`
	DeviceCgroupRuleCount         int                 `json:"device_cgroup_rule_count"`
	UnrestrictedDeviceAccessState string              `json:"unrestricted_device_access_state"`
	MountAssessmentState          string              `json:"mount_assessment_state"`
	MountCount                    int                 `json:"mount_count"`
	MountsTruncated               bool                `json:"mounts_truncated"`
	Mounts                        []MountPosture      `json:"mounts,omitempty"`
	HostRootMountState            string              `json:"host_root_mount_state"`
	RuntimeSocketMountState       string              `json:"runtime_socket_mount_state"`
	CredentialMountState          string              `json:"credential_mount_state"`
	DeviceMountState              string              `json:"device_mount_state"`
	SensitiveHostPathMountState   string              `json:"sensitive_host_path_mount_state"`
	CollectionSource              string              `json:"collection_source"`
	Confidence                    evidence.Confidence `json:"confidence"`
	Reason                        string              `json:"reason,omitempty"`
}

// RuntimeEndpointPosture describes only local container-runtime control-endpoint
// metadata. never opens a runtime API over the network and never
// changes socket/pipe ACLs. Network listener exposure is correlated separately
// from the normalized local network inventory.
type RuntimeEndpointPosture struct {
	ID                        string              `json:"id"`
	Runtime                   string              `json:"runtime"`
	Endpoint                  string              `json:"endpoint"`
	EndpointKind              string              `json:"endpoint_kind"`
	State                     evidence.State      `json:"state"`
	PermissionAssessmentState string              `json:"permission_assessment_state"`
	Mode                      string              `json:"mode,omitempty"`
	OwnerUID                  string              `json:"owner_uid,omitempty"`
	OwnerGID                  string              `json:"owner_gid,omitempty"`
	OwnerAssessmentState      string              `json:"owner_assessment_state"`
	WorldWritableState        string              `json:"world_writable_state"`
	GroupWritableState        string              `json:"group_writable_state"`
	LocalTransportState       string              `json:"local_transport_state"`
	CollectionSource          string              `json:"collection_source"`
	Confidence                evidence.Confidence `json:"confidence"`
	Reason                    string              `json:"reason,omitempty"`
}

type ConfigFile struct {
	ID               string              `json:"id"`
	Runtime          string              `json:"runtime"`
	Path             string              `json:"path"`
	Exists           bool                `json:"exists"`
	ReadableMetadata bool                `json:"readable_metadata"`
	SizeBytes        int64               `json:"size_bytes,omitempty"`
	Mode             string              `json:"mode,omitempty"`
	ModifiedAt       *time.Time          `json:"modified_at,omitempty"`
	State            evidence.State      `json:"state"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Runtimes                      int `json:"runtimes"`
	InstalledRuntimes             int `json:"installed_runtimes"`
	RunningRuntimes               int `json:"running_runtimes"`
	AccessibleRuntimes            int `json:"accessible_runtimes"`
	RootlessRuntimes              int `json:"rootless_runtimes"`
	Containers                    int `json:"containers"`
	RunningContainers             int `json:"running_containers"`
	StoppedContainers             int `json:"stopped_containers"`
	UnknownContainers             int `json:"unknown_containers"`
	SecurityPostures              int `json:"security_postures"`
	Privileged                    int `json:"privileged_containers"`
	RootExecution                 int `json:"root_execution_containers"`
	HostPID                       int `json:"host_pid_namespace_containers"`
	HostNetwork                   int `json:"host_network_namespace_containers"`
	HostUserNamespace             int `json:"host_user_namespace_containers"`
	DangerousCaps                 int `json:"dangerous_capability_containers"`
	UnboundedCaps                 int `json:"unbounded_capability_containers"`
	SeccompUnconfined             int `json:"seccomp_unconfined_containers"`
	MACUnconfined                 int `json:"mandatory_access_unconfined_containers"`
	WritableRootFS                int `json:"writable_rootfs_containers"`
	NewPrivilegesAllowed          int `json:"new_privileges_allowed_containers"`
	UnrestrictedDevice            int `json:"unrestricted_device_containers"`
	HostRootMounts                int `json:"host_root_mount_containers"`
	RuntimeSocketMounts           int `json:"runtime_socket_mount_containers"`
	CredentialMounts              int `json:"credential_mount_containers"`
	DeviceMounts                  int `json:"device_mount_containers"`
	SensitiveHostMounts           int `json:"sensitive_host_path_mount_containers"`
	RuntimeEndpoints              int `json:"runtime_endpoints"`
	EndpointPermissions           int `json:"endpoint_permissions_assessed"`
	WorldWritableSockets          int `json:"world_writable_runtime_endpoints"`
	GroupWritableSockets          int `json:"group_writable_runtime_endpoints"`
	EndpointUnknown               int `json:"runtime_endpoint_permissions_unknown"`
	ConfigFiles                   int `json:"config_files"`
	KubernetesObserved            int `json:"kubernetes_observed"`
	Kubeconfigs                   int `json:"kubeconfigs"`
	KubeconfigsPermissionAssessed int `json:"kubeconfigs_permissions_assessed"`
	BroadKubeconfigRead           int `json:"broad_kubeconfig_read"`
	BroadKubeconfigWrite          int `json:"broad_kubeconfig_write"`
	EmbeddedCredentialConfigs     int `json:"embedded_credential_configs"`
	KubernetesCredentialPaths     int `json:"kubernetes_credential_paths"`
	BroadCredentialPathRead       int `json:"broad_credential_path_read"`
	BroadCredentialPathWrite      int `json:"broad_credential_path_write"`
	Hypervisors                   int `json:"hypervisors"`
	RunningHypervisors            int `json:"running_hypervisors"`
	HypervisorInterfaces          int `json:"hypervisor_management_interfaces"`
	BroadHypervisorInterfaces     int `json:"broad_hypervisor_management_interfaces"`
	GroupControlledInterfaces     int `json:"group_controlled_hypervisor_management_interfaces"`
	DeveloperSurfaces             int `json:"developer_surfaces"`
	DeveloperNetworkReachable     int `json:"developer_network_reachable"`
	DeveloperLocalOnly            int `json:"developer_local_only"`
	DeveloperUnknownExposure      int `json:"developer_unknown_exposure"`
	DegradedProviders             int `json:"degraded_providers"`
}

type Inventory struct {
	Schema                    string                            `json:"schema"`
	EvidenceSchema            string                            `json:"evidence_schema"`
	Collector                 string                            `json:"collector"`
	CollectorVersion          string                            `json:"collector_version"`
	Platform                  string                            `json:"platform"`
	Architecture              string                            `json:"architecture"`
	CollectedAt               time.Time                         `json:"collected_at"`
	Runtimes                  []Runtime                         `json:"runtimes"`
	Containers                []Container                       `json:"containers"`
	Security                  []SecurityPosture                 `json:"security"`
	RuntimeEndpoints          []RuntimeEndpointPosture          `json:"runtime_endpoints"`
	ConfigFiles               []ConfigFile                      `json:"config_files"`
	Kubernetes                KubernetesPosture                 `json:"kubernetes"`
	Kubeconfigs               []KubeconfigPosture               `json:"kubeconfigs"`
	KubernetesCredentialPaths []KubernetesCredentialPathPosture `json:"kubernetes_credential_paths"`
	Hypervisors               []HypervisorPosture               `json:"hypervisors"`
	HypervisorInterfaces      []HypervisorManagementInterface   `json:"hypervisor_management_interfaces"`
	DeveloperSurfaces         []DeveloperSurface                `json:"developer_surfaces"`
	Sources                   []SourceStatus                    `json:"sources"`
	Summary                   Summary                           `json:"summary"`
	Evidence                  []evidence.Observation            `json:"evidence"`
	Degraded                  []string                          `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	return collect(ctx, nil)
}

// CollectWithNetwork reuses an already-collected normalized listener inventory.
// The full assessment uses this on Windows so the containers/developer-surface
// provider never launches a second hidden network acquisition behind the scan
// scheduler. Standalone container collection retains the legacy self-contained
// behavior through Collect.
func CollectWithNetwork(ctx context.Context, networkInventory networkinv.Inventory) Inventory {
	return collect(ctx, &networkInventory)
}

func collect(ctx context.Context, sharedNetwork *networkinv.Inventory) Inventory {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
	}
	collectPlatform(ctx, &inv)
	collectKubernetesPosture(ctx, &inv)
	collectVirtualizationPosture(ctx, &inv)
	collectDeveloperSurfaces(ctx, &inv, sharedNetwork)
	inv.Runtimes = normalizeRuntimes(inv.Runtimes)
	inv.Containers = normalizeContainers(inv.Containers)
	inv.Security = normalizeSecurity(inv.Security)
	inv.RuntimeEndpoints = normalizeRuntimeEndpoints(inv.RuntimeEndpoints)
	inv.ConfigFiles = normalizeConfigs(inv.ConfigFiles)
	inv.Kubernetes = normalizeKubernetesPosture(inv.Kubernetes)
	inv.Kubeconfigs = normalizeKubeconfigs(inv.Kubeconfigs)
	inv.KubernetesCredentialPaths = normalizeKubernetesCredentialPaths(inv.KubernetesCredentialPaths)
	inv.Hypervisors = normalizeHypervisors(inv.Hypervisors)
	inv.HypervisorInterfaces = normalizeHypervisorInterfaces(inv.HypervisorInterfaces)
	inv.DeveloperSurfaces = normalizeDeveloperSurfaces(inv.DeveloperSurfaces)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected container-runtime collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("container inventory identity is incomplete")
	}
	if len(inv.Runtimes) > maxRuntimes || len(inv.Containers) > maxContainers || len(inv.Security) > maxSecurity || len(inv.RuntimeEndpoints) > maxRuntimeEndpoints || len(inv.ConfigFiles) > maxConfigs || len(inv.Kubeconfigs) > maxKubeconfigs || len(inv.KubernetesCredentialPaths) > maxCredentialPaths || len(inv.Hypervisors) > maxHypervisors || len(inv.HypervisorInterfaces) > maxHypervisorInterfaces || len(inv.DeveloperSurfaces) > maxDeveloperSurfaces {
		return fmt.Errorf("container inventory exceeds bounded record limits")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, r := range inv.Runtimes {
		if r.ID == "" || r.Name == "" || r.InstallationState == "" || r.RuntimeState == "" || r.Accessibility == "" || r.RootlessState == "" || r.CollectionSource == "" || r.Confidence == "" {
			return fmt.Errorf("container runtime record %d is incomplete", i)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate container runtime id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if last != "" && r.ID < last {
			return fmt.Errorf("container runtime records are not deterministically ordered")
		}
		last = r.ID
	}
	seen = map[string]struct{}{}
	last = ""
	for i, c := range inv.Containers {
		if c.ID == "" || c.Runtime == "" || c.RuntimeContainerID == "" || c.State == "" || c.CollectionSource == "" || c.Confidence == "" || c.PID < 0 {
			return fmt.Errorf("container record %d is incomplete", i)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate container id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && containerSortKey(c) < last {
			return fmt.Errorf("container records are not deterministically ordered")
		}
		last = containerSortKey(c)
	}
	seen = map[string]struct{}{}
	last = ""
	for i, c := range inv.Security {
		if c.ID == "" || c.Runtime == "" || c.RuntimeContainerID == "" || c.State == "" || c.PrivilegedState == "" || c.RootExecutionState == "" || c.PIDNamespace == "" || c.NetworkNamespace == "" || c.UserNamespace == "" || c.CapabilityAssessmentState == "" || c.CapabilityBoundingState == "" || c.SeccompState == "" || c.MandatoryAccessControlState == "" || c.ReadOnlyRootFSState == "" || c.NoNewPrivilegesState == "" || c.UnrestrictedDeviceAccessState == "" || c.MountAssessmentState == "" || c.HostRootMountState == "" || c.RuntimeSocketMountState == "" || c.CredentialMountState == "" || c.DeviceMountState == "" || c.SensitiveHostPathMountState == "" || c.CollectionSource == "" || c.Confidence == "" || c.DeviceCount < 0 || c.DeviceCgroupRuleCount < 0 || c.MountCount < 0 {
			return fmt.Errorf("container security posture %d is incomplete", i)
		}
		if len(c.Mounts) > maxMountsPerContainer || c.MountCount < len(c.Mounts) {
			return fmt.Errorf("container security posture %q has invalid bounded mount metadata", c.ID)
		}
		if c.MountsTruncated && c.MountCount <= len(c.Mounts) {
			return fmt.Errorf("container security posture %q marks mounts truncated without a larger total", c.ID)
		}
		if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("container security posture %q requires degradation reason", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate container security id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && securitySortKey(c) < last {
			return fmt.Errorf("container security records are not deterministically ordered")
		}
		last = securitySortKey(c)
	}

	seen = map[string]struct{}{}
	last = ""
	for i, ep := range inv.RuntimeEndpoints {
		if ep.ID == "" || ep.Runtime == "" || ep.Endpoint == "" || ep.EndpointKind == "" || ep.State == "" || ep.PermissionAssessmentState == "" || ep.OwnerAssessmentState == "" || ep.WorldWritableState == "" || ep.GroupWritableState == "" || ep.LocalTransportState == "" || ep.CollectionSource == "" || ep.Confidence == "" {
			return fmt.Errorf("container runtime endpoint posture %d is incomplete", i)
		}
		if ep.State != evidence.StateObserved && strings.TrimSpace(ep.Reason) == "" {
			return fmt.Errorf("container runtime endpoint posture %q requires degradation reason", ep.ID)
		}
		if _, ok := seen[ep.ID]; ok {
			return fmt.Errorf("duplicate container runtime endpoint id %q", ep.ID)
		}
		seen[ep.ID] = struct{}{}
		if last != "" && runtimeEndpointSortKey(ep) < last {
			return fmt.Errorf("container runtime endpoint records are not deterministically ordered")
		}
		last = runtimeEndpointSortKey(ep)
	}

	seen = map[string]struct{}{}
	last = ""
	for i, c := range inv.ConfigFiles {
		if c.ID == "" || c.Runtime == "" || c.Path == "" || c.State == "" || c.CollectionSource == "" || c.Confidence == "" {
			return fmt.Errorf("container config record %d is incomplete", i)
		}
		if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("container config %q requires degradation reason", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate container config id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if last != "" && configSortKey(c) < last {
			return fmt.Errorf("container config records are not deterministically ordered")
		}
		last = configSortKey(c)
	}
	if inv.Kubernetes.ID == "" || inv.Kubernetes.State == "" || inv.Kubernetes.InstallationState == "" || inv.Kubernetes.Applicability == "" || inv.Kubernetes.CollectionSource == "" || inv.Kubernetes.Confidence == "" {
		return fmt.Errorf("Kubernetes posture is incomplete")
	}
	if inv.Kubernetes.State != evidence.StateObserved && inv.Kubernetes.State != evidence.StateNotApplicable && strings.TrimSpace(inv.Kubernetes.Reason) == "" {
		return fmt.Errorf("Kubernetes posture requires degradation reason")
	}
	seen = map[string]struct{}{}
	last = ""
	for i, c := range inv.Kubeconfigs {
		if c.ID == "" || c.Path == "" || c.Scope == "" || c.State == "" || c.PermissionAssessmentState == "" || c.OwnerAssessmentState == "" || c.WorldReadableState == "" || c.WorldWritableState == "" || c.GroupReadableState == "" || c.GroupWritableState == "" || c.StructureAssessmentState == "" || c.EmbeddedCredentialState == "" || c.CollectionSource == "" || c.Confidence == "" || c.CredentialReferenceCount < 0 || c.ServerEndpointCount < 0 || c.LocalServerEndpointCount < 0 || c.LocalServerEndpointCount > c.ServerEndpointCount {
			return fmt.Errorf("kubeconfig posture %d is incomplete", i)
		}
		if c.State != evidence.StateObserved && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("kubeconfig posture %q requires degradation reason", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate kubeconfig posture id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		key := strings.ToLower(c.Path)
		if last != "" && key < last {
			return fmt.Errorf("kubeconfig posture records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, p := range inv.KubernetesCredentialPaths {
		if p.ID == "" || p.KubeconfigID == "" || p.Kind == "" || p.Path == "" || p.State == "" || p.PermissionAssessmentState == "" || p.OwnerAssessmentState == "" || p.WorldReadableState == "" || p.WorldWritableState == "" || p.GroupReadableState == "" || p.GroupWritableState == "" || p.CollectionSource == "" || p.Confidence == "" {
			return fmt.Errorf("Kubernetes credential path posture %d is incomplete", i)
		}
		if p.State != evidence.StateObserved && strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("Kubernetes credential path posture %q requires degradation reason", p.ID)
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate Kubernetes credential path id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		key := p.Kind + "\x00" + strings.ToLower(p.Path)
		if last != "" && key < last {
			return fmt.Errorf("Kubernetes credential path records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, h := range inv.Hypervisors {
		if h.ID == "" || h.Name == "" || h.Kind == "" || h.State == "" || h.InstallationState == "" || h.RuntimeState == "" || h.ServiceState == "" || h.ManagementInterfaceState == "" || h.LocalAccessState == "" || h.CollectionSource == "" || h.Confidence == "" {
			return fmt.Errorf("hypervisor posture %d is incomplete", i)
		}
		if h.State != evidence.StateObserved && h.State != evidence.StateNotApplicable && strings.TrimSpace(h.Reason) == "" {
			return fmt.Errorf("hypervisor posture %q requires degradation reason", h.ID)
		}
		if _, ok := seen[h.ID]; ok {
			return fmt.Errorf("duplicate hypervisor posture id %q", h.ID)
		}
		seen[h.ID] = struct{}{}
		if last != "" && h.ID < last {
			return fmt.Errorf("hypervisor posture records are not deterministically ordered")
		}
		last = h.ID
	}
	seen = map[string]struct{}{}
	last = ""
	for i, h := range inv.HypervisorInterfaces {
		if h.ID == "" || h.Hypervisor == "" || h.Kind == "" || h.Endpoint == "" || h.State == "" || h.PermissionAssessmentState == "" || h.OwnerAssessmentState == "" || h.WorldWritableState == "" || h.GroupWritableState == "" || h.LocalAccessState == "" || h.CollectionSource == "" || h.Confidence == "" {
			return fmt.Errorf("hypervisor management interface %d is incomplete", i)
		}
		if h.State != evidence.StateObserved && strings.TrimSpace(h.Reason) == "" {
			return fmt.Errorf("hypervisor management interface %q requires degradation reason", h.ID)
		}
		if _, ok := seen[h.ID]; ok {
			return fmt.Errorf("duplicate hypervisor management interface id %q", h.ID)
		}
		seen[h.ID] = struct{}{}
		key := h.Hypervisor + "\x00" + h.Kind + "\x00" + strings.ToLower(h.Endpoint)
		if last != "" && key < last {
			return fmt.Errorf("hypervisor management interface records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, d := range inv.DeveloperSurfaces {
		if d.ID == "" || d.Kind == "" || d.Product == "" || d.PID < 0 || d.State == "" || d.ActivationState == "" || d.ListenerState == "" || d.BindingState == "" || d.ExposureState == "" || d.CollectionSource == "" || d.Confidence == "" {
			return fmt.Errorf("developer surface %d is incomplete", i)
		}
		if _, ok := seen[d.ID]; ok {
			return fmt.Errorf("duplicate developer surface id %q", d.ID)
		}
		seen[d.ID] = struct{}{}
		key := fmt.Sprintf("%010d\x00%s\x00%s\x00%s\x00%05d", d.PID, d.Kind, d.Product, d.LocalAddress, d.LocalPort)
		if last != "" && key < last {
			return fmt.Errorf("developer surface records are not deterministically ordered")
		}
		last = key
	}
	for i, src := range inv.Sources {
		if src.ID == "" || src.Source == "" || src.State == "" || src.ItemCount < 0 {
			return fmt.Errorf("container source %d is incomplete", i)
		}
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable && strings.TrimSpace(src.Reason) == "" {
			return fmt.Errorf("container source %q requires degradation reason", src.ID)
		}
	}
	if inv.Summary != summarize(inv) {
		return fmt.Errorf("container summary does not match inventory")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func normalizeRuntimes(in []Runtime) []Runtime {
	byID := map[string]Runtime{}
	for _, r := range in {
		r.Name = strings.ToLower(strings.TrimSpace(r.Name))
		if r.Name == "" {
			continue
		}
		r.ID = slug(fallback(r.ID, r.Name))
		r.BinaryPath = strings.TrimSpace(r.BinaryPath)
		r.Version = strings.TrimSpace(r.Version)
		r.InstallationState = normalizeWord(fallback(r.InstallationState, "NOT_OBSERVED"))
		r.RuntimeState = normalizeWord(fallback(r.RuntimeState, "UNKNOWN"))
		r.Accessibility = normalizeWord(fallback(r.Accessibility, "UNKNOWN"))
		r.RootlessState = normalizeWord(fallback(r.RootlessState, "UNKNOWN"))
		r.Endpoint = strings.TrimSpace(r.Endpoint)
		r.EndpointKind = normalizeWordOptional(r.EndpointKind)
		r.CollectionSource = fallback(r.CollectionSource, "local runtime metadata")
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceMedium
		}
		r.Reason = strings.TrimSpace(r.Reason)
		byID[r.ID] = r
	}
	out := make([]Runtime, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > maxRuntimes {
		out = out[:maxRuntimes]
	}
	return out
}

func normalizeContainers(in []Container) []Container {
	byID := map[string]Container{}
	for _, c := range in {
		c.Runtime = strings.ToLower(strings.TrimSpace(c.Runtime))
		c.RuntimeContainerID = strings.TrimSpace(c.RuntimeContainerID)
		if c.Runtime == "" || c.RuntimeContainerID == "" {
			continue
		}
		c.Namespace = strings.TrimSpace(c.Namespace)
		c.Name = strings.TrimSpace(c.Name)
		c.Image = strings.TrimSpace(c.Image)
		c.State = normalizeContainerState(c.State)
		c.Status = strings.TrimSpace(c.Status)
		c.CollectionSource = fallback(c.CollectionSource, "local container runtime metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		c.ID = stableID(c.Runtime, c.Namespace, c.RuntimeContainerID)
		byID[c.ID] = c
	}
	out := make([]Container, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return containerSortKey(out[i]) < containerSortKey(out[j]) })
	if len(out) > maxContainers {
		out = out[:maxContainers]
	}
	return out
}

func normalizeSecurity(in []SecurityPosture) []SecurityPosture {
	byID := map[string]SecurityPosture{}
	for _, c := range in {
		c.Runtime = strings.ToLower(strings.TrimSpace(c.Runtime))
		c.RuntimeContainerID = strings.TrimSpace(c.RuntimeContainerID)
		if c.Runtime == "" || c.RuntimeContainerID == "" {
			continue
		}
		c.Namespace = strings.TrimSpace(c.Namespace)
		c.Name = strings.TrimPrefix(strings.TrimSpace(c.Name), "/")
		c.ID = stableID(c.Runtime, c.Namespace, c.RuntimeContainerID)
		if c.State == "" {
			c.State = evidence.StateObserved
		}
		c.PrivilegedState = normalizeTriState(c.PrivilegedState)
		c.RootExecutionState = normalizeTriState(c.RootExecutionState)
		c.PIDNamespace = normalizeNamespaceState(c.PIDNamespace)
		c.NetworkNamespace = normalizeNamespaceState(c.NetworkNamespace)
		c.UserNamespace = normalizeNamespaceState(c.UserNamespace)
		c.CapabilityAssessmentState = normalizeObservedState(c.CapabilityAssessmentState)
		c.CapabilityBoundingState = normalizeCapabilityBoundingState(c.CapabilityBoundingState)
		c.SeccompState = normalizeSeccompState(c.SeccompState)
		c.MandatoryAccessControlState = normalizeMACState(c.MandatoryAccessControlState)
		c.ReadOnlyRootFSState = normalizeTriState(c.ReadOnlyRootFSState)
		c.NoNewPrivilegesState = normalizeTriState(c.NoNewPrivilegesState)
		c.UnrestrictedDeviceAccessState = normalizeTriState(c.UnrestrictedDeviceAccessState)
		c.MountAssessmentState = normalizeObservedState(c.MountAssessmentState)
		c.Mounts = normalizeMounts(c.Mounts)
		if c.MountCount < len(c.Mounts) {
			c.MountCount = len(c.Mounts)
		}
		if c.MountsTruncated && c.MountCount <= len(c.Mounts) {
			c.MountsTruncated = false
		}
		c.HostRootMountState = normalizeTriState(c.HostRootMountState)
		c.RuntimeSocketMountState = normalizeTriState(c.RuntimeSocketMountState)
		c.CredentialMountState = normalizeTriState(c.CredentialMountState)
		c.DeviceMountState = normalizeTriState(c.DeviceMountState)
		c.SensitiveHostPathMountState = normalizeTriState(c.SensitiveHostPathMountState)
		c.ConfiguredUser = strings.TrimSpace(c.ConfiguredUser)
		c.AddedCapabilities = normalizeStringSet(c.AddedCapabilities)
		c.DroppedCapabilities = normalizeStringSet(c.DroppedCapabilities)
		c.DangerousCapabilities = normalizeStringSet(c.DangerousCapabilities)
		c.SeccompProfile = strings.TrimSpace(c.SeccompProfile)
		c.AppArmorProfile = strings.TrimSpace(c.AppArmorProfile)
		c.SELinuxProcessLabel = strings.TrimSpace(c.SELinuxProcessLabel)
		c.CollectionSource = fallback(c.CollectionSource, "local container security metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		c.Reason = strings.TrimSpace(c.Reason)
		byID[c.ID] = c
	}
	out := make([]SecurityPosture, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return securitySortKey(out[i]) < securitySortKey(out[j]) })
	if len(out) > maxSecurity {
		out = out[:maxSecurity]
	}
	return out
}

func normalizeMounts(in []MountPosture) []MountPosture {
	byKey := map[string]MountPosture{}
	for _, m := range in {
		m.Type = normalizeWordOptional(m.Type)
		m.Source = strings.TrimSpace(m.Source)
		m.Destination = strings.TrimSpace(m.Destination)
		m.Access = normalizeWord(fallback(m.Access, "UNKNOWN"))
		m.Propagation = normalizeWordOptional(m.Propagation)
		m.RiskTags = uniqueSortedUpper(m.RiskTags)
		if m.Source == "" && m.Destination == "" {
			continue
		}
		k := strings.ToLower(m.Type + "\x00" + m.Source + "\x00" + m.Destination)
		byKey[k] = m
	}
	out := make([]MountPosture, 0, len(byKey))
	for _, m := range byKey {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a := strings.ToLower(out[i].Source + "\x00" + out[i].Destination + "\x00" + out[i].Type)
		b := strings.ToLower(out[j].Source + "\x00" + out[j].Destination + "\x00" + out[j].Type)
		return a < b
	})
	if len(out) > maxMountsPerContainer {
		out = out[:maxMountsPerContainer]
	}
	return out
}

func normalizeRuntimeEndpoints(in []RuntimeEndpointPosture) []RuntimeEndpointPosture {
	byID := map[string]RuntimeEndpointPosture{}
	for _, ep := range in {
		ep.Runtime = strings.ToLower(strings.TrimSpace(ep.Runtime))
		ep.Endpoint = strings.TrimSpace(ep.Endpoint)
		ep.EndpointKind = normalizeWord(ep.EndpointKind)
		if ep.Runtime == "" || ep.Endpoint == "" || ep.EndpointKind == "" {
			continue
		}
		ep.ID = stableID(ep.Runtime, ep.EndpointKind, ep.Endpoint)
		if ep.State == "" {
			ep.State = evidence.StateObserved
		}
		ep.PermissionAssessmentState = normalizeAssessmentState(ep.PermissionAssessmentState)
		ep.OwnerAssessmentState = normalizeAssessmentState(ep.OwnerAssessmentState)
		ep.WorldWritableState = normalizeTriState(ep.WorldWritableState)
		ep.GroupWritableState = normalizeTriState(ep.GroupWritableState)
		ep.LocalTransportState = normalizeLocalTransportState(ep.LocalTransportState)
		ep.Mode = strings.TrimSpace(ep.Mode)
		ep.OwnerUID = strings.TrimSpace(ep.OwnerUID)
		ep.OwnerGID = strings.TrimSpace(ep.OwnerGID)
		ep.CollectionSource = fallback(ep.CollectionSource, "local runtime endpoint metadata")
		if ep.Confidence == "" {
			ep.Confidence = evidence.ConfidenceHigh
		}
		ep.Reason = strings.TrimSpace(ep.Reason)
		byID[ep.ID] = ep
	}
	out := make([]RuntimeEndpointPosture, 0, len(byID))
	for _, ep := range byID {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return runtimeEndpointSortKey(out[i]) < runtimeEndpointSortKey(out[j]) })
	if len(out) > maxRuntimeEndpoints {
		out = out[:maxRuntimeEndpoints]
	}
	return out
}

func normalizeAssessmentState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "OBSERVED", "UNKNOWN", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeLocalTransportState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "LOCAL_ONLY", "UNKNOWN":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeConfigs(in []ConfigFile) []ConfigFile {
	byID := map[string]ConfigFile{}
	for _, c := range in {
		c.Runtime = strings.ToLower(strings.TrimSpace(c.Runtime))
		c.Path = strings.TrimSpace(c.Path)
		if c.Runtime == "" || c.Path == "" {
			continue
		}
		if runtime.GOOS != "windows" {
			c.Path = filepath.Clean(c.Path)
		}
		c.ID = stableID("config", c.Runtime, c.Path)
		c.CollectionSource = fallback(c.CollectionSource, "local configuration-file metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		c.Reason = strings.TrimSpace(c.Reason)
		byID[c.ID] = c
	}
	out := make([]ConfigFile, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return configSortKey(out[i]) < configSortKey(out[j]) })
	if len(out) > maxConfigs {
		out = out[:maxConfigs]
	}
	return out
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	byID := map[string]SourceStatus{}
	for _, s := range in {
		s.ID = slug(s.ID)
		if s.ID == "" {
			continue
		}
		s.Source = fallback(s.Source, "local container provider")
		if s.State == "" {
			s.State = evidence.StateUnavailable
		}
		s.Reason = strings.TrimSpace(s.Reason)
		byID[s.ID] = s
	}
	out := make([]SourceStatus, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func summarize(inv Inventory) Summary {
	s := Summary{Runtimes: len(inv.Runtimes), Containers: len(inv.Containers), SecurityPostures: len(inv.Security), ConfigFiles: len(inv.ConfigFiles), Kubeconfigs: len(inv.Kubeconfigs), KubernetesCredentialPaths: len(inv.KubernetesCredentialPaths), Hypervisors: len(inv.Hypervisors), HypervisorInterfaces: len(inv.HypervisorInterfaces), DeveloperSurfaces: len(inv.DeveloperSurfaces)}
	for _, r := range inv.Runtimes {
		if r.InstallationState == "PRESENT" {
			s.InstalledRuntimes++
		}
		if r.RuntimeState == "RUNNING" {
			s.RunningRuntimes++
		}
		if r.Accessibility == "ACCESSIBLE" {
			s.AccessibleRuntimes++
		}
		if r.RootlessState == "TRUE" {
			s.RootlessRuntimes++
		}
	}
	for _, c := range inv.Containers {
		switch c.State {
		case "RUNNING":
			s.RunningContainers++
		case "STOPPED", "EXITED", "CREATED", "PAUSED":
			s.StoppedContainers++
		default:
			s.UnknownContainers++
		}
	}
	for _, c := range inv.Security {
		if c.State != evidence.StateObserved {
			continue
		}
		if c.PrivilegedState == "TRUE" {
			s.Privileged++
		}
		if c.RootExecutionState == "TRUE" {
			s.RootExecution++
		}
		if c.PIDNamespace == "HOST" {
			s.HostPID++
		}
		if c.NetworkNamespace == "HOST" {
			s.HostNetwork++
		}
		if c.UserNamespace == "HOST" {
			s.HostUserNamespace++
		}
		if len(c.DangerousCapabilities) > 0 {
			s.DangerousCaps++
		}
		if c.CapabilityBoundingState == "UNBOUNDED" {
			s.UnboundedCaps++
		}
		if c.SeccompState == "UNCONFINED" {
			s.SeccompUnconfined++
		}
		if c.MandatoryAccessControlState == "UNCONFINED" {
			s.MACUnconfined++
		}
		if c.ReadOnlyRootFSState == "FALSE" {
			s.WritableRootFS++
		}
		if c.NoNewPrivilegesState == "FALSE" {
			s.NewPrivilegesAllowed++
		}
		if c.UnrestrictedDeviceAccessState == "TRUE" {
			s.UnrestrictedDevice++
		}
		if c.HostRootMountState == "TRUE" {
			s.HostRootMounts++
		}
		if c.RuntimeSocketMountState == "TRUE" {
			s.RuntimeSocketMounts++
		}
		if c.CredentialMountState == "TRUE" {
			s.CredentialMounts++
		}
		if c.DeviceMountState == "TRUE" {
			s.DeviceMounts++
		}
		if c.SensitiveHostPathMountState == "TRUE" {
			s.SensitiveHostMounts++
		}
	}
	for _, ep := range inv.RuntimeEndpoints {
		s.RuntimeEndpoints++
		if ep.PermissionAssessmentState == "OBSERVED" {
			s.EndpointPermissions++
		} else {
			s.EndpointUnknown++
		}
		if ep.WorldWritableState == "TRUE" {
			s.WorldWritableSockets++
		}
		if ep.GroupWritableState == "TRUE" {
			s.GroupWritableSockets++
		}
	}
	if inv.Kubernetes.State == evidence.StateObserved {
		s.KubernetesObserved = 1
	}
	for _, c := range inv.Kubeconfigs {
		if c.PermissionAssessmentState == "OBSERVED" {
			s.KubeconfigsPermissionAssessed++
		}
		if c.WorldReadableState == "TRUE" || c.GroupReadableState == "TRUE" {
			s.BroadKubeconfigRead++
		}
		if c.WorldWritableState == "TRUE" || c.GroupWritableState == "TRUE" {
			s.BroadKubeconfigWrite++
		}
		if c.EmbeddedCredentialState == "TRUE" {
			s.EmbeddedCredentialConfigs++
		}
	}
	for _, p := range inv.KubernetesCredentialPaths {
		if p.WorldReadableState == "TRUE" || p.GroupReadableState == "TRUE" {
			s.BroadCredentialPathRead++
		}
		if p.WorldWritableState == "TRUE" || p.GroupWritableState == "TRUE" {
			s.BroadCredentialPathWrite++
		}
	}
	for _, h := range inv.Hypervisors {
		if h.RuntimeState == "RUNNING" {
			s.RunningHypervisors++
		}
	}
	for _, h := range inv.HypervisorInterfaces {
		switch h.LocalAccessState {
		case "BROAD":
			s.BroadHypervisorInterfaces++
		case "GROUP_CONTROLLED":
			s.GroupControlledInterfaces++
		}
	}
	for _, d := range inv.DeveloperSurfaces {
		switch d.ExposureState {
		case "NETWORK_REACHABLE":
			s.DeveloperNetworkReachable++
		case "LOCAL_ONLY":
			s.DeveloperLocalOnly++
		default:
			s.DeveloperUnknownExposure++
		}
	}
	for _, src := range inv.Sources {
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable {
			s.DegradedProviders++
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("container.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.summary", inv.Summary, "normalized container runtime inventory", at, evidence.ConfidenceHigh),
	}
	if len(inv.Sources) == 0 {
		out = append(out, evidence.NewState("container.inventory.provider", evidence.StateUnavailable, "local container providers", at, evidence.ConfidenceLow, "no local container provider returned a status"))
	}
	for _, src := range inv.Sources {
		key := "container.source." + src.ID
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState(key, src.State, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "container provider metadata unavailable")))
		}
	}
	for _, r := range inv.Runtimes {
		out = append(out, evidence.NewObserved("container.runtime."+r.ID, r, r.CollectionSource, at, r.Confidence))
	}
	for _, c := range inv.Containers {
		out = append(out, evidence.NewObserved("container.instance."+c.ID, c, c.CollectionSource, at, c.Confidence))
	}
	for _, c := range inv.Security {
		key := "container.security." + c.ID
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c, c.CollectionSource, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.CollectionSource, at, c.Confidence, fallback(c.Reason, "container security metadata unavailable")))
		}
	}
	for _, ep := range inv.RuntimeEndpoints {
		key := "container.runtime_endpoint." + ep.ID
		if ep.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, ep, ep.CollectionSource, at, ep.Confidence))
		} else {
			out = append(out, evidence.NewState(key, ep.State, ep.CollectionSource, at, ep.Confidence, fallback(ep.Reason, "runtime endpoint metadata unavailable")))
		}
	}
	for _, c := range inv.ConfigFiles {
		key := "container.config." + c.ID
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c, c.CollectionSource, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.CollectionSource, at, c.Confidence, fallback(c.Reason, "container configuration metadata unavailable")))
		}
	}
	kubeKey := "container.orchestration.kubernetes"
	if inv.Kubernetes.State == evidence.StateObserved {
		out = append(out, evidence.NewObserved(kubeKey, inv.Kubernetes, inv.Kubernetes.CollectionSource, at, inv.Kubernetes.Confidence))
	} else {
		out = append(out, evidence.NewState(kubeKey, inv.Kubernetes.State, inv.Kubernetes.CollectionSource, at, inv.Kubernetes.Confidence, fallback(inv.Kubernetes.Reason, "Kubernetes was not observed locally")))
	}
	for _, c := range inv.Kubeconfigs {
		key := "container.orchestration.kubeconfig." + c.ID
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c, c.CollectionSource, at, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.CollectionSource, at, c.Confidence, fallback(c.Reason, "Kubernetes configuration posture unavailable")))
		}
	}
	for _, p := range inv.KubernetesCredentialPaths {
		key := "container.orchestration.credential_path." + p.ID
		if p.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, p, p.CollectionSource, at, p.Confidence))
		} else {
			out = append(out, evidence.NewState(key, p.State, p.CollectionSource, at, p.Confidence, fallback(p.Reason, "Kubernetes credential path posture unavailable")))
		}
	}
	for _, h := range inv.Hypervisors {
		key := "container.virtualization.hypervisor." + h.ID
		if h.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, h, h.CollectionSource, at, h.Confidence))
		} else {
			out = append(out, evidence.NewState(key, h.State, h.CollectionSource, at, h.Confidence, fallback(h.Reason, "hypervisor technology not observed")))
		}
	}
	for _, h := range inv.HypervisorInterfaces {
		key := "container.virtualization.management_interface." + h.ID
		if h.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, h, h.CollectionSource, at, h.Confidence))
		} else {
			out = append(out, evidence.NewState(key, h.State, h.CollectionSource, at, h.Confidence, fallback(h.Reason, "hypervisor management interface metadata unavailable")))
		}
	}
	for _, d := range inv.DeveloperSurfaces {
		key := "container.developer.surface." + d.ID
		if d.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, d, d.CollectionSource, at, d.Confidence))
		} else {
			out = append(out, evidence.NewState(key, d.State, d.CollectionSource, at, d.Confidence, fallback(d.Reason, "developer surface metadata unavailable")))
		}
	}
	return out
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	s := SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)}
	inv.Sources = append(inv.Sources, s)
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && strings.TrimSpace(reason) != "" {
		inv.Degraded = append(inv.Degraded, slug(id)+": "+strings.TrimSpace(reason))
	}
}

func stableID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

func containerSortKey(c Container) string {
	return c.Runtime + "\x00" + c.Namespace + "\x00" + c.RuntimeContainerID
}
func securitySortKey(c SecurityPosture) string {
	return c.Runtime + "\x00" + c.Namespace + "\x00" + c.RuntimeContainerID
}
func runtimeEndpointSortKey(ep RuntimeEndpointPosture) string {
	return ep.Runtime + "\x00" + ep.EndpointKind + "\x00" + strings.ToLower(ep.Endpoint)
}
func configSortKey(c ConfigFile) string { return c.Runtime + "\x00" + strings.ToLower(c.Path) }

func normalizeObservedState(v string) string {
	v = normalizeWord(v)
	if v == "OBSERVED" {
		return "OBSERVED"
	}
	return "UNKNOWN"
}

func normalizeTriState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "TRUE", "YES", "ENABLED":
		return "TRUE"
	case "FALSE", "NO", "DISABLED":
		return "FALSE"
	default:
		return "UNKNOWN"
	}
}
func normalizeNamespaceState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "HOST", "PRIVATE", "REMAPPED", "SHARED_CONTAINER", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeCapabilityBoundingState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "BOUNDED", "REDUCED", "UNBOUNDED", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeSeccompState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "DEFAULT", "CUSTOM", "UNCONFINED", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeMACState(v string) string {
	v = normalizeWord(v)
	switch v {
	case "ENFORCED", "UNCONFINED", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}

func normalizeStringSet(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToUpper(strings.TrimSpace(v))
		v = strings.TrimPrefix(v, "CAP_")
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func normalizeContainerState(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "RUNNING", "UP":
		return "RUNNING"
	case "EXITED", "STOPPED", "DEAD", "REMOVING":
		return "STOPPED"
	case "CREATED":
		return "CREATED"
	case "PAUSED":
		return "PAUSED"
	default:
		return "UNKNOWN"
	}
}
func normalizeWord(v string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", " ", "_").Replace(strings.TrimSpace(v)))
}
func normalizeWordOptional(v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return normalizeWord(v)
}
func fallback(v, f string) string {
	if strings.TrimSpace(v) == "" {
		return f
	}
	return strings.TrimSpace(v)
}
func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	dash := false
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
func uniqueSortedUpper(in []string) []string {
	m := map[string]struct{}{}
	for _, v := range in {
		v = normalizeWord(v)
		if v != "" {
			m[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

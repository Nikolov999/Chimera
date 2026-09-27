package render

import (
	"fmt"
	"io"
	"strings"

	containerinv "github.com/Nikolov999/chimera/internal/containers"
)

func ContainersHuman(w io.Writer, inv containerinv.Inventory, verbose bool) {
	fmt.Fprintln(w, "CONTAINER RUNTIME INVENTORY")
	fmt.Fprintf(w, "  Platform            %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Runtimes            %d (observed=%d running=%d accessible=%d rootless=%d)\n", inv.Summary.Runtimes, inv.Summary.InstalledRuntimes, inv.Summary.RunningRuntimes, inv.Summary.AccessibleRuntimes, inv.Summary.RootlessRuntimes)
	fmt.Fprintf(w, "  Containers          %d (running=%d stopped=%d unknown=%d)\n", inv.Summary.Containers, inv.Summary.RunningContainers, inv.Summary.StoppedContainers, inv.Summary.UnknownContainers)
	fmt.Fprintf(w, "  Security posture    %d (privileged=%d root=%d host-pid=%d host-net=%d host-userns=%d dangerous-caps=%d unrestricted-devices=%d)\n", inv.Summary.SecurityPostures, inv.Summary.Privileged, inv.Summary.RootExecution, inv.Summary.HostPID, inv.Summary.HostNetwork, inv.Summary.HostUserNamespace, inv.Summary.DangerousCaps, inv.Summary.UnrestrictedDevice)
	fmt.Fprintf(w, "  Config files        %d\n", inv.Summary.ConfigFiles)
	fmt.Fprintf(w, "  Kubernetes          %s (role=%s kubeconfigs=%d credential-paths=%d)\n", inv.Kubernetes.InstallationState, inv.Kubernetes.Applicability, inv.Summary.Kubeconfigs, inv.Summary.KubernetesCredentialPaths)
	fmt.Fprintf(w, "  Virtualization      %d hypervisor/layer record(s) (running=%d interfaces=%d broad=%d group-controlled=%d)\n", inv.Summary.Hypervisors, inv.Summary.RunningHypervisors, inv.Summary.HypervisorInterfaces, inv.Summary.BroadHypervisorInterfaces, inv.Summary.GroupControlledInterfaces)
	if inv.Summary.DegradedProviders > 0 {
		fmt.Fprintf(w, "  Limited providers   %d\n", inv.Summary.DegradedProviders)
	}

	fmt.Fprintln(w, "\nRUNTIMES")
	for _, r := range inv.Runtimes {
		fmt.Fprintf(w, "  %-11s %-12s %-11s %-11s %s\n", r.Name, r.InstallationState, r.RuntimeState, r.Accessibility, truncate(fallbackRender(r.Version, "-"), 70))
		if verbose {
			if r.BinaryPath != "" {
				fmt.Fprintf(w, "    binary:        %s\n", truncate(r.BinaryPath, 130))
			}
			if r.Endpoint != "" {
				fmt.Fprintf(w, "    endpoint:      %s (%s)\n", truncate(r.Endpoint, 130), r.EndpointKind)
			}
			fmt.Fprintf(w, "    rootless:      %s\n", r.RootlessState)
			if r.Reason != "" {
				fmt.Fprintf(w, "    note:          %s\n", truncate(r.Reason, 180))
			}
			fmt.Fprintf(w, "    source:        %s\n", truncate(r.CollectionSource, 140))
		}
	}

	fmt.Fprintln(w, "\nCONTAINERS")
	if len(inv.Containers) == 0 {
		fmt.Fprintln(w, "  No local container instances were observable through the bounded runtime providers.")
	}
	for _, c := range inv.Containers {
		label := c.Name
		if label == "" {
			label = c.RuntimeContainerID
		}
		fmt.Fprintf(w, "  %-11s %-10s %-26s %s\n", c.Runtime, c.State, truncate(label, 26), truncate(fallbackRender(c.Image, "-"), 70))
		if verbose {
			fmt.Fprintf(w, "    id:            %s\n", truncate(c.RuntimeContainerID, 130))
			if c.Namespace != "" {
				fmt.Fprintf(w, "    namespace:     %s\n", truncate(c.Namespace, 80))
			}
			if c.PID > 0 {
				fmt.Fprintf(w, "    pid:           %d\n", c.PID)
			}
			if c.Status != "" {
				fmt.Fprintf(w, "    status:        %s\n", truncate(c.Status, 140))
			}
			fmt.Fprintf(w, "    source:        %s\n", truncate(c.CollectionSource, 140))
		}
	}

	if len(inv.Security) > 0 {
		fmt.Fprintln(w, "\nSECURITY POSTURE")
		for _, c := range inv.Security {
			label := c.Name
			if label == "" {
				label = c.RuntimeContainerID
			}
			fmt.Fprintf(w, "  %-11s %-26s privileged=%-7s root=%-7s pid=%-8s net=%-8s userns=%-10s\n", c.Runtime, truncate(label, 26), c.PrivilegedState, c.RootExecutionState, c.PIDNamespace, c.NetworkNamespace, c.UserNamespace)
			if verbose {
				fmt.Fprintf(w, "    caps:          state=%s added=%d dangerous=%s\n", c.CapabilityAssessmentState, len(c.AddedCapabilities), fallbackRender(joinRender(c.DangerousCapabilities), "-"))
				fmt.Fprintf(w, "    devices:       mapped=%d rules=%d unrestricted=%s\n", c.DeviceCount, c.DeviceCgroupRuleCount, c.UnrestrictedDeviceAccessState)
				if c.ConfiguredUser != "" {
					fmt.Fprintf(w, "    configured user: %s\n", truncate(c.ConfiguredUser, 80))
				}
				if c.Reason != "" {
					fmt.Fprintf(w, "    note:          %s\n", truncate(c.Reason, 170))
				}
				fmt.Fprintf(w, "    source:        %s\n", truncate(c.CollectionSource, 140))
			}
		}
	}

	if inv.Kubernetes.State == "OBSERVED" || len(inv.Kubeconfigs) > 0 {
		fmt.Fprintln(w, "\nKUBERNETES / ORCHESTRATION POSTURE")
		fmt.Fprintf(w, "  %-14s role=%-12s clients=%d server-components=%d kubeconfigs=%d\n", inv.Kubernetes.InstallationState, inv.Kubernetes.Applicability, len(inv.Kubernetes.ClientTools), len(inv.Kubernetes.ServerComponents), len(inv.Kubeconfigs))
		if verbose {
			if len(inv.Kubernetes.ClientTools) > 0 {
				fmt.Fprintf(w, "    client tools:      %s\n", truncate(strings.Join(inv.Kubernetes.ClientTools, ", "), 170))
			}
			if len(inv.Kubernetes.ServerComponents) > 0 {
				fmt.Fprintf(w, "    server components: %s\n", truncate(strings.Join(inv.Kubernetes.ServerComponents, ", "), 170))
			}
		}
		for _, c := range inv.Kubeconfigs {
			fmt.Fprintf(w, "  %-14s %-12s %s\n", c.Scope, c.State, truncate(c.Path, 120))
			if verbose {
				fmt.Fprintf(w, "    permissions:     state=%s mode=%s world-r=%s world-w=%s group-r=%s group-w=%s\n", c.PermissionAssessmentState, fallbackRender(c.Mode, "-"), c.WorldReadableState, c.WorldWritableState, c.GroupReadableState, c.GroupWritableState)
				fmt.Fprintf(w, "    structure:       state=%s embedded-credentials=%s refs=%d servers=%d local-servers=%d\n", c.StructureAssessmentState, c.EmbeddedCredentialState, c.CredentialReferenceCount, c.ServerEndpointCount, c.LocalServerEndpointCount)
				if c.Reason != "" {
					fmt.Fprintf(w, "    note:            %s\n", truncate(c.Reason, 170))
				}
			}
		}
		if verbose && len(inv.KubernetesCredentialPaths) > 0 {
			fmt.Fprintln(w, "\nKUBERNETES CREDENTIAL PATH METADATA")
			for _, p := range inv.KubernetesCredentialPaths {
				fmt.Fprintf(w, "  %-12s %-12s %s\n", p.Kind, p.State, truncate(p.Path, 120))
				fmt.Fprintf(w, "    permissions:     state=%s mode=%s world-r=%s world-w=%s group-r=%s group-w=%s\n", p.PermissionAssessmentState, fallbackRender(p.Mode, "-"), p.WorldReadableState, p.WorldWritableState, p.GroupReadableState, p.GroupWritableState)
				if p.Reason != "" {
					fmt.Fprintf(w, "    note:            %s\n", truncate(p.Reason, 170))
				}
			}
		}
	}

	if len(inv.Hypervisors) > 0 {
		fmt.Fprintln(w, "\nVIRTUALIZATION / HYPERVISOR SURFACE")
		for _, h := range inv.Hypervisors {
			fmt.Fprintf(w, "  %-16s %-12s runtime=%-14s service=%-14s local-access=%s\n", h.Name, h.InstallationState, h.RuntimeState, h.ServiceState, h.LocalAccessState)
			if verbose {
				if h.BinaryPath != "" {
					fmt.Fprintf(w, "    binary:         %s\n", truncate(h.BinaryPath, 130))
				}
				if h.Version != "" {
					fmt.Fprintf(w, "    version:        %s\n", truncate(h.Version, 130))
				}
				if len(h.ServiceNames) > 0 {
					fmt.Fprintf(w, "    services:       %s\n", truncate(strings.Join(h.ServiceNames, ", "), 150))
				}
				fmt.Fprintf(w, "    mgmt interface: %s\n", h.ManagementInterfaceState)
				if h.Reason != "" {
					fmt.Fprintf(w, "    note:           %s\n", truncate(h.Reason, 170))
				}
			}
		}
		if len(inv.HypervisorInterfaces) > 0 {
			fmt.Fprintln(w, "\nHYPERVISOR LOCAL MANAGEMENT INTERFACES")
			for _, h := range inv.HypervisorInterfaces {
				fmt.Fprintf(w, "  %-16s %-12s access=%-18s %s\n", h.Hypervisor, h.Kind, h.LocalAccessState, truncate(h.Endpoint, 110))
				if verbose {
					fmt.Fprintf(w, "    permissions:    state=%s mode=%s world-w=%s group-w=%s owner-state=%s\n", h.PermissionAssessmentState, fallbackRender(h.Mode, "-"), h.WorldWritableState, h.GroupWritableState, h.OwnerAssessmentState)
				}
			}
		}
	}

	if verbose && len(inv.ConfigFiles) > 0 {
		fmt.Fprintln(w, "\nCONFIGURATION METADATA")
		for _, c := range inv.ConfigFiles {
			fmt.Fprintf(w, "  %-11s %-12s %s\n", c.Runtime, c.State, truncate(c.Path, 120))
			if c.State == "OBSERVED" {
				fmt.Fprintf(w, "    mode/size:     %s / %d bytes\n", fallbackRender(c.Mode, "-"), c.SizeBytes)
			}
			if c.Reason != "" {
				fmt.Fprintf(w, "    note:          %s\n", truncate(c.Reason, 170))
			}
		}
	}
	if len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nLIMITATIONS")
		for _, d := range inv.Degraded {
			fmt.Fprintf(w, "  - %s\n", truncate(d, 180))
		}
	}
}

func joinRender(values []string) string {
	return strings.Join(values, ",")
}

package containers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxHypervisors = 32
const maxHypervisorInterfaces = 64

// HypervisorPosture is read-only local presence/service posture for virtualization
// and hypervisor technologies. Chimera does not enumerate guest contents or attach
// to a VM management plane.
type HypervisorPosture struct {
	ID                       string              `json:"id"`
	Name                     string              `json:"name"`
	Kind                     string              `json:"kind"`
	State                    evidence.State      `json:"state"`
	InstallationState        string              `json:"installation_state"`
	RuntimeState             string              `json:"runtime_state"`
	BinaryPath               string              `json:"binary_path,omitempty"`
	Version                  string              `json:"version,omitempty"`
	ServiceNames             []string            `json:"service_names,omitempty"`
	ServiceState             string              `json:"service_state"`
	ManagementInterfaceState string              `json:"management_interface_state"`
	LocalAccessState         string              `json:"local_access_state"`
	CollectionSource         string              `json:"collection_source"`
	Confidence               evidence.Confidence `json:"confidence"`
	Reason                   string              `json:"reason,omitempty"`
}

// HypervisorManagementInterface contains metadata for a local hypervisor control
// socket/device only. It never opens the interface or sends a management request.
type HypervisorManagementInterface struct {
	ID                        string              `json:"id"`
	Hypervisor                string              `json:"hypervisor"`
	Kind                      string              `json:"kind"`
	Endpoint                  string              `json:"endpoint"`
	State                     evidence.State      `json:"state"`
	PermissionAssessmentState string              `json:"permission_assessment_state"`
	Mode                      string              `json:"mode,omitempty"`
	OwnerUID                  string              `json:"owner_uid,omitempty"`
	OwnerGID                  string              `json:"owner_gid,omitempty"`
	OwnerAssessmentState      string              `json:"owner_assessment_state"`
	WorldWritableState        string              `json:"world_writable_state"`
	GroupWritableState        string              `json:"group_writable_state"`
	LocalAccessState          string              `json:"local_access_state"`
	CollectionSource          string              `json:"collection_source"`
	Confidence                evidence.Confidence `json:"confidence"`
	Reason                    string              `json:"reason,omitempty"`
}

type hypervisorSpec struct {
	Name        string
	Kind        string
	Binaries    []string
	VersionArgs []string
	Paths       []string
	Services    []string
}

type hypervisorInterfaceCandidate struct {
	Hypervisor string
	Kind       string
	Path       string
}

func collectVirtualizationPosture(ctx context.Context, inv *Inventory) {
	specs := platformHypervisorSpecs()
	interfaces := platformHypervisorInterfaces()
	observedInterfaces := map[string]int{}
	interfaceAccess := map[string]string{}

	for _, c := range interfaces {
		if len(inv.HypervisorInterfaces) >= maxHypervisorInterfaces {
			break
		}
		rec, ok := inspectHypervisorInterface(c)
		if !ok {
			continue
		}
		inv.HypervisorInterfaces = append(inv.HypervisorInterfaces, rec)
		observedInterfaces[c.Hypervisor]++
		interfaceAccess[c.Hypervisor] = mergeLocalAccessState(interfaceAccess[c.Hypervisor], rec.LocalAccessState)
	}

	for _, spec := range specs {
		if len(inv.Hypervisors) >= maxHypervisors {
			break
		}
		p := detectHypervisor(ctx, spec, observedInterfaces[spec.Name] > 0, interfaceAccess[spec.Name])
		inv.Hypervisors = append(inv.Hypervisors, p)
	}

	observed := 0
	for _, h := range inv.Hypervisors {
		if h.InstallationState == "PRESENT" {
			observed++
		}
	}
	if observed > 0 {
		addSource(inv, "virtualization-hypervisors", evidence.StateObserved, "local hypervisor binaries, services, and platform metadata", observed, "")
	} else {
		addSource(inv, "virtualization-hypervisors", evidence.StateNotApplicable, "local hypervisor binaries, services, and platform metadata", 0, "no supported local hypervisor or virtualization layer was observed")
	}

	if len(inv.HypervisorInterfaces) > 0 {
		addSource(inv, "virtualization-management-interfaces", evidence.StateObserved, "local hypervisor socket/device metadata", len(inv.HypervisorInterfaces), "")
	} else if observed > 0 {
		addSource(inv, "virtualization-management-interfaces", evidence.StateUnavailable, "local hypervisor socket/device metadata", 0, "a supported virtualization technology was observed but no safely inspectable local management socket/device was found")
	} else {
		addSource(inv, "virtualization-management-interfaces", evidence.StateNotApplicable, "local hypervisor socket/device metadata", 0, "no supported local hypervisor or virtualization layer was observed")
	}
}

func detectHypervisor(ctx context.Context, spec hypervisorSpec, hasInterface bool, interfaceAccess string) HypervisorPosture {
	p := HypervisorPosture{
		Name: spec.Name, Kind: spec.Kind, State: evidence.StateObserved,
		InstallationState: "NOT_OBSERVED", RuntimeState: "UNKNOWN", ServiceState: "UNKNOWN",
		ManagementInterfaceState: "NOT_OBSERVED", LocalAccessState: "UNKNOWN",
		ServiceNames:     append([]string(nil), spec.Services...),
		CollectionSource: "local hypervisor binary/path/service metadata", Confidence: evidence.ConfidenceMedium,
	}
	if hasInterface {
		p.InstallationState = "PRESENT"
		p.ManagementInterfaceState = "OBSERVED"
		p.LocalAccessState = fallback(interfaceAccess, "UNKNOWN")
	}
	for _, b := range spec.Binaries {
		if path, err := exec.LookPath(b); err == nil {
			p.InstallationState = "PRESENT"
			if p.BinaryPath == "" {
				p.BinaryPath = path
				if len(spec.VersionArgs) > 0 {
					if out, err := localCommand(ctx, 1200*time.Millisecond, b, spec.VersionArgs...); err == nil {
						p.Version = trimVersion(out)
					} else {
						p.Reason = appendReason(p.Reason, "version metadata unavailable: "+shortErr(err))
					}
				}
			}
		}
	}
	for _, path := range spec.Paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			p.InstallationState = "PRESENT"
			break
		}
	}
	state, reason := hypervisorServiceState(ctx, spec.Services)
	if state != "UNKNOWN" {
		p.ServiceState = state
		if state == "RUNNING" {
			p.RuntimeState = "RUNNING"
			p.InstallationState = "PRESENT"
		} else if state == "STOPPED" && p.InstallationState == "PRESENT" {
			p.RuntimeState = "STOPPED"
		}
	}
	p.Reason = appendReason(p.Reason, reason)
	if p.InstallationState != "PRESENT" {
		p.State = evidence.StateNotApplicable
		p.RuntimeState = "NOT_APPLICABLE"
		p.ServiceState = "NOT_APPLICABLE"
		p.ManagementInterfaceState = "NOT_APPLICABLE"
		p.LocalAccessState = "NOT_APPLICABLE"
		p.Confidence = evidence.ConfidenceHigh
		p.Reason = fallback(p.Reason, "technology not observed through local metadata")
	}
	return p
}

func hypervisorServiceState(ctx context.Context, services []string) (string, string) {
	if len(services) == 0 {
		return "UNKNOWN", ""
	}
	sawStopped := false
	var lastErr string
	for _, svc := range services {
		switch runtime.GOOS {
		case "windows":
			if _, err := exec.LookPath("sc.exe"); err != nil {
				return "UNKNOWN", "Windows service-control provider unavailable"
			}
			out, err := localCommand(ctx, 900*time.Millisecond, "sc.exe", "query", svc)
			low := strings.ToLower(out)
			if strings.Contains(low, "running") {
				return "RUNNING", ""
			}
			if strings.Contains(low, "stopped") {
				sawStopped = true
			}
			if err != nil {
				lastErr = shortErr(err)
			}
		case "linux":
			if _, err := exec.LookPath("systemctl"); err != nil {
				return "UNKNOWN", "systemd service-state provider unavailable"
			}
			out, err := localCommand(ctx, 900*time.Millisecond, "systemctl", "is-active", svc)
			s := strings.ToLower(strings.TrimSpace(out))
			if err == nil && s == "active" {
				return "RUNNING", ""
			}
			if s == "inactive" || s == "failed" || s == "deactivating" {
				sawStopped = true
			}
			if err != nil {
				lastErr = shortErr(err)
			}
		case "darwin":
			// launchctl labels vary by product/version. Presence is retained, but
			// runtime state is not guessed from application installation metadata.
			return "UNKNOWN", "launchd service labels are product/version specific; runtime state not inferred"
		default:
			return "UNKNOWN", "service-state provider unsupported on this platform"
		}
	}
	if sawStopped {
		return "STOPPED", ""
	}
	if lastErr != "" {
		return "UNKNOWN", "service state unavailable: " + lastErr
	}
	return "UNKNOWN", ""
}

func mergeLocalAccessState(current, next string) string {
	rank := map[string]int{"": 0, "UNKNOWN": 1, "CONTROLLED": 2, "GROUP_CONTROLLED": 3, "BROAD": 4}
	current = normalizeWord(current)
	next = normalizeWord(next)
	if rank[next] > rank[current] {
		return next
	}
	return current
}

func inspectHypervisorInterface(c hypervisorInterfaceCandidate) (HypervisorManagementInterface, bool) {
	if strings.TrimSpace(c.Path) == "" {
		return HypervisorManagementInterface{}, false
	}
	info, err := os.Lstat(c.Path)
	if err != nil {
		return HypervisorManagementInterface{}, false
	}
	rec := HypervisorManagementInterface{
		Hypervisor: c.Hypervisor, Kind: c.Kind, Endpoint: c.Path, State: evidence.StateObserved,
		PermissionAssessmentState: "OBSERVED", OwnerAssessmentState: "UNKNOWN",
		WorldWritableState: "FALSE", GroupWritableState: "FALSE", LocalAccessState: "CONTROLLED",
		CollectionSource: "os.Lstat local endpoint metadata", Confidence: evidence.ConfidenceExact,
	}
	mode := info.Mode().Perm()
	rec.Mode = fmt.Sprintf("%04o", mode)
	if mode&0002 != 0 {
		rec.WorldWritableState = "TRUE"
		rec.LocalAccessState = "BROAD"
	}
	if mode&0020 != 0 {
		rec.GroupWritableState = "TRUE"
		if rec.LocalAccessState != "BROAD" {
			rec.LocalAccessState = "GROUP_CONTROLLED"
		}
	}
	if uid, gid, ok := endpointOwnerMetadata(info); ok {
		rec.OwnerUID, rec.OwnerGID = uid, gid
		rec.OwnerAssessmentState = "OBSERVED"
	}
	return rec, true
}

func platformHypervisorSpecs() []hypervisorSpec {
	switch runtime.GOOS {
	case "linux":
		return []hypervisorSpec{
			{Name: "kvm-libvirt", Kind: "HYPERVISOR", Binaries: []string{"virsh", "libvirtd", "virtqemud"}, VersionArgs: []string{"--version"}, Paths: []string{"/dev/kvm", "/etc/libvirt"}, Services: []string{"libvirtd.service", "virtqemud.service"}},
			{Name: "virtualbox", Kind: "HYPERVISOR", Binaries: []string{"VBoxManage", "VirtualBox"}, VersionArgs: []string{"--version"}, Paths: []string{"/dev/vboxdrv", "/etc/vbox"}, Services: []string{"vboxdrv.service"}},
			{Name: "vmware", Kind: "HYPERVISOR", Binaries: []string{"vmware", "vmrun"}, VersionArgs: []string{"--version"}, Paths: []string{"/dev/vmmon", "/etc/vmware"}, Services: []string{"vmware.service"}},
		}
	case "windows":
		sys := os.Getenv("SystemRoot")
		if sys == "" {
			sys = `C:\Windows`
		}
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		return []hypervisorSpec{
			{Name: "hyper-v", Kind: "HYPERVISOR", Binaries: []string{"vmconnect.exe", "vmcompute.exe"}, Paths: []string{filepath.Join(sys, "System32", "vmms.exe"), filepath.Join(sys, "System32", "vmcompute.exe")}, Services: []string{"vmms", "vmcompute"}},
			{Name: "wsl", Kind: "VM_LAYER", Binaries: []string{"wsl.exe"}, VersionArgs: []string{"--version"}, Paths: []string{filepath.Join(sys, "System32", "wsl.exe")}, Services: []string{"WslService", "LxssManager"}},
			{Name: "virtualbox", Kind: "HYPERVISOR", Binaries: []string{"VBoxManage.exe"}, VersionArgs: []string{"--version"}, Paths: []string{filepath.Join(pf, "Oracle", "VirtualBox", "VBoxManage.exe")}, Services: []string{"VBoxDrv"}},
			{Name: "vmware", Kind: "HYPERVISOR", Binaries: []string{"vmrun.exe"}, Paths: []string{filepath.Join(pf, "VMware", "VMware Workstation"), filepath.Join(pf86, "VMware", "VMware Workstation")}, Services: []string{"VMAuthdService", "VMnetDHCP", "VMware NAT Service"}},
		}
	case "darwin":
		return []hypervisorSpec{
			{Name: "virtualbox", Kind: "HYPERVISOR", Binaries: []string{"VBoxManage"}, VersionArgs: []string{"--version"}, Paths: []string{"/Applications/VirtualBox.app"}},
			{Name: "vmware-fusion", Kind: "HYPERVISOR", Binaries: []string{"vmrun"}, Paths: []string{"/Applications/VMware Fusion.app"}},
		}
	default:
		return nil
	}
}

func platformHypervisorInterfaces() []hypervisorInterfaceCandidate {
	switch runtime.GOOS {
	case "linux":
		return []hypervisorInterfaceCandidate{
			{"kvm-libvirt", "UNIX_SOCKET", "/run/libvirt/libvirt-sock"},
			{"kvm-libvirt", "UNIX_SOCKET", "/var/run/libvirt/libvirt-sock"},
			{"kvm-libvirt", "UNIX_SOCKET", "/run/libvirt/virtqemud-sock"},
			{"kvm-libvirt", "UNIX_SOCKET", "/var/run/libvirt/virtqemud-sock"},
			{"kvm-libvirt", "DEVICE", "/dev/kvm"},
			{"virtualbox", "DEVICE", "/dev/vboxdrv"},
			{"vmware", "DEVICE", "/dev/vmmon"},
		}
	default:
		return nil
	}
}

func normalizeHypervisors(in []HypervisorPosture) []HypervisorPosture {
	byID := map[string]HypervisorPosture{}
	for _, p := range in {
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		if p.Name == "" {
			continue
		}
		p.ID = slug(fallback(p.ID, p.Name))
		p.Kind = normalizeWord(fallback(p.Kind, "HYPERVISOR"))
		if p.State == "" {
			p.State = evidence.StateObserved
		}
		p.InstallationState = normalizeWord(fallback(p.InstallationState, "NOT_OBSERVED"))
		p.RuntimeState = normalizeWord(fallback(p.RuntimeState, "UNKNOWN"))
		p.ServiceState = normalizeWord(fallback(p.ServiceState, "UNKNOWN"))
		p.ManagementInterfaceState = normalizeWord(fallback(p.ManagementInterfaceState, "UNKNOWN"))
		p.LocalAccessState = normalizeWord(fallback(p.LocalAccessState, "UNKNOWN"))
		p.BinaryPath = strings.TrimSpace(p.BinaryPath)
		p.Version = strings.TrimSpace(p.Version)
		p.ServiceNames = normalizeStringSetPreserveCase(p.ServiceNames)
		p.CollectionSource = fallback(p.CollectionSource, "local hypervisor metadata")
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceMedium
		}
		p.Reason = strings.TrimSpace(p.Reason)
		byID[p.ID] = p
	}
	out := make([]HypervisorPosture, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > maxHypervisors {
		out = out[:maxHypervisors]
	}
	return out
}

func normalizeHypervisorInterfaces(in []HypervisorManagementInterface) []HypervisorManagementInterface {
	byID := map[string]HypervisorManagementInterface{}
	for _, p := range in {
		p.Hypervisor = strings.ToLower(strings.TrimSpace(p.Hypervisor))
		p.Endpoint = strings.TrimSpace(p.Endpoint)
		if p.Hypervisor == "" || p.Endpoint == "" {
			continue
		}
		p.Kind = normalizeWord(fallback(p.Kind, "LOCAL_INTERFACE"))
		p.ID = stableID("hypervisor-interface", p.Hypervisor, p.Kind, p.Endpoint)
		if p.State == "" {
			p.State = evidence.StateObserved
		}
		p.PermissionAssessmentState = normalizeAssessmentState(p.PermissionAssessmentState)
		p.OwnerAssessmentState = normalizeAssessmentState(p.OwnerAssessmentState)
		p.WorldWritableState = normalizeTriState(p.WorldWritableState)
		p.GroupWritableState = normalizeTriState(p.GroupWritableState)
		p.LocalAccessState = normalizeWord(fallback(p.LocalAccessState, "UNKNOWN"))
		p.Mode = strings.TrimSpace(p.Mode)
		p.OwnerUID = strings.TrimSpace(p.OwnerUID)
		p.OwnerGID = strings.TrimSpace(p.OwnerGID)
		p.CollectionSource = fallback(p.CollectionSource, "local hypervisor interface metadata")
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceHigh
		}
		p.Reason = strings.TrimSpace(p.Reason)
		byID[p.ID] = p
	}
	out := make([]HypervisorManagementInterface, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a := out[i].Hypervisor + "\x00" + out[i].Kind + "\x00" + strings.ToLower(out[i].Endpoint)
		b := out[j].Hypervisor + "\x00" + out[j].Kind + "\x00" + strings.ToLower(out[j].Endpoint)
		return a < b
	})
	if len(out) > maxHypervisorInterfaces {
		out = out[:maxHypervisorInterfaces]
	}
	return out
}

func normalizeStringSetPreserveCase(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

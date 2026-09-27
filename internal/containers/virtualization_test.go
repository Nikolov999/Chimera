package containers

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeHypervisorsDeterministicAndBounded(t *testing.T) {
	in := []HypervisorPosture{
		{Name: "VirtualBox", Kind: "hypervisor", State: evidence.StateObserved, InstallationState: "present", RuntimeState: "running", ServiceState: "running", ManagementInterfaceState: "observed", LocalAccessState: "controlled", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
		{Name: "kvm-libvirt", Kind: "hypervisor", State: evidence.StateObserved, InstallationState: "present", RuntimeState: "stopped", ServiceState: "stopped", ManagementInterfaceState: "observed", LocalAccessState: "group_controlled", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
	}
	got := normalizeHypervisors(in)
	if len(got) != 2 || got[0].ID != "kvm-libvirt" || got[1].ID != "virtualbox" {
		t.Fatalf("unexpected normalized hypervisors: %#v", got)
	}
	inv := Inventory{Hypervisors: got}
	s := summarize(inv)
	if s.Hypervisors != 2 || s.RunningHypervisors != 1 {
		t.Fatalf("unexpected hypervisor summary: %#v", s)
	}
}

func TestInspectHypervisorInterfaceClassifiesBroadWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode-bit classification test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "control")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	rec, ok := inspectHypervisorInterface(hypervisorInterfaceCandidate{Hypervisor: "test-hv", Kind: "UNIX_SOCKET", Path: path})
	if !ok {
		t.Fatal("expected interface metadata")
	}
	if rec.WorldWritableState != "TRUE" || rec.GroupWritableState != "TRUE" || rec.LocalAccessState != "BROAD" {
		t.Fatalf("unexpected access classification: %#v", rec)
	}
}

func TestVirtualizationEvidenceKeys(t *testing.T) {
	inv := Inventory{
		CollectedAt: time.Unix(1, 0).UTC(), Platform: "linux", Architecture: "amd64",
		Hypervisors:          []HypervisorPosture{{ID: "kvm-libvirt", Name: "kvm-libvirt", Kind: "HYPERVISOR", State: evidence.StateObserved, InstallationState: "PRESENT", RuntimeState: "RUNNING", ServiceState: "RUNNING", ManagementInterfaceState: "OBSERVED", LocalAccessState: "GROUP_CONTROLLED", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}},
		HypervisorInterfaces: []HypervisorManagementInterface{{ID: "abc", Hypervisor: "kvm-libvirt", Kind: "UNIX_SOCKET", Endpoint: "/run/libvirt/libvirt-sock", State: evidence.StateObserved, PermissionAssessmentState: "OBSERVED", OwnerAssessmentState: "OBSERVED", WorldWritableState: "FALSE", GroupWritableState: "TRUE", LocalAccessState: "GROUP_CONTROLLED", CollectionSource: "test", Confidence: evidence.ConfidenceExact}},
	}
	inv.Summary = summarize(inv)
	obs := buildEvidence(inv)
	keys := map[string]bool{}
	for _, o := range obs {
		keys[o.Key] = true
	}
	if !keys["container.virtualization.hypervisor.kvm-libvirt"] || !keys["container.virtualization.management_interface.abc"] {
		t.Fatalf("missing virtualization evidence keys: %#v", keys)
	}
}

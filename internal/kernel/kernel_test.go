package kernel

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
	"testing"
	"time"
)

func TestCollectContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	k := Collect(ctx)
	if k.Schema != SchemaVersion || k.EvidenceSchema != evidence.SchemaVersion {
		t.Fatalf("bad schemas: %#v", k)
	}
	if k.Platform == "" || k.Architecture == "" || k.KernelRelease == "" {
		t.Fatalf("incomplete inventory: %#v", k)
	}
	if len(k.HardeningCapabilities) == 0 {
		t.Fatal("expected hardening capability inventory")
	}
	if k.SecureBoot.CollectionState == "" || k.SecureBoot.State == "" || k.SecureBoot.Provider == "" || k.SecureBoot.Source == "" || k.SecureBoot.Confidence == "" {
		t.Fatalf("incomplete Secure Boot assessment: %#v", k.SecureBoot)
	}
	if len(k.IntegrityControls) == 0 {
		t.Fatal("expected integrity controls")
	}
	for _, c := range k.IntegrityControls {
		if c.ID == "" || c.Name == "" || c.CollectionState == "" || c.State == "" || c.Provider == "" || c.Source == "" || c.Confidence == "" {
			t.Fatalf("incomplete integrity control: %#v", c)
		}
	}
	if len(k.MemoryMitigations) == 0 {
		t.Fatal("expected memory mitigations")
	}
	for _, m := range k.MemoryMitigations {
		if m.ID == "" || m.Name == "" || m.CollectionState == "" || m.State == "" || m.Provider == "" || m.Source == "" || m.Confidence == "" {
			t.Fatalf("incomplete memory mitigation: %#v", m)
		}
	}
	if len(k.DebugExposure) == 0 {
		t.Fatal("expected kernel/debug exposure assessments")
	}
	for _, d := range k.DebugExposure {
		if d.ID == "" || d.Name == "" || d.CollectionState == "" || d.State == "" || d.Provider == "" || d.Source == "" || d.Confidence == "" {
			t.Fatalf("incomplete debug exposure assessment: %#v", d)
		}
	}
	if len(k.UnprivilegedFeatures) == 0 {
		t.Fatal("expected unprivileged-kernel-feature assessments")
	}
	for _, u := range k.UnprivilegedFeatures {
		if u.ID == "" || u.Name == "" || u.CollectionState == "" || u.State == "" || u.Provider == "" || u.Source == "" || u.Confidence == "" {
			t.Fatalf("incomplete unprivileged feature assessment: %#v", u)
		}
	}
	if len(k.LoadedModules) == 0 {
		t.Fatal("expected loaded module/driver inventory")
	}
	for _, m := range k.LoadedModules {
		if m.ID == "" || m.Name == "" || m.CollectionState == "" || m.LoadState == "" || m.Provider == "" || m.Source == "" || m.SignatureState == "" || m.TrustState == "" || m.BackingState == "" || m.Confidence == "" {
			t.Fatalf("incomplete loaded module/driver assessment: %#v", m)
		}
	}
	if k.DriverIntelligence.Schema != DriverIntelligenceSchema || k.DriverIntelligence.Version == "" || k.DriverIntelligence.Source == "" || k.DriverIntelligence.InstalledCollectionState == "" || k.DriverIntelligence.InstalledCollectionSource == "" {
		t.Fatalf("incomplete driver intelligence status: %#v", k.DriverIntelligence)
	}
	for _, v := range k.VulnerableDrivers {
		if v.ID == "" || v.DriverName == "" || v.CollectionState == "" || v.InstalledState == "" || v.LoadState == "" || v.ExposureState == "" || v.ResolutionState == "" || v.IntelligenceID == "" || v.IntelligenceVer == "" || v.FingerprintState == "" || v.Source == "" || v.Confidence == "" {
			t.Fatalf("incomplete vulnerable-driver assessment: %#v", v)
		}
	}
	if len(k.MandatoryAccess) == 0 {
		t.Fatal("expected mandatory-access/isolation assessments")
	}
	for _, m := range k.MandatoryAccess {
		if m.ID == "" || m.Name == "" || m.Framework == "" || m.CollectionState == "" || m.State == "" || m.Provider == "" || m.Source == "" || m.Confidence == "" {
			t.Fatalf("incomplete mandatory-access assessment: %#v", m)
		}
	}
	if err := evidence.ValidateAll(k.Evidence); err != nil {
		t.Fatal(err)
	}
}
func TestSlug(t *testing.T) {
	if got := slug("Kernel Pointer / Debug"); got != "kernel_pointer_debug" {
		t.Fatalf("slug=%q", got)
	}
}

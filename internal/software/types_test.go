package software

import (
	"context"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeItemsIsDeterministicAndExplicit(t *testing.T) {
	in := []Item{
		{Kind: "package", Product: "zeta", PackageID: "zeta", Version: "1.0", Architecture: "amd64", PackageSource: "dpkg", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact},
		{Kind: "package", Product: "alpha", PackageID: "alpha", Version: "2.0", Architecture: "amd64", PackageSource: "dpkg", CollectionSource: "fixture", Confidence: evidence.ConfidenceHigh},
		{Kind: "package", Product: "alpha", PackageID: "alpha", Version: "2.0", Architecture: "amd64", PackageSource: "dpkg", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact},
	}
	out := normalizeItems(in)
	if len(out) != 2 {
		t.Fatalf("expected deduped items, got %d", len(out))
	}
	if out[0].Product != "alpha" || out[1].Product != "zeta" {
		t.Fatalf("unexpected ordering: %#v", out)
	}
	if out[0].Vendor != "UNKNOWN" || out[0].InstallPath != "UNKNOWN" || out[0].SupportState != "UNKNOWN" {
		t.Fatalf("unknown fields were not explicit: %#v", out[0])
	}
	if out[0].Confidence != evidence.ConfidenceExact {
		t.Fatalf("strongest duplicate confidence not retained: %#v", out[0])
	}
	if len(out[0].ID) != 23 || out[0].ID[:3] != "sw-" {
		t.Fatalf("bad stable id %q", out[0].ID)
	}
}

func TestEvidenceContract(t *testing.T) {
	at := time.Date(2026, 8, 18, 18, 0, 0, 0, time.UTC)
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, Platform: "linux", Architecture: "amd64",
		Items:   normalizeItems([]Item{{Kind: "package", Product: "alpha", PackageID: "alpha", Version: "1", Architecture: "amd64", PackageSource: "dpkg", CollectionSource: "fixture", Confidence: evidence.ConfidenceExact}}),
		Sources: []SourceStatus{{ID: "dpkg", State: evidence.StateObserved, Source: "fixture", ItemCount: 1}},
	}
	obs := buildEvidence(inv)
	if err := evidence.ValidateAll(obs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range obs {
		if len(o.Key) > 14 && o.Key[:14] == "software.item." {
			found = true
		}
	}
	if !found {
		t.Fatal("missing per-item evidence")
	}
}

func TestCollectContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv := Collect(ctx)
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Platform == "" || inv.Architecture == "" {
		t.Fatalf("bad inventory contract: %#v", inv)
	}
	if len(inv.Sources) == 0 {
		t.Fatal("expected at least one source status")
	}
	if err := evidence.ValidateAll(inv.Evidence); err != nil {
		t.Fatal(err)
	}
	for _, item := range inv.Items {
		if item.ID == "" || item.Product == "" || item.Version == "" || item.Architecture == "" || item.Vendor == "" || item.PackageSource == "" || item.InstallPath == "" || item.SupportState == "" || item.CollectionSource == "" || item.Confidence == "" {
			t.Fatalf("incomplete normalized item: %#v", item)
		}
	}
}

package firewall

import (
	"github.com/Nikolov999/chimera/internal/evidence"
	"testing"
	"time"
)

func TestInventoryContractAndDeterministicOrdering(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at}
	addProvider(&inv, ProviderStatus{ID: "ufw", Name: "UFW", State: evidence.StateObserved, Enabled: "ENABLED", Source: "test"})
	addProvider(&inv, ProviderStatus{ID: "nftables", Name: "nftables", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "test", Reason: "not installed"})
	addPolicy(&inv, Policy{Provider: "ufw", Scope: "global", Enabled: "ENABLED", DefaultInbound: "deny", DefaultOutbound: "allow", Source: "test", Confidence: evidence.ConfidenceHigh})
	inv.Policies = normalizePolicies(inv.Policies)
	inv.Providers = normalizeProviders(inv.Providers, inv.Policies)
	inv.Summary = summarize(inv.Providers, inv.Policies, inv.Restrictions, inv.ListenerCoverage)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Providers[0].ID != "nftables" || inv.Providers[1].ID != "ufw" {
		t.Fatalf("providers not ordered: %#v", inv.Providers)
	}
	if inv.Summary.EnabledProviders != 1 || inv.Summary.NotApplicableProviders != 1 || inv.Summary.Policies != 1 {
		t.Fatalf("bad summary: %#v", inv.Summary)
	}
}

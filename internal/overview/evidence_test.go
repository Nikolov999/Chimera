package overview

import (
	"context"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestCollectEmitsNormalizedEvidenceContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	o := Collect(ctx)
	if o.EvidenceSchema != evidence.SchemaVersion {
		t.Fatalf("unexpected evidence schema: %q", o.EvidenceSchema)
	}
	if o.PrivilegeSchema != PrivilegeSchemaVersion || o.Privilege.Schema != PrivilegeSchemaVersion {
		t.Fatalf("unexpected privilege schema: top=%q context=%q", o.PrivilegeSchema, o.Privilege.Schema)
	}
	if err := o.Privilege.Validate(); err != nil {
		t.Fatalf("invalid collected privilege contract: %v", err)
	}
	if len(o.Evidence) == 0 {
		t.Fatal("overview emitted no normalized evidence")
	}
	if err := evidence.ValidateAll(o.Evidence); err != nil {
		t.Fatalf("overview evidence contract invalid: %v", err)
	}

	required := map[string]bool{
		"host.hostname":                            false,
		"host.os.name":                             false,
		"host.kernel":                              false,
		"host.architecture":                        false,
		"host.privilege":                           false,
		"host.privilege.schema":                    false,
		"host.privilege.elevated":                  false,
		"host.privilege.collection_tier":           false,
		"host.privilege.deeper_evidence_available": false,
		"host.privilege.elevation_note":            false,
		"host.cpu.logical_count":                   false,
		"host.memory.total_bytes":                  false,
		"host.process.count":                       false,
		"host.network.tcp_listener_count":          false,
		"overview.collection_health":               false,
	}
	for _, obs := range o.Evidence {
		if _, ok := required[obs.Key]; ok {
			required[obs.Key] = true
		}
	}
	for key, seen := range required {
		if !seen {
			t.Fatalf("missing normalized evidence key %q", key)
		}
	}
}

func TestControlObservationPreservesExplicitUnavailableState(t *testing.T) {
	at := time.Now().UTC()
	o := controlObservation("security.control.example", Control{
		Name: "Example", State: "unavailable", Detail: "permission restricted", Source: "fixture",
	}, at)
	if o.State != evidence.StateUnavailable {
		t.Fatalf("got state %s", o.State)
	}
	if o.Reason != "permission restricted" {
		t.Fatalf("got reason %q", o.Reason)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("invalid observation: %v", err)
	}
}

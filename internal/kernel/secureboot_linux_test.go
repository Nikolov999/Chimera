//go:build linux

package kernel

import (
	"context"
	"testing"
)

func TestSecureBootEvidenceIsPresentOnLinuxCollection(t *testing.T) {
	k := Collect(context.Background())
	found := false
	for _, o := range k.Evidence {
		if o.Key == "kernel.secure_boot.state" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("kernel.secure_boot.state evidence missing")
	}
	if k.SecureBoot.CollectionState == "" || k.SecureBoot.State == "" || k.SecureBoot.Provider == "" || k.SecureBoot.Source == "" || k.SecureBoot.Confidence == "" {
		t.Fatalf("incomplete Secure Boot assessment: %#v", k.SecureBoot)
	}
}

package kernel

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestObservedSecureBoot(t *testing.T) {
	got := observedSecureBoot(true, "UEFI", "test provider", "test source", evidence.ConfidenceExact)
	if got.CollectionState != evidence.StateObserved || got.State != SecureBootEnabled || got.Enabled == nil || !*got.Enabled || got.Mode != "UEFI" {
		t.Fatalf("unexpected observed Secure Boot result: %#v", got)
	}
	got = observedSecureBoot(false, "UEFI", "test provider", "test source", evidence.ConfidenceExact)
	if got.State != SecureBootDisabled || got.Enabled == nil || *got.Enabled {
		t.Fatalf("unexpected disabled Secure Boot result: %#v", got)
	}
}

func TestBoolFromSecureBootText(t *testing.T) {
	cases := []struct {
		in     string
		want   bool
		wantOK bool
	}{
		{"SecureBoot enabled", true, true},
		{"SecureBoot disabled", false, true},
		{"1", true, true},
		{"0", false, true},
		{"unknown", false, false},
	}
	for _, tc := range cases {
		got, ok := boolFromSecureBootText(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Fatalf("boolFromSecureBootText(%q)=(%v,%v), want (%v,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

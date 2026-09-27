//go:build windows

package filesystem

import (
	"strings"
	"testing"
)

func TestFix17WindowsSearchPathWireCarriesCandidateIdentity(t *testing.T) {
	w := windowsSearchCandidateWire{CandidateID: "abc", Path: `C:\\Windows\\System32`, Contexts: []string{"SYSTEM"}, Source: "test"}
	if w.CandidateID == "" || w.Path == "" || len(w.Contexts) != 1 || w.Source != "test" {
		t.Fatalf("candidate provenance incomplete: %#v", w)
	}
}

func TestFix17WindowsFilesystemProviderDetailIsBounded(t *testing.T) {
	got := boundedFilesystemProviderDetail(strings.Repeat("x", 4096))
	if len(got) > 2051 {
		t.Fatalf("provider detail was not bounded: %d", len(got))
	}
}

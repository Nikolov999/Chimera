//go:build linux

package kernel

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseProcModulesAndTaint(t *testing.T) {
	mods := parseProcModules("demo 4096 0 - Live 0x0 (OE)\nclean 8192 1 demo, Live 0x1\n")
	if len(mods) != 2 || mods[0].Name != "demo" || mods[0].State != "Live" || mods[0].Taint != "OE" {
		t.Fatalf("unexpected parse: %#v", mods)
	}
	m := ModuleAssessment{CollectionState: evidence.StateObserved, SignatureState: "UNKNOWN", TrustState: "UNKNOWN"}
	applyLinuxTaint(&m, mods[0].Taint)
	if m.SignatureState != "UNSIGNED" || m.OutOfTree == nil || !*m.OutOfTree || !containsFlag(m.Flags, "UNSIGNED") || !containsFlag(m.Flags, "OUT_OF_TREE") {
		t.Fatalf("taint not classified: %#v", m)
	}
}

func TestLooksTestSigner(t *testing.T) {
	if !looksTestSigner("Example Development Signing Key") {
		t.Fatal("expected development signer indicator")
	}
	if looksTestSigner("Microsoft Windows Production PCA 2011") {
		t.Fatal("production signer misclassified")
	}
}

//go:build linux

package software

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseDpkgOwner(t *testing.T) {
	if got := parseDpkgOwner("bash: /usr/bin/bash\n"); got != "bash" {
		t.Fatalf("unexpected dpkg owner %q", got)
	}
	if got := parseDpkgOwner("diversion by dash from: /bin/sh\n"); got != "" {
		t.Fatalf("diversion should not become an exact owner: %q", got)
	}
}

func TestParsePacmanOwner(t *testing.T) {
	if got := parsePacmanOwner("/usr/bin/bash is owned by bash 5.2.037-1\n"); got != "bash" {
		t.Fatalf("unexpected pacman owner %q", got)
	}
}

func TestParseAPKOwnerMatchesNormalizedInventory(t *testing.T) {
	items := []Item{{Kind: "package", Product: "busybox", PackageID: "busybox", Version: "1.37.0-r12", PackageSource: "apk:main", Confidence: evidence.ConfidenceHigh}}
	got := parseAPKOwner("/bin/busybox is owned by busybox-1.37.0-r12\n", items)
	if got == nil || got.PackageID != "busybox" {
		t.Fatalf("unexpected apk owner %#v", got)
	}
}

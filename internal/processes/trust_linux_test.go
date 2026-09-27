//go:build linux

package processes

import "testing"

func TestParseLinuxPackageOwner(t *testing.T) {
	cases := []struct {
		provider string
		text     string
		want     string
	}{
		{"dpkg-query", "coreutils: /usr/bin/ls", "coreutils"},
		{"rpm", "coreutils-9.4-1.fc40", "coreutils-9.4-1.fc40"},
		{"apk", "/bin/busybox is owned by busybox-1.36.1-r15", "busybox-1.36.1-r15"},
		{"pacman", "/usr/bin/ls is owned by coreutils 9.5-1", "coreutils"},
	}
	for _, tc := range cases {
		if got := parseLinuxPackageOwner(tc.provider, tc.text); got != tc.want {
			t.Fatalf("%s parse=%q want=%q", tc.provider, got, tc.want)
		}
	}
}

func TestLinuxOwnershipNotFound(t *testing.T) {
	cases := []struct {
		provider string
		text     string
	}{
		{"dpkg-query", "dpkg-query: no path found matching pattern /tmp/x"},
		{"rpm", "file /tmp/x is not owned by any package"},
		{"pacman", "error: No package owns /tmp/x"},
		{"apk", "ERROR: Could not find owner package for /tmp/x"},
	}
	for _, tc := range cases {
		if !linuxOwnershipNotFound(tc.provider, tc.text) {
			t.Fatalf("expected not-owned classification for %s: %q", tc.provider, tc.text)
		}
	}
}

func TestParseDpkgSearchOutputMapsExactPaths(t *testing.T) {
	got := parseDpkgSearchOutput("coreutils: /usr/bin/ls\nbash: /usr/bin/bash\n")
	if got["/usr/bin/ls"] != "coreutils" || got["/usr/bin/bash"] != "bash" {
		t.Fatalf("unexpected dpkg batch parse: %#v", got)
	}
}

func TestDpkgSearchOnlyMissing(t *testing.T) {
	if !dpkgSearchOnlyMissing("dpkg-query: no path found matching pattern /tmp/a\ndpkg-query: no path found matching pattern /tmp/b") {
		t.Fatal("expected missing-only stderr to be recognized")
	}
	if dpkgSearchOnlyMissing("dpkg-query: database is locked") {
		t.Fatal("generic dpkg failure must not be classified as an unmanaged path")
	}
}

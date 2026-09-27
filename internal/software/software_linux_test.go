//go:build linux

package software

import "testing"

func TestSplitAPKNameVersion(t *testing.T) {
	tests := map[string][2]string{
		"busybox-1.36.1-r2":    {"busybox", "1.36.1-r2"},
		"libfoo-bar-2.1-r0":    {"libfoo-bar", "2.1-r0"},
		"name-without-version": {"name-without-version", "UNKNOWN"},
	}
	for in, want := range tests {
		n, v := splitAPKNameVersion(in)
		if n != want[0] || v != want[1] {
			t.Fatalf("%q => %q %q, want %q %q", in, n, v, want[0], want[1])
		}
	}
}

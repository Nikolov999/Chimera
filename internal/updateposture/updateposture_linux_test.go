//go:build linux

package updateposture

import "testing"

func TestAPTInstParser(t *testing.T) {
	line := "Inst openssl [3.0.2-0ubuntu1.20] (3.0.2-0ubuntu1.21 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])"
	m := aptInstRE.FindStringSubmatch(line)
	if len(m) == 0 {
		t.Fatal("no match")
	}
	if m[1] != "openssl" || m[2] != "3.0.2-0ubuntu1.20" || m[3] != "3.0.2-0ubuntu1.21" {
		t.Fatalf("bad parse %#v", m)
	}
}
func TestSplitAPK(t *testing.T) {
	n, v := splitAPK("openssl-3.3.2-r1")
	if n != "openssl" || v != "3.3.2-r1" {
		t.Fatalf("got %q %q", n, v)
	}
}

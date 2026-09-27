//go:build linux

package remotemgmt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSambaConfigIncludeAndShares(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "shares.conf")
	if err := os.WriteFile(inc, []byte("[public]\npath = /srv/public\nguest ok = yes\nread only = no\nsmb encrypt = required\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "smb.conf")
	cfg := "[global]\nserver min protocol = SMB2_10\nserver signing = mandatory\nmap to guest = Never\ninclude = shares.conf\n"
	if err := os.WriteFile(root, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := parseSambaConfig(root)
	if got := sambaValue(parsed.Sections["global"], "server min protocol"); got != "SMB2_10" {
		t.Fatalf("min protocol=%q", got)
	}
	shares := sambaShares(parsed, "test")
	if len(shares) != 1 || shares[0].Name != "public" || !shares[0].GuestAllowed || !shares[0].WritableKnown || !shares[0].Writable || !shares[0].EncryptionRequired {
		t.Fatalf("share=%#v", shares)
	}
}

func TestParseSambaTextCanonicalizesAliases(t *testing.T) {
	parsed := parseSambaText("[global]\nmin protocol = NT1\n[docs]\npublic = yes\nwriteable = yes\npath = /srv/docs\n", "testparm")
	if got := sambaValue(parsed.Sections["global"], "server min protocol"); got != "NT1" {
		t.Fatalf("alias not canonicalized: %q", got)
	}
	shares := sambaShares(parsed, "test")
	if len(shares) != 1 || !shares[0].GuestAllowed || !shares[0].Writable {
		t.Fatalf("aliases not reflected in share: %#v", shares)
	}
}

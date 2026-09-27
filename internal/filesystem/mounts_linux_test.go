//go:build linux

package filesystem

import "testing"

func TestParseLinuxMountInfoLine(t *testing.T) {
	line := `36 25 0:32 / /mnt/test\040space rw,nosuid,nodev - tmpfs tmpfs rw,size=1024k`
	m, ok := parseLinuxMountInfoLine(line)
	if !ok {
		t.Fatal("expected mountinfo record")
	}
	if m.Path != "/mnt/test space" || m.Filesystem != "tmpfs" || m.Device != "tmpfs" || m.ReadOnly || !m.Writable || m.AccessMode != MountAccessReadWrite || m.Classification != MountClassVirtual || m.EncryptionState != MountEncryptionNotApplicable || m.MajorMinor != "0:32" {
		t.Fatalf("unexpected mount: %#v", m)
	}
}

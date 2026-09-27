//go:build linux

package filesystem

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestDecodeLinuxFileCapabilitiesRevision3(t *testing.T) {
	raw := make([]byte, 24)
	binary.LittleEndian.PutUint32(raw[0:4], 0x03000001) // revision 3 + effective
	// CAP_NET_BIND_SERVICE (10) + CAP_SETUID (7) permitted.
	binary.LittleEndian.PutUint32(raw[4:8], (1<<10)|(1<<7))
	// CAP_SETGID (6) inheritable.
	binary.LittleEndian.PutUint32(raw[8:12], 1<<6)
	binary.LittleEndian.PutUint32(raw[20:24], 1000)
	got, err := decodeLinuxFileCapabilities(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 3 || !got.Effective || got.RootID != "1000" {
		t.Fatalf("unexpected metadata: %#v", got)
	}
	if !containsString(got.Permitted, "CAP_NET_BIND_SERVICE") || !containsString(got.Permitted, "CAP_SETUID") {
		t.Fatalf("missing permitted capabilities: %#v", got.Permitted)
	}
	if !containsString(got.Inheritable, "CAP_SETGID") {
		t.Fatalf("missing inheritable capability: %#v", got.Inheritable)
	}
}

func TestClassifyPrivilegedFileCustomPathRequiresReview(t *testing.T) {
	rec := PrivilegedFileRecord{
		Path: "/usr/local/bin/custom-helper", State: evidence.StateObserved,
		SetUID: true, OwnerID: "0", GroupID: "0", PackageOwnership: "UNKNOWN",
		Classification: "UNRESOLVED", DiscoverySource: "test", CollectionSource: "test",
		Confidence: evidence.ConfidenceHigh,
	}
	classifyPrivilegedFile(&rec)
	if !rec.ReviewRequired || rec.Classification != "CUSTOM_OR_UNEXPECTED" || len(rec.ReviewReasons) == 0 {
		t.Fatalf("unexpected classification: %#v", rec)
	}
}

func TestParseGetcapLine(t *testing.T) {
	path, got, ok := parseGetcapLine("/usr/bin/ping cap_net_raw,cap_net_admin=ep")
	if !ok || path != "/usr/bin/ping" || !got.Effective {
		t.Fatalf("unexpected parse: %q %#v %v", path, got, ok)
	}
	if !containsString(got.Permitted, "CAP_NET_RAW") || !containsString(got.Permitted, "CAP_NET_ADMIN") {
		t.Fatalf("missing parsed capabilities: %#v", got.Permitted)
	}
}

func TestParseFilesystemDpkgSearchOutput(t *testing.T) {
	got := parseFilesystemDpkgSearchOutput("iputils-ping: /usr/bin/ping\nlibcap2-bin: /usr/sbin/getcap\n")
	if got["/usr/bin/ping"] != "iputils-ping" || got["/usr/sbin/getcap"] != "libcap2-bin" {
		t.Fatalf("unexpected dpkg ownership parse: %#v", got)
	}
}

func TestFilesystemDpkgOnlyMissing(t *testing.T) {
	if !filesystemDpkgOnlyMissing("dpkg-query: no path found matching pattern /opt/missing") {
		t.Fatal("expected missing-only dpkg stderr to be recognized")
	}
	if filesystemDpkgOnlyMissing("dpkg-query: database lock failure") {
		t.Fatal("unexpected provider failure classified as a negative ownership result")
	}
}

func TestFix68SinglePassCandidateInspectionFindsSetIDWithoutGetcapTraversal(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "priv-helper")
	plain := filepath.Join(dir, "plain-helper")
	if err := os.WriteFile(priv, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(priv, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	records := map[string]*PrivilegedFileRecord{}
	complete, degraded := inspectLinuxPrivilegeCandidates(context.Background(), []string{plain, priv}, records)
	if !complete || len(degraded) != 0 {
		t.Fatalf("unexpected candidate inspection state complete=%v degraded=%v", complete, degraded)
	}
	if _, ok := records[priv]; !ok {
		t.Fatalf("set-ID candidate was not retained: %#v", records)
	}
	if _, ok := records[plain]; ok {
		t.Fatalf("ordinary executable unexpectedly retained as privileged: %#v", records[plain])
	}
}

func TestFix68ExecutableCandidateFindUsesSingleTraversalContract(t *testing.T) {
	dir := t.TempDir()
	find := filepath.Join(dir, "fake-find")
	candidate := filepath.Join(dir, "candidate")
	if err := os.WriteFile(candidate, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\0' " + strconv.Quote(candidate) + "\n"
	if err := os.WriteFile(find, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	got, complete, err := discoverExecutablePrivilegeCandidatesWithFind(context.Background(), find, []string{dir})
	if err != nil || !complete {
		t.Fatalf("unexpected traversal result complete=%v err=%v", complete, err)
	}
	if len(got) != 1 || got[0] != candidate {
		t.Fatalf("unexpected candidate set: %#v", got)
	}
}

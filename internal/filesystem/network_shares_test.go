package filesystem

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseLinuxNFSExportsDetectsBroadWriteAndRootBoundary(t *testing.T) {
	recs := parseLinuxNFSExports(`/srv/public *(rw,sync,no_root_squash,anonuid=0)
/srv/readonly 10.20.0.0/16(ro,root_squash,sec=krb5p)
`, "/etc/exports")
	if len(recs) != 2 {
		t.Fatalf("records=%d want 2: %#v", len(recs), recs)
	}
	var public NetworkShareRecord
	for _, r := range recs {
		if r.LocalPath == "/srv/public" {
			public = r
		}
	}
	if public.Protocol != NetworkShareProtocolNFS || public.Direction != NetworkShareDirectionExported || !public.BroadAccess || !public.BroadWrite || !public.Writable || !public.AccessKnown {
		t.Fatalf("unexpected public export: %#v", public)
	}
	if !containsString(public.DangerousOptions, "no_root_squash") || !containsString(public.DangerousOptions, "anonymous-uid-0") {
		t.Fatalf("expected root-boundary danger tags: %#v", public.DangerousOptions)
	}
	if public.CollectionSource != "/etc/exports" || public.State != evidence.StateObserved {
		t.Fatalf("unexpected source/state: %#v", public)
	}
}

func TestMountedSMBNetworkShareSecurityOptionsAreNormalizedWithoutSecrets(t *testing.T) {
	mount := MountBoundary{
		Path: "/mnt/team", BackingSource: "//files/team", Filesystem: "cifs",
		Options:    []string{"rw", "guest", "noperm", "vers=1.0", "password=do-not-emit"},
		AccessMode: MountAccessReadWrite, Writable: true, Classification: MountClassNetwork, Network: true,
		EncryptionState: MountEncryptionUnknown, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	recs := mountedNetworkShares([]MountBoundary{mount})
	if len(recs) != 1 {
		t.Fatalf("records=%d want 1", len(recs))
	}
	r := recs[0]
	if r.Protocol != NetworkShareProtocolSMB || !r.GuestAllowed || !r.BroadWrite {
		t.Fatalf("unexpected SMB mount posture: %#v", r)
	}
	for _, opt := range r.SecurityOptions {
		if opt == "password=do-not-emit" || opt == "password" {
			t.Fatalf("secret-bearing option leaked into security options: %#v", r.SecurityOptions)
		}
	}
	for _, want := range []string{"guest-access", "noperm", "legacy-smb1"} {
		if !containsString(r.DangerousOptions, want) {
			t.Fatalf("missing %q in %#v", want, r.DangerousOptions)
		}
	}
}

func TestNormalizeNetworkSharesDeterministicAndDeduplicated(t *testing.T) {
	a := NetworkShareRecord{Direction: "mounted", Protocol: "cifs", LocalPath: "/mnt/z", Remote: "//srv/z", AccessMode: MountAccessReadOnly, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	b := NetworkShareRecord{Direction: "exported", Protocol: "nfs4", LocalPath: "/srv/a", Remote: "10.0.0.0/24", AccessMode: MountAccessReadOnly, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	out := normalizeNetworkShares([]NetworkShareRecord{a, b, a})
	if len(out) != 2 {
		t.Fatalf("normalized=%d want 2: %#v", len(out), out)
	}
	if out[0].Direction != NetworkShareDirectionExported || out[0].Protocol != NetworkShareProtocolNFS || out[1].Protocol != NetworkShareProtocolSMB {
		t.Fatalf("unexpected deterministic normalization: %#v", out)
	}
}

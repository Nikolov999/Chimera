package filesystem

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeACLBoundariesIsDeterministic(t *testing.T) {
	in := []ACLBoundaryRecord{
		{Path: "/z", Contexts: []string{"sensitive_file"}, State: evidence.StateObserved, ACLModel: "POSIX_ACL", DiscoverySources: []string{"b"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
		{Path: "/a", Contexts: []string{"system_root"}, State: evidence.StateObserved, ACLModel: "POSIX_ACL", DiscoverySources: []string{"a"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
	}
	got := normalizeACLBoundaries(in)
	if len(got) != 2 || got[0].Path != "/a" || got[1].Path != "/z" {
		t.Fatalf("ACL boundaries not deterministically ordered: %#v", got)
	}
	if got[0].ID == "" || got[1].ID == "" || got[0].ID == got[1].ID {
		t.Fatalf("stable ACL IDs not assigned: %#v", got)
	}
}

func TestClassifyACLBoundarySeparatesBroadAndNamedWriters(t *testing.T) {
	rec := ACLBoundaryRecord{Grants: []ACLGrant{
		{Principal: "other", PrincipalClass: "OTHER", Access: ACLGrantAllow, Rights: []string{"WRITE"}, Effective: true, Broad: true, WriteLike: true},
		{Principal: "user:1001", PrincipalClass: "NAMED_USER", Access: ACLGrantAllow, Rights: []string{"WRITE"}, Effective: true, WriteLike: true},
		{Principal: "user:0", PrincipalClass: "NAMED_USER", Access: ACLGrantAllow, Rights: []string{"WRITE"}, Effective: true, Trusted: true, WriteLike: true},
		{Principal: "guest", PrincipalClass: "BROAD_PRINCIPAL", Access: ACLGrantDeny, Rights: []string{"WRITE"}, Effective: true, Broad: true, WriteLike: true},
	}}
	classifyACLBoundary(&rec)
	if !rec.DangerousBroadWrite || len(rec.DangerousPrincipals) != 1 || rec.DangerousPrincipals[0] != "other" {
		t.Fatalf("broad ACL classification incorrect: %#v", rec)
	}
	if !rec.ReviewWriteGrant || len(rec.ReviewPrincipals) != 1 || rec.ReviewPrincipals[0] != "user:1001" {
		t.Fatalf("named ACL review classification incorrect: %#v", rec)
	}
}

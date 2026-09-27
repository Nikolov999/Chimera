//go:build linux

package filesystem

import "testing"

func TestLinuxACLGrantsApplyMaskAndTrust(t *testing.T) {
	entries := []posixACLEntry{
		{Tag: aclUserObj, Perm: 7},
		{Tag: aclUser, Perm: 7, ID: 1001},
		{Tag: aclGroupObj, Perm: 7, ID: 0xffffffff},
		{Tag: aclMask, Perm: 5},
		{Tag: aclOther, Perm: 5},
	}
	grants := linuxACLGrants(entries, false, "0")
	var named *ACLGrant
	for i := range grants {
		if grants[i].PrincipalID == "1001" {
			named = &grants[i]
			break
		}
	}
	if named == nil {
		t.Fatal("named user grant missing")
	}
	if named.WriteLike {
		t.Fatalf("ACL mask should remove named-user write permission: %#v", *named)
	}
	if !containsString(named.Rights, "READ") || !containsString(named.Rights, "EXECUTE") {
		t.Fatalf("masked read/execute rights missing: %#v", *named)
	}
}

func TestLinuxACLDefaultOtherWriteIsBroad(t *testing.T) {
	grants := linuxACLGrants([]posixACLEntry{{Tag: aclOther, Perm: 3}}, true, "0")
	if len(grants) != 1 || !grants[0].Broad || !grants[0].WriteLike || grants[0].PrincipalClass != "DEFAULT_OTHER" {
		t.Fatalf("unexpected default ACL grant: %#v", grants)
	}
	rec := ACLBoundaryRecord{Grants: grants}
	classifyACLBoundary(&rec)
	if !rec.DangerousBroadWrite {
		t.Fatalf("default broad write ACL was not classified: %#v", rec)
	}
}

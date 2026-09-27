//go:build linux || darwin

package scheduled

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// enrichPathPosture adds numeric ownership metadata without NSS/user-directory
// lookups. Avoiding name service resolution keeps an ordinary Chimera scan
// local-only even on hosts configured with remote identity providers.
//
// Unix ownership semantics are resolved here, not by common persistence code.
// UID 0 remains the trusted owner boundary used by the existing Chimera rules.
func enrichPathPosture(_ string, info os.FileInfo, p *PathPosture) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return
	}
	p.Owner = fmt.Sprint(st.Uid)
	p.Group = fmt.Sprint(st.Gid)
	p.PermissionBasis = "POSIX mode/uid/gid"
	p.DACLState = "NOT_APPLICABLE"
	if st.Uid == 0 {
		p.OwnerTrust = "TRUSTED"
	} else {
		p.OwnerTrust = "UNTRUSTED"
	}

	// Preserve the pre-Fix15 Unix behavior exactly: a non-root owner can alter
	// permissions on its own object, non-root group-write is a lower-trust
	// mutation boundary, and other-write is broadly writable.
	p.UntrustedWritable = p.OtherWritable || (p.GroupWritable && st.Gid != 0) || st.Uid != 0
	if !p.UntrustedWritable {
		return
	}

	reasons := []string{}
	principals := []string{}
	if st.Uid != 0 {
		principals = append(principals, "uid:"+p.Owner)
		reasons = append(reasons, "non-root owner can change target permissions")
	}
	if p.GroupWritable && st.Gid != 0 {
		principals = append(principals, "gid:"+p.Group)
		reasons = append(reasons, "non-root group has write permission")
	}
	if p.OtherWritable {
		principals = append(principals, "other")
		reasons = append(reasons, "other-write permission is set")
	}
	p.WritePrincipals = uniqueSorted(principals)
	p.Reason = strings.Join(uniqueSorted(reasons), "; ")
}

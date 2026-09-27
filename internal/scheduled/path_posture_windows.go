//go:build windows

package scheduled

import "os"

// Windows scheduled-task collection pre-populates ACL-aware path posture in a
// single PowerShell provider pass. Generic os.Stat fallback intentionally does
// not claim Windows ACL effective-write semantics.
func enrichPathPosture(_ string, _ os.FileInfo, p *PathPosture) {
	if p.PermissionBasis == "" {
		p.PermissionBasis = "filesystem metadata; Windows DACL write state unavailable"
	}
	p.DACLState = "UNAVAILABLE"
	p.OwnerTrust = "UNKNOWN"
	p.UntrustedWritable = false
	p.InheritedUntrustedWrite = false
	p.WritePrincipals = nil
}

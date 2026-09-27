package persistence

import (
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
)

func TestFix15ScheduledWindowsTrustedOwnerSafeDACLIsNotWeak(t *testing.T) {
	got := scheduledPathPosture(scheduled.PathPosture{
		Path:            `C:\Windows\System32\notepad.exe`,
		State:           "OBSERVED",
		Exists:          true,
		Owner:           `NT AUTHORITY\SYSTEM`,
		OwnerSID:        "S-1-5-18",
		OwnerTrust:      "TRUSTED",
		DACLState:       "OBSERVED",
		PermissionBasis: "Windows NTFS DACL lower-trust write grants",
	}, "test")
	if got.UntrustedWrite || got.BroadlyWritable {
		t.Fatalf("safe Windows DACL became weak: %#v", got)
	}
	if got.OwnerID != "S-1-5-18" || got.OwnerPrincipal != `NT AUTHORITY\SYSTEM` || got.OwnerTrust != "TRUSTED" {
		t.Fatalf("Windows owner metadata was not preserved: %#v", got)
	}
	if got.DACLState != "OBSERVED" {
		t.Fatalf("unexpected DACL state: %#v", got)
	}
}

func TestFix15ScheduledWindowsNonProtectedOwnerSafeDACLIsNotWeak(t *testing.T) {
	got := scheduledPathPosture(scheduled.PathPosture{
		Path:            `C:\Tools\task.exe`,
		State:           "OBSERVED",
		Exists:          true,
		Owner:           `HOST\operator`,
		OwnerSID:        "S-1-5-21-1000-1000-1000-1001",
		OwnerTrust:      "UNTRUSTED",
		DACLState:       "OBSERVED",
		PermissionBasis: "Windows NTFS DACL lower-trust write grants",
	}, "test")
	if got.UntrustedWrite {
		t.Fatalf("owner classification alone must not prove a Windows write boundary: %#v", got)
	}
	if got.OwnerTrust != "UNTRUSTED" {
		t.Fatalf("expected owner trust metadata to remain visible: %#v", got)
	}
}

func TestFix15ScheduledWindowsWeakDACLUsesExplicitWriteGrant(t *testing.T) {
	got := scheduledPathPosture(scheduled.PathPosture{
		Path:                    `C:\Tools\task.exe`,
		State:                   "OBSERVED",
		Exists:                  true,
		Owner:                   `NT SERVICE\TrustedInstaller`,
		OwnerSID:                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		OwnerTrust:              "TRUSTED",
		DACLState:               "OBSERVED",
		UntrustedWritable:       true,
		InheritedUntrustedWrite: true,
		WritePrincipals:         []string{"S-1-5-32-545", "S-1-1-0"},
		PermissionBasis:         "Windows NTFS DACL lower-trust write grants",
	}, "test")
	if !got.UntrustedWrite || !got.InheritedUntrustedWrite {
		t.Fatalf("explicit lower-trust Windows write grant was lost: %#v", got)
	}
	if len(got.WritePrincipals) != 2 || got.WritePrincipals[0] != "S-1-1-0" || got.WritePrincipals[1] != "S-1-5-32-545" {
		t.Fatalf("write principals not normalized deterministically: %#v", got.WritePrincipals)
	}
	if !strings.Contains(got.Reason, "lower-trust principal") {
		t.Fatalf("weak Windows path lacks an actionable reason: %#v", got)
	}
}

func TestFix15ScheduledWindowsUnknownACLDoesNotBecomeWeak(t *testing.T) {
	got := scheduledPathPosture(scheduled.PathPosture{
		Path:            `C:\Restricted\task.exe`,
		State:           "DENIED",
		OwnerTrust:      "UNKNOWN",
		DACLState:       "DENIED",
		PermissionBasis: "Windows NTFS DACL lower-trust write grants",
		Reason:          "access denied",
	}, "test")
	if got.State != evidence.StateDenied || got.UntrustedWrite {
		t.Fatalf("unknown Windows ACL must remain unresolved, not weak or clean: %#v", got)
	}
}

func TestFix15ScheduledWindowsSafeOwnersDoNotCreateWeakRoles(t *testing.T) {
	safe := func(path, owner, sid, trust string, dir bool) scheduled.PathPosture {
		return scheduled.PathPosture{
			Path: path, State: "OBSERVED", Exists: true, IsDirectory: dir,
			Owner: owner, OwnerSID: sid, OwnerTrust: trust, DACLState: "OBSERVED",
			PermissionBasis: "Windows NTFS DACL lower-trust write grants",
		}
	}
	na := scheduled.PathPosture{State: "NOT_APPLICABLE", OwnerTrust: "NOT_APPLICABLE", DACLState: "NOT_APPLICABLE", PermissionBasis: "Windows NTFS DACL lower-trust write grants"}
	entry := scheduled.Entry{
		PrivilegeContext:            "SYSTEM",
		ActionPath:                  safe(`C:\Windows\System32\task.exe`, `NT AUTHORITY\SYSTEM`, "S-1-5-18", "TRUSTED", false),
		ActionDirectoryPosture:      safe(`C:\Windows\System32`, `NT SERVICE\TrustedInstaller`, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "TRUSTED", true),
		ReferencedScriptPathPosture: na,
		DefinitionPathPosture:       safe(`C:\Windows\System32\Tasks\Example`, `BUILTIN\Administrators`, "S-1-5-32-544", "TRUSTED", false),
		DefinitionDirectoryPosture:  safe(`C:\Windows\System32\Tasks`, `NT SERVICE\TrustedInstaller`, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "TRUSTED", true),
	}
	got := composeScheduledPathIntegrity(entry)
	if got.State != evidence.StateObserved || len(got.WeakRoles) != 0 {
		t.Fatalf("safe Windows scheduled-task boundaries became weak: %#v", got)
	}
}

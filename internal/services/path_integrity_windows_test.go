//go:build windows

package services

import "testing"

func TestFix18WindowsPathIntegrityPreservesObservedExecutableWhenRegistryUnavailable(t *testing.T) {
	sec := &WindowsSecurity{
		State:                         "DEGRADED",
		AccountAdminState:             "NO",
		ExecutableACL:                 WindowsACLPosture{State: "OBSERVED", BroadWriteGranted: true, Principals: []string{"S-1-5-32-545"}, Rights: []string{"Modify"}, OwnerSID: "S-1-5-18"},
		ExecutableDirectoryACL:        WindowsACLPosture{State: "OBSERVED", OwnerSID: "S-1-5-32-544"},
		RegistryState:                 "UNAVAILABLE",
		RegistryACL:                   WindowsACLPosture{State: "UNAVAILABLE", Reason: "access unavailable"},
		ServiceACL:                    WindowsServiceACLPosture{State: "OBSERVED"},
		ServiceDLLACL:                 WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: WindowsACLPosture{State: "NOT_APPLICABLE"},
	}
	sec.refreshComponents()
	svc := Service{Name: "Demo", ExecutablePath: `C:\Program Files\Demo\demo.exe`, DefinitionPath: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`, PrivilegeContext: "SYSTEM", WindowsSecurity: sec}
	pi := windowsServicePathIntegrity(svc)
	if !pi.Executable.LowerPrivilegeWritable || pi.Executable.State != "OBSERVED" {
		t.Fatalf("observed executable weakness was discarded: %#v", pi.Executable)
	}
	if pi.Executable.Owner != "S-1-5-18" {
		t.Fatalf("stable owner SID not carried into path posture: %#v", pi.Executable)
	}
	if pi.Configuration.State != "UNAVAILABLE" || pi.State != "DEGRADED" {
		t.Fatalf("unavailable registry dimension should degrade only that boundary: %#v", pi)
	}
}

func TestFix18WindowsPathIntegrityCarriesWeakRegistryACL(t *testing.T) {
	sec := &WindowsSecurity{
		State:                         "COMPLETE",
		AccountAdminState:             "NO",
		ExecutableACL:                 WindowsACLPosture{State: "OBSERVED", OwnerSID: "S-1-5-18"},
		ExecutableDirectoryACL:        WindowsACLPosture{State: "OBSERVED", OwnerSID: "S-1-5-32-544"},
		RegistryState:                 "OBSERVED",
		RegistryACL:                   WindowsACLPosture{State: "OBSERVED", BroadWriteGranted: true, Principals: []string{"S-1-5-32-545"}, Rights: []string{"SetValue"}, OwnerSID: "S-1-5-18"},
		ServiceACL:                    WindowsServiceACLPosture{State: "OBSERVED"},
		ServiceDLLACL:                 WindowsACLPosture{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          WindowsACLPosture{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: WindowsACLPosture{State: "NOT_APPLICABLE"},
	}
	sec.refreshComponents()
	svc := Service{Name: "Demo", ExecutablePath: `C:\Windows\System32\demo.exe`, DefinitionPath: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`, PrivilegeContext: "SYSTEM", WindowsSecurity: sec}
	pi := windowsServicePathIntegrity(svc)
	if pi.Configuration.State != "OBSERVED" || !pi.Configuration.LowerPrivilegeWritable {
		t.Fatalf("weak registry ACL did not flow into configuration path posture: %#v", pi.Configuration)
	}
	found := false
	for _, role := range pi.WeakRoles {
		if role == "configuration" {
			found = true
		}
	}
	if !found {
		t.Fatalf("configuration weak role missing: %#v", pi.WeakRoles)
	}
}

func TestFix32PathIntegrityPreservesRegistryACLFailureReason(t *testing.T) {
	svc := Service{
		Name: "Demo", ExecutablePath: `C:\Windows\System32\demo.exe`, DefinitionPath: `HKLM\SYSTEM\CurrentControlSet\Services\Demo`,
		PrivilegeContext: "SYSTEM",
		WindowsSecurity: &WindowsSecurity{
			ExecutableACL:          WindowsACLPosture{State: "OBSERVED"},
			ExecutableDirectoryACL: WindowsACLPosture{State: "OBSERVED"},
			RegistryACL:            WindowsACLPosture{State: "DENIED", Reason: "registry ACL access denied"},
		},
	}
	pi := windowsServicePathIntegrity(svc)
	if pi.State != "DEGRADED" {
		t.Fatalf("expected degraded path integrity, got %#v", pi)
	}
	found := false
	for _, reason := range pi.Degraded {
		if reason == "service registry ACL: registry ACL access denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("registry ACL reason was not preserved: %#v", pi.Degraded)
	}
}

package services

import (
	"strings"
	"testing"
)

func TestWindowsUnquotedExecutablePath(t *testing.T) {
	cases := []struct {
		raw  string
		exe  string
		want bool
	}{
		{`C:\Program Files\Vendor\agent.exe --service`, `C:\Program Files\Vendor\agent.exe`, true},
		{`"C:\Program Files\Vendor\agent.exe" --service`, `C:\Program Files\Vendor\agent.exe`, false},
		{`C:\Windows\System32\svchost.exe -k netsvcs`, `C:\Windows\System32\svchost.exe`, false},
		{"", "", false},
	}
	for _, tc := range cases {
		if got := windowsUnquotedExecutablePath(tc.raw, tc.exe); got != tc.want {
			t.Fatalf("windowsUnquotedExecutablePath(%q,%q)=%v want %v", tc.raw, tc.exe, got, tc.want)
		}
	}
}

func TestParseWindowsServiceSDDLDangerousBroadGrant(t *testing.T) {
	got := parseWindowsServiceSDDL(`D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`)
	if got.State != "OBSERVED" || !got.Weak || !got.Dangerous || got.ControlOnly {
		t.Fatalf("unexpected dangerous ACL posture: %#v", got)
	}
	if len(got.Principals) != 1 || got.Principals[0] != "S-1-1-0" {
		t.Fatalf("unexpected principals: %#v", got.Principals)
	}
}

func TestParseWindowsServiceSDDLControlOnly(t *testing.T) {
	got := parseWindowsServiceSDDL(`D:(A;;CCLCSWLOCRRC;;;SY)(A;;RPWP;;;AU)`)
	if got.State != "OBSERVED" || got.Weak || got.Dangerous || !got.ControlOnly {
		t.Fatalf("unexpected control-only ACL posture: %#v", got)
	}
}

func TestParseWindowsServiceSDDLSafeAdministrativeGrants(t *testing.T) {
	got := parseWindowsServiceSDDL(`D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`)
	if got.State != "OBSERVED" || got.Weak || got.Dangerous || got.ControlOnly {
		t.Fatalf("unexpected safe ACL posture: %#v", got)
	}
}

func TestNormalizeWindowsSecurityDiscardsCommandValuesAndValidates(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceSDDL:       `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;RP;;;AU)`,
		AccountAdminState: "NO",
		RegistryState:     "OBSERVED",
		RegistryACL:       windowsPathACLRecord{State: "OBSERVED"},
		ExecutableACL: windowsPathACLRecord{
			State: "OBSERVED",
		},
		ExecutableDirectoryACL: windowsPathACLRecord{State: "OBSERVED"},
		ServiceDLLACL:          windowsPathACLRecord{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL: windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableACL:   windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{
			State: "NOT_APPLICABLE",
		},
	}
	sec := normalizeWindowsSecurity(raw, `"C:\Program Files\Vendor\agent.exe" --token secret`, `C:\Program Files\Vendor\agent.exe`)
	if sec.UnquotedExecutablePath {
		t.Fatal("quoted executable should not be classified as unquoted")
	}
	if sec.State != "COMPLETE" {
		t.Fatalf("expected complete security metadata, got %#v", sec)
	}
	if err := sec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSecurityOptionalDimensionsDoNotDegradeCore(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceSDDL:                   `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`,
		ServiceACLState:               "OBSERVED",
		AccountAdminState:             "NO",
		RegistryState:                 "OBSERVED",
		RegistryACL:                   windowsPathACLRecord{State: "OBSERVED"},
		ExecutableACL:                 windowsPathACLRecord{State: "OBSERVED", OwnerSID: "S-1-5-18"},
		ExecutableDirectoryACL:        windowsPathACLRecord{State: "OBSERVED", OwnerSID: "S-1-5-32-544"},
		ServiceDLLACL:                 windowsPathACLRecord{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{State: "NOT_APPLICABLE"},
	}
	sec := normalizeWindowsSecurity(raw, `"C:\Program Files\Vendor\agent.exe" --service`, `C:\Program Files\Vendor\agent.exe`)
	if sec.State != "COMPLETE" {
		t.Fatalf("optional absent dimensions must not degrade security: %#v", sec)
	}
	if sec.Components.ServiceDLLACL != "NOT_APPLICABLE" || sec.Components.ServiceDLLDirectoryACL != "NOT_APPLICABLE" || sec.Components.RecoveryExecutableACL != "NOT_APPLICABLE" || sec.Components.RecoveryExecutableDirACL != "NOT_APPLICABLE" {
		t.Fatalf("unexpected optional component states: %#v", sec.Components)
	}
	if sec.Components.ExecutableACL != "OBSERVED" || sec.Components.ExecutableDirectoryACL != "OBSERVED" || sec.Components.RegistryMetadata != "OBSERVED" || sec.Components.RegistryACL != "OBSERVED" || sec.Components.ServiceObject != "OBSERVED" || sec.Components.Account != "OBSERVED" {
		t.Fatalf("core component coverage not observed: %#v", sec.Components)
	}
	if sec.ExecutableACL.OwnerSID != "S-1-5-18" {
		t.Fatalf("owner SID was not preserved: %#v", sec.ExecutableACL)
	}
	if err := sec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSecurityOneUnavailableDimensionPreservesObservedACLs(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceACLState:   "UNAVAILABLE",
		ServiceACLReason:  "sdshow denied",
		AccountAdminState: "NO",
		RegistryState:     "OBSERVED",
		RegistryACL:       windowsPathACLRecord{State: "OBSERVED"},
		ExecutableACL: windowsPathACLRecord{
			State: "OBSERVED", BroadWriteGranted: true,
			Principals: []string{"S-1-5-32-545"}, Rights: []string{"Modify"}, InheritedWrite: true,
		},
		ExecutableDirectoryACL:        windowsPathACLRecord{State: "OBSERVED"},
		ServiceDLLACL:                 windowsPathACLRecord{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{State: "NOT_APPLICABLE"},
	}
	sec := normalizeWindowsSecurity(raw, `C:\Program Files\Vendor\agent.exe --service`, `C:\Program Files\Vendor\agent.exe`)
	if sec.State != "DEGRADED" || sec.Components.ServiceObject != "UNAVAILABLE" {
		t.Fatalf("expected only aggregate degradation for missing service ACL: %#v", sec)
	}
	if !sec.ExecutableACL.BroadWriteGranted || sec.Components.ExecutableACL != "OBSERVED" || !sec.ExecutableACL.InheritedWrite {
		t.Fatalf("observed executable ACL was discarded by unrelated degradation: %#v", sec.ExecutableACL)
	}
}

func TestFix39UnavailableWindowsSecurityDoesNotInventOptionalAbsence(t *testing.T) {
	sec := unavailableWindowsSecurity("provider failed")
	if sec.State != "DEGRADED" || sec.Components.ExecutableACL == "OBSERVED" || sec.Components.RegistryMetadata == "OBSERVED" {
		t.Fatalf("unexpected unavailable security posture: %#v", sec)
	}
	if sec.Components.ServiceDLLMetadata != "UNAVAILABLE" || sec.Components.ServiceDLLACL != "UNAVAILABLE" || sec.Components.ServiceDLLDirectoryACL != "UNAVAILABLE" || sec.Components.RecoveryConfiguration != "UNAVAILABLE" || sec.Components.RecoveryExecutableACL != "UNAVAILABLE" || sec.Components.RecoveryExecutableDirACL != "UNAVAILABLE" {
		t.Fatalf("provider failure must remain distinct from proven optional absence: %#v", sec.Components)
	}
	if err := sec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFix18WritableDirectoryAndRegistryACLRemainObservedEvidence(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceSDDL:       `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`,
		AccountAdminState: "NO",
		RegistryState:     "OBSERVED",
		RegistryACL: windowsPathACLRecord{
			State: "OBSERVED", BroadWriteGranted: true,
			Principals: []string{"S-1-5-32-545"}, Rights: []string{"SetValue"}, OwnerSID: "S-1-5-18",
		},
		ExecutableACL: windowsPathACLRecord{State: "OBSERVED", OwnerSID: "S-1-5-18"},
		ExecutableDirectoryACL: windowsPathACLRecord{
			State: "OBSERVED", BroadWriteGranted: true,
			Principals: []string{"S-1-5-11"}, Rights: []string{"Modify"}, OwnerSID: "S-1-5-32-544",
		},
		ServiceDLLACL:                 windowsPathACLRecord{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableACL:          windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{State: "NOT_APPLICABLE"},
	}
	sec := normalizeWindowsSecurity(raw, `"C:\Program Files\Demo\demo.exe"`, `C:\Program Files\Demo\demo.exe`)
	if sec.State != "COMPLETE" {
		t.Fatalf("observed weakness is a security result, not collection degradation: %#v", sec)
	}
	if !sec.ExecutableDirectoryACL.BroadWriteGranted || !sec.RegistryACL.BroadWriteGranted {
		t.Fatalf("expected weak observed ACL facts to survive normalization: %#v", sec)
	}
	if sec.Components.ExecutableDirectoryACL != "OBSERVED" || sec.Components.RegistryACL != "OBSERVED" {
		t.Fatalf("weak ACLs must remain observed component evidence: %#v", sec.Components)
	}
}

func TestFix18ApplicableServiceDLLUnavailableDegradesOnlyDLLComponent(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceSDDL:                   `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`,
		AccountAdminState:             "NO",
		RegistryState:                 "OBSERVED",
		RegistryACL:                   windowsPathACLRecord{State: "OBSERVED"},
		ExecutableACL:                 windowsPathACLRecord{State: "OBSERVED"},
		ExecutableDirectoryACL:        windowsPathACLRecord{State: "OBSERVED"},
		ServiceDLLPath:                `C:\Program Files\Demo\plugin.dll`,
		ServiceDLLACL:                 windowsPathACLRecord{State: "DENIED", Reason: "access denied"},
		ServiceDLLDirectoryACL:        windowsPathACLRecord{State: "OBSERVED"},
		FailureExecutableACL:          windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{State: "NOT_APPLICABLE"},
	}
	sec := normalizeWindowsSecurity(raw, `"C:\Windows\System32\svchost.exe" -k demo`, `C:\Windows\System32\svchost.exe`)
	if sec.State != "DEGRADED" || sec.Components.ServiceDLLACL != "DENIED" || sec.Components.ServiceDLLDirectoryACL != "OBSERVED" {
		t.Fatalf("unexpected applicable ServiceDll component posture: %#v", sec)
	}
	if sec.Components.ExecutableACL != "OBSERVED" || sec.Components.RegistryACL != "OBSERVED" || sec.Components.ServiceObject != "OBSERVED" {
		t.Fatalf("ServiceDll failure erased unrelated observed evidence: %#v", sec.Components)
	}
	found := false
	for _, d := range sec.Degraded {
		if d == "service DLL ACL: access denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing explicit ServiceDll degradation reason: %#v", sec.Degraded)
	}
}

func TestFix18RecoveryExecutableCanDegradeIndependently(t *testing.T) {
	raw := windowsSecurityRecord{
		ServiceSDDL:                   `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`,
		AccountAdminState:             "NO",
		RegistryState:                 "OBSERVED",
		RegistryACL:                   windowsPathACLRecord{State: "OBSERVED"},
		ExecutableACL:                 windowsPathACLRecord{State: "OBSERVED"},
		ExecutableDirectoryACL:        windowsPathACLRecord{State: "OBSERVED"},
		ServiceDLLACL:                 windowsPathACLRecord{State: "NOT_APPLICABLE"},
		ServiceDLLDirectoryACL:        windowsPathACLRecord{State: "NOT_APPLICABLE"},
		FailureCommandPresent:         true,
		FailureExecutablePath:         `C:\Program Files\Demo\recover.exe`,
		FailureExecutableACL:          windowsPathACLRecord{State: "UNAVAILABLE", Reason: "path inaccessible"},
		FailureExecutableDirectoryACL: windowsPathACLRecord{State: "OBSERVED"},
	}
	sec := normalizeWindowsSecurity(raw, `"C:\Program Files\Demo\demo.exe"`, `C:\Program Files\Demo\demo.exe`)
	if sec.State != "DEGRADED" || sec.Components.RecoveryExecutableACL != "UNAVAILABLE" || sec.Components.RecoveryExecutableDirACL != "OBSERVED" {
		t.Fatalf("unexpected recovery component posture: %#v", sec)
	}
	if sec.Components.ExecutableACL != "OBSERVED" || sec.Components.RegistryMetadata != "OBSERVED" {
		t.Fatalf("recovery failure erased core evidence: %#v", sec.Components)
	}
}

func TestFix32MixedDangerousAndControlGrantIsDangerousNotControlOnly(t *testing.T) {
	got := parseWindowsServiceSDDL(`D:(A;;DCRPWP;;;AU)`)
	if got.State != "OBSERVED" || !got.Weak || !got.Dangerous || got.ControlOnly {
		t.Fatalf("mixed service-object rights were not calibrated correctly: %#v", got)
	}
}

func TestFix32ControlOnlyServiceACLIsVisibleWithoutInflatingWeakCount(t *testing.T) {
	s := summarize([]Service{{WindowsSecurity: &WindowsSecurity{ServiceACL: WindowsServiceACLPosture{State: "OBSERVED", ControlOnly: true}}}})
	if s.WeakServiceACLs != 0 || s.DangerousServiceACLs != 0 || s.ControlOnlyServiceACLs != 1 {
		t.Fatalf("unexpected calibrated service ACL summary: %#v", s)
	}
}

func TestFix36RegistryACLEntriesPreserveSIDAndAtomicRights(t *testing.T) {
	raw := windowsPathACLRecord{
		State:    "OBSERVED",
		OwnerSID: " S-1-5-18 ",
		Entries: []windowsACLEntryRecord{
			{
				SID:                  "S-1-5-32-545",
				Principal:            `BUILTIN\Users`,
				PrincipalResolution:  "observed",
				AccessType:           "Allow",
				Inherited:            true,
				Explicit:             false,
				InheritanceFlags:     "None",
				PropagationFlags:     "None",
				Rights:               "SetValue, ReadKey",
				RightsMask:           131099,
				AtomicMutatingRights: []string{"SetValue", "SetValue"},
			},
			{
				SID:                 " S-1-5-21-999 ",
				PrincipalResolution: "unavailable",
				AccessType:          "Deny",
				Explicit:            true,
				Rights:              "CreateSubKey",
				RightsMask:          4,
			},
		},
	}
	got := normalizeWindowsACL(raw)
	if got.OwnerSID != "S-1-5-18" || !got.BroadWriteGranted || !got.InheritedWrite {
		t.Fatalf("registry ACL summary was not derived from normalized ACEs: %#v", got)
	}
	if len(got.Principals) != 1 || got.Principals[0] != "S-1-5-32-545" {
		t.Fatalf("unexpected broad-write principals: %#v", got.Principals)
	}
	if len(got.Rights) != 1 || got.Rights[0] != "SetValue" {
		t.Fatalf("registry summary did not retain atomic rights: %#v", got.Rights)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("registry ACL entry count=%d, want 2", len(got.Entries))
	}
	entry := got.Entries[1]
	if entry.SID != "S-1-5-21-999" || entry.PrincipalResolution != "UNAVAILABLE" || entry.AccessType != "DENY" || !entry.Explicit {
		t.Fatalf("unresolved/deny entry was not preserved: %#v", entry)
	}
	if len(entry.AtomicMutatingRights) != 1 || entry.AtomicMutatingRights[0] != "CreateSubKey" {
		t.Fatalf("atomic rights were not derived from the registry mask: %#v", entry.AtomicMutatingRights)
	}
}

func TestFix36RegistryACLAllowsUnresolvedPrincipalNameWhenSIDExists(t *testing.T) {
	acl := WindowsACLPosture{
		State: "OBSERVED",
		Entries: []WindowsACLEntry{{
			SID:                 "S-1-5-21-123-456-789-1001",
			PrincipalResolution: "UNAVAILABLE",
			AccessType:          "ALLOW",
			Rights:              "ReadKey",
			RightsMask:          131097,
		}},
	}
	if err := validateWindowsACL("registry", acl); err != nil {
		t.Fatalf("raw SID evidence must survive principal-name translation failure: %v", err)
	}
}

func TestFix36RegistryACLFailureAndPartialFixtures(t *testing.T) {
	cases := []struct {
		name      string
		raw       windowsPathACLRecord
		wantState string
		wantWhy   string
	}{
		{
			name:      "access-denied",
			raw:       windowsPathACLRecord{State: "DENIED", Reason: "stage=open_subkey; requested registry access is not allowed"},
			wantState: "DENIED",
			wantWhy:   "stage=open_subkey",
		},
		{
			name:      "service-removed-mid-collection",
			raw:       windowsPathACLRecord{State: "UNAVAILABLE", Reason: "stage=open_subkey; service registry key was not found"},
			wantState: "UNAVAILABLE",
			wantWhy:   "stage=open_subkey",
		},
		{
			name: "malformed-entry-isolated",
			raw: windowsPathACLRecord{
				State:  "DEGRADED",
				Reason: "registry ACL partially normalized; failed_components=1; stage=normalize_rule; ACL entry has no SID identity",
				Entries: []windowsACLEntryRecord{{
					SID:                 "S-1-5-18",
					Principal:           `NT AUTHORITY\SYSTEM`,
					PrincipalResolution: "OBSERVED",
					AccessType:          "ALLOW",
					Rights:              "FullControl",
					RightsMask:          983103,
				}},
			},
			wantState: "DEGRADED",
			wantWhy:   "stage=normalize_rule",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeWindowsACL(tc.raw)
			if got.State != tc.wantState || !strings.Contains(got.Reason, tc.wantWhy) {
				t.Fatalf("unexpected registry ACL fixture result: %#v", got)
			}
			if tc.name == "malformed-entry-isolated" && len(got.Entries) != 1 {
				t.Fatalf("usable registry ACL entries were lost after one malformed entry: %#v", got.Entries)
			}
		})
	}
}

func TestFix39ServiceObjectControlRightsIncludeInterrogateAndUserDefinedControl(t *testing.T) {
	got := parseWindowsServiceSDDL(`D:(A;;LOCR;;;AU)`)
	if got.State != "OBSERVED" || !got.ControlOnly || got.Weak || got.Dangerous {
		t.Fatalf("interrogate/user-defined control rights must remain visible but non-mutating: %#v", got)
	}
	joined := strings.Join(got.Rights, ",")
	if !strings.Contains(joined, "LO") || !strings.Contains(joined, "CR") {
		t.Fatalf("control rights were not retained: %#v", got.Rights)
	}
}

func TestFix39NumericServiceControlRightsRemainNonMutating(t *testing.T) {
	// START|STOP|PAUSE_CONTINUE|INTERROGATE|USER_DEFINED_CONTROL
	got := parseWindowsServiceSDDL(`D:(A;;0x000001F0;;;AU)`)
	if got.State != "OBSERVED" || !got.ControlOnly || got.Weak || got.Dangerous {
		t.Fatalf("numeric service-control rights must not become mutation weakness: %#v", got)
	}
}

func TestFix39ExecutableResolutionIsExplicit(t *testing.T) {
	cases := []struct {
		raw, exe, want string
	}{
		{`C:\Program Files\Vendor\agent.exe --service`, `C:\Program Files\Vendor\agent.exe`, "UNQUOTED"},
		{`"C:\Program Files\Vendor\agent.exe" --service`, `C:\Program Files\Vendor\agent.exe`, "QUOTED_OR_ABSOLUTE"},
		{`C:\Windows\System32\svchost.exe -k netsvcs`, `C:\Windows\System32\svchost.exe`, "QUOTED_OR_ABSOLUTE"},
		{"", "", "UNAVAILABLE"},
	}
	for _, tc := range cases {
		if got := windowsExecutableResolution(tc.raw, tc.exe); got != tc.want {
			t.Fatalf("windowsExecutableResolution(%q,%q)=%q want %q", tc.raw, tc.exe, got, tc.want)
		}
	}
}

func TestFix39ComponentStateCombinationPreservesFailureClass(t *testing.T) {
	cases := []struct {
		states []string
		want   string
	}{
		{[]string{"NOT_APPLICABLE", "NOT_APPLICABLE"}, "NOT_APPLICABLE"},
		{[]string{"OBSERVED", "NOT_APPLICABLE"}, "OBSERVED"},
		{[]string{"OBSERVED", "DENIED"}, "DENIED"},
		{[]string{"OBSERVED", "UNAVAILABLE"}, "UNAVAILABLE"},
		{[]string{"OBSERVED", "DEGRADED"}, "DEGRADED"},
	}
	for _, tc := range cases {
		if got := combineSecurityComponentStates(tc.states...); got != tc.want {
			t.Fatalf("combineSecurityComponentStates(%v)=%q want %q", tc.states, got, tc.want)
		}
	}
}

func TestFix47RegistryACLCompatibilityMetadataIsPreserved(t *testing.T) {
	raw := windowsPathACLRecord{
		State:             "unavailable",
		Stage:             "read_security_descriptor",
		AcquisitionMethod: "native_reggetkeysecurity",
		Reason:            "stage=READ_SECURITY_DESCRIPTOR; native descriptor read failed",
	}
	got := normalizeWindowsACL(raw)
	if got.State != "UNAVAILABLE" {
		t.Fatalf("registry ACL state=%q, want UNAVAILABLE", got.State)
	}
	if got.Stage != "READ_SECURITY_DESCRIPTOR" {
		t.Fatalf("registry ACL stage=%q, want READ_SECURITY_DESCRIPTOR", got.Stage)
	}
	if got.AcquisitionMethod != "NATIVE_REGGETKEYSECURITY" {
		t.Fatalf("registry ACL acquisition method=%q, want NATIVE_REGGETKEYSECURITY", got.AcquisitionMethod)
	}
	if !strings.Contains(got.Reason, "READ_SECURITY_DESCRIPTOR") {
		t.Fatalf("registry ACL reason lost the failing stage: %q", got.Reason)
	}
}

func TestFix47SIDTranslationFailurePreservesRawSIDAndReason(t *testing.T) {
	raw := windowsPathACLRecord{
		State:             "OBSERVED",
		Stage:             "OBSERVED",
		AcquisitionMethod: "REGISTRYKEY_GETACCESSCONTROL",
		Entries: []windowsACLEntryRecord{{
			SID:                       " S-1-5-21-123-456-789-1001 ",
			PrincipalResolution:       "unavailable",
			PrincipalResolutionReason: "stage=SID_TRANSLATION; account could not be mapped",
			AccessType:                "Allow",
			Rights:                    "ReadKey",
			RightsMask:                131097,
		}},
	}
	got := normalizeWindowsACL(raw)
	if len(got.Entries) != 1 {
		t.Fatalf("registry ACL entries=%d, want 1", len(got.Entries))
	}
	entry := got.Entries[0]
	if entry.SID != "S-1-5-21-123-456-789-1001" {
		t.Fatalf("raw SID was not preserved: %#v", entry)
	}
	if entry.PrincipalResolution != "UNAVAILABLE" || !strings.Contains(entry.PrincipalResolutionReason, "SID_TRANSLATION") {
		t.Fatalf("SID translation failure metadata was not preserved: %#v", entry)
	}
	if err := validateWindowsACL("registry", got); err != nil {
		t.Fatalf("SID translation failure must not invalidate raw SID rights evidence: %v", err)
	}
}

func TestFix47RegistryACLStageAndAcquisitionMetadataNormalizeOnExistingEvidence(t *testing.T) {
	in := WindowsACLPosture{
		State:             "observed",
		Stage:             "get_access_rules",
		AcquisitionMethod: "registrykey_getaccesscontrol",
		Entries: []WindowsACLEntry{{
			SID:                       "S-1-5-18",
			PrincipalResolution:       "observed",
			PrincipalResolutionReason: "  ",
			AccessType:                "allow",
			Rights:                    "FullControl",
			RightsMask:                983103,
		}},
	}
	got := normalizeExistingWindowsACL(in)
	if got.Stage != "GET_ACCESS_RULES" || got.AcquisitionMethod != "REGISTRYKEY_GETACCESSCONTROL" {
		t.Fatalf("existing registry ACL compatibility metadata not normalized: %#v", got)
	}
	if got.Entries[0].PrincipalResolution != "OBSERVED" || got.Entries[0].AccessType != "ALLOW" {
		t.Fatalf("entry normalization regressed: %#v", got.Entries[0])
	}
}

func TestFix49PowerShell51NormalizedRegistryACLRemainsObserved(t *testing.T) {
	raw := windowsPathACLRecord{
		State:             "OBSERVED",
		Stage:             "OBSERVED",
		AcquisitionMethod: "NATIVE_REGGETKEYSECURITY",
		OwnerSID:          "S-1-5-18",
		Entries: []windowsACLEntryRecord{
			{
				SID:                  "S-1-5-18",
				Principal:            `NT AUTHORITY\SYSTEM`,
				PrincipalResolution:  "OBSERVED",
				AccessType:           "ALLOW",
				Rights:               "FullControl",
				RightsMask:           983103,
				AtomicMutatingRights: []string{"SetValue", "CreateSubKey", "Delete", "ChangePermissions", "TakeOwnership"},
			},
			{
				SID:                 "S-1-5-21-999-1001",
				PrincipalResolution: "UNAVAILABLE",
				AccessType:          "ALLOW",
				Rights:              "ReadKey",
				RightsMask:          131097,
			},
		},
	}
	got := normalizeWindowsACL(raw)
	if got.State != "OBSERVED" || got.Stage != "OBSERVED" || got.AcquisitionMethod != "NATIVE_REGGETKEYSECURITY" {
		t.Fatalf("Fix49 normalized ACL metadata regressed: %#v", got)
	}
	if got.OwnerSID != "S-1-5-18" || len(got.Entries) != 2 {
		t.Fatalf("Fix49 normalized ACL entries/owner were lost: %#v", got)
	}
	if got.Entries[1].SID != "S-1-5-21-999-1001" || got.Entries[1].PrincipalResolution != "UNAVAILABLE" {
		t.Fatalf("Fix49 unresolved SID evidence was not preserved: %#v", got.Entries[1])
	}
	if err := validateWindowsACL("registry", got); err != nil {
		t.Fatalf("Fix49 normalized registry ACL should validate: %v", err)
	}
}

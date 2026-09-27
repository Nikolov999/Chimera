package persistence

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase098Entry(account, privilege string, weak bool) Entry {
	roles := []string{}
	if weak {
		roles = []string{"executable"}
	}
	return Entry{Account: account, PrivilegeContext: privilege, PathIntegrity: PathIntegrity{Privileged: false, PrivilegeBasis: privilege, WeakRoles: roles}}
}

func TestPhase098CorrelatesCustomAdminAccount(t *testing.T) {
	idx := buildAccountAliasIndex([]accounts.Account{{ID: "acct-admin", Name: "opsadmin", Principal: "opsadmin", Privileged: true, PrivilegeBasis: []string{"administrators membership"}, Confidence: evidence.ConfidenceHigh}})
	pc := correlateEntryPrivilege(phase098Entry("opsadmin", "SERVICE_ACCOUNT", true), idx, true)
	if pc.State != evidence.StateObserved || !pc.HighPrivilege || pc.AccountMatchState != "MATCHED" || pc.RiskContext != "WEAK_HIGH_PRIVILEGE_PERSISTENCE" {
		t.Fatalf("unexpected admin correlation: %#v", pc)
	}
}

func TestPhase098KeepsPlaceholderIdentityUnresolved(t *testing.T) {
	pc := correlateEntryPrivilege(phase098Entry("CURRENT_USER", "USER", true), map[string][]accounts.Account{}, true)
	if pc.State != evidence.StateUnavailable || pc.HighPrivilege || pc.AccountMatchState != "UNRESOLVED" || pc.RiskContext != "PRIVILEGE_UNRESOLVED" {
		t.Fatalf("placeholder identity must remain unresolved: %#v", pc)
	}
}

func TestPhase098BuiltinRootDoesNotDependOnAccountInventory(t *testing.T) {
	e := phase098Entry("root", "ROOT", true)
	e.PathIntegrity.Privileged = true
	pc := correlateEntryPrivilege(e, nil, false)
	if pc.State != evidence.StateObserved || !pc.HighPrivilege || pc.ExecutionLevel != "HIGH_PRIVILEGE" {
		t.Fatalf("root privilege should be directly observable: %#v", pc)
	}
}

func TestPhase098CorrelatesKnownNonPrivilegedAccount(t *testing.T) {
	idx := buildAccountAliasIndex([]accounts.Account{{ID: "acct-svc", Name: "svc-demo", Principal: "svc-demo", Privileged: false, Confidence: evidence.ConfidenceHigh}})
	pc := correlateEntryPrivilege(phase098Entry("svc-demo", "SERVICE_ACCOUNT", true), idx, true)
	if pc.State != evidence.StateObserved || pc.HighPrivilege || pc.ExecutionLevel != "NON_PRIVILEGED" || pc.RiskContext != "WEAK_NON_PRIVILEGED_PERSISTENCE" {
		t.Fatalf("unexpected non-privileged correlation: %#v", pc)
	}
}

func windowsAccountCapabilityFixture() accounts.Inventory {
	return accounts.Inventory{
		Platform: "windows",
		Accounts: []accounts.Account{{
			ID: "acct-admin", Name: "opsadmin", Principal: `CONTOSO\opsadmin`, SID: "S-1-5-21-1000",
			Privileged: true, PrivilegeBasis: []string{"member of privileged group Administrators"},
			Confidence: evidence.ConfidenceHigh,
		}},
		Groups: []accounts.Group{{Name: "Administrators", SID: "S-1-5-32-544", Privileged: true, Confidence: evidence.ConfidenceHigh}},
		Sources: []accounts.SourceStatus{
			{ID: "windows-local-accounts", State: evidence.StateObserved, ItemCount: 1},
			{ID: "windows-local-groups", State: evidence.StateObserved, ItemCount: 1},
		},
	}
}

func TestFix29CredentialProtectionDegradationDoesNotPoisonPrivilegeCapability(t *testing.T) {
	ac := windowsAccountCapabilityFixture()
	ac.Degraded = []string{"windows-credential-protection: credential-guard-lsa-config: registry value is absent"}
	ac.CredentialProtection.State = evidence.StateDegraded
	ac.CredentialProtection.Reason = "credential-guard-lsa-config: registry value is absent"

	cap := assessAccountPrivilegeCapability(ac)
	if cap.State != evidence.StateObserved || !cap.Usable || cap.Reason != "" {
		t.Fatalf("unrelated credential-protection degradation must not poison local account/group capability: %#v", cap)
	}

	idx := buildAccountAliasIndex(ac.Accounts)
	pc := correlateEntryPrivilegeWithCapability(phase098Entry(`CONTOSO\opsadmin`, "SERVICE_ACCOUNT", false), idx, cap)
	if pc.State != evidence.StateObserved || !pc.HighPrivilege || pc.AccountMatchState != "MATCHED" {
		t.Fatalf("expected observed privileged account correlation despite credential-protection degradation: %#v", pc)
	}
}

func TestFix29RelevantGroupProviderDegradationIsScoped(t *testing.T) {
	ac := windowsAccountCapabilityFixture()
	ac.Sources[1].State = evidence.StateDegraded
	ac.Sources[1].Reason = "one group membership unavailable"
	cap := assessAccountPrivilegeCapability(ac)
	if cap.State != evidence.StateDegraded || !cap.Usable || cap.Reason == "" {
		t.Fatalf("relevant group degradation must produce usable DEGRADED capability: %#v", cap)
	}

	idx := buildAccountAliasIndex(ac.Accounts)
	pc := correlateEntryPrivilegeWithCapability(phase098Entry(`CONTOSO\opsadmin`, "SERVICE_ACCOUNT", false), idx, cap)
	if pc.State != evidence.StateObserved || !pc.HighPrivilege {
		t.Fatalf("an exact normalized account record remains usable under scoped provider degradation: %#v", pc)
	}
}

func TestFix29NoLocalAccountRecordsMakesCapabilityUnavailable(t *testing.T) {
	ac := windowsAccountCapabilityFixture()
	ac.Accounts = nil
	cap := assessAccountPrivilegeCapability(ac)
	if cap.State != evidence.StateUnavailable || cap.Usable {
		t.Fatalf("missing local account records must make privilege capability unavailable: %#v", cap)
	}
}

func TestFix29BuiltinLowPrivilegeWindowsIdentityDoesNotNeedLocalAccountRecord(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	pc := correlateEntryPrivilegeWithCapability(phase098Entry(`NT AUTHORITY\LOCAL SERVICE`, "SERVICE_ACCOUNT", true), nil, cap)
	if pc.State != evidence.StateObserved || pc.HighPrivilege || pc.ExecutionLevel != "NON_PRIVILEGED" || pc.AccountMatchState != "BUILTIN" || pc.Reason != "" {
		t.Fatalf("expected built-in low-privilege service identity to be resolved without local-account inventory: %#v", pc)
	}
}

func TestFix29CorrelationIgnoresUnrelatedAccountsDegradedSlice(t *testing.T) {
	ac := windowsAccountCapabilityFixture()
	ac.Degraded = []string{"windows-credential-protection: credential-guard-lsa-config: registry value is absent"}
	inv := Inventory{Entries: []Entry{phase098Entry(`CONTOSO\opsadmin`, "SERVICE_ACCOUNT", true)}}

	correlateAccountPrivileges(&inv, ac)

	if len(inv.Entries) != 1 || inv.Entries[0].PrivilegeCorrelation.State != evidence.StateObserved || !inv.Entries[0].PrivilegeCorrelation.HighPrivilege {
		t.Fatalf("expected normalized account privilege evidence to remain usable: %#v", inv.Entries)
	}
	if len(inv.Degraded) != 0 {
		t.Fatalf("unrelated account posture degradation leaked into persistence capability: %#v", inv.Degraded)
	}
	if len(inv.Sources) != 1 || inv.Sources[0].ID != "account-privilege-correlation" || inv.Sources[0].State != evidence.StateObserved {
		t.Fatalf("unexpected correlation source status: %#v", inv.Sources)
	}
}

func TestFix29DegradedGroupCapabilityDoesNotAssertNonPrivileged(t *testing.T) {
	ac := windowsAccountCapabilityFixture()
	ac.Accounts[0].Privileged = false
	ac.Accounts[0].PrivilegeBasis = nil
	ac.Sources[1].State = evidence.StateDegraded
	ac.Sources[1].Reason = "group membership unavailable"
	cap := assessAccountPrivilegeCapability(ac)
	idx := buildAccountAliasIndex(ac.Accounts)
	pc := correlateEntryPrivilegeWithCapability(phase098Entry(`CONTOSO\opsadmin`, "SERVICE_ACCOUNT", false), idx, cap)
	if pc.State != evidence.StateDegraded || pc.ExecutionLevel != "UNKNOWN" || pc.AccountMatchState != "MATCHED" {
		t.Fatalf("degraded group evidence must not assert non-privileged execution: %#v", pc)
	}
}

func TestFix41WellKnownWindowsSystemAliasesNormalizeSID(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateUnavailable, Usable: false, Reason: "local account provider unavailable"}
	for _, principal := range []string{"LocalSystem", `NT AUTHORITY\SYSTEM`, "S-1-5-18"} {
		pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(principal, "SERVICE_ACCOUNT", true), nil, nil, cap)
		if pc.State != evidence.StateObserved || pc.PrivilegeState != PrivilegeStateBuiltinSystem || !pc.HighPrivilege || pc.ExecutionLevel != "HIGH_PRIVILEGE" || pc.PrincipalSID != "S-1-5-18" || pc.AccountMatchState != "BUILTIN" {
			t.Fatalf("SYSTEM alias %q was not normalized as built-in SYSTEM: %#v", principal, pc)
		}
	}
}

func TestFix41WellKnownWindowsServiceAliasesNormalizeSID(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateUnavailable, Usable: false, Reason: "local account provider unavailable"}
	cases := []struct {
		principal string
		sid       string
	}{
		{"LocalService", "S-1-5-19"},
		{`NT AUTHORITY\LOCAL SERVICE`, "S-1-5-19"},
		{"S-1-5-19", "S-1-5-19"},
		{"NetworkService", "S-1-5-20"},
		{`NT AUTHORITY\NETWORK SERVICE`, "S-1-5-20"},
		{"S-1-5-20", "S-1-5-20"},
	}
	for _, tc := range cases {
		pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(tc.principal, "SERVICE_ACCOUNT", true), nil, nil, cap)
		if pc.State != evidence.StateObserved || pc.PrivilegeState != PrivilegeStateBuiltinService || pc.HighPrivilege || pc.ExecutionLevel != "NON_PRIVILEGED" || pc.PrincipalSID != tc.sid || pc.AccountMatchState != "BUILTIN" {
			t.Fatalf("built-in service alias %q was not normalized safely: %#v", tc.principal, pc)
		}
	}
}

func TestFix41ServiceVirtualAccountIsExplicitWithoutPrivilegeInference(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`NT SERVICE\TrustedInstaller`, "SERVICE_ACCOUNT", true), nil, map[string]struct{}{"demo": {}}, cap)
	if pc.State != evidence.StateUnavailable || pc.PrivilegeState != PrivilegeStateServiceVirtualAccount || pc.AccountMatchState != "SERVICE_VIRTUAL" || pc.HighPrivilege || pc.ExecutionLevel != "UNKNOWN" {
		t.Fatalf("service virtual account must be explicit without inferred privilege: %#v", pc)
	}
	if pc.Reason == "" {
		t.Fatalf("service virtual account with unknown effective privilege needs an explicit reason: %#v", pc)
	}
}

func TestFix41ServiceSIDIsRecognizedAsVirtualIdentity(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	principal := "S-1-5-80-123-456-789"
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(principal, "SERVICE_ACCOUNT", false), nil, nil, cap)
	if pc.PrivilegeState != PrivilegeStateServiceVirtualAccount || pc.PrincipalSID != principal || pc.HighPrivilege {
		t.Fatalf("service SID must be classified without privilege inference: %#v", pc)
	}
}

func TestFix41DomainIdentityIsNotFailedLocalLookup(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\svc-backup`, "SERVICE_ACCOUNT", true), nil, map[string]struct{}{"demo": {}}, cap)
	if pc.State != evidence.StateUnavailable || pc.PrivilegeState != PrivilegeStateDomainOrExternal || pc.AccountMatchState != "NON_LOCAL" || pc.HighPrivilege || pc.ExecutionLevel != "UNKNOWN" {
		t.Fatalf("domain identity must remain non-local with privilege unresolved: %#v", pc)
	}
}

func TestFix41ManagedServiceAccountIsExternalWithoutPrivilegeInference(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\chimera-agent$`, "SERVICE_ACCOUNT", false), nil, map[string]struct{}{"demo": {}}, cap)
	if pc.PrivilegeState != PrivilegeStateDomainOrExternal || pc.HighPrivilege || pc.ExecutionLevel != "UNKNOWN" {
		t.Fatalf("managed service identity must not be inferred privileged: %#v", pc)
	}
}

func TestFix41LocalAuthorityMissingAccountStaysIdentityNotFound(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\ghost`, "SERVICE_ACCOUNT", false), nil, map[string]struct{}{"demo": {}}, cap)
	if pc.PrivilegeState != PrivilegeStateIdentityNotFound || pc.AccountMatchState != "UNRESOLVED" {
		t.Fatalf("missing local identity must not be mislabeled as domain/external: %#v", pc)
	}
}

func TestFix41ExactLocalAccountStatesAndSID(t *testing.T) {
	acct := accounts.Account{ID: "acct-user", Name: "svc-demo", Principal: `CONTOSO\svc-demo`, SID: "S-1-5-21-1000-1001", Privileged: false, Confidence: evidence.ConfidenceHigh}
	idx := buildAccountAliasIndex([]accounts.Account{acct})
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\svc-demo`, "SERVICE_ACCOUNT", false), idx, buildLocalAccountAuthorities([]accounts.Account{acct}), accountPrivilegeCapability{State: evidence.StateObserved, Usable: true})
	if pc.State != evidence.StateObserved || pc.PrivilegeState != PrivilegeStateLocalStandard || pc.HighPrivilege || pc.PrincipalSID != acct.SID {
		t.Fatalf("exact local account should be a normalized local-standard identity: %#v", pc)
	}
}

func TestFix41GroupMembershipGapHasDedicatedState(t *testing.T) {
	acct := accounts.Account{ID: "acct-user", Name: "svc-demo", Principal: `CONTOSO\svc-demo`, SID: "S-1-5-21-1000-1001", Privileged: false, Confidence: evidence.ConfidenceHigh}
	idx := buildAccountAliasIndex([]accounts.Account{acct})
	cap := accountPrivilegeCapability{State: evidence.StateDegraded, Usable: true, Reason: "windows-local-groups: group membership unavailable"}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\svc-demo`, "SERVICE_ACCOUNT", false), idx, buildLocalAccountAuthorities([]accounts.Account{acct}), cap)
	if pc.State != evidence.StateDegraded || pc.PrivilegeState != PrivilegeStateGroupMembershipUnavailable || pc.HighPrivilege || pc.ExecutionLevel != "UNKNOWN" {
		t.Fatalf("degraded group membership must have a dedicated privilege state: %#v", pc)
	}
}

func TestFix41ProviderUnavailableHasDedicatedState(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateUnavailable, Usable: false, Reason: "windows-local-accounts unavailable"}
	pc := correlateEntryPrivilegeWithIdentityContext(phase098Entry("svc-local", "SERVICE_ACCOUNT", false), nil, nil, cap)
	if pc.PrivilegeState != PrivilegeStateProviderUnavailable || pc.HighPrivilege {
		t.Fatalf("provider failure must not look like an identity miss or privilege assertion: %#v", pc)
	}
}

func TestFix41DomainPrivilegeRequiresDirectEvidence(t *testing.T) {
	cap := accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	authorities := map[string]struct{}{"demo": {}}
	unknown := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\ops`, "SERVICE_ACCOUNT", true), nil, authorities, cap)
	if unknown.HighPrivilege || unknown.State == evidence.StateObserved {
		t.Fatalf("domain account name alone must not infer privilege: %#v", unknown)
	}
	direct := correlateEntryPrivilegeWithIdentityContext(phase098Entry(`CONTOSO\ops`, "ADMINISTRATOR", true), nil, authorities, cap)
	if direct.PrivilegeState != PrivilegeStateDomainOrExternal || direct.State != evidence.StateObserved || !direct.HighPrivilege || direct.ExecutionLevel != "HIGH_PRIVILEGE" {
		t.Fatalf("explicit provider privilege evidence should remain usable for a domain identity: %#v", direct)
	}
}

func TestFix41SummaryAggregatesPrivilegeStates(t *testing.T) {
	entries := []Entry{
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateObserved, PrivilegeState: PrivilegeStateLocalPrivileged, HighPrivilege: true}},
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateObserved, PrivilegeState: PrivilegeStateBuiltinSystem, HighPrivilege: true}},
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateObserved, PrivilegeState: PrivilegeStateBuiltinService}},
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateUnavailable, PrivilegeState: PrivilegeStateServiceVirtualAccount}},
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateUnavailable, PrivilegeState: PrivilegeStateDomainOrExternal}},
		{PrivilegeCorrelation: PrivilegeCorrelation{State: evidence.StateUnavailable, PrivilegeState: PrivilegeStateIdentityNotFound}},
	}
	s := summarize(entries)
	if s.PrivilegeLocalPrivileged != 1 || s.PrivilegeBuiltinSystem != 1 || s.PrivilegeBuiltinService != 1 || s.PrivilegeServiceVirtualAccount != 1 || s.PrivilegeDomainOrExternal != 1 || s.PrivilegeIdentityNotFound != 1 || s.PrivilegeUnresolved != 3 {
		t.Fatalf("unexpected Fix41 privilege-state aggregation: %#v", s)
	}
}

func TestFix62XDGLoginUserIsProviderClassifiedSessionIdentity(t *testing.T) {
	e := Entry{
		Name: "desktop-autostart", Mechanism: "XDG_AUTOSTART", Manager: "xdg-autostart", Scope: "SYSTEM",
		Account: "LOGIN_USER", PrivilegeContext: "USER", Confidence: evidence.ConfidenceHigh,
		PathIntegrity: PathIntegrity{State: evidence.StateObserved, PrivilegeBasis: "USER"},
	}
	pc := correlateEntryPrivilegeWithIdentityContext(e, map[string][]accounts.Account{}, nil, accountPrivilegeCapability{State: evidence.StateObserved, Usable: true})
	if pc.State != evidence.StateObserved || pc.PrivilegeState != PrivilegeStateLocalStandard || pc.ExecutionLevel != "NON_PRIVILEGED" || pc.AccountMatchState != "PROVIDER" || pc.HighPrivilege {
		t.Fatalf("unexpected XDG login-session classification: %#v", pc)
	}
	if len(pc.PrivilegeBasis) != 1 || pc.PrivilegeBasis[0] != "XDG_LOGIN_SESSION_USER_CONTEXT" {
		t.Fatalf("unexpected XDG privilege basis: %#v", pc.PrivilegeBasis)
	}
}

func TestFix62GenericCurrentUserPlaceholderRemainsUnresolved(t *testing.T) {
	e := Entry{Account: "CURRENT_USER", PrivilegeContext: "USER", Mechanism: "RUN_KEY", Manager: "test", Confidence: evidence.ConfidenceHigh, PathIntegrity: PathIntegrity{State: evidence.StateObserved, PrivilegeBasis: "USER"}}
	pc := correlateEntryPrivilegeWithIdentityContext(e, map[string][]accounts.Account{}, nil, accountPrivilegeCapability{State: evidence.StateObserved, Usable: true})
	if pc.State != evidence.StateUnavailable || pc.PrivilegeState != PrivilegeStateUnknown || pc.AccountMatchState != "UNRESOLVED" {
		t.Fatalf("non-XDG placeholder must remain unresolved: %#v", pc)
	}
}

func TestFix63MissingConcreteSystemdIdentityIsNotProviderFailure(t *testing.T) {
	e := Entry{
		Name: "atftpd.service", Mechanism: "SYSTEMD_SERVICE", Manager: "systemd", Scope: "SYSTEM",
		Account: "atftpd", PrivilegeContext: "SERVICE_ACCOUNT", Confidence: evidence.ConfidenceHigh,
		PathIntegrity: PathIntegrity{State: evidence.StateObserved, PrivilegeBasis: "SERVICE_ACCOUNT"},
	}
	pc := correlateEntryPrivilegeWithIdentityContext(e, map[string][]accounts.Account{}, nil, accountPrivilegeCapability{State: evidence.StateObserved, Usable: true})
	if pc.State != evidence.StateNotApplicable || pc.PrivilegeState != PrivilegeStateIdentityNotFound || pc.AccountMatchState != "UNRESOLVED" || pc.HighPrivilege || pc.ExecutionLevel != "UNKNOWN" {
		t.Fatalf("missing concrete systemd identity should be an observed-not-applicable identity condition: %#v", pc)
	}
	if len(pc.PrivilegeBasis) != 1 || pc.PrivilegeBasis[0] != "CONFIGURED_LOCAL_IDENTITY_ABSENT" {
		t.Fatalf("unexpected absent-identity basis: %#v", pc.PrivilegeBasis)
	}
}

func TestFix63WindowsStyleMissingIdentitySemanticsRemainUnchanged(t *testing.T) {
	e := Entry{Account: "ghost-local", PrivilegeContext: "SERVICE_ACCOUNT", Mechanism: "SERVICE", Manager: "windows-scm", Confidence: evidence.ConfidenceHigh, PathIntegrity: PathIntegrity{State: evidence.StateObserved, PrivilegeBasis: "SERVICE_ACCOUNT"}}
	pc := correlateEntryPrivilegeWithIdentityContext(e, map[string][]accounts.Account{}, nil, accountPrivilegeCapability{State: evidence.StateObserved, Usable: true})
	if pc.State != evidence.StateUnavailable || pc.PrivilegeState != PrivilegeStateIdentityNotFound {
		t.Fatalf("non-Linux missing identity behavior must remain unchanged: %#v", pc)
	}
}

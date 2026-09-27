package persistence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	PrivilegeStateLocalPrivileged            = "LOCAL_PRIVILEGED"
	PrivilegeStateLocalStandard              = "LOCAL_STANDARD"
	PrivilegeStateBuiltinSystem              = "BUILTIN_SYSTEM"
	PrivilegeStateBuiltinService             = "BUILTIN_SERVICE"
	PrivilegeStateServiceVirtualAccount      = "SERVICE_VIRTUAL_ACCOUNT"
	PrivilegeStateDomainOrExternal           = "DOMAIN_OR_EXTERNAL"
	PrivilegeStateIdentityNotFound           = "IDENTITY_NOT_FOUND"
	PrivilegeStateProviderUnavailable        = "PROVIDER_UNAVAILABLE"
	PrivilegeStateGroupMembershipUnavailable = "GROUP_MEMBERSHIP_UNAVAILABLE"
	PrivilegeStateUnknown                    = "UNKNOWN"
)

// PrivilegeCorrelation is the join between a persistence execution
// identity, the normalized local-account inventory, and native well-known
// identity semantics. PrivilegeState is deliberately explicit so non-local and
// service identities are not misreported as failed local-account lookups.
type PrivilegeCorrelation struct {
	State             evidence.State      `json:"state"`
	PrivilegeState    string              `json:"privilege_state"`
	ExecutionLevel    string              `json:"execution_level"`
	HighPrivilege     bool                `json:"high_privilege"`
	AccountMatchState string              `json:"account_match_state"`
	AccountID         string              `json:"account_id,omitempty"`
	Principal         string              `json:"principal,omitempty"`
	PrincipalSID      string              `json:"principal_sid,omitempty"`
	PrivilegeBasis    []string            `json:"privilege_basis,omitempty"`
	WeakPath          bool                `json:"weak_path"`
	WeakRoles         []string            `json:"weak_roles,omitempty"`
	RiskContext       string              `json:"risk_context"`
	CollectionSource  string              `json:"collection_source"`
	Confidence        evidence.Confidence `json:"confidence"`
	Reason            string              `json:"reason,omitempty"`
}

type accountPrivilegeCapability struct {
	State  evidence.State
	Usable bool
	Reason string
}

func correlateAccountPrivileges(inv *Inventory, ac accounts.Inventory) {
	capability := assessAccountPrivilegeCapability(ac)
	if capability.Reason != "" && capability.State != evidence.StateObserved {
		inv.Degraded = append(inv.Degraded, "account-privilege-correlation: "+capability.Reason)
	}

	index := map[string][]accounts.Account{}
	localAuthorities := map[string]struct{}{}
	if capability.Usable {
		index = buildAccountAliasIndex(ac.Accounts)
		localAuthorities = buildLocalAccountAuthorities(ac.Accounts)
	}
	classified := 0
	for i := range inv.Entries {
		inv.Entries[i].PrivilegeCorrelation = correlateEntryPrivilegeWithIdentityContext(inv.Entries[i], index, localAuthorities, capability)
		switch inv.Entries[i].PrivilegeCorrelation.PrivilegeState {
		case PrivilegeStateLocalPrivileged, PrivilegeStateLocalStandard, PrivilegeStateBuiltinSystem, PrivilegeStateBuiltinService, PrivilegeStateServiceVirtualAccount, PrivilegeStateDomainOrExternal:
			classified++
		}
	}
	addSource(inv, "account-privilege-correlation", capability.State, "normalized local-account/group capability + native persistence identity classification", classified, capability.Reason)
}

func assessAccountPrivilegeCapability(ac accounts.Inventory) accountPrivilegeCapability {
	// Deliberately do not call accounts.Inventory.Validate here. That validator
	// covers independent account posture such as Credential Guard, security
	// policy, SSH keys, sudo/PAM, and macOS authorization. Persistence privilege
	// correlation consumes only normalized local-account/group identity facts;
	// unrelated posture degradation must not invalidate this capability.
	if err := validateAccountPrivilegeRecords(ac); err != nil {
		return accountPrivilegeCapability{
			State:  evidence.StateUnavailable,
			Usable: false,
			Reason: "normalized local-account/group identity records are unavailable or invalid: " + err.Error(),
		}
	}

	required := accountPrivilegeSourceIDs(ac.Platform)
	if len(required) == 0 {
		if len(ac.Accounts) == 0 && len(ac.Groups) == 0 {
			return accountPrivilegeCapability{State: evidence.StateUnavailable, Usable: false, Reason: "no normalized local-account/group evidence is available"}
		}
		return accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
	}

	byID := make(map[string]accounts.SourceStatus, len(ac.Sources))
	for _, src := range ac.Sources {
		byID[strings.ToLower(strings.TrimSpace(src.ID))] = src
	}

	degraded := []string{}
	unavailable := []string{}
	for _, id := range required {
		src, ok := byID[id]
		if !ok {
			degraded = append(degraded, id+": provider status is missing")
			continue
		}
		switch src.State {
		case evidence.StateObserved:
			// Fully usable.
		case evidence.StateDegraded:
			degraded = append(degraded, id+": "+fallback(src.Reason, "provider returned partial local-account/group evidence"))
		case evidence.StateDenied, evidence.StateUnavailable:
			unavailable = append(unavailable, id+": "+fallback(src.Reason, "provider did not return usable local-account/group evidence"))
		case evidence.StateNotApplicable:
			unavailable = append(unavailable, id+": provider is unexpectedly not applicable for local-account privilege correlation")
		default:
			unavailable = append(unavailable, id+": provider state is unknown")
		}
	}

	// Existing normalized account records remain useful even when one relevant
	// provider is partially degraded. This is deliberately independent of
	// CredentialProtection/SecurityPolicy degradation, which is not consumed by
	// persistence privilege correlation.
	usable := len(ac.Accounts) > 0
	if !usable {
		reasons := append(unavailable, degraded...)
		if len(reasons) == 0 {
			reasons = append(reasons, "local-account inventory contains no account records")
		}
		return accountPrivilegeCapability{State: evidence.StateUnavailable, Usable: false, Reason: strings.Join(uniqueSorted(reasons), "; ")}
	}
	if len(unavailable) > 0 || len(degraded) > 0 {
		reasons := append(unavailable, degraded...)
		return accountPrivilegeCapability{State: evidence.StateDegraded, Usable: true, Reason: strings.Join(uniqueSorted(reasons), "; ")}
	}
	return accountPrivilegeCapability{State: evidence.StateObserved, Usable: true}
}

func validateAccountPrivilegeRecords(ac accounts.Inventory) error {
	if strings.TrimSpace(ac.Platform) == "" {
		return fmt.Errorf("platform identity is missing")
	}
	seen := map[string]struct{}{}
	for i, a := range ac.Accounts {
		if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Principal) == "" || a.Confidence == "" {
			return fmt.Errorf("account record %d is incomplete for privilege correlation", i)
		}
		if _, ok := seen[a.ID]; ok {
			return fmt.Errorf("duplicate account id %q", a.ID)
		}
		seen[a.ID] = struct{}{}
	}
	return nil
}

func accountPrivilegeSourceIDs(platform string) []string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "windows":
		return []string{"windows-local-accounts", "windows-local-groups"}
	case "linux":
		return []string{"linux-group", "linux-passwd"}
	case "darwin":
		return []string{"darwin-groups", "darwin-opendirectory"}
	default:
		return nil
	}
}

func buildAccountAliasIndex(items []accounts.Account) map[string][]accounts.Account {
	out := map[string][]accounts.Account{}
	for _, a := range items {
		aliases := []string{a.Name, a.Principal, a.UID, a.SID}
		for _, raw := range aliases {
			key := canonicalPrincipal(raw)
			if key == "" || isPlaceholderPrincipal(key) {
				continue
			}
			duplicate := false
			for _, existing := range out[key] {
				if existing.ID == a.ID {
					duplicate = true
					break
				}
			}
			if !duplicate {
				out[key] = append(out[key], a)
			}
		}
	}
	for key := range out {
		sort.Slice(out[key], func(i, j int) bool { return out[key][i].ID < out[key][j].ID })
	}
	return out
}

func buildLocalAccountAuthorities(items []accounts.Account) map[string]struct{} {
	out := map[string]struct{}{}
	for _, a := range items {
		p := canonicalPrincipal(a.Principal)
		i := strings.IndexByte(p, '\\')
		if i <= 0 {
			continue
		}
		authority := strings.TrimSpace(p[:i])
		switch authority {
		case "", "nt authority", "nt service", "builtin":
			continue
		}
		out[authority] = struct{}{}
	}
	return out
}

func correlateEntryPrivilege(e Entry, index map[string][]accounts.Account, accountInventoryValid bool) PrivilegeCorrelation {
	capability := accountPrivilegeCapability{State: evidence.StateObserved, Usable: accountInventoryValid}
	if !accountInventoryValid {
		capability.State = evidence.StateUnavailable
		capability.Reason = "local-account privilege inventory is unavailable"
	}
	return correlateEntryPrivilegeWithCapability(e, index, capability)
}

func correlateEntryPrivilegeWithCapability(e Entry, index map[string][]accounts.Account, capability accountPrivilegeCapability) PrivilegeCorrelation {
	return correlateEntryPrivilegeWithIdentityContext(e, index, nil, capability)
}

func correlateEntryPrivilegeWithIdentityContext(e Entry, index map[string][]accounts.Account, localAuthorities map[string]struct{}, capability accountPrivilegeCapability) PrivilegeCorrelation {
	pc := PrivilegeCorrelation{
		State:             evidence.StateUnavailable,
		PrivilegeState:    PrivilegeStateUnknown,
		ExecutionLevel:    "UNKNOWN",
		AccountMatchState: "UNRESOLVED",
		WeakPath:          len(e.PathIntegrity.WeakRoles) > 0,
		WeakRoles:         append([]string(nil), e.PathIntegrity.WeakRoles...),
		RiskContext:       "UNKNOWN",
		CollectionSource:  "persistence account/privilege correlation",
		Confidence:        minConfidence(e.Confidence, evidence.ConfidenceMedium),
	}

	directPriv, directBasis := directPersistencePrivilege(e)
	if wk, ok := classifyWellKnownPrincipal(e.Account); ok {
		pc.State = evidence.StateObserved
		pc.PrivilegeState = wk.PrivilegeState
		pc.ExecutionLevel = wk.ExecutionLevel
		pc.HighPrivilege = wk.HighPrivilege
		pc.AccountMatchState = "BUILTIN"
		pc.Principal = wk.Principal
		pc.PrincipalSID = wk.SID
		pc.PrivilegeBasis = append(pc.PrivilegeBasis, wk.Basis...)
		pc.Confidence = minConfidence(e.Confidence, evidence.ConfidenceHigh)
		if directPriv {
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, directBasis...)
		}
	}

	key := canonicalPrincipal(e.Account)
	matches := index[key]
	if len(matches) == 1 {
		a := matches[0]
		pc.AccountID = a.ID
		pc.Principal = a.Principal
		pc.PrincipalSID = strings.TrimSpace(a.SID)
		pc.AccountMatchState = "MATCHED"
		pc.PrivilegeBasis = append(pc.PrivilegeBasis, a.PrivilegeBasis...)
		switch {
		case a.Privileged:
			pc.State = evidence.StateObserved
			pc.PrivilegeState = PrivilegeStateLocalPrivileged
			pc.ExecutionLevel = "HIGH_PRIVILEGE"
			pc.HighPrivilege = true
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "NORMALIZED_ACCOUNT_PRIVILEGED")
			pc.Confidence = minConfidence(e.Confidence, a.Confidence)
		case directPriv:
			pc.State = evidence.StateObserved
			pc.PrivilegeState = PrivilegeStateLocalPrivileged
			pc.ExecutionLevel = "HIGH_PRIVILEGE"
			pc.HighPrivilege = true
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, directBasis...)
			pc.Confidence = minConfidence(e.Confidence, a.Confidence)
		case capability.State == evidence.StateObserved:
			pc.State = evidence.StateObserved
			pc.PrivilegeState = PrivilegeStateLocalStandard
			pc.ExecutionLevel = "NON_PRIVILEGED"
			pc.HighPrivilege = false
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "NORMALIZED_ACCOUNT_NON_PRIVILEGED")
			pc.Confidence = minConfidence(e.Confidence, a.Confidence)
		default:
			pc.State = evidence.StateDegraded
			pc.PrivilegeState = PrivilegeStateGroupMembershipUnavailable
			pc.ExecutionLevel = "UNKNOWN"
			pc.HighPrivilege = false
			pc.Reason = "execution account matched, but local-group privilege membership is unavailable or degraded: " + capability.Reason
			pc.Confidence = evidence.ConfidenceLow
		}
	} else if len(matches) > 1 && pc.PrivilegeState == PrivilegeStateUnknown {
		pc.State = evidence.StateDegraded
		pc.AccountMatchState = "AMBIGUOUS"
		pc.Reason = fmt.Sprintf("execution account %q matched %d normalized local-account records", e.Account, len(matches))
		pc.Confidence = evidence.ConfidenceLow
	} else if pc.PrivilegeState == PrivilegeStateUnknown {
		switch {
		case isServiceVirtualPrincipal(key):
			pc.PrivilegeState = PrivilegeStateServiceVirtualAccount
			pc.AccountMatchState = "SERVICE_VIRTUAL"
			pc.Principal = normalizePrincipalDisplay(e.Account)
			if strings.HasPrefix(strings.ToUpper(key), "S-1-5-80-") {
				pc.PrincipalSID = strings.ToUpper(strings.TrimSpace(e.Account))
			}
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "WINDOWS_SERVICE_VIRTUAL_ACCOUNT")
			if directPriv {
				pc.State = evidence.StateObserved
				pc.ExecutionLevel = "HIGH_PRIVILEGE"
				pc.HighPrivilege = true
				pc.PrivilegeBasis = append(pc.PrivilegeBasis, directBasis...)
			} else {
				pc.Reason = "Windows service virtual account identified; effective privilege is not inferred without direct token/group evidence"
			}
		case isDomainOrExternalPrincipal(key, localAuthorities):
			pc.PrivilegeState = PrivilegeStateDomainOrExternal
			pc.AccountMatchState = "NON_LOCAL"
			pc.Principal = normalizePrincipalDisplay(e.Account)
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "NON_LOCAL_OR_MANAGED_IDENTITY")
			if directPriv {
				pc.State = evidence.StateObserved
				pc.ExecutionLevel = "HIGH_PRIVILEGE"
				pc.HighPrivilege = true
				pc.PrivilegeBasis = append(pc.PrivilegeBasis, directBasis...)
			} else {
				pc.Reason = "domain, managed-service, or external identity identified; local privilege is not inferred without direct evidence"
			}
		case directPriv:
			pc.State = evidence.StateObserved
			pc.PrivilegeState = PrivilegeStateLocalPrivileged
			pc.ExecutionLevel = "HIGH_PRIVILEGE"
			pc.HighPrivilege = true
			pc.AccountMatchState = "PROVIDER"
			pc.Principal = normalizePrincipalDisplay(e.Account)
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, directBasis...)
			pc.Confidence = minConfidence(e.Confidence, evidence.ConfidenceHigh)
		case isXDGLoginSessionPrincipal(e, key):
			// A system XDG autostart definition is intentionally instantiated in
			// each graphical login session. LOGIN_USER is therefore not a failed
			// local-account lookup: the launch identity is the session's ordinary
			// user EUID, while privilege escalation (sudo/polkit/etc.) is outside
			// the autostart execution boundary itself.
			pc.State = evidence.StateObserved
			pc.PrivilegeState = PrivilegeStateLocalStandard
			pc.ExecutionLevel = "NON_PRIVILEGED"
			pc.HighPrivilege = false
			pc.AccountMatchState = "PROVIDER"
			pc.Principal = "LOGIN_USER"
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "XDG_LOGIN_SESSION_USER_CONTEXT")
			pc.Confidence = minConfidence(e.Confidence, evidence.ConfidenceHigh)
		case capability.Usable && capability.State == evidence.StateObserved && isConcreteLinuxLocalPrincipalReference(e, key):
			// A concrete Linux service/scheduler identity that is absent from a
			// fully observed local-account inventory is an observed host condition,
			// not a collector failure. The configured persistence definition cannot
			// currently execute as that local identity until the account exists, so
			// privilege classification is not applicable for the current snapshot.
			// Keep IDENTITY_NOT_FOUND explicit for reporting without degrading the
			// persistence provider or inventing a non-privileged classification.
			pc.State = evidence.StateNotApplicable
			pc.PrivilegeState = PrivilegeStateIdentityNotFound
			pc.ExecutionLevel = "UNKNOWN"
			pc.HighPrivilege = false
			pc.AccountMatchState = "UNRESOLVED"
			pc.Principal = normalizePrincipalDisplay(e.Account)
			pc.PrivilegeBasis = append(pc.PrivilegeBasis, "CONFIGURED_LOCAL_IDENTITY_ABSENT")
			pc.Reason = fmt.Sprintf("configured local execution identity %q is not present in the fully observed local-account inventory", e.Account)
			pc.Confidence = minConfidence(e.Confidence, evidence.ConfidenceHigh)
		case key == "" || isPlaceholderPrincipal(key):
			pc.PrivilegeState = PrivilegeStateUnknown
			pc.Reason = "persistence execution account is a placeholder or unresolved identity"
		case !capability.Usable:
			pc.PrivilegeState = PrivilegeStateProviderUnavailable
			pc.Reason = fallback(capability.Reason, "local-account privilege inventory is unavailable")
		case capability.State == evidence.StateDegraded:
			pc.State = evidence.StateDegraded
			pc.PrivilegeState = PrivilegeStateIdentityNotFound
			pc.Reason = "execution account was not resolved and local-account/group evidence is partially degraded: " + capability.Reason
		default:
			pc.PrivilegeState = PrivilegeStateIdentityNotFound
			pc.Reason = fmt.Sprintf("execution account %q was not resolved in the normalized local-account inventory", e.Account)
		}
	}

	pc.PrivilegeBasis = uniqueSorted(pc.PrivilegeBasis)
	pc.WeakRoles = uniqueSorted(pc.WeakRoles)
	switch {
	case pc.HighPrivilege && pc.WeakPath:
		pc.RiskContext = "WEAK_HIGH_PRIVILEGE_PERSISTENCE"
	case pc.HighPrivilege:
		pc.RiskContext = "HIGH_PRIVILEGE_PERSISTENCE"
	case pc.State == evidence.StateObserved && pc.ExecutionLevel == "NON_PRIVILEGED" && pc.WeakPath:
		pc.RiskContext = "WEAK_NON_PRIVILEGED_PERSISTENCE"
	case pc.State == evidence.StateObserved && pc.ExecutionLevel == "NON_PRIVILEGED":
		pc.RiskContext = "NON_PRIVILEGED_PERSISTENCE"
	default:
		pc.RiskContext = "PRIVILEGE_UNRESOLVED"
	}
	return normalizePrivilegeCorrelation(pc)
}

type wellKnownPrincipal struct {
	PrivilegeState string
	ExecutionLevel string
	HighPrivilege  bool
	Principal      string
	SID            string
	Basis          []string
}

func classifyWellKnownPrincipal(v string) (wellKnownPrincipal, bool) {
	switch canonicalPrincipal(v) {
	case "system", "localsystem", `nt authority\system`, "s-1-5-18":
		return wellKnownPrincipal{PrivilegeState: PrivilegeStateBuiltinSystem, ExecutionLevel: "HIGH_PRIVILEGE", HighPrivilege: true, Principal: `NT AUTHORITY\SYSTEM`, SID: "S-1-5-18", Basis: []string{"BUILTIN_SYSTEM_IDENTITY"}}, true
	case "localservice", "local service", `nt authority\localservice`, `nt authority\local service`, "s-1-5-19":
		return wellKnownPrincipal{PrivilegeState: PrivilegeStateBuiltinService, ExecutionLevel: "NON_PRIVILEGED", Principal: `NT AUTHORITY\LOCAL SERVICE`, SID: "S-1-5-19", Basis: []string{"BUILTIN_LOW_PRIVILEGE_SERVICE_IDENTITY"}}, true
	case "networkservice", "network service", `nt authority\networkservice`, `nt authority\network service`, "s-1-5-20":
		return wellKnownPrincipal{PrivilegeState: PrivilegeStateBuiltinService, ExecutionLevel: "NON_PRIVILEGED", Principal: `NT AUTHORITY\NETWORK SERVICE`, SID: "S-1-5-20", Basis: []string{"BUILTIN_LOW_PRIVILEGE_SERVICE_IDENTITY"}}, true
	default:
		return wellKnownPrincipal{}, false
	}
}

func isServiceVirtualPrincipal(v string) bool {
	v = canonicalPrincipal(v)
	return strings.HasPrefix(v, `nt service\`) || strings.HasPrefix(v, "s-1-5-80-")
}

func isDomainOrExternalPrincipal(v string, localAuthorities map[string]struct{}) bool {
	v = canonicalPrincipal(v)
	if v == "" || isPlaceholderPrincipal(v) || isServiceVirtualPrincipal(v) {
		return false
	}
	if strings.Contains(v, "@") || strings.HasSuffix(v, "$") {
		return true
	}
	i := strings.IndexByte(v, '\\')
	if i <= 0 {
		return false
	}
	authority := v[:i]
	switch authority {
	case "nt authority", "nt service", "builtin":
		return true
	}
	if len(localAuthorities) == 0 {
		return false
	}
	_, local := localAuthorities[authority]
	return !local
}

func normalizePrincipalDisplay(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "/", `\`)
	return v
}

func directPersistencePrivilege(e Entry) (bool, []string) {
	basis := []string{}
	switch normalizeWord(e.PrivilegeContext) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT", "ADMINISTRATOR":
		basis = append(basis, "PRIVILEGE_CONTEXT_"+normalizeWord(e.PrivilegeContext))
	}
	if e.PathIntegrity.Privileged {
		basis = append(basis, "PATH_INTEGRITY_"+normalizeWord(e.PathIntegrity.PrivilegeBasis))
	}
	key := canonicalPrincipal(e.Account)
	if isBuiltinHighPrincipal(key) {
		basis = append(basis, "BUILTIN_HIGH_PRIVILEGE_IDENTITY")
	}
	return len(basis) > 0, uniqueSorted(basis)
}

func isBuiltinHighPrincipal(v string) bool {
	switch canonicalPrincipal(v) {
	case "root", "0", "system", "localsystem", "nt authority\\system":
		return true
	default:
		return false
	}
}

func isBuiltinLowPrivilegePrincipal(v string) bool {
	switch canonicalPrincipal(v) {
	case "localservice", "local service", "nt authority\\local service", "networkservice", "network service", "nt authority\\network service":
		return true
	default:
		return false
	}
}

func canonicalPrincipal(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "/", `\`)
	v = strings.TrimPrefix(v, `.\`)
	return v
}

func isXDGLoginSessionPrincipal(e Entry, key string) bool {
	if !strings.EqualFold(strings.TrimSpace(e.Manager), "xdg-autostart") || normalizeWord(e.Mechanism) != "XDG_AUTOSTART" || normalizeWord(e.PrivilegeContext) != "USER" {
		return false
	}
	switch canonicalPrincipal(key) {
	case "login_user", "session_user", "current_user":
		return true
	default:
		return false
	}
}

func isConcreteLinuxLocalPrincipalReference(e Entry, key string) bool {
	manager := strings.ToLower(strings.TrimSpace(e.Manager))
	switch manager {
	case "systemd", "cron", "crond", "init-compat", "sysv-init":
		// Linux-native managers use local account names/UIDs for these fields.
	default:
		return false
	}
	key = canonicalPrincipal(key)
	if key == "" || isPlaceholderPrincipal(key) || strings.Contains(key, `\`) || strings.Contains(key, "@") || strings.HasSuffix(key, "$") {
		return false
	}
	return true
}

func isPlaceholderPrincipal(v string) bool {
	switch canonicalPrincipal(v) {
	case "", "unknown", "current_user", "login_user", "session_user", "user":
		return true
	default:
		return false
	}
}

func minConfidence(a, b evidence.Confidence) evidence.Confidence {
	rank := func(c evidence.Confidence) int {
		switch c {
		case evidence.ConfidenceExact:
			return 4
		case evidence.ConfidenceHigh:
			return 3
		case evidence.ConfidenceMedium:
			return 2
		case evidence.ConfidenceLow:
			return 1
		default:
			return 0
		}
	}
	if rank(a) == 0 {
		return b
	}
	if rank(b) == 0 {
		return a
	}
	if rank(a) <= rank(b) {
		return a
	}
	return b
}

func normalizePrivilegeCorrelation(pc PrivilegeCorrelation) PrivilegeCorrelation {
	if pc.State == "" {
		pc.State = evidence.StateUnavailable
	}
	if strings.TrimSpace(pc.PrivilegeState) == "" {
		pc.PrivilegeState = PrivilegeStateUnknown
	} else {
		pc.PrivilegeState = normalizeWord(pc.PrivilegeState)
	}
	if strings.TrimSpace(pc.ExecutionLevel) == "" {
		pc.ExecutionLevel = "UNKNOWN"
	} else {
		pc.ExecutionLevel = normalizeWord(pc.ExecutionLevel)
	}
	if strings.TrimSpace(pc.AccountMatchState) == "" {
		pc.AccountMatchState = "UNRESOLVED"
	} else {
		pc.AccountMatchState = normalizeWord(pc.AccountMatchState)
	}
	pc.AccountID = strings.TrimSpace(pc.AccountID)
	pc.Principal = strings.TrimSpace(pc.Principal)
	pc.PrincipalSID = strings.ToUpper(strings.TrimSpace(pc.PrincipalSID))
	pc.PrivilegeBasis = uniqueSorted(pc.PrivilegeBasis)
	pc.WeakRoles = uniqueSorted(pc.WeakRoles)
	if strings.TrimSpace(pc.RiskContext) == "" {
		pc.RiskContext = "PRIVILEGE_UNRESOLVED"
	} else {
		pc.RiskContext = normalizeWord(pc.RiskContext)
	}
	pc.CollectionSource = fallback(pc.CollectionSource, "persistence account/privilege correlation")
	if pc.Confidence == "" {
		pc.Confidence = evidence.ConfidenceMedium
	}
	pc.Reason = strings.TrimSpace(pc.Reason)
	if pc.State != evidence.StateObserved && pc.Reason == "" {
		pc.Reason = "execution privilege correlation is unresolved"
	}
	return pc
}

func (pc PrivilegeCorrelation) validate() error {
	switch pc.State {
	case evidence.StateObserved, evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateNotApplicable:
	default:
		return fmt.Errorf("invalid privilege-correlation state %q", pc.State)
	}
	switch pc.PrivilegeState {
	case PrivilegeStateLocalPrivileged, PrivilegeStateLocalStandard, PrivilegeStateBuiltinSystem, PrivilegeStateBuiltinService, PrivilegeStateServiceVirtualAccount, PrivilegeStateDomainOrExternal, PrivilegeStateIdentityNotFound, PrivilegeStateProviderUnavailable, PrivilegeStateGroupMembershipUnavailable, PrivilegeStateUnknown:
	default:
		return fmt.Errorf("invalid privilege state %q", pc.PrivilegeState)
	}
	switch pc.ExecutionLevel {
	case "HIGH_PRIVILEGE", "NON_PRIVILEGED", "UNKNOWN":
	default:
		return fmt.Errorf("invalid execution privilege level %q", pc.ExecutionLevel)
	}
	switch pc.AccountMatchState {
	case "MATCHED", "BUILTIN", "PROVIDER", "SERVICE_VIRTUAL", "NON_LOCAL", "UNRESOLVED", "AMBIGUOUS":
	default:
		return fmt.Errorf("invalid account match state %q", pc.AccountMatchState)
	}
	if pc.HighPrivilege && (pc.State != evidence.StateObserved || pc.ExecutionLevel != "HIGH_PRIVILEGE") {
		return fmt.Errorf("high privilege requires observed HIGH_PRIVILEGE correlation")
	}
	switch pc.PrivilegeState {
	case PrivilegeStateLocalPrivileged, PrivilegeStateBuiltinSystem:
		if pc.State != evidence.StateObserved || !pc.HighPrivilege || pc.ExecutionLevel != "HIGH_PRIVILEGE" {
			return fmt.Errorf("%s requires observed high-privilege evidence", pc.PrivilegeState)
		}
	case PrivilegeStateLocalStandard, PrivilegeStateBuiltinService:
		if pc.State != evidence.StateObserved || pc.HighPrivilege || pc.ExecutionLevel != "NON_PRIVILEGED" {
			return fmt.Errorf("%s requires observed non-privileged evidence", pc.PrivilegeState)
		}
	case PrivilegeStateIdentityNotFound, PrivilegeStateProviderUnavailable, PrivilegeStateGroupMembershipUnavailable, PrivilegeStateUnknown:
		if pc.HighPrivilege {
			return fmt.Errorf("%s cannot assert high privilege", pc.PrivilegeState)
		}
	}
	if pc.PrincipalSID != "" && !strings.HasPrefix(strings.ToUpper(pc.PrincipalSID), "S-") {
		return fmt.Errorf("invalid principal SID %q", pc.PrincipalSID)
	}
	if pc.WeakPath != (len(pc.WeakRoles) > 0) {
		return fmt.Errorf("weak-path flag does not match weak roles")
	}
	if strings.TrimSpace(pc.RiskContext) == "" || strings.TrimSpace(pc.CollectionSource) == "" || pc.Confidence == "" {
		return fmt.Errorf("privilege-correlation provenance is incomplete")
	}
	if !sort.StringsAreSorted(pc.PrivilegeBasis) || !sort.StringsAreSorted(pc.WeakRoles) {
		return fmt.Errorf("privilege-correlation lists must be deterministically ordered")
	}
	return nil
}

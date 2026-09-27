package persistence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
	"github.com/Nikolov999/chimera/internal/services"
)

const (
	SchemaVersion    = "chimera.persistence/v1"
	CollectorName    = "persistence"
	CollectorVersion = "persistence/phase098-v1"
	maxEntries       = 32768
)

type Entry struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Mechanism            string               `json:"mechanism"`
	Manager              string               `json:"manager"`
	Scope                string               `json:"scope"`
	EnabledState         string               `json:"enabled_state"`
	RuntimeState         string               `json:"runtime_state"`
	Account              string               `json:"account"`
	PrivilegeContext     string               `json:"privilege_context"`
	ExecutablePath       string               `json:"executable_path,omitempty"`
	ReferencedScriptPath string               `json:"referenced_script_path,omitempty"`
	ArgumentsPresent     bool                 `json:"arguments_present"`
	DefinitionPath       string               `json:"definition_path,omitempty"`
	ConfigurationSource  string               `json:"configuration_source"`
	CollectionSource     string               `json:"collection_source"`
	Confidence           evidence.Confidence  `json:"confidence"`
	PathIntegrity        PathIntegrity        `json:"path_integrity"`
	PrivilegeCorrelation PrivilegeCorrelation `json:"privilege_correlation"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Entries                             int `json:"entries"`
	Services                            int `json:"services"`
	Scheduled                           int `json:"scheduled"`
	RunKeys                             int `json:"run_keys"`
	StartupFolders                      int `json:"startup_folders"`
	SystemdAutostart                    int `json:"systemd_autostart"`
	XDGAutostart                        int `json:"xdg_autostart"`
	Launchd                             int `json:"launchd"`
	LoginItems                          int `json:"login_items"`
	Cron                                int `json:"cron"`
	Enabled                             int `json:"enabled"`
	Disabled                            int `json:"disabled"`
	UnknownEnabled                      int `json:"unknown_enabled"`
	Privileged                          int `json:"privileged"`
	WithExecutable                      int `json:"with_executable"`
	WithDefinition                      int `json:"with_definition"`
	PathIntegrityAssessed               int `json:"path_integrity_assessed"`
	WeakPathEntries                     int `json:"weak_path_entries"`
	PrivilegedWeakPathEntries           int `json:"privileged_weak_path_entries"`
	PathIntegrityUnresolved             int `json:"path_integrity_unresolved"`
	PrivilegeCorrelated                 int `json:"privilege_correlated"`
	HighPrivilegeExecution              int `json:"high_privilege_execution"`
	WeakHighPrivilegeEntries            int `json:"weak_high_privilege_entries"`
	PrivilegeUnresolved                 int `json:"privilege_unresolved"`
	PrivilegeLocalPrivileged            int `json:"privilege_local_privileged"`
	PrivilegeLocalStandard              int `json:"privilege_local_standard"`
	PrivilegeBuiltinSystem              int `json:"privilege_builtin_system"`
	PrivilegeBuiltinService             int `json:"privilege_builtin_service"`
	PrivilegeServiceVirtualAccount      int `json:"privilege_service_virtual_account"`
	PrivilegeDomainOrExternal           int `json:"privilege_domain_or_external"`
	PrivilegeIdentityNotFound           int `json:"privilege_identity_not_found"`
	PrivilegeProviderUnavailable        int `json:"privilege_provider_unavailable"`
	PrivilegeGroupMembershipUnavailable int `json:"privilege_group_membership_unavailable"`
	PrivilegeStateUnknown               int `json:"privilege_state_unknown"`
}

type Inventory struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Entries          []Entry                `json:"entries"`
	Sources          []SourceStatus         `json:"sources"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

// Collect produces the standalone persistence inventory. Service and
// scheduler collectors are reused rather than reimplementing those persistence
// mechanisms, while platform startup providers add mechanisms not represented
// by the earlier inventories.
func Collect(ctx context.Context) Inventory {
	sv := services.Collect(ctx)
	sch := scheduled.Collect(ctx)
	ac := accounts.Collect(ctx)
	return CollectFrom(ctx, sv, sch, ac)
}

// CollectFrom composes persistence evidence from already-collected service and
// scheduled-execution snapshots and adds platform-specific startup mechanisms.
// It is used by the full scan to avoid recollecting expensive host providers.
func CollectFrom(ctx context.Context, sv services.Inventory, sch scheduled.Inventory, ac accounts.Inventory) Inventory {
	at := time.Now().UTC()
	if sv.CollectedAt.After(at) {
		at = sv.CollectedAt
	}
	if sch.CollectedAt.After(at) {
		at = sch.CollectedAt
	}
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
	}
	composeServices(&inv, sv)
	composeScheduled(&inv, sch)
	collectPlatform(ctx, &inv)
	inv.Entries = normalizeEntries(inv.Entries)
	assessPlatformPathIntegrity(ctx, &inv)
	inv.Entries = normalizeEntries(inv.Entries)
	correlateAccountPrivileges(&inv, ac)
	inv.Entries = normalizeEntries(inv.Entries)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Entries)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func composeServices(inv *Inventory, sv services.Inventory) {
	state, reason := sourceStateFromDegraded(sv.Degraded)
	if err := sv.Validate(); err != nil {
		state, reason = evidence.StateUnavailable, "service inventory contract unavailable: "+err.Error()
		inv.Degraded = append(inv.Degraded, reason)
		addSource(inv, "services", state, "normalized service inventory", 0, reason)
		return
	}
	for _, svc := range sv.Services {
		mechanism := "SERVICE"
		if strings.EqualFold(svc.Manager, "launchd") {
			mechanism = "LAUNCHD"
		} else if strings.EqualFold(svc.Manager, "systemd") {
			mechanism = "SYSTEMD_SERVICE"
		}
		inv.Entries = append(inv.Entries, Entry{
			Name: svc.Name, Mechanism: mechanism, Manager: svc.Manager, Scope: serviceScope(svc),
			EnabledState: serviceEnabledState(svc.StartMode), RuntimeState: normalizeWord(svc.RuntimeState),
			Account: fallback(svc.Account, "UNKNOWN"), PrivilegeContext: normalizeWord(svc.PrivilegeContext),
			ExecutablePath: cleanPath(svc.ExecutablePath), DefinitionPath: cleanPath(svc.DefinitionPath),
			ConfigurationSource: fallback(svc.ConfigurationSource, "service inventory"),
			CollectionSource:    "normalized service inventory", Confidence: svc.Confidence,
			PathIntegrity: composeServicePathIntegrity(svc),
		})
	}
	addSource(inv, "services", state, "normalized service inventory", len(sv.Services), reason)
}

func composeScheduled(inv *Inventory, sch scheduled.Inventory) {
	state, reason := sourceStateFromDegraded(sch.Degraded)
	if err := sch.Validate(); err != nil {
		state, reason = evidence.StateUnavailable, "scheduled-execution inventory contract unavailable: "+err.Error()
		inv.Degraded = append(inv.Degraded, reason)
		addSource(inv, "scheduled", state, "normalized scheduled-execution inventory", 0, reason)
		return
	}
	for _, item := range sch.Entries {
		mechanism := scheduledMechanism(item)
		inv.Entries = append(inv.Entries, Entry{
			Name: item.Name, Mechanism: mechanism, Manager: item.Manager, Scope: scheduledScope(item),
			EnabledState: normalizeWord(item.EnabledState), RuntimeState: normalizeWord(item.RuntimeState),
			Account: fallback(item.Account, "UNKNOWN"), PrivilegeContext: normalizeWord(item.PrivilegeContext),
			ExecutablePath: cleanPath(item.ActionExecutable), ReferencedScriptPath: cleanPath(item.ReferencedScriptPath), ArgumentsPresent: item.ArgumentsPresent,
			DefinitionPath: cleanPath(item.DefinitionPath), ConfigurationSource: fallback(item.ConfigurationSource, "scheduler inventory"),
			CollectionSource: "normalized scheduled-execution inventory", Confidence: item.Confidence,
			PathIntegrity: composeScheduledPathIntegrity(item),
		})
	}
	addSource(inv, "scheduled", state, "normalized scheduled-execution inventory", len(sch.Entries), reason)
}

func sourceStateFromDegraded(degraded []string) (evidence.State, string) {
	if len(degraded) == 0 {
		return evidence.StateObserved, ""
	}
	return evidence.StateDegraded, strings.Join(uniqueSorted(degraded), "; ")
}

func scheduledMechanism(e scheduled.Entry) string {
	manager := strings.ToLower(strings.TrimSpace(e.Manager))
	kind := strings.ToLower(strings.TrimSpace(e.Kind))
	switch {
	case strings.Contains(manager, "cron") || strings.Contains(kind, "cron"):
		return "CRON"
	case strings.Contains(manager, "systemd") || strings.Contains(kind, "timer"):
		return "SYSTEMD_TIMER"
	case strings.Contains(manager, "launchd"):
		return "LAUNCHD_SCHEDULE"
	case strings.Contains(manager, "task") || strings.Contains(kind, "task"):
		return "SCHEDULED_TASK"
	default:
		return "SCHEDULED_EXECUTION"
	}
}

func serviceScope(s services.Service) string {
	if strings.EqualFold(s.Manager, "launchd") && strings.Contains(strings.ToLower(s.ServiceType), "agent") {
		return "USER"
	}
	return "SYSTEM"
}

func scheduledScope(s scheduled.Entry) string {
	switch strings.ToUpper(strings.TrimSpace(s.PrivilegeContext)) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT":
		return "SYSTEM"
	default:
		return "USER_OR_SYSTEM"
	}
}

func serviceEnabledState(mode string) string {
	switch strings.ToUpper(strings.TrimSpace(mode)) {
	case "ENABLED", "ENABLED_RUNTIME", "AUTOMATIC", "AUTO", "BOOT", "SYSTEM", "RUN_AT_LOAD", "KEEP_ALIVE":
		return "ENABLED"
	case "DISABLED", "MASKED":
		return "DISABLED"
	default:
		return "UNKNOWN"
	}
}

func normalizeEntries(in []Entry) []Entry {
	byID := map[string]Entry{}
	for _, e := range in {
		e.Name = fallback(e.Name, "UNKNOWN")
		e.Mechanism = normalizeWord(e.Mechanism)
		e.Manager = fallback(e.Manager, "UNKNOWN")
		e.Scope = normalizeWord(e.Scope)
		e.EnabledState = normalizeWord(e.EnabledState)
		e.RuntimeState = normalizeWord(e.RuntimeState)
		e.Account = fallback(e.Account, "UNKNOWN")
		e.PrivilegeContext = normalizeWord(e.PrivilegeContext)
		e.ExecutablePath = cleanPath(e.ExecutablePath)
		e.ReferencedScriptPath = cleanPath(e.ReferencedScriptPath)
		e.DefinitionPath = cleanPath(e.DefinitionPath)
		e.PathIntegrity = normalizePathIntegrity(e.PathIntegrity)
		e.PrivilegeCorrelation = normalizePrivilegeCorrelation(e.PrivilegeCorrelation)
		e.ConfigurationSource = fallback(e.ConfigurationSource, "UNKNOWN")
		e.CollectionSource = fallback(e.CollectionSource, "platform persistence provider")
		if e.Confidence == "" {
			e.Confidence = evidence.ConfidenceMedium
		}
		e.ID = stableID(e)
		byID[e.ID] = e
	}
	out := make([]Entry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return entrySortKey(out[i]) < entrySortKey(out[j]) })
	if len(out) > maxEntries {
		out = out[:maxEntries]
	}
	return out
}

func stableID(e Entry) string {
	raw := strings.Join([]string{strings.ToLower(e.Mechanism), strings.ToLower(e.Manager), strings.ToLower(e.Name), strings.ToLower(e.DefinitionPath), strings.ToLower(e.ConfigurationSource)}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return "per-" + hex.EncodeToString(sum[:10])
}

func entrySortKey(e Entry) string {
	return strings.ToLower(e.Mechanism) + "\x00" + strings.ToLower(e.Manager) + "\x00" + strings.ToLower(e.Name) + "\x00" + strings.ToLower(e.DefinitionPath) + "\x00" + e.ID
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	byID := map[string]SourceStatus{}
	for _, s := range in {
		s.ID = strings.ToLower(strings.TrimSpace(s.ID))
		s.Source = fallback(s.Source, "platform persistence provider")
		if s.ItemCount < 0 {
			s.ItemCount = 0
		}
		byID[s.ID] = s
	}
	out := make([]SourceStatus, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	id = strings.ToLower(strings.TrimSpace(id))
	source = strings.TrimSpace(source)
	reason = strings.TrimSpace(reason)
	inv.Sources = append(inv.Sources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: reason})
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && reason != "" {
		inv.Degraded = append(inv.Degraded, id+": "+reason)
	}
}

func summarize(entries []Entry) Summary {
	s := Summary{Entries: len(entries)}
	for _, e := range entries {
		switch e.Mechanism {
		case "SERVICE", "SYSTEMD_SERVICE", "LAUNCHD":
			s.Services++
		case "SCHEDULED_TASK", "SCHEDULED_EXECUTION", "SYSTEMD_TIMER", "LAUNCHD_SCHEDULE", "CRON":
			s.Scheduled++
		}
		switch e.Mechanism {
		case "RUN_KEY", "RUN_ONCE_KEY":
			s.RunKeys++
		case "STARTUP_FOLDER":
			s.StartupFolders++
		case "SYSTEMD_AUTOSTART":
			s.SystemdAutostart++
		case "XDG_AUTOSTART":
			s.XDGAutostart++
		case "LAUNCHD", "LAUNCHD_SCHEDULE":
			s.Launchd++
		case "LOGIN_ITEM":
			s.LoginItems++
		case "CRON":
			s.Cron++
		}
		switch e.EnabledState {
		case "ENABLED":
			s.Enabled++
		case "DISABLED":
			s.Disabled++
		default:
			s.UnknownEnabled++
		}
		switch e.PrivilegeContext {
		case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT":
			s.Privileged++
		}
		if e.ExecutablePath != "" {
			s.WithExecutable++
		}
		if e.DefinitionPath != "" {
			s.WithDefinition++
		}
		if e.PathIntegrity.State != evidence.StateNotApplicable {
			s.PathIntegrityAssessed++
		}
		if len(e.PathIntegrity.WeakRoles) > 0 {
			s.WeakPathEntries++
			if e.PathIntegrity.Privileged {
				s.PrivilegedWeakPathEntries++
			}
		}
		if entryPathIntegrityUnresolved(e) {
			s.PathIntegrityUnresolved++
		}
		pc := e.PrivilegeCorrelation
		switch pc.State {
		case evidence.StateObserved:
			s.PrivilegeCorrelated++
			if pc.HighPrivilege {
				s.HighPrivilegeExecution++
				if pc.WeakPath {
					s.WeakHighPrivilegeEntries++
				}
			}
		default:
			s.PrivilegeUnresolved++
		}
		switch pc.PrivilegeState {
		case PrivilegeStateLocalPrivileged:
			s.PrivilegeLocalPrivileged++
		case PrivilegeStateLocalStandard:
			s.PrivilegeLocalStandard++
		case PrivilegeStateBuiltinSystem:
			s.PrivilegeBuiltinSystem++
		case PrivilegeStateBuiltinService:
			s.PrivilegeBuiltinService++
		case PrivilegeStateServiceVirtualAccount:
			s.PrivilegeServiceVirtualAccount++
		case PrivilegeStateDomainOrExternal:
			s.PrivilegeDomainOrExternal++
		case PrivilegeStateIdentityNotFound:
			s.PrivilegeIdentityNotFound++
		case PrivilegeStateProviderUnavailable:
			s.PrivilegeProviderUnavailable++
		case PrivilegeStateGroupMembershipUnavailable:
			s.PrivilegeGroupMembershipUnavailable++
		default:
			s.PrivilegeStateUnknown++
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	out := make([]evidence.Observation, 0, len(inv.Entries)*2+len(inv.Sources)+1)
	out = append(out, evidence.NewObserved("persistence.summary", inv.Summary, "persistence inventory", inv.CollectedAt, evidence.ConfidenceHigh))
	for _, src := range inv.Sources {
		key := "persistence.source." + sanitizeKey(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"item_count": src.ItemCount, "source": src.Source}, src.Source, inv.CollectedAt, evidence.ConfidenceHigh))
		} else {
			conf := evidence.ConfidenceMedium
			if src.State == evidence.StateNotApplicable {
				conf = evidence.ConfidenceExact
			}
			out = append(out, evidence.NewState(key, src.State, src.Source, inv.CollectedAt, conf, fallback(src.Reason, "provider did not yield normal observed evidence")))
		}
	}
	for _, e := range inv.Entries {
		out = append(out, evidence.NewObserved("persistence.entry."+sanitizeKey(e.ID), e, e.CollectionSource, inv.CollectedAt, e.Confidence))
		key := "persistence.privilege." + sanitizeKey(e.ID)
		pc := e.PrivilegeCorrelation
		if pc.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, pc, pc.CollectionSource, inv.CollectedAt, pc.Confidence))
		} else {
			out = append(out, evidence.NewState(key, pc.State, pc.CollectionSource, inv.CollectedAt, pc.Confidence, fallback(pc.Reason, "execution privilege correlation is unresolved")))
		}
	}
	return out
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected persistence collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("persistence inventory identity is incomplete")
	}
	if len(inv.Entries) > maxEntries {
		return fmt.Errorf("persistence inventory exceeds maximum record count")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, e := range inv.Entries {
		if e.ID == "" || e.Name == "" || e.Mechanism == "" || e.Manager == "" || e.Scope == "" || e.EnabledState == "" || e.RuntimeState == "" || e.Account == "" || e.PrivilegeContext == "" || e.ConfigurationSource == "" || e.CollectionSource == "" || e.Confidence == "" {
			return fmt.Errorf("persistence entry %d is incomplete", i)
		}
		if err := e.PathIntegrity.validate(); err != nil {
			return fmt.Errorf("persistence entry %d path integrity: %w", i, err)
		}
		if err := e.PrivilegeCorrelation.validate(); err != nil {
			return fmt.Errorf("persistence entry %d privilege correlation: %w", i, err)
		}
		if _, ok := seen[e.ID]; ok {
			return fmt.Errorf("duplicate persistence entry id %q", e.ID)
		}
		seen[e.ID] = struct{}{}
		key := entrySortKey(e)
		if last != "" && key < last {
			return fmt.Errorf("persistence entries are not deterministically ordered")
		}
		last = key
	}
	if inv.Summary != summarize(inv.Entries) {
		return fmt.Errorf("persistence summary does not match records")
	}
	identityStates := inv.Summary.PrivilegeLocalPrivileged + inv.Summary.PrivilegeLocalStandard + inv.Summary.PrivilegeBuiltinSystem + inv.Summary.PrivilegeBuiltinService + inv.Summary.PrivilegeServiceVirtualAccount + inv.Summary.PrivilegeDomainOrExternal + inv.Summary.PrivilegeIdentityNotFound + inv.Summary.PrivilegeProviderUnavailable + inv.Summary.PrivilegeGroupMembershipUnavailable + inv.Summary.PrivilegeStateUnknown
	if identityStates != len(inv.Entries) {
		return fmt.Errorf("persistence privilege-state accounting does not cover every entry: states=%d entries=%d", identityStates, len(inv.Entries))
	}
	for i, src := range inv.Sources {
		if src.ID == "" || src.Source == "" || src.State == "" || src.ItemCount < 0 {
			return fmt.Errorf("persistence source %d is incomplete", i)
		}
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable && strings.TrimSpace(src.Reason) == "" {
			return fmt.Errorf("persistence source %q requires a degradation reason", src.ID)
		}
	}
	return evidence.ValidateAll(inv.Evidence)
}

func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func normalizeWord(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(strings.ReplaceAll(v, "-", "_"))
}

func cleanPath(v string) string { return strings.TrimSpace(v) }

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sanitizeKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

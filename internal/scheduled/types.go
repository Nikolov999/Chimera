package scheduled

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.scheduled/v2"
	CollectorName    = "scheduled-execution"
	CollectorVersion = "scheduled/phase050-v1"
	maxEntries       = 32768
)

type PathPosture struct {
	Path                    string   `json:"path,omitempty"`
	State                   string   `json:"state"`
	Exists                  bool     `json:"exists"`
	IsDirectory             bool     `json:"is_directory"`
	Mode                    string   `json:"mode,omitempty"`
	Owner                   string   `json:"owner,omitempty"`
	OwnerSID                string   `json:"owner_sid,omitempty"`
	OwnerTrust              string   `json:"owner_trust,omitempty"`
	Group                   string   `json:"group,omitempty"`
	GroupWritable           bool     `json:"group_writable"`
	OtherWritable           bool     `json:"other_writable"`
	BroadlyWritable         bool     `json:"broadly_writable"`
	UntrustedWritable       bool     `json:"untrusted_writable"`
	InheritedUntrustedWrite bool     `json:"inherited_untrusted_write"`
	WritePrincipals         []string `json:"write_principals,omitempty"`
	DACLState               string   `json:"dacl_state,omitempty"`
	PermissionBasis         string   `json:"permission_basis,omitempty"`
	Reason                  string   `json:"reason,omitempty"`
}

type Entry struct {
	ID                          string              `json:"id"`
	Name                        string              `json:"name"`
	Manager                     string              `json:"manager"`
	Kind                        string              `json:"kind"`
	EnabledState                string              `json:"enabled_state"`
	RuntimeState                string              `json:"runtime_state"`
	Account                     string              `json:"account"`
	PrivilegeContext            string              `json:"privilege_context"`
	Schedule                    string              `json:"schedule"`
	TriggerTarget               string              `json:"trigger_target,omitempty"`
	ActionExecutable            string              `json:"action_executable,omitempty"`
	ArgumentsPresent            bool                `json:"arguments_present"`
	ReferencedScriptPath        string              `json:"referenced_script_path,omitempty"`
	WorkingDirectory            string              `json:"working_directory,omitempty"`
	DefinitionPath              string              `json:"definition_path,omitempty"`
	RunLevel                    string              `json:"run_level"`
	LogonType                   string              `json:"logon_type"`
	HiddenState                 string              `json:"hidden_state"`
	ConfigurationSource         string              `json:"configuration_source"`
	CollectionSource            string              `json:"collection_source"`
	Confidence                  evidence.Confidence `json:"confidence"`
	ActionPath                  PathPosture         `json:"action_path"`
	ActionDirectoryPosture      PathPosture         `json:"action_directory_posture"`
	ReferencedScriptPathPosture PathPosture         `json:"referenced_script_path_posture"`
	WorkingDirectoryPosture     PathPosture         `json:"working_directory_posture"`
	DefinitionPathPosture       PathPosture         `json:"definition_path_posture"`
	DefinitionDirectoryPosture  PathPosture         `json:"definition_directory_posture"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Entries                   int `json:"entries"`
	Enabled                   int `json:"enabled"`
	Disabled                  int `json:"disabled"`
	EnabledUnknown            int `json:"enabled_unknown"`
	Privileged                int `json:"privileged"`
	WithAction                int `json:"with_action"`
	WithDefinition            int `json:"with_definition"`
	ActionPathAssessed        int `json:"action_path_assessed"`
	DefinitionPathAssessed    int `json:"definition_path_assessed"`
	BroadlyWritableAction     int `json:"broadly_writable_action"`
	BroadlyWritableDefinition int `json:"broadly_writable_definition"`
	WithReferencedScript      int `json:"with_referenced_script"`
	WorkingDirectoryAssessed  int `json:"working_directory_assessed"`
	BroadlyWritableWorkdir    int `json:"broadly_writable_working_directory"`
	Hidden                    int `json:"hidden"`
	HiddenPrivileged          int `json:"hidden_privileged"`
	CustomPrivilegedAccounts  int `json:"custom_privileged_accounts"`
	SystemdTimers             int `json:"systemd_timers"`
	CronEntries               int `json:"cron_entries"`
	WindowsTasks              int `json:"windows_tasks"`
	LaunchdSchedules          int `json:"launchd_schedules"`
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

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at}
	collectPlatform(ctx, &inv)
	inv.Entries = normalizeEntries(inv.Entries)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Entries)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected scheduled collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("scheduled inventory identity is incomplete")
	}
	if len(inv.Entries) > maxEntries {
		return fmt.Errorf("scheduled inventory exceeds maximum record count")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, e := range inv.Entries {
		if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Manager) == "" || strings.TrimSpace(e.Kind) == "" || strings.TrimSpace(e.EnabledState) == "" || strings.TrimSpace(e.RuntimeState) == "" || strings.TrimSpace(e.Account) == "" || strings.TrimSpace(e.PrivilegeContext) == "" || strings.TrimSpace(e.Schedule) == "" || strings.TrimSpace(e.RunLevel) == "" || strings.TrimSpace(e.LogonType) == "" || strings.TrimSpace(e.HiddenState) == "" || strings.TrimSpace(e.ConfigurationSource) == "" || strings.TrimSpace(e.CollectionSource) == "" || e.Confidence == "" {
			return fmt.Errorf("scheduled entry %d is incomplete", i)
		}
		for label, posture := range map[string]PathPosture{
			"action": e.ActionPath, "action_directory": e.ActionDirectoryPosture,
			"referenced_script": e.ReferencedScriptPathPosture, "working_directory": e.WorkingDirectoryPosture,
			"definition": e.DefinitionPathPosture, "definition_directory": e.DefinitionDirectoryPosture,
		} {
			if err := validatePathPosture(label, posture); err != nil {
				return fmt.Errorf("scheduled entry %d: %w", i, err)
			}
		}
		if _, ok := seen[e.ID]; ok {
			return fmt.Errorf("duplicate scheduled entry id %q", e.ID)
		}
		seen[e.ID] = struct{}{}
		key := entrySortKey(e)
		if last != "" && key < last {
			return fmt.Errorf("scheduled entries are not deterministically ordered")
		}
		last = key
	}
	if inv.Summary != summarize(inv.Entries) {
		return fmt.Errorf("scheduled summary does not match records")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func normalizeEntries(in []Entry) []Entry {
	byID := map[string]Entry{}
	for _, e := range in {
		e.Name = fallback(e.Name, "UNKNOWN")
		e.Manager = normalizeWord(e.Manager)
		e.Kind = normalizeWord(e.Kind)
		e.EnabledState = normalizeWord(e.EnabledState)
		e.RuntimeState = normalizeWord(e.RuntimeState)
		e.Account = fallback(e.Account, "UNKNOWN")
		e.PrivilegeContext = normalizeWord(e.PrivilegeContext)
		e.Schedule = fallback(e.Schedule, "UNKNOWN")
		e.RunLevel = normalizeWord(e.RunLevel)
		e.LogonType = normalizeWord(e.LogonType)
		e.HiddenState = normalizeWord(e.HiddenState)
		e.ConfigurationSource = fallback(e.ConfigurationSource, "UNKNOWN")
		e.CollectionSource = fallback(e.CollectionSource, "platform scheduled-execution provider")
		if e.Confidence == "" {
			e.Confidence = evidence.ConfidenceMedium
		}
		e.ActionExecutable = cleanPath(e.ActionExecutable)
		e.ReferencedScriptPath = cleanPath(e.ReferencedScriptPath)
		e.WorkingDirectory = cleanPath(e.WorkingDirectory)
		e.DefinitionPath = cleanPath(e.DefinitionPath)
		if e.ActionPath.State == "" {
			e.ActionPath = inspectActionPath(e.ActionExecutable)
		}
		if e.ActionDirectoryPosture.State == "" {
			e.ActionDirectoryPosture = inspectContainingDirectory(e.ActionPath.Path)
		}
		if e.ReferencedScriptPathPosture.State == "" {
			e.ReferencedScriptPathPosture = inspectReferencedPath(e.ReferencedScriptPath, e.WorkingDirectory)
		}
		if e.WorkingDirectoryPosture.State == "" {
			e.WorkingDirectoryPosture = inspectPath(e.WorkingDirectory)
		}
		if e.DefinitionPathPosture.State == "" {
			e.DefinitionPathPosture = inspectPath(e.DefinitionPath)
		}
		if e.DefinitionDirectoryPosture.State == "" {
			e.DefinitionDirectoryPosture = inspectContainingDirectory(e.DefinitionPath)
		}
		e.ActionPath = normalizePathPosture(e.ActionPath)
		e.ActionDirectoryPosture = normalizePathPosture(e.ActionDirectoryPosture)
		e.ReferencedScriptPathPosture = normalizePathPosture(e.ReferencedScriptPathPosture)
		e.WorkingDirectoryPosture = normalizePathPosture(e.WorkingDirectoryPosture)
		e.DefinitionPathPosture = normalizePathPosture(e.DefinitionPathPosture)
		e.DefinitionDirectoryPosture = normalizePathPosture(e.DefinitionDirectoryPosture)
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

func normalizePathPosture(p PathPosture) PathPosture {
	p.Path = strings.TrimSpace(p.Path)
	p.State = normalizeOptionalWord(p.State)
	p.Mode = strings.TrimSpace(p.Mode)
	p.Owner = strings.TrimSpace(p.Owner)
	p.OwnerSID = strings.TrimSpace(p.OwnerSID)
	p.OwnerTrust = normalizeOptionalWord(p.OwnerTrust)
	p.Group = strings.TrimSpace(p.Group)
	p.DACLState = normalizeOptionalWord(p.DACLState)
	p.PermissionBasis = strings.TrimSpace(p.PermissionBasis)
	p.WritePrincipals = uniqueSorted(p.WritePrincipals)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.State == "" {
		p.State = "UNAVAILABLE"
	}
	if p.OwnerTrust == "" {
		if p.State == "NOT_APPLICABLE" {
			p.OwnerTrust = "NOT_APPLICABLE"
		} else {
			p.OwnerTrust = "UNKNOWN"
		}
	}
	if p.DACLState == "" {
		if strings.Contains(strings.ToUpper(p.PermissionBasis), "WINDOWS") {
			p.DACLState = p.State
		} else {
			p.DACLState = "NOT_APPLICABLE"
		}
	}
	if !p.UntrustedWritable {
		p.InheritedUntrustedWrite = false
	}
	return p
}

func validatePathPosture(label string, p PathPosture) error {
	switch p.State {
	case "OBSERVED", "DEGRADED", "DENIED", "UNAVAILABLE", "UNSUPPORTED", "NOT_APPLICABLE":
	default:
		return fmt.Errorf("%s path has invalid state %q", label, p.State)
	}
	switch p.OwnerTrust {
	case "TRUSTED", "UNTRUSTED", "UNKNOWN", "NOT_APPLICABLE":
	default:
		return fmt.Errorf("%s path has invalid owner trust %q", label, p.OwnerTrust)
	}
	switch p.DACLState {
	case "OBSERVED", "DEGRADED", "DENIED", "UNAVAILABLE", "UNSUPPORTED", "NOT_APPLICABLE":
	default:
		return fmt.Errorf("%s path has invalid DACL state %q", label, p.DACLState)
	}
	if p.UntrustedWritable && p.State != "OBSERVED" {
		return fmt.Errorf("%s path cannot assert untrusted write without observed metadata", label)
	}
	if p.InheritedUntrustedWrite && !p.UntrustedWritable {
		return fmt.Errorf("%s path inherited write requires untrusted writable state", label)
	}
	if !sort.StringsAreSorted(p.WritePrincipals) {
		return fmt.Errorf("%s path write principals are not deterministically ordered", label)
	}
	return nil
}

func normalizeOptionalWord(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return normalizeWord(v)
}

func stableID(e Entry) string {
	s := strings.Join([]string{strings.ToLower(e.Manager), strings.ToLower(e.Name), strings.ToLower(e.DefinitionPath), strings.ToLower(e.TriggerTarget)}, "\x00")
	h := sha256.Sum256([]byte(s))
	return "sch-" + hex.EncodeToString(h[:10])
}
func entrySortKey(e Entry) string {
	return strings.ToLower(e.Manager) + "\x00" + strings.ToLower(e.Name) + "\x00" + strings.ToLower(e.DefinitionPath) + "\x00" + e.ID
}
func summarize(items []Entry) Summary {
	var s Summary
	s.Entries = len(items)
	for _, e := range items {
		switch e.EnabledState {
		case "ENABLED", "ENABLED_RUNTIME", "RUN_AT_LOAD", "KEEP_ALIVE", "ACTIVE":
			s.Enabled++
		case "DISABLED", "MASKED":
			s.Disabled++
		default:
			s.EnabledUnknown++
		}
		switch e.PrivilegeContext {
		case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT", "ADMINISTRATOR":
			s.Privileged++
		}
		if e.ActionExecutable != "" {
			s.WithAction++
		}
		if e.DefinitionPath != "" {
			s.WithDefinition++
		}
		if e.ReferencedScriptPath != "" {
			s.WithReferencedScript++
		}
		if e.HiddenState == "YES" || e.HiddenState == "HIDDEN" {
			s.Hidden++
			if isPrivilegedContext(e.PrivilegeContext) {
				s.HiddenPrivileged++
			}
		}
		if isPrivilegedContext(e.PrivilegeContext) && !isBuiltinPrivilegedAccount(e.Account) && e.Account != "UNKNOWN" {
			s.CustomPrivilegedAccounts++
		}
		if e.WorkingDirectoryPosture.State == "OBSERVED" {
			s.WorkingDirectoryAssessed++
			if e.WorkingDirectoryPosture.BroadlyWritable {
				s.BroadlyWritableWorkdir++
			}
		}
		if e.ActionPath.State == "OBSERVED" {
			s.ActionPathAssessed++
			if e.ActionPath.BroadlyWritable {
				s.BroadlyWritableAction++
			}
		}
		if e.DefinitionPathPosture.State == "OBSERVED" {
			s.DefinitionPathAssessed++
			if e.DefinitionPathPosture.BroadlyWritable {
				s.BroadlyWritableDefinition++
			}
		}
		switch e.Manager {
		case "SYSTEMD_TIMER":
			s.SystemdTimers++
		case "CRON":
			s.CronEntries++
		case "WINDOWS_TASK_SCHEDULER":
			s.WindowsTasks++
		case "LAUNCHD":
			s.LaunchdSchedules++
		}
	}
	return s
}
func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{evidence.NewObserved("scheduled.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact), evidence.NewObserved("scheduled.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact), evidence.NewObserved("scheduled.inventory.count", len(inv.Entries), "normalized scheduled-execution inventory", at, evidence.ConfidenceExact), evidence.NewObserved("scheduled.inventory.summary", inv.Summary, "normalized scheduled-execution inventory", at, evidence.ConfidenceHigh)}
	for _, src := range inv.Sources {
		key := "scheduled.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			st := src.State
			if st == "" {
				st = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, st, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "scheduled-execution provider unavailable")))
		}
	}
	for _, e := range inv.Entries {
		out = append(out, evidence.NewObserved("scheduled.item."+e.ID, e, e.CollectionSource, at, e.Confidence))
	}
	return out
}
func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	if state == "" {
		state = evidence.StateUnavailable
	}
	s := SourceStatus{ID: strings.TrimSpace(id), State: state, Source: fallback(source, "scheduled-execution provider"), ItemCount: count, Reason: strings.TrimSpace(reason)}
	inv.Sources = append(inv.Sources, s)
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && s.Reason != "" {
		inv.Degraded = append(inv.Degraded, s.ID+": "+s.Reason)
	}
}
func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func fallback(v, f string) string {
	if strings.TrimSpace(v) == "" {
		return f
	}
	return strings.TrimSpace(v)
}
func normalizeWord(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "UNKNOWN"
	}
	v = strings.NewReplacer("-", "_", " ", "_").Replace(v)
	return strings.ToUpper(v)
}
func cleanPath(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "\"'"))
	if v == "" {
		return ""
	}
	return filepath.Clean(v)
}
func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	sep := false
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			sep = false
		} else if !sep {
			b.WriteByte('_')
			sep = true
		}
	}
	return strings.Trim(b.String(), "_")
}
func inspectPath(path string) PathPosture {
	path = cleanPath(path)
	if path == "" {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	if !filepath.IsAbs(path) {
		return PathPosture{Path: path, State: "UNAVAILABLE", Reason: "relative path cannot be assessed without an explicit resolution directory"}
	}
	info, err := os.Stat(path)
	if err != nil {
		st := "UNAVAILABLE"
		if os.IsPermission(err) {
			st = "DENIED"
		}
		return PathPosture{Path: path, State: st, Reason: err.Error()}
	}
	mode := info.Mode()
	p := PathPosture{Path: path, State: "OBSERVED", Exists: true, IsDirectory: info.IsDir(), Mode: fmt.Sprintf("%#o", mode.Perm()), GroupWritable: mode.Perm()&0020 != 0, OtherWritable: mode.Perm()&0002 != 0, BroadlyWritable: mode.Perm()&0002 != 0, PermissionBasis: "filesystem mode"}
	enrichPathPosture(path, info, &p)
	return p
}

func inspectActionPath(path string) PathPosture {
	path = cleanPath(path)
	if path == "" {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	if filepath.IsAbs(path) {
		return inspectPath(path)
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return PathPosture{Path: path, State: "UNAVAILABLE", Reason: "action executable could not be resolved through the local PATH"}
	}
	return inspectPath(resolved)
}

func inspectReferencedPath(path, workingDirectory string) PathPosture {
	path = cleanPath(path)
	if path == "" {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	if filepath.IsAbs(path) {
		return inspectPath(path)
	}
	workingDirectory = cleanPath(workingDirectory)
	if workingDirectory != "" && filepath.IsAbs(workingDirectory) {
		return inspectPath(filepath.Join(workingDirectory, path))
	}
	return PathPosture{Path: path, State: "UNAVAILABLE", Reason: "relative referenced script path has no explicit absolute working directory"}
}

func inspectContainingDirectory(path string) PathPosture {
	path = cleanPath(path)
	if path == "" {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	if !filepath.IsAbs(path) {
		return PathPosture{Path: filepath.Dir(path), State: "UNAVAILABLE", Reason: "relative path resolution directory is not explicit"}
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == path {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	return inspectPath(dir)
}

func isPrivilegedContext(v string) bool {
	switch normalizeWord(v) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT", "ADMINISTRATOR":
		return true
	default:
		return false
	}
}

func isBuiltinPrivilegedAccount(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, ".\\")
	switch v {
	case "root", "0", "system", "localsystem", "nt authority\\system", "local service", "nt authority\\local service", "network service", "nt authority\\network service":
		return true
	default:
		return false
	}
}

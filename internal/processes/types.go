package processes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.processes/v1"
	CollectorName    = "processes"
	CollectorVersion = "processes/v1"
	maxProcesses     = 65536
)

type Principal struct {
	User     string `json:"user"`
	UserID   string `json:"user_id"`
	Group    string `json:"group,omitempty"`
	GroupID  string `json:"group_id,omitempty"`
	Elevated bool   `json:"elevated"`
	Context  string `json:"context"`
}

type CommandLineMetadata struct {
	Available     bool   `json:"available"`
	ArgumentCount int    `json:"argument_count"`
	ByteCount     int    `json:"byte_count"`
	Redacted      bool   `json:"redacted"`
	Source        string `json:"source"`
	Reason        string `json:"reason,omitempty"`
}

type TrustContext struct {
	State          string `json:"state"`
	Basis          string `json:"basis"`
	Owner          string `json:"owner,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Signature      string `json:"signature,omitempty"`
	DeletedBacking bool   `json:"deleted_backing"`
	Reason         string `json:"reason,omitempty"`
}

type IsolationSummary struct {
	State            string `json:"state"`
	PIDNamespace     bool   `json:"pid_namespace,omitempty"`
	MountNamespace   bool   `json:"mount_namespace,omitempty"`
	NetworkNamespace bool   `json:"network_namespace,omitempty"`
	UserNamespace    bool   `json:"user_namespace,omitempty"`
	Seccomp          string `json:"seccomp,omitempty"`
	NoNewPrivileges  bool   `json:"no_new_privileges,omitempty"`
	Cgroup           string `json:"cgroup,omitempty"`
	AppContainer     string `json:"app_container,omitempty"`
	JobObject        string `json:"job_object,omitempty"`
	Sandbox          string `json:"sandbox,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type Process struct {
	ID               string              `json:"id"`
	PID              int                 `json:"pid"`
	PPID             int                 `json:"ppid"`
	Name             string              `json:"name"`
	Executable       string              `json:"executable"`
	ExecutablePath   string              `json:"executable_path"`
	StartTime        string              `json:"start_time,omitempty"`
	Principal        Principal           `json:"principal"`
	SessionID        string              `json:"session_id"`
	PrivilegeContext string              `json:"privilege_context"`
	RuntimeState     string              `json:"runtime_state"`
	CommandLine      CommandLineMetadata `json:"command_line"`
	Trust            TrustContext        `json:"trust"`
	Isolation        IsolationSummary    `json:"isolation"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Processes                 int `json:"processes"`
	Elevated                  int `json:"elevated"`
	WithExecutablePath        int `json:"with_executable_path"`
	WithCommandMetadata       int `json:"with_command_metadata"`
	Isolated                  int `json:"isolated"`
	DeletedBacking            int `json:"deleted_backing"`
	TrustUnknown              int `json:"trust_unknown"`
	PermissionWeak            int `json:"permission_weak"`
	PermissionUnknown         int `json:"permission_unknown"`
	ExecutableWriteWeak       int `json:"executable_write_weak"`
	ParentDirectoryWeak       int `json:"parent_directory_weak"`
	PrivilegeObserved         int `json:"privilege_observed"`
	PrivilegeElevated         int `json:"privilege_elevated"`
	PrivilegeExcess           int `json:"privilege_excess"`
	PrivilegeUnknown          int `json:"privilege_unknown"`
	IdentityTransitions       int `json:"identity_transitions"`
	HighImpactPrivilegeSets   int `json:"high_impact_privilege_sets"`
	ElevatedUserContexts      int `json:"elevated_user_contexts"`
	MemoryObserved            int `json:"memory_observed"`
	MemoryUnknown             int `json:"memory_unknown"`
	ExecutableMemory          int `json:"executable_memory"`
	WritableExecutableMemory  int `json:"writable_executable_memory"`
	AnonymousExecutableMemory int `json:"anonymous_executable_memory"`
	DeletedExecutableMemory   int `json:"deleted_executable_memory"`
	JITLikeContexts           int `json:"jit_like_contexts"`
	ModuleContexts            int `json:"module_contexts"`
	LoadedModules             int `json:"loaded_modules"`
	DeletedLoadedModules      int `json:"deleted_loaded_modules"`
	ModuleTrustFailures       int `json:"module_trust_failures"`
	UnsignedLoadedModules     int `json:"unsigned_loaded_modules"`
	UnmanagedLoadedModules    int `json:"unmanaged_loaded_modules"`
	WritableModuleLocations   int `json:"writable_module_locations"`
	ModuleTrustMismatches     int `json:"module_trust_mismatches"`
	IsolationObserved         int `json:"isolation_observed"`
	IsolationUnknown          int `json:"isolation_unknown"`
	IsolationIsolated         int `json:"isolation_isolated"`
	IsolationPartial          int `json:"isolation_partial"`
	NamespaceIsolated         int `json:"namespace_isolated"`
	SeccompFiltered           int `json:"seccomp_filtered"`
	NoNewPrivileges           int `json:"no_new_privileges"`
	CgroupScoped              int `json:"cgroup_scoped"`
	ContainerContexts         int `json:"container_contexts"`
	AppContainerContexts      int `json:"appcontainer_contexts"`
	JobObjectContexts         int `json:"job_object_contexts"`
	SandboxContexts           int `json:"sandbox_contexts"`
	EnvironmentObserved       int `json:"environment_observed"`
	EnvironmentUnknown        int `json:"environment_unknown"`
	EnvironmentOverrides      int `json:"environment_overrides"`
	EnvironmentHighRisk       int `json:"environment_high_risk"`
	LoaderEnvironmentHooks    int `json:"loader_environment_hooks"`
	RuntimeSearchOverrides    int `json:"runtime_search_overrides"`
	RuntimeStartupHooks       int `json:"runtime_startup_hooks"`
	RuntimeDebugControls      int `json:"runtime_debug_controls"`
	RuntimeProxyOverrides     int `json:"runtime_proxy_overrides"`
	TLSKeyLoggingContexts     int `json:"tls_key_logging_contexts"`
}

type Inventory struct {
	Schema             string                      `json:"schema"`
	EvidenceSchema     string                      `json:"evidence_schema"`
	Collector          string                      `json:"collector"`
	CollectorVersion   string                      `json:"collector_version"`
	Platform           string                      `json:"platform"`
	Architecture       string                      `json:"architecture"`
	CollectedAt        time.Time                   `json:"collected_at"`
	Processes          []Process                   `json:"processes"`
	PathPermissions    []PathPermissionContext     `json:"path_permissions,omitempty"`
	RuntimePrivileges  []RuntimePrivilegeContext   `json:"runtime_privileges,omitempty"`
	ExecutionMemory    []ExecutionMemoryContext    `json:"execution_memory,omitempty"`
	LoadedModules      []LoadedModuleContext       `json:"loaded_modules,omitempty"`
	IsolationPosture   []IsolationContext          `json:"isolation_posture,omitempty"`
	RuntimeEnvironment []RuntimeEnvironmentContext `json:"runtime_environment,omitempty"`
	Sources            []SourceStatus              `json:"sources"`
	Summary            Summary                     `json:"summary"`
	Evidence           []evidence.Observation      `json:"evidence"`
	Degraded           []string                    `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{
		Schema:           SchemaVersion,
		EvidenceSchema:   evidence.SchemaVersion,
		Collector:        CollectorName,
		CollectorVersion: CollectorVersion,
		Platform:         runtime.GOOS,
		Architecture:     runtime.GOARCH,
		CollectedAt:      at,
	}
	collectPlatform(ctx, &inv)
	enrichTrust(ctx, &inv)
	inv.Processes = normalize(inv.Processes)
	inv.RuntimePrivileges = normalizeRuntimePrivileges(inv.Processes, inv.RuntimePrivileges, inv.Platform)
	if !collectConcurrentSecondary(ctx, &inv) {
		inv.PathPermissions = collectPathPermissions(ctx, inv.Processes, inv.Platform)
		var memorySource SourceStatus
		inv.ExecutionMemory, memorySource = collectExecutionMemory(ctx, inv.Processes, inv.Platform)
		if memorySource.ID != "" {
			inv.Sources = append(inv.Sources, memorySource)
			if memorySource.State != evidence.StateObserved && memorySource.State != evidence.StateNotApplicable && memorySource.State != evidence.StateUnsupported && strings.TrimSpace(memorySource.Reason) != "" {
				inv.Degraded = append(inv.Degraded, memorySource.ID+": "+strings.TrimSpace(memorySource.Reason))
			}
		}
		var moduleSource SourceStatus
		inv.LoadedModules, moduleSource = collectLoadedModules(ctx, inv.Processes, inv.Platform)
		if moduleSource.ID != "" {
			inv.Sources = append(inv.Sources, moduleSource)
			if moduleSource.State != evidence.StateObserved && moduleSource.State != evidence.StateNotApplicable && moduleSource.State != evidence.StateUnsupported && strings.TrimSpace(moduleSource.Reason) != "" {
				inv.Degraded = append(inv.Degraded, moduleSource.ID+": "+strings.TrimSpace(moduleSource.Reason))
			}
		}
		var isolationSource SourceStatus
		inv.IsolationPosture, isolationSource = collectIsolationPosture(ctx, inv.Processes, inv.Platform)
		if isolationSource.ID != "" {
			inv.Sources = append(inv.Sources, isolationSource)
			if isolationSource.State != evidence.StateObserved && isolationSource.State != evidence.StateNotApplicable && isolationSource.State != evidence.StateUnsupported && strings.TrimSpace(isolationSource.Reason) != "" {
				inv.Degraded = append(inv.Degraded, isolationSource.ID+": "+strings.TrimSpace(isolationSource.Reason))
			}
		}
		var environmentSource SourceStatus
		inv.RuntimeEnvironment, environmentSource = collectRuntimeEnvironment(ctx, inv.Processes, inv.Platform)
		if environmentSource.ID != "" {
			inv.Sources = append(inv.Sources, environmentSource)
			if environmentSource.State != evidence.StateObserved && environmentSource.State != evidence.StateNotApplicable && environmentSource.State != evidence.StateUnsupported && strings.TrimSpace(environmentSource.Reason) != "" {
				inv.Degraded = append(inv.Degraded, environmentSource.ID+": "+strings.TrimSpace(environmentSource.Reason))
			}
		}
	}
	applyIsolationSummaries(inv.Processes, inv.IsolationPosture)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Processes, inv.PathPermissions, inv.RuntimePrivileges, inv.ExecutionMemory, inv.LoadedModules, inv.IsolationPosture, inv.RuntimeEnvironment)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion {
		return fmt.Errorf("unexpected process schema %q", inv.Schema)
	}
	if inv.EvidenceSchema != evidence.SchemaVersion {
		return fmt.Errorf("unexpected process evidence schema %q", inv.EvidenceSchema)
	}
	if inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected process collector identity")
	}
	if inv.CollectedAt.IsZero() {
		return fmt.Errorf("process collection timestamp is required")
	}
	seen := map[string]struct{}{}
	lastPID := -1
	for i, p := range inv.Processes {
		if p.PID <= 0 {
			return fmt.Errorf("process %d has invalid pid %d", i, p.PID)
		}
		if p.ID == "" || p.Name == "" || p.CollectionSource == "" {
			return fmt.Errorf("process %d is incomplete", i)
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate process id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		if p.PID < lastPID {
			return fmt.Errorf("process inventory is not deterministically ordered")
		}
		lastPID = p.PID
		if p.CommandLine.Redacted != true {
			return fmt.Errorf("process %d command line metadata must remain redacted", i)
		}
	}
	if len(inv.PathPermissions) != 0 && len(inv.PathPermissions) != len(inv.Processes) {
		return fmt.Errorf("process permission context count %d does not match process count %d", len(inv.PathPermissions), len(inv.Processes))
	}
	if len(inv.RuntimePrivileges) != 0 && len(inv.RuntimePrivileges) != len(inv.Processes) {
		return fmt.Errorf("runtime privilege context count %d does not match process count %d", len(inv.RuntimePrivileges), len(inv.Processes))
	}
	if len(inv.ExecutionMemory) != 0 && len(inv.ExecutionMemory) != len(inv.Processes) {
		return fmt.Errorf("execution-memory context count %d does not match process count %d", len(inv.ExecutionMemory), len(inv.Processes))
	}
	if len(inv.LoadedModules) != 0 && len(inv.LoadedModules) != len(inv.Processes) {
		return fmt.Errorf("loaded-module context count %d does not match process count %d", len(inv.LoadedModules), len(inv.Processes))
	}
	if len(inv.IsolationPosture) != 0 && len(inv.IsolationPosture) != len(inv.Processes) {
		return fmt.Errorf("isolation context count %d does not match process count %d", len(inv.IsolationPosture), len(inv.Processes))
	}
	if len(inv.RuntimeEnvironment) != 0 && len(inv.RuntimeEnvironment) != len(inv.Processes) {
		return fmt.Errorf("runtime environment context count %d does not match process count %d", len(inv.RuntimeEnvironment), len(inv.Processes))
	}
	privSeen := map[string]struct{}{}
	lastPrivPID := -1
	for i, c := range inv.RuntimePrivileges {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" || c.State == "" || c.PrivilegeSetState == "" {
			return fmt.Errorf("runtime privilege context %d is incomplete", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("runtime privilege context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := privSeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate runtime privilege context for %q", c.ProcessID)
		}
		privSeen[c.ProcessID] = struct{}{}
		if c.PID < lastPrivPID {
			return fmt.Errorf("runtime privilege contexts are not deterministically ordered")
		}
		lastPrivPID = c.PID
	}
	memorySeen := map[string]struct{}{}
	lastMemoryPID := -1
	for i, c := range inv.ExecutionMemory {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" || c.State == "" {
			return fmt.Errorf("execution-memory context %d is incomplete", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("execution-memory context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := memorySeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate execution-memory context for %q", c.ProcessID)
		}
		memorySeen[c.ProcessID] = struct{}{}
		if c.PID < lastMemoryPID {
			return fmt.Errorf("execution-memory contexts are not deterministically ordered")
		}
		lastMemoryPID = c.PID
		if c.RegionsObserved < 0 || c.ExecutableRegions < 0 || c.WritableExecutableRegions < 0 || c.AnonymousExecutableRegions < 0 || c.FileBackedExecutableRegions < 0 {
			return fmt.Errorf("execution-memory context %d has invalid negative counters", i)
		}
		if c.WritableExecutableRegions > c.ExecutableRegions || c.AnonymousExecutableRegions > c.ExecutableRegions || c.FileBackedExecutableRegions > c.ExecutableRegions {
			return fmt.Errorf("execution-memory context %d counters are inconsistent", i)
		}
	}

	permSeen := map[string]struct{}{}
	lastPermPID := -1
	for i, c := range inv.PathPermissions {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" {
			return fmt.Errorf("process permission context %d is incomplete", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("process permission context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := permSeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate process permission context for %q", c.ProcessID)
		}
		permSeen[c.ProcessID] = struct{}{}
		if c.PID < lastPermPID {
			return fmt.Errorf("process permission contexts are not deterministically ordered")
		}
		lastPermPID = c.PID
	}

	isolationSeen := map[string]struct{}{}
	lastIsolationPID := -1
	for i, c := range inv.IsolationPosture {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" || c.State == "" || c.IsolationState == "" {
			return fmt.Errorf("isolation context %d is incomplete", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("isolation context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := isolationSeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate isolation context for %q", c.ProcessID)
		}
		isolationSeen[c.ProcessID] = struct{}{}
		if c.PID < lastIsolationPID {
			return fmt.Errorf("isolation contexts are not deterministically ordered")
		}
		lastIsolationPID = c.PID
		if c.NamespaceCount != countIsolationNamespaces(c) {
			return fmt.Errorf("isolation context %d namespace count mismatch", i)
		}
	}

	environmentSeen := map[string]struct{}{}
	lastEnvironmentPID := -1
	for i, c := range inv.RuntimeEnvironment {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" || c.State == "" || c.Posture == "" || !c.ValuesRedacted {
			return fmt.Errorf("runtime environment context %d is incomplete or not redacted", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("runtime environment context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := environmentSeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate runtime environment context for %q", c.ProcessID)
		}
		environmentSeen[c.ProcessID] = struct{}{}
		if c.PID < lastEnvironmentPID {
			return fmt.Errorf("runtime environment contexts are not deterministically ordered")
		}
		lastEnvironmentPID = c.PID
		if c.RelevantVariables != len(c.Indicators) || c.VariablesObserved < 0 || c.RelevantVariables < 0 || c.HighRiskIndicators < 0 {
			return fmt.Errorf("runtime environment context %d counters are inconsistent", i)
		}
		lastKey := ""
		for j, ind := range c.Indicators {
			if ind.Name == "" || ind.Category == "" || ind.RiskClass == "" || !ind.NonEmpty {
				return fmt.Errorf("runtime environment context %d indicator %d is incomplete", i, j)
			}
			key := ind.Name + "\x00" + ind.Category
			if lastKey != "" && key < lastKey {
				return fmt.Errorf("runtime environment context %d indicators are not deterministically ordered", i)
			}
			lastKey = key
		}
	}

	moduleSeen := map[string]struct{}{}
	lastModulePID := -1
	for i, c := range inv.LoadedModules {
		if c.ProcessID == "" || c.PID <= 0 || c.Source == "" || c.Confidence == "" || c.State == "" {
			return fmt.Errorf("loaded-module context %d is incomplete", i)
		}
		if _, ok := seen[c.ProcessID]; !ok {
			return fmt.Errorf("loaded-module context %d references unknown process %q", i, c.ProcessID)
		}
		if _, ok := moduleSeen[c.ProcessID]; ok {
			return fmt.Errorf("duplicate loaded-module context for %q", c.ProcessID)
		}
		moduleSeen[c.ProcessID] = struct{}{}
		if c.PID < lastModulePID {
			return fmt.Errorf("loaded-module contexts are not deterministically ordered")
		}
		lastModulePID = c.PID
		if c.ModuleCount != len(c.Modules) {
			return fmt.Errorf("loaded-module context %d module count mismatch", i)
		}
		lastPath := ""
		for j, m := range c.Modules {
			if strings.TrimSpace(m.Path) == "" || strings.TrimSpace(m.TrustState) == "" || strings.TrimSpace(m.DirectoryState) == "" || strings.TrimSpace(m.Source) == "" || m.Confidence == "" {
				return fmt.Errorf("loaded-module context %d module %d is incomplete", i, j)
			}
			pathKey := strings.ToLower(filepath.Clean(m.Path))
			if lastPath != "" && pathKey < lastPath {
				return fmt.Errorf("loaded-module context %d modules are not deterministically ordered", i)
			}
			lastPath = pathKey
		}
	}
	return evidence.ValidateAll(inv.Evidence)
}

func normalize(in []Process) []Process {
	seen := make(map[int]Process, len(in))
	for _, p := range in {
		if p.PID <= 0 {
			continue
		}
		p.Name = fallback(strings.TrimSpace(p.Name), "UNKNOWN")
		p.Executable = fallback(strings.TrimSpace(p.Executable), p.Name)
		p.ExecutablePath = strings.TrimSpace(p.ExecutablePath)
		p.SessionID = fallback(strings.TrimSpace(p.SessionID), "UNKNOWN")
		p.PrivilegeContext = fallback(strings.TrimSpace(p.PrivilegeContext), "UNKNOWN")
		p.RuntimeState = fallback(strings.TrimSpace(p.RuntimeState), "UNKNOWN")
		p.CollectionSource = fallback(strings.TrimSpace(p.CollectionSource), "platform process metadata")
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceHigh
		}
		p.CommandLine.Redacted = true
		p.CommandLine.Source = fallback(strings.TrimSpace(p.CommandLine.Source), p.CollectionSource)
		p.Trust.State = fallback(strings.ToUpper(strings.TrimSpace(p.Trust.State)), "UNKNOWN")
		p.Trust.Basis = fallback(strings.TrimSpace(p.Trust.Basis), "insufficient local provenance metadata")
		p.Isolation.State = fallback(strings.ToUpper(strings.TrimSpace(p.Isolation.State)), "UNKNOWN")
		p.ID = stableID(p)
		old, ok := seen[p.PID]
		if !ok || confidenceRank(p.Confidence) > confidenceRank(old.Confidence) {
			seen[p.PID] = p
		}
	}
	out := make([]Process, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxProcesses {
		out = out[:maxProcesses]
	}
	return out
}

func stableID(p Process) string {
	identity := fmt.Sprintf("%d\x00%d\x00%s\x00%s\x00%s", p.PID, p.PPID, strings.ToLower(p.Name), strings.ToLower(p.ExecutablePath), p.SessionID)
	sum := sha256.Sum256([]byte(identity))
	return "proc-" + hex.EncodeToString(sum[:10])
}

func summarize(items []Process, permissions []PathPermissionContext, privileges []RuntimePrivilegeContext, memory []ExecutionMemoryContext, modules []LoadedModuleContext, isolation []IsolationContext, environments []RuntimeEnvironmentContext) Summary {
	s := Summary{Processes: len(items)}
	for _, p := range items {
		if p.Principal.Elevated {
			s.Elevated++
		}
		if p.ExecutablePath != "" {
			s.WithExecutablePath++
		}
		if p.CommandLine.Available {
			s.WithCommandMetadata++
		}
		if p.Isolation.State == "ISOLATED" || p.Isolation.PIDNamespace || p.Isolation.MountNamespace || p.Isolation.NetworkNamespace || p.Isolation.UserNamespace || p.Isolation.AppContainer == "TRUE" || p.Isolation.Sandbox == "TRUE" {
			s.Isolated++
		}
		if p.Trust.DeletedBacking {
			s.DeletedBacking++
		}
		if p.Trust.State == "UNKNOWN" {
			s.TrustUnknown++
		}
	}
	for _, c := range privileges {
		switch c.State {
		case "STANDARD":
			s.PrivilegeObserved++
		case "ELEVATED":
			s.PrivilegeObserved++
			s.PrivilegeElevated++
		case "EXCESS":
			s.PrivilegeObserved++
			s.PrivilegeElevated++
			s.PrivilegeExcess++
		default:
			s.PrivilegeUnknown++
		}
		if c.IdentityTransition {
			s.IdentityTransitions++
		}
		if len(c.HighImpactPrivileges) > 0 {
			s.HighImpactPrivilegeSets++
		}
		if c.ElevatedUserContext {
			s.ElevatedUserContexts++
		}
	}
	for _, c := range memory {
		switch c.State {
		case "OBSERVED", "DEGRADED":
			s.MemoryObserved++
		default:
			s.MemoryUnknown++
		}
		if c.ExecutableRegions > 0 {
			s.ExecutableMemory++
		}
		if c.WritableExecutableRegions > 0 {
			s.WritableExecutableMemory++
		}
		if c.AnonymousExecutableRegions > 0 {
			s.AnonymousExecutableMemory++
		}
		if c.DeletedExecutableRegions > 0 {
			s.DeletedExecutableMemory++
		}
		if c.JITLikeContext {
			s.JITLikeContexts++
		}
	}
	for _, c := range modules {
		s.ModuleContexts++
		s.LoadedModules += c.ModuleCount
		s.DeletedLoadedModules += c.DeletedMappings
		s.ModuleTrustFailures += c.ExplicitTrustFailures
		s.UnsignedLoadedModules += c.UnsignedModules
		s.UnmanagedLoadedModules += c.UnmanagedModules
		s.WritableModuleLocations += c.WritableLocationModules
		s.ModuleTrustMismatches += c.TrustMismatches
	}
	for _, c := range isolation {
		switch c.State {
		case "OBSERVED", "DEGRADED":
			s.IsolationObserved++
		default:
			s.IsolationUnknown++
		}
		switch c.IsolationState {
		case "ISOLATED":
			s.IsolationIsolated++
		case "PARTIAL":
			s.IsolationPartial++
		}
		if c.NamespaceCount > 0 {
			s.NamespaceIsolated++
		}
		if c.Seccomp == "FILTER" || c.Seccomp == "STRICT" {
			s.SeccompFiltered++
		}
		if c.NoNewPrivileges {
			s.NoNewPrivileges++
		}
		if c.CgroupScoped {
			s.CgroupScoped++
		}
		if c.ContainerHint {
			s.ContainerContexts++
		}
		if c.AppContainer == "TRUE" {
			s.AppContainerContexts++
		}
		if c.JobObject == "TRUE" {
			s.JobObjectContexts++
		}
		if c.Sandbox == "ENFORCED" || c.Sandbox == "PROFILED" || c.Sandbox == "ENTITLED" {
			s.SandboxContexts++
		}
	}
	for _, c := range environments {
		switch c.State {
		case "OBSERVED", "DEGRADED":
			s.EnvironmentObserved++
		default:
			s.EnvironmentUnknown++
		}
		if c.RelevantVariables > 0 {
			s.EnvironmentOverrides++
		}
		if c.HighRiskIndicators > 0 {
			s.EnvironmentHighRisk++
		}
		s.LoaderEnvironmentHooks += c.LoaderHooks + c.LoaderOverrides
		s.RuntimeSearchOverrides += c.RuntimeSearchPaths
		s.RuntimeStartupHooks += c.StartupHooks
		s.RuntimeDebugControls += c.DebugControls
		s.RuntimeProxyOverrides += c.ProxyOverrides
		if c.TLSKeyLogging {
			s.TLSKeyLoggingContexts++
		}
	}
	for _, c := range permissions {
		switch c.State {
		case "WEAK":
			s.PermissionWeak++
		case "UNKNOWN":
			s.PermissionUnknown++
		}
		if c.UntrustedExecutableWrite {
			s.ExecutableWriteWeak++
		}
		if c.UntrustedParentWrite {
			s.ParentDirectoryWeak++
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("process.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("process.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.count", len(inv.Processes), "normalized process inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("process.inventory.summary", inv.Summary, "normalized process inventory", at, evidence.ConfidenceHigh),
	}
	if len(inv.Sources) == 0 {
		out = append(out, evidence.NewState("process.inventory.provider", evidence.StateUnavailable, "platform process inventory", at, evidence.ConfidenceLow, "no supported local process provider returned a status"))
	}
	for _, src := range inv.Sources {
		key := "process.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "process provider did not return usable metadata")))
		}
	}
	permissions := make(map[string]PathPermissionContext, len(inv.PathPermissions))
	for _, c := range inv.PathPermissions {
		permissions[c.ProcessID] = c
	}
	privileges := make(map[string]RuntimePrivilegeContext, len(inv.RuntimePrivileges))
	for _, c := range inv.RuntimePrivileges {
		privileges[c.ProcessID] = c
	}
	memory := make(map[string]ExecutionMemoryContext, len(inv.ExecutionMemory))
	for _, c := range inv.ExecutionMemory {
		memory[c.ProcessID] = c
	}
	modules := make(map[string]LoadedModuleContext, len(inv.LoadedModules))
	for _, c := range inv.LoadedModules {
		modules[c.ProcessID] = c
	}
	isolation := make(map[string]IsolationContext, len(inv.IsolationPosture))
	for _, c := range inv.IsolationPosture {
		isolation[c.ProcessID] = c
	}
	environments := make(map[string]RuntimeEnvironmentContext, len(inv.RuntimeEnvironment))
	for _, c := range inv.RuntimeEnvironment {
		environments[c.ProcessID] = c
	}
	for _, p := range inv.Processes {
		out = append(out, evidence.NewObserved("process.item."+p.ID, p, p.CollectionSource, at, p.Confidence))
		privilege, ok := privileges[p.ID]
		if !ok {
			privilege = RuntimePrivilegeContext{ProcessID: p.ID, PID: p.PID, Platform: inv.Platform, State: "UNKNOWN", AccountClass: "UNKNOWN", PrivilegeSetState: "UNKNOWN", Source: "platform runtime privilege metadata", Confidence: evidence.ConfidenceLow, Reason: "runtime privilege metadata unavailable"}
		}
		out = append(out, evidence.NewObserved("process.privilege."+p.ID, privilege, privilege.Source, at, privilege.Confidence))
		location := classifyExecutionLocation(p, inv.Platform)
		out = append(out, evidence.NewObserved("process.location."+p.ID, location, location.Source, at, location.Confidence))
		permission, ok := permissions[p.ID]
		if !ok {
			permission = unknownPermissionContext(p, inv.Platform, "permission context unavailable")
		}
		out = append(out, evidence.NewObserved("process.permission."+p.ID, permission, permission.Source, at, permission.Confidence))
		memoryContext, ok := memory[p.ID]
		if !ok {
			memoryContext = ExecutionMemoryContext{ProcessID: p.ID, PID: p.PID, Platform: inv.Platform, State: "UNKNOWN", Source: "platform executable-memory metadata", Confidence: evidence.ConfidenceLow, Reason: "executable-memory metadata unavailable"}
		}
		out = append(out, evidence.NewObserved("process.memory."+p.ID, memoryContext, memoryContext.Source, at, memoryContext.Confidence))
		moduleContext, ok := modules[p.ID]
		if !ok {
			moduleContext = LoadedModuleContext{ProcessID: p.ID, PID: p.PID, Platform: inv.Platform, State: "UNKNOWN", Source: "platform loaded-module metadata", Confidence: evidence.ConfidenceLow, Reason: "loaded-module metadata unavailable"}
		}
		out = append(out, evidence.NewObserved("process.modules."+p.ID, moduleContext, moduleContext.Source, at, moduleContext.Confidence))
		isolationContext, ok := isolation[p.ID]
		if !ok {
			isolationContext = IsolationContext{ProcessID: p.ID, PID: p.PID, Platform: inv.Platform, State: "UNKNOWN", IsolationState: "UNKNOWN", AppContainer: "UNKNOWN", JobObject: "UNKNOWN", Sandbox: "UNKNOWN", Source: "platform process-isolation metadata", Confidence: evidence.ConfidenceLow, Reason: "process-isolation metadata unavailable"}
		}
		out = append(out, evidence.NewObserved("process.isolation."+p.ID, isolationContext, isolationContext.Source, at, isolationContext.Confidence))
		environmentContext, ok := environments[p.ID]
		if !ok {
			environmentContext = RuntimeEnvironmentContext{ProcessID: p.ID, PID: p.PID, Platform: inv.Platform, State: "UNKNOWN", Posture: "UNKNOWN", ValuesRedacted: true, Source: "platform process environment metadata", Confidence: evidence.ConfidenceLow, Reason: "process environment metadata unavailable"}
		}
		out = append(out, evidence.NewObserved("process.environment."+p.ID, environmentContext, environmentContext.Source, at, environmentContext.Confidence))
	}
	return out
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	inv.Sources = append(inv.Sources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)})
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && strings.TrimSpace(reason) != "" {
		inv.Degraded = append(inv.Degraded, id+": "+strings.TrimSpace(reason))
	}
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
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
func confidenceRank(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceExact:
		return 4
	case evidence.ConfidenceHigh:
		return 3
	case evidence.ConfidenceMedium:
		return 2
	case evidence.ConfidenceLow:
		return 1
	}
	return 0
}
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	sep := false
	for _, r := range s {
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

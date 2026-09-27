package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.services/v1"
	CollectorName    = "services"
	CollectorVersion = "services/phase048-v1"
	maxServices      = 16384
)

type Service struct {
	ID                  string                  `json:"id"`
	Name                string                  `json:"name"`
	DisplayName         string                  `json:"display_name,omitempty"`
	Description         string                  `json:"description,omitempty"`
	Manager             string                  `json:"manager"`
	ServiceType         string                  `json:"service_type,omitempty"`
	Executable          string                  `json:"executable,omitempty"`
	ExecutablePath      string                  `json:"executable_path,omitempty"`
	Account             string                  `json:"account"`
	AccountGroup        string                  `json:"account_group,omitempty"`
	StartMode           string                  `json:"start_mode"`
	RuntimePID          int                     `json:"runtime_pid,omitempty"`
	RuntimeState        string                  `json:"runtime_state"`
	SubState            string                  `json:"sub_state,omitempty"`
	PrivilegeContext    string                  `json:"privilege_context"`
	DefinitionState     string                  `json:"definition_state,omitempty"`
	DefinitionPath      string                  `json:"definition_path,omitempty"`
	ConfigurationSource string                  `json:"configuration_source"`
	CollectionSource    string                  `json:"collection_source"`
	Confidence          evidence.Confidence     `json:"confidence"`
	WindowsSecurity     *WindowsSecurity        `json:"windows_security,omitempty"`
	SystemdHardening    *SystemdHardening       `json:"systemd_hardening,omitempty"`
	LaunchdHardening    *LaunchdHardening       `json:"launchd_hardening,omitempty"`
	PathIntegrity       *ServicePathIntegrity   `json:"path_integrity,omitempty"`
	Exposure            *ServiceExposurePosture `json:"exposure,omitempty"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type SecurityComponentCoverage struct {
	Observed      int `json:"observed"`
	Degraded      int `json:"degraded"`
	Denied        int `json:"denied"`
	Unavailable   int `json:"unavailable"`
	NotApplicable int `json:"not_applicable"`
}

// WindowsServiceSecurityCoverage is an additive, component-by-component
// release-quality summary. It deliberately keeps access denial, provider
// degradation, unavailable evidence, and true non-applicability separate so
// optional Windows service features cannot poison unrelated security coverage.
type WindowsServiceSecurityCoverage struct {
	BaseConfiguration      SecurityComponentCoverage `json:"base_configuration"`
	ExecutablePath         SecurityComponentCoverage `json:"executable_path"`
	ExecutableACL          SecurityComponentCoverage `json:"executable_acl"`
	ExecutableDirectoryACL SecurityComponentCoverage `json:"executable_directory_acl"`
	ExecutableResolution   SecurityComponentCoverage `json:"executable_resolution"`
	ServiceObject          SecurityComponentCoverage `json:"service_object"`
	RegistryMetadata       SecurityComponentCoverage `json:"registry_metadata"`
	RegistryACL            SecurityComponentCoverage `json:"registry_acl"`
	ServiceDLL             SecurityComponentCoverage `json:"service_dll"`
	RecoveryCommand        SecurityComponentCoverage `json:"recovery_command"`
	Account                SecurityComponentCoverage `json:"account"`
	PathIntegrity          SecurityComponentCoverage `json:"path_integrity"`
}

type Summary struct {
	Services                      int                            `json:"services"`
	InventoryFingerprint          string                         `json:"inventory_fingerprint"`
	Running                       int                            `json:"running"`
	Stopped                       int                            `json:"stopped"`
	RuntimeUnknown                int                            `json:"runtime_unknown"`
	Enabled                       int                            `json:"enabled"`
	Disabled                      int                            `json:"disabled"`
	StartModeUnknown              int                            `json:"start_mode_unknown"`
	Privileged                    int                            `json:"privileged"`
	WithRuntimePID                int                            `json:"with_runtime_pid"`
	WithExecutablePath            int                            `json:"with_executable_path"`
	WithConfigurationSource       int                            `json:"with_configuration_source"`
	AccountUnknown                int                            `json:"account_unknown"`
	WindowsSecurityAssessed       int                            `json:"windows_security_assessed"`
	UnquotedServicePaths          int                            `json:"unquoted_service_paths"`
	WritableExecutables           int                            `json:"writable_executables"`
	WritableDirectories           int                            `json:"writable_directories"`
	WeakServiceACLs               int                            `json:"weak_service_acls"`
	DangerousServiceACLs          int                            `json:"dangerous_service_acls"`
	ControlOnlyServiceACLs        int                            `json:"control_only_service_acls"`
	AdminServiceAccounts          int                            `json:"admin_service_accounts"`
	InteractiveServices           int                            `json:"interactive_services"`
	WeakRecoveryCommands          int                            `json:"weak_recovery_commands"`
	WindowsSecurityComplete       int                            `json:"windows_security_complete"`
	WindowsSecurityDegraded       int                            `json:"windows_security_degraded"`
	WindowsSecurityCoverage       WindowsServiceSecurityCoverage `json:"windows_security_coverage"`
	SystemdHardeningAssessed      int                            `json:"systemd_hardening_assessed"`
	SystemdNoNewPrivileges        int                            `json:"systemd_no_new_privileges"`
	SystemdProtectSystem          int                            `json:"systemd_protect_system"`
	SystemdProtectHome            int                            `json:"systemd_protect_home"`
	SystemdPrivateTmp             int                            `json:"systemd_private_tmp"`
	SystemdCapabilityBounded      int                            `json:"systemd_capability_bounded"`
	SystemdNamespaceRestricted    int                            `json:"systemd_namespace_restricted"`
	LaunchdHardeningAssessed      int                            `json:"launchd_hardening_assessed"`
	LaunchdDefinitionWritable     int                            `json:"launchd_definition_writable"`
	LaunchdExecutableWritable     int                            `json:"launchd_executable_writable"`
	LaunchdParentWritable         int                            `json:"launchd_parent_writable"`
	LaunchdDangerousEnvironment   int                            `json:"launchd_dangerous_environment"`
	LaunchdDangerousConfiguration int                            `json:"launchd_dangerous_configuration"`
	PathIntegrityAssessed         int                            `json:"path_integrity_assessed"`
	PathIntegrityComplete         int                            `json:"path_integrity_complete"`
	PathIntegrityDegraded         int                            `json:"path_integrity_degraded"`
	PrivilegedPathAssessed        int                            `json:"privileged_path_assessed"`
	PrivilegedWeakExecutable      int                            `json:"privileged_weak_executable"`
	PrivilegedWeakConfiguration   int                            `json:"privileged_weak_configuration"`
	PrivilegedWeakSearchPath      int                            `json:"privileged_weak_search_path"`
	ExposureClassified            int                            `json:"exposure_classified"`
	RemoteCapable                 int                            `json:"remote_capable"`
	ActiveRemoteCapable           int                            `json:"active_remote_capable"`
	LegacyRemoteCapable           int                            `json:"legacy_remote_capable"`
	InsecureRemoteCapable         int                            `json:"insecure_remote_capable"`
}

type Inventory struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Services         []Service              `json:"services"`
	Sources          []SourceStatus         `json:"sources"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
	}
	collectPlatform(ctx, &inv)
	collectPathIntegrity(ctx, &inv)
	inv.Services = normalize(inv.Services)
	classifyServiceExposure(inv.Services)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Services)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion {
		return fmt.Errorf("unexpected service schema %q", inv.Schema)
	}
	if inv.EvidenceSchema != evidence.SchemaVersion {
		return fmt.Errorf("unexpected evidence schema %q", inv.EvidenceSchema)
	}
	if inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected service collector identity %q/%q", inv.Collector, inv.CollectorVersion)
	}
	if strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" || inv.CollectedAt.IsZero() {
		return fmt.Errorf("service inventory platform, architecture, and timestamp are required")
	}
	if len(inv.Services) > maxServices {
		return fmt.Errorf("service inventory exceeds maximum record count")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, s := range inv.Services {
		if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Manager) == "" || strings.TrimSpace(s.Account) == "" || strings.TrimSpace(s.StartMode) == "" || strings.TrimSpace(s.RuntimeState) == "" || strings.TrimSpace(s.PrivilegeContext) == "" || strings.TrimSpace(s.ConfigurationSource) == "" || strings.TrimSpace(s.CollectionSource) == "" || s.Confidence == "" {
			return fmt.Errorf("service record %d is incomplete", i)
		}
		if s.RuntimePID < 0 {
			return fmt.Errorf("service record %d has invalid runtime pid", i)
		}
		if s.WindowsSecurity != nil {
			if inv.Platform != "windows" {
				return fmt.Errorf("service record %d contains Windows security metadata on platform %q", i, inv.Platform)
			}
			if err := s.WindowsSecurity.Validate(); err != nil {
				return fmt.Errorf("service record %d Windows security: %w", i, err)
			}
		}
		if s.SystemdHardening != nil {
			if inv.Platform != "linux" || !strings.EqualFold(s.Manager, "systemd") {
				return fmt.Errorf("service record %d contains systemd hardening metadata outside a Linux systemd service", i)
			}
			if err := s.SystemdHardening.Validate(); err != nil {
				return fmt.Errorf("service record %d systemd hardening: %w", i, err)
			}
		}
		if s.LaunchdHardening != nil {
			if inv.Platform != "darwin" || !strings.EqualFold(s.Manager, "launchd") {
				return fmt.Errorf("service record %d contains launchd hardening metadata outside a macOS launchd service", i)
			}
			if err := s.LaunchdHardening.Validate(); err != nil {
				return fmt.Errorf("service record %d launchd hardening: %w", i, err)
			}
		}
		if s.PathIntegrity != nil {
			if err := s.PathIntegrity.Validate(); err != nil {
				return fmt.Errorf("service record %d path integrity: %w", i, err)
			}
		}
		if s.Exposure != nil {
			if err := s.Exposure.Validate(); err != nil {
				return fmt.Errorf("service record %d exposure: %w", i, err)
			}
		}
		if _, ok := seen[s.ID]; ok {
			return fmt.Errorf("duplicate service id %q", s.ID)
		}
		seen[s.ID] = struct{}{}
		key := serviceSortKey(s)
		if last != "" && key < last {
			return fmt.Errorf("service records are not deterministically ordered")
		}
		last = key
	}
	if inv.Summary != summarize(inv.Services) {
		return fmt.Errorf("service summary does not match service records")
	}
	for i, src := range inv.Sources {
		if strings.TrimSpace(src.ID) == "" || strings.TrimSpace(src.Source) == "" || src.State == "" || src.ItemCount < 0 {
			return fmt.Errorf("service source %d is incomplete", i)
		}
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable && strings.TrimSpace(src.Reason) == "" {
			return fmt.Errorf("service source %q requires degradation reason", src.ID)
		}
	}
	return evidence.ValidateAll(inv.Evidence)
}

func normalize(in []Service) []Service {
	byID := make(map[string]Service, len(in))
	for _, s := range in {
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			continue
		}
		s.Manager = fallback(strings.ToLower(strings.TrimSpace(s.Manager)), "unknown")
		s.DisplayName = strings.TrimSpace(s.DisplayName)
		s.Description = strings.TrimSpace(s.Description)
		s.ServiceType = strings.TrimSpace(s.ServiceType)
		s.ExecutablePath = cleanExecutablePath(s.ExecutablePath)
		s.Executable = strings.TrimSpace(s.Executable)
		if s.Executable == "" && s.ExecutablePath != "" {
			s.Executable = filepath.Base(s.ExecutablePath)
		}
		s.Account = fallback(strings.TrimSpace(s.Account), "UNKNOWN")
		s.AccountGroup = strings.TrimSpace(s.AccountGroup)
		s.StartMode = normalizeWord(s.StartMode)
		s.RuntimeState = normalizeWord(s.RuntimeState)
		s.SubState = normalizeWordOptional(s.SubState)
		s.PrivilegeContext = normalizeWord(s.PrivilegeContext)
		s.DefinitionState = normalizeWordOptional(s.DefinitionState)
		s.DefinitionPath = strings.TrimSpace(s.DefinitionPath)
		s.ConfigurationSource = fallback(strings.TrimSpace(s.ConfigurationSource), "platform service manager")
		s.CollectionSource = fallback(strings.TrimSpace(s.CollectionSource), s.ConfigurationSource)
		if s.WindowsSecurity != nil {
			s.WindowsSecurity.normalize()
		}
		if s.SystemdHardening != nil {
			s.SystemdHardening.normalize()
		}
		if s.LaunchdHardening != nil {
			s.LaunchdHardening.normalize()
		}
		if s.PathIntegrity != nil {
			s.PathIntegrity.normalize()
		}
		if s.Exposure != nil {
			s.Exposure.normalize()
		}
		if s.Confidence == "" {
			s.Confidence = evidence.ConfidenceHigh
		}
		s.ID = stableID(s)
		if old, ok := byID[s.ID]; !ok || confidenceRank(s.Confidence) > confidenceRank(old.Confidence) {
			byID[s.ID] = s
		}
	}
	out := make([]Service, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return serviceSortKey(out[i]) < serviceSortKey(out[j]) })
	if len(out) > maxServices {
		out = out[:maxServices]
	}
	return out
}

func stableID(s Service) string {
	identity := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(s.Manager)),
		strings.ToLower(strings.TrimSpace(s.Name)),
		strings.ToLower(strings.TrimSpace(s.DefinitionPath)),
		strings.ToLower(strings.TrimSpace(s.ConfigurationSource)),
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	return "svc-" + hex.EncodeToString(sum[:10])
}

func serviceSortKey(s Service) string {
	return strings.ToLower(s.Manager) + "\x00" + strings.ToLower(s.Name) + "\x00" + strings.ToLower(s.DefinitionPath) + "\x00" + s.ID
}

func summarize(items []Service) Summary {
	s := Summary{Services: len(items), InventoryFingerprint: serviceInventoryFingerprint(items)}
	for _, item := range items {
		state := strings.ToUpper(item.RuntimeState)
		switch state {
		case "RUNNING", "ACTIVE", "STARTED":
			s.Running++
		case "STOPPED", "INACTIVE", "DEAD", "FAILED", "EXITED":
			s.Stopped++
		default:
			s.RuntimeUnknown++
		}
		mode := strings.ToUpper(item.StartMode)
		switch mode {
		case "ENABLED", "ENABLED_RUNTIME", "AUTOMATIC", "AUTO", "BOOT", "SYSTEM", "RUN_AT_LOAD", "KEEP_ALIVE":
			s.Enabled++
		case "DISABLED", "MASKED":
			s.Disabled++
		case "UNKNOWN", "UNAVAILABLE":
			s.StartModeUnknown++
		}
		switch strings.ToUpper(item.PrivilegeContext) {
		case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT":
			s.Privileged++
		}
		if item.RuntimePID > 0 {
			s.WithRuntimePID++
		}
		if item.ExecutablePath != "" {
			s.WithExecutablePath++
		}
		if item.ConfigurationSource != "" && !strings.EqualFold(item.ConfigurationSource, "UNKNOWN") {
			s.WithConfigurationSource++
		}
		if strings.EqualFold(item.Account, "UNKNOWN") || strings.TrimSpace(item.Account) == "" {
			s.AccountUnknown++
		}
		if ws := item.WindowsSecurity; ws != nil {
			s.WindowsSecurityAssessed++
			if ws.State == "COMPLETE" {
				s.WindowsSecurityComplete++
			} else {
				s.WindowsSecurityDegraded++
			}
			addWindowsServiceCoverage(&s.WindowsSecurityCoverage, item)
			if ws.UnquotedExecutablePath {
				s.UnquotedServicePaths++
			}
			if ws.ExecutableACL.BroadWriteGranted || ws.ServiceDLLACL.BroadWriteGranted {
				s.WritableExecutables++
			}
			if ws.ExecutableDirectoryACL.BroadWriteGranted || ws.ServiceDLLDirectoryACL.BroadWriteGranted {
				s.WritableDirectories++
			}
			if ws.ServiceACL.Weak {
				s.WeakServiceACLs++
			}
			if ws.ServiceACL.Dangerous {
				s.DangerousServiceACLs++
			}
			if ws.ServiceACL.ControlOnly {
				s.ControlOnlyServiceACLs++
			}
			if ws.AccountAdminState == "YES" && !windowsBuiltinServiceAccount(item.Account) {
				s.AdminServiceAccounts++
			}
			if ws.InteractiveProcess {
				s.InteractiveServices++
			}
			if ws.FailureCommandPresent && (ws.FailureExecutableUnquoted || ws.FailureExecutableACL.BroadWriteGranted || ws.FailureExecutableDirectoryACL.BroadWriteGranted) {
				s.WeakRecoveryCommands++
			}
		}
		if sh := item.SystemdHardening; sh != nil {
			s.SystemdHardeningAssessed++
			if sh.NoNewPrivileges == "YES" {
				s.SystemdNoNewPrivileges++
			}
			if sh.ProtectSystem == "STRICT" || sh.ProtectSystem == "FULL" || sh.ProtectSystem == "YES" {
				s.SystemdProtectSystem++
			}
			if sh.ProtectHome == "YES" || sh.ProtectHome == "READ_ONLY" || sh.ProtectHome == "TMPFS" {
				s.SystemdProtectHome++
			}
			if sh.PrivateTmp == "YES" || sh.PrivateTmp == "DISCONNECTED" {
				s.SystemdPrivateTmp++
			}
			if sh.CapabilityBoundingSetState == "RESTRICTED" || sh.CapabilityBoundingSetState == "EMPTY" {
				s.SystemdCapabilityBounded++
			}
			if sh.RestrictNamespacesState == "RESTRICTED" {
				s.SystemdNamespaceRestricted++
			}
		}
		if lh := item.LaunchdHardening; lh != nil {
			s.LaunchdHardeningAssessed++
			if lh.DefinitionBroadlyWritable {
				s.LaunchdDefinitionWritable++
			}
			if lh.ExecutableBroadlyWritable {
				s.LaunchdExecutableWritable++
			}
			if lh.ExecutableParentBroadlyWritable {
				s.LaunchdParentWritable++
			}
			if len(lh.DangerousEnvironmentKeys) > 0 {
				s.LaunchdDangerousEnvironment++
			}
			if len(lh.DangerousConfiguration) > 0 {
				s.LaunchdDangerousConfiguration++
			}
		}
		if ep := item.Exposure; ep != nil {
			if ep.State == "CLASSIFIED" {
				s.ExposureClassified++
			}
			if ep.RemoteCapable {
				s.RemoteCapable++
				if exposureActive(ep) {
					s.ActiveRemoteCapable++
				}
				if ep.Legacy {
					s.LegacyRemoteCapable++
				}
				if ep.InsecureByDesign {
					s.InsecureRemoteCapable++
				}
			}
		}
		if pi := item.PathIntegrity; pi != nil {
			s.PathIntegrityAssessed++
			if pi.State == "COMPLETE" {
				s.PathIntegrityComplete++
			} else {
				s.PathIntegrityDegraded++
			}
			if pi.Privileged {
				s.PrivilegedPathAssessed++
				if pi.Executable.LowerPrivilegeWritable || pi.ExecutableDirectory.LowerPrivilegeWritable {
					s.PrivilegedWeakExecutable++
				}
				if pi.Configuration.LowerPrivilegeWritable || pi.ConfigurationDirectory.LowerPrivilegeWritable {
					s.PrivilegedWeakConfiguration++
				}
				if pi.SearchPathWritable {
					s.PrivilegedWeakSearchPath++
				}
			}
		}
	}
	return s
}

func serviceInventoryFingerprint(items []Service) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" && strings.TrimSpace(item.Name) != "" {
			id = stableID(item)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return hex.EncodeToString(sum[:12])
}

func addWindowsServiceCoverage(c *WindowsServiceSecurityCoverage, item Service) {
	if c == nil || item.WindowsSecurity == nil {
		return
	}
	ws := item.WindowsSecurity
	baseState := "UNAVAILABLE"
	if strings.TrimSpace(item.DefinitionPath) != "" && strings.TrimSpace(item.ConfigurationSource) != "" && !strings.EqualFold(strings.TrimSpace(item.ConfigurationSource), "UNKNOWN") {
		baseState = "OBSERVED"
	}
	addSecurityCoverageState(&c.BaseConfiguration, baseState)
	if strings.TrimSpace(item.ExecutablePath) == "" {
		addSecurityCoverageState(&c.ExecutablePath, "UNAVAILABLE")
	} else {
		addSecurityCoverageState(&c.ExecutablePath, "OBSERVED")
	}
	addSecurityCoverageState(&c.ExecutableACL, ws.Components.ExecutableACL)
	addSecurityCoverageState(&c.ExecutableDirectoryACL, ws.Components.ExecutableDirectoryACL)
	if strings.TrimSpace(ws.ExecutableResolution) == "" || ws.ExecutableResolution == "UNAVAILABLE" {
		addSecurityCoverageState(&c.ExecutableResolution, "UNAVAILABLE")
	} else {
		addSecurityCoverageState(&c.ExecutableResolution, "OBSERVED")
	}
	addSecurityCoverageState(&c.ServiceObject, ws.Components.ServiceObject)
	addSecurityCoverageState(&c.RegistryMetadata, ws.Components.RegistryMetadata)
	addSecurityCoverageState(&c.RegistryACL, ws.Components.RegistryACL)
	addSecurityCoverageState(&c.ServiceDLL, combineSecurityComponentStates(ws.Components.ServiceDLLMetadata, ws.Components.ServiceDLLACL, ws.Components.ServiceDLLDirectoryACL))
	addSecurityCoverageState(&c.RecoveryCommand, combineSecurityComponentStates(ws.Components.RecoveryConfiguration, ws.Components.RecoveryExecutableACL, ws.Components.RecoveryExecutableDirACL))
	addSecurityCoverageState(&c.Account, ws.Components.Account)
	addSecurityCoverageState(&c.PathIntegrity, pathIntegrityCoverageState(item.PathIntegrity))
}

func addSecurityCoverageState(c *SecurityComponentCoverage, state string) {
	if c == nil {
		return
	}
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "OBSERVED", "COMPLETE":
		c.Observed++
	case "DEGRADED":
		c.Degraded++
	case "DENIED":
		c.Denied++
	case "NOT_APPLICABLE":
		c.NotApplicable++
	default:
		c.Unavailable++
	}
}

func pathIntegrityCoverageState(pi *ServicePathIntegrity) string {
	if pi == nil {
		return "UNAVAILABLE"
	}
	if pi.State == "COMPLETE" {
		return "OBSERVED"
	}
	return "DEGRADED"
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("service.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.count", len(inv.Services), "normalized service inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("service.inventory.summary", inv.Summary, "normalized service inventory", at, evidence.ConfidenceHigh),
	}
	if len(inv.Sources) == 0 {
		out = append(out, evidence.NewState("service.inventory.provider", evidence.StateUnavailable, "platform service manager", at, evidence.ConfidenceLow, "no supported local service provider returned a status"))
	}
	for _, src := range inv.Sources {
		key := "service.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "service provider did not return usable metadata")))
		}
	}
	for _, s := range inv.Services {
		out = append(out, evidence.NewObserved("service.item."+s.ID, s, s.CollectionSource, at, s.Confidence))
		if s.WindowsSecurity != nil {
			out = append(out, evidence.NewObserved("service.security."+s.ID, *s.WindowsSecurity, "Windows SCM/registry/NTFS security metadata", at, evidence.ConfidenceHigh))
		}
		if s.SystemdHardening != nil {
			confidence := s.Confidence
			if s.SystemdHardening.State == "COMPLETE" {
				confidence = evidence.ConfidenceHigh
			}
			out = append(out, evidence.NewObserved("service.systemd."+s.ID, *s.SystemdHardening, "systemd effective service hardening metadata", at, confidence))
		}
		if s.LaunchdHardening != nil {
			confidence := s.Confidence
			if s.LaunchdHardening.State == "COMPLETE" {
				confidence = evidence.ConfidenceHigh
			}
			out = append(out, evidence.NewObserved("service.launchd."+s.ID, *s.LaunchdHardening, "launchd plist + local filesystem hardening metadata", at, confidence))
		}
		if s.PathIntegrity != nil {
			confidence := s.Confidence
			if s.PathIntegrity.State == "COMPLETE" {
				confidence = evidence.ConfidenceHigh
			}
			out = append(out, evidence.NewObserved("service.path_integrity."+s.ID, *s.PathIntegrity, "service privilege-to-path correlation metadata", at, confidence))
		}
		if s.Exposure != nil {
			out = append(out, evidence.NewObserved("service.exposure."+s.ID, *s.Exposure, "deterministic local service-class classification", at, evidence.ConfidenceHigh))
		}
	}
	return out
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	if state == "" {
		state = evidence.StateUnavailable
	}
	src := SourceStatus{ID: strings.TrimSpace(id), State: state, Source: fallback(source, "platform service manager"), ItemCount: count, Reason: strings.TrimSpace(reason)}
	inv.Sources = append(inv.Sources, src)
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && strings.TrimSpace(reason) != "" {
		inv.Degraded = append(inv.Degraded, src.ID+": "+strings.TrimSpace(reason))
	}
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

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

func normalizeWordOptional(v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return normalizeWord(v)
}

func cleanExecutablePath(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "\"'"))
	if v == "" {
		return ""
	}
	return filepath.Clean(v)
}

func parsePID(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return n
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
	default:
		return 0
	}
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

package reliability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = "chimera.reliability/v1-phase116"
	EngineVersion = "reliability/phase116-v1"

	// MaxWorkers is the hard process-wide ceiling for rule-evaluation workers.
	// The CLI may request fewer workers, but never more.
	MaxWorkers = 64

	// Evidence limits bound memory consumption on unusually large or corrupt
	// hosts/providers. Providers are truncated deterministically rather than
	// allowing unbounded allocation growth.
	MaxEvidenceObservations = 250000
	MaxProviderEvidence     = 100000
	MaxDegradationReasons   = 4096

	// Stable local reads reject unexpectedly huge configuration/intelligence
	// inputs before JSON decoding allocates from attacker-controlled sizes.
	MaxConfigBytes               int64 = 8 << 20
	MaxIntelligencePointerBytes  int64 = 1 << 20
	MaxIntelligenceManifestBytes int64 = 64 << 20
	MaxIntelligenceAuxBytes      int64 = 64 << 20

	// CollectorTimeout remains the portable/default cooperative ceiling. Fix38
	// keeps Linux/macOS on this established contract while Windows providers use
	// explicit workload classes derived through CollectorContextFor.
	CollectorTimeout = 20 * time.Second

	// WindowsNormalAssessmentTimeout is the normal live Windows assessment
	// budget. Fix57 moves the release path away from the historical one-minute
	// command ceiling after repeat Windows 11 gates showed otherwise healthy late
	// providers starting with sub-second parent budgets. Provider-level ceilings
	// remain unchanged, so one slow provider still cannot consume the full scan.
	WindowsNormalAssessmentTimeout = 120 * time.Second

	// Windows provider budgets are intentionally bounded rather than globally
	// enlarged. The fourth live Windows 11 release-gate run showed network close
	// to the legacy 20s ceiling and services reaching it. Heavy providers receive
	// additional room while fast configuration providers stay tightly bounded.
	WindowsFastCollectorTimeout   = 12 * time.Second
	WindowsMediumCollectorTimeout = 26 * time.Second
	WindowsHeavyCollectorTimeout  = 36 * time.Second

	// Fix57 refuses to start expensive Windows providers when the parent
	// collection context is already too close to expiry to perform meaningful
	// work. This converts tail-of-scan starvation into explicit assessment-budget
	// exhaustion instead of misleading provider-exit/product-defect noise.
	WindowsDefaultCollectorMinimumStart = 3 * time.Second
	WindowsFastCollectorMinimumStart    = 2 * time.Second
	WindowsMediumCollectorMinimumStart  = 4 * time.Second
	WindowsHeavyCollectorMinimumStart   = 6 * time.Second

	// CollectorCleanupReserve is held back from an existing parent deadline so a
	// child provider cannot consume the exact remainder needed by merge, typed
	// validation, and cancellation cleanup.
	CollectorCleanupReserve = 750 * time.Millisecond

	// MaxCollectionWorkers bounds live-host provider concurrency independently
	// from rule evaluation. Fix44 keeps the portable/global ceiling at eight but
	// adds smaller Windows execution lanes so expensive management providers do
	// not saturate PowerShell/CIM/WMI/SCM simply because unrelated native work can
	// still run in parallel.
	MaxCollectionWorkers = 8

	// Fix44 Windows management-lane limits are deliberately below the global
	// collection worker ceiling. PowerShell/CIM work may overlap in pairs, heavy
	// security enrichment may overlap in pairs, and the two expensive lanes share
	// one aggregate cap of three. This preserves useful concurrency while avoiding
	// the eight-provider contention reproduced by the fifth Windows 11 host run.
	WindowsPowerShellCIMLaneLimit = 2
	WindowsHeavySecurityLaneLimit = 2
	WindowsManagementLaneLimit    = 3

	// Fix56 prevents a ready Windows management provider from remaining at the
	// tail of a busy lane indefinitely. Every complete aging interval improves
	// its effective admission priority by one point, up to a conservative cap.
	// This affects scheduling only; it does not extend the provider or assessment
	// deadline and is ignored on Linux/macOS.
	WindowsQueueAgingInterval = 1500 * time.Millisecond
	WindowsQueueAgingMaxBoost = 10

	// The collection soft deadline reserves the final fifth of a bounded scan
	// for rule evaluation/finalization, with practical bounds for longer scans.
	MinEvaluationReserve = 3 * time.Second
	MaxEvaluationReserve = 10 * time.Second
)

// ProviderBudgetClass describes expected live-host collector cost. The class is
// a scheduling/budget hint only; it never changes evidence semantics.
type ProviderBudgetClass string

const (
	ProviderBudgetDefault ProviderBudgetClass = "DEFAULT"
	ProviderBudgetFast    ProviderBudgetClass = "FAST"
	ProviderBudgetMedium  ProviderBudgetClass = "MEDIUM"
	ProviderBudgetHeavy   ProviderBudgetClass = "HEAVY"
)

// ProviderExecutionLane identifies the host resource family a collector mainly
// consumes. It is a scheduling hint only: evidence semantics and provider budget
// classes remain independent. Non-Windows platforms ignore lane limits.
type ProviderExecutionLane string

const (
	ProviderLaneDefault       ProviderExecutionLane = "DEFAULT"
	ProviderLaneNativeLight   ProviderExecutionLane = "NATIVE_LIGHT"
	ProviderLanePowerShellCIM ProviderExecutionLane = "POWERSHELL_CIM"
	ProviderLaneHeavySecurity ProviderExecutionLane = "HEAVY_SECURITY"
)

// NormalizeExecutionLane gives unspecified production/test collectors a safe
// non-management default. Every Windows production collector is explicitly
// classified by the app layer, but keeping DEFAULT portable avoids changing
// integrations that construct NamedEvidenceCollector directly.
func NormalizeExecutionLane(lane ProviderExecutionLane) ProviderExecutionLane {
	switch lane {
	case ProviderLaneNativeLight, ProviderLanePowerShellCIM, ProviderLaneHeavySecurity:
		return lane
	default:
		return ProviderLaneNativeLight
	}
}

// IsWindowsManagementLane reports whether a lane participates in the shared
// Windows management concurrency cap.
func IsWindowsManagementLane(lane ProviderExecutionLane) bool {
	lane = NormalizeExecutionLane(lane)
	return lane == ProviderLanePowerShellCIM || lane == ProviderLaneHeavySecurity
}

// ExecutionLaneLimit returns the per-lane admission limit for the current
// platform and configured collection worker count. Non-Windows behavior remains
// constrained only by the existing global collection-worker bound.
func ExecutionLaneLimit(platform string, lane ProviderExecutionLane, workers int) int {
	if workers < 1 {
		return 0
	}
	if strings.ToLower(strings.TrimSpace(platform)) != "windows" {
		return workers
	}
	switch NormalizeExecutionLane(lane) {
	case ProviderLanePowerShellCIM:
		if workers < WindowsPowerShellCIMLaneLimit {
			return workers
		}
		return WindowsPowerShellCIMLaneLimit
	case ProviderLaneHeavySecurity:
		if workers < WindowsHeavySecurityLaneLimit {
			return workers
		}
		return WindowsHeavySecurityLaneLimit
	default:
		return workers
	}
}

// WindowsManagementLimit bounds the aggregate of POWERSHELL_CIM and
// HEAVY_SECURITY work. It is intentionally independent of per-lane limits.
func WindowsManagementLimit(platform string, workers int) int {
	if workers < 1 {
		return 0
	}
	if strings.ToLower(strings.TrimSpace(platform)) != "windows" {
		return workers
	}
	if workers < WindowsManagementLaneLimit {
		return workers
	}
	return WindowsManagementLaneLimit
}

// BudgetDecision records the deadline actually granted to a provider/stage.
// Durations are kept internal; scan JSON converts the stable fields to
// milliseconds so live release-gate output can explain budget pressure.
type BudgetDecision struct {
	Class           ProviderBudgetClass
	Requested       time.Duration
	Applied         time.Duration
	ParentRemaining time.Duration
	Reserve         time.Duration
	CappedByParent  bool
}

// ProviderBudgetFor preserves the historical 20s collector contract on
// non-Windows platforms. Windows uses workload classes justified by real-host
// timing evidence rather than one global timeout.
func ProviderBudgetFor(platform string, class ProviderBudgetClass) time.Duration {
	if strings.ToLower(strings.TrimSpace(platform)) != "windows" {
		return CollectorTimeout
	}
	switch class {
	case ProviderBudgetFast:
		return WindowsFastCollectorTimeout
	case ProviderBudgetMedium:
		return WindowsMediumCollectorTimeout
	case ProviderBudgetHeavy:
		return WindowsHeavyCollectorTimeout
	default:
		return CollectorTimeout
	}
}

// CollectorStartMinimumFor returns the minimum parent collection time required
// before a Windows provider is allowed to begin. Non-Windows collectors retain
// the portable behavior and have no admission minimum.
func CollectorStartMinimumFor(platform string, class ProviderBudgetClass) time.Duration {
	if strings.ToLower(strings.TrimSpace(platform)) != "windows" {
		return 0
	}
	switch class {
	case ProviderBudgetFast:
		return WindowsFastCollectorMinimumStart
	case ProviderBudgetMedium:
		return WindowsMediumCollectorMinimumStart
	case ProviderBudgetHeavy:
		return WindowsHeavyCollectorMinimumStart
	default:
		return WindowsDefaultCollectorMinimumStart
	}
}

// CollectorStartAllowed reports whether a collector should enter its provider
// implementation at all. A false result is an assessment-budget decision, not a
// provider defect. The returned remaining/minimum values are suitable for
// structured scheduler diagnostics.
func CollectorStartAllowed(ctx context.Context, platform string, class ProviderBudgetClass) (allowed bool, remaining, minimum time.Duration) {
	minimum = CollectorStartMinimumFor(platform, class)
	if ctx == nil {
		return true, 0, minimum
	}
	if err := ctx.Err(); err != nil {
		return false, 0, minimum
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return true, 0, minimum
	}
	remaining = time.Until(deadline)
	if remaining <= 0 {
		return false, remaining, minimum
	}
	if minimum > 0 && remaining < minimum {
		return false, remaining, minimum
	}
	return true, remaining, minimum
}

// CollectorContextFor creates a provider context using the platform/class
// budget and reserves cleanup time whenever the parent itself is bounded.
func CollectorContextFor(parent context.Context, platform string, class ProviderBudgetClass) (context.Context, context.CancelFunc, BudgetDecision) {
	if parent == nil {
		parent = context.Background()
	}
	platform = strings.ToLower(strings.TrimSpace(platform))
	if class == "" {
		class = ProviderBudgetDefault
	}
	if platform != "windows" {
		// Preserve the exact Phase116 Linux/macOS behavior: a shorter parent
		// deadline is reused directly and no extra cleanup reserve is inserted.
		decision := BudgetDecision{Class: ProviderBudgetDefault, Requested: CollectorTimeout, Applied: CollectorTimeout}
		if deadline, ok := parent.Deadline(); ok {
			remaining := time.Until(deadline)
			decision.ParentRemaining = remaining
			if remaining <= CollectorTimeout {
				decision.Applied = remaining
				decision.CappedByParent = true
				return parent, func() {}, decision
			}
		}
		ctx, cancel := context.WithTimeout(parent, CollectorTimeout)
		return ctx, cancel, decision
	}
	return StageContext(parent, ProviderBudgetFor(platform, class), CollectorCleanupReserve, class)
}

// StageContext derives a bounded child stage from the remaining parent budget.
// It guarantees that a bounded child receives less than the parent's remaining
// time, leaving an explicit reserve for cleanup/aggregation.
func StageContext(parent context.Context, preferred, reserve time.Duration, class ProviderBudgetClass) (context.Context, context.CancelFunc, BudgetDecision) {
	if parent == nil {
		parent = context.Background()
	}
	if preferred <= 0 {
		preferred = CollectorTimeout
	}
	if reserve < 0 {
		reserve = 0
	}
	decision := BudgetDecision{Class: class, Requested: preferred, Applied: preferred, Reserve: reserve}
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		decision.ParentRemaining = remaining
		if remaining <= 0 {
			ctx, cancel := context.WithCancel(parent)
			cancel()
			decision.Applied = 0
			decision.CappedByParent = true
			return ctx, func() {}, decision
		}
		effectiveReserve := reserve
		if effectiveReserve >= remaining {
			effectiveReserve = remaining / 2
		}
		available := remaining - effectiveReserve
		if available <= 0 {
			available = remaining / 2
		}
		if available <= 0 {
			available = time.Millisecond
		}
		decision.Reserve = effectiveReserve
		if available < decision.Applied {
			decision.Applied = available
			decision.CappedByParent = true
		}
	}
	ctx, cancel := context.WithTimeout(parent, decision.Applied)
	return ctx, cancel, decision
}

type Contract struct {
	Schema                        string   `json:"schema"`
	Engine                        string   `json:"engine"`
	MaxWorkers                    int      `json:"max_workers"`
	MaxEvidenceObservations       int      `json:"max_evidence_observations"`
	MaxProviderEvidence           int      `json:"max_provider_evidence"`
	MaxDegradationReasons         int      `json:"max_degradation_reasons"`
	CollectorTimeout              string   `json:"collector_timeout"`
	StableConfigReadLimitBytes    int64    `json:"stable_config_read_limit_bytes"`
	StableIntelReadLimitBytes     int64    `json:"stable_intelligence_read_limit_bytes"`
	SupportedBuildTargets         []string `json:"supported_build_targets"`
	OrdinaryScanNetworkPolicy     string   `json:"ordinary_scan_network_policy"`
	ProviderPanicPolicy           string   `json:"provider_panic_policy"`
	InvalidProviderEvidencePolicy string   `json:"invalid_provider_evidence_policy"`
}

func CurrentContract() Contract {
	targets := []string{
		"darwin/amd64", "darwin/arm64",
		"linux/amd64", "linux/arm64",
		"windows/amd64", "windows/arm64",
	}
	sort.Strings(targets)
	return Contract{
		Schema:                        SchemaVersion,
		Engine:                        EngineVersion,
		MaxWorkers:                    MaxWorkers,
		MaxEvidenceObservations:       MaxEvidenceObservations,
		MaxProviderEvidence:           MaxProviderEvidence,
		MaxDegradationReasons:         MaxDegradationReasons,
		CollectorTimeout:              CollectorTimeout.String(),
		StableConfigReadLimitBytes:    MaxConfigBytes,
		StableIntelReadLimitBytes:     MaxIntelligenceManifestBytes,
		SupportedBuildTargets:         targets,
		OrdinaryScanNetworkPolicy:     "no direct outbound network APIs; intelligence refresh is explicit maintenance only",
		ProviderPanicPolicy:           "contain panic, mark provider PARTIAL, continue assessment with explicit degradation",
		InvalidProviderEvidencePolicy: "quarantine invalid/duplicate observations, preserve valid bounded evidence, mark provider degraded",
	}
}

func ValidateContract() error {
	c := CurrentContract()
	if c.Schema != SchemaVersion || c.Engine != EngineVersion {
		return errors.New("reliability schema/engine mismatch")
	}
	if MaxWorkers < 1 || MaxWorkers > 256 {
		return fmt.Errorf("max workers %d is outside safe bounds", MaxWorkers)
	}
	if MaxProviderEvidence < 1 || MaxProviderEvidence > MaxEvidenceObservations {
		return fmt.Errorf("provider evidence limit %d is invalid for global limit %d", MaxProviderEvidence, MaxEvidenceObservations)
	}
	if MaxDegradationReasons < 1 || CollectorTimeout <= 0 {
		return errors.New("degradation or collector deadline bounds are invalid")
	}
	if WindowsNormalAssessmentTimeout <= WindowsHeavyCollectorTimeout {
		return errors.New("Windows normal assessment timeout must exceed the heaviest provider budget")
	}
	if WindowsFastCollectorTimeout <= 0 || WindowsMediumCollectorTimeout <= WindowsFastCollectorTimeout || WindowsHeavyCollectorTimeout <= WindowsMediumCollectorTimeout {
		return errors.New("Windows collector budget classes are invalid")
	}
	if WindowsFastCollectorMinimumStart <= 0 || WindowsMediumCollectorMinimumStart < WindowsFastCollectorMinimumStart || WindowsHeavyCollectorMinimumStart < WindowsMediumCollectorMinimumStart {
		return errors.New("Windows collector admission minimums are invalid")
	}
	if WindowsHeavyCollectorMinimumStart >= WindowsHeavyCollectorTimeout {
		return errors.New("Windows heavy collector admission minimum exceeds its provider budget")
	}
	if CollectorCleanupReserve <= 0 || CollectorCleanupReserve >= WindowsFastCollectorTimeout {
		return errors.New("Windows collector cleanup reserve is invalid")
	}
	if WindowsPowerShellCIMLaneLimit < 1 || WindowsHeavySecurityLaneLimit < 1 || WindowsManagementLaneLimit < 1 {
		return errors.New("Windows collector execution-lane limits are invalid")
	}
	if WindowsPowerShellCIMLaneLimit > WindowsManagementLaneLimit || WindowsHeavySecurityLaneLimit > WindowsManagementLaneLimit {
		return errors.New("Windows per-lane collector limit exceeds management-lane limit")
	}
	if WindowsManagementLaneLimit > MaxCollectionWorkers {
		return errors.New("Windows management-lane limit exceeds collection-worker ceiling")
	}
	if MaxConfigBytes < 1024 || MaxIntelligenceManifestBytes < MaxConfigBytes {
		return errors.New("stable-read size limits are invalid")
	}
	if len(c.SupportedBuildTargets) != 6 {
		return fmt.Errorf("supported build target count=%d want=6", len(c.SupportedBuildTargets))
	}
	return nil
}

// BoundWorkers applies the hard concurrency ceiling and the number
// of available jobs. It never returns a negative worker count.
func BoundWorkers(requested, jobs int) int {
	if requested < 1 || jobs < 1 {
		return 0
	}
	if requested > MaxWorkers {
		requested = MaxWorkers
	}
	if requested > jobs {
		requested = jobs
	}
	return requested
}

// BoundCollectionWorkers applies the smaller live-provider concurrency ceiling
// while honoring the user's global max-workers request.
func BoundCollectionWorkers(requested, jobs int) int {
	if requested < 1 || jobs < 1 {
		return 0
	}
	if requested > MaxCollectionWorkers {
		requested = MaxCollectionWorkers
	}
	if requested > jobs {
		requested = jobs
	}
	return requested
}

// CollectionContext derives a soft collection deadline from the parent command
// deadline. The original parent context remains available to rule evaluation and
// finalization, preventing expensive collection from consuming the whole scan.
// The returned reserve is informational and zero when the parent has no deadline.
func CollectionContext(parent context.Context) (context.Context, func(), time.Duration) {
	if parent == nil {
		parent = context.Background()
	}
	deadline, ok := parent.Deadline()
	if !ok {
		ctx, cancel := context.WithCancel(parent)
		return ctx, cancel, 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}, 0
	}

	reserve := remaining / 5
	if remaining >= 15*time.Second && reserve < MinEvaluationReserve {
		reserve = MinEvaluationReserve
	}
	if reserve > MaxEvaluationReserve {
		reserve = MaxEvaluationReserve
	}
	if reserve <= 0 {
		reserve = remaining / 5
	}
	if reserve >= remaining {
		reserve = remaining / 2
	}
	softDeadline := deadline.Add(-reserve)
	ctx, cancel := context.WithDeadline(parent, softDeadline)
	return ctx, cancel, reserve
}

// CollectorContext preserves the Phase116 portable/default API. New Windows
// production collectors use CollectorContextFor so workload classes are explicit.
func CollectorContext(parent context.Context) (context.Context, func()) {
	ctx, cancel, _ := CollectorContextFor(parent, "", ProviderBudgetDefault)
	return ctx, cancel
}

// StableReadFile reads a single opened file descriptor, checks that the file
// did not change in place while being consumed, and retries once on change.
// Atomic rename by a writer is naturally safe because the open descriptor
// continues to refer to one immutable version.
func StableReadFile(path string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("path is required")
	}
	if maxBytes < 1 {
		return nil, errors.New("maxBytes must be positive")
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		b, changed, err := stableReadOnce(path, maxBytes)
		if err != nil {
			return nil, err
		}
		if !changed {
			return b, nil
		}
		last = fmt.Errorf("file changed during read")
	}
	return nil, fmt.Errorf("stable read %q: %w", path, last)
}

func stableReadOnce(path string, maxBytes int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if before.Size() > maxBytes {
		return nil, false, fmt.Errorf("file %q exceeds %d-byte safety limit", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, false, fmt.Errorf("file %q exceeds %d-byte safety limit", path, maxBytes)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	changed := before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime())
	return data, changed, nil
}

// LimitStrings deduplicates, sorts, and caps diagnostic strings so a corrupt
// provider cannot create an unbounded error list.
func LimitStrings(in []string, limit int) []string {
	if limit < 1 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
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
	if len(out) > limit {
		omitted := len(out) - limit
		out = append(append([]string(nil), out[:limit-1]...), fmt.Sprintf("%d additional degradation reasons omitted by safety limit", omitted+1))
	}
	return out
}

func PanicReason(provider string, recovered any) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "unknown"
	}
	// Do not serialize the panic value: provider errors may contain local paths,
	// command output, or secret-bearing content. Type is sufficient diagnostics.
	return fmt.Sprintf("provider %s panic contained (%T)", provider, recovered)
}

// RuntimeCollectorBudgetSummary describes the effective top-level provider
// deadline policy without changing the frozen Phase116 reliability JSON schema.
func RuntimeCollectorBudgetSummary() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("FAST=%s MEDIUM=%s HEAVY=%s cleanup-reserve=%s", WindowsFastCollectorTimeout, WindowsMediumCollectorTimeout, WindowsHeavyCollectorTimeout, CollectorCleanupReserve)
	}
	return "DEFAULT=" + CollectorTimeout.String()
}

func RuntimeTarget() string { return runtime.GOOS + "/" + runtime.GOARCH }

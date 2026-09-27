package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/assessmentdiff"
	"github.com/Nikolov999/chimera/internal/baseline"
	"github.com/Nikolov999/chimera/internal/cisalign"
	"github.com/Nikolov999/chimera/internal/config"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/exporter"
	"github.com/Nikolov999/chimera/internal/intelligence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/persistence"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/releasecontract"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/report"
	"github.com/Nikolov999/chimera/internal/scheduled"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
	"github.com/Nikolov999/chimera/internal/services"
	"github.com/Nikolov999/chimera/internal/suppression"
)

// SchemaVersion identifies the collector-health diagnostic contract.
const SchemaVersion = "chimera.doctor/v1"

type State string

const (
	StatePass          State = "PASS"
	StateWarn          State = "WARN"
	StateFail          State = "FAIL"
	StateNotApplicable State = "NOT_APPLICABLE"
)

type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	State    State  `json:"state"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
	Source   string `json:"source,omitempty"`
	Remedy   string `json:"remedy,omitempty"`
}

type Dependency struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
}

type DependencyCheck struct {
	ID          string       `json:"id"`
	Purpose     string       `json:"purpose"`
	State       State        `json:"state"`
	Required    bool         `json:"required"`
	Requirement string       `json:"requirement"`
	Providers   []Dependency `json:"providers"`
	Detail      string       `json:"detail"`
}

type ConfigHealth struct {
	State   State    `json:"state"`
	Sources []string `json:"sources,omitempty"`
	Detail  string   `json:"detail"`
}

type IntelligenceHealth struct {
	State              State      `json:"state"`
	Mode               string     `json:"mode"`
	Path               string     `json:"path,omitempty"`
	Version            string     `json:"version,omitempty"`
	Schema             string     `json:"schema,omitempty"`
	Digest             string     `json:"digest,omitempty"`
	RetrievedAt        *time.Time `json:"retrieved_at,omitempty"`
	Age                string     `json:"age,omitempty"`
	Freshness          string     `json:"freshness"`
	SourceCount        int        `json:"source_count,omitempty"`
	ProductCount       int        `json:"product_count,omitempty"`
	VulnerabilityCount int        `json:"vulnerability_count,omitempty"`
	LifecycleCount     int        `json:"lifecycle_count,omitempty"`
	Detail             string     `json:"detail"`
}

type Summary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Warn          int `json:"warn"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
}

type Result struct {
	Schema         string             `json:"doctor_schema"`
	CollectedAt    time.Time          `json:"collected_at"`
	State          string             `json:"state"`
	Platform       string             `json:"platform"`
	Architecture   string             `json:"architecture"`
	Supported      bool               `json:"supported"`
	Privilege      overview.Privilege `json:"privilege"`
	Config         ConfigHealth       `json:"config"`
	Intelligence   IntelligenceHealth `json:"intelligence"`
	Collectors     []Check            `json:"collectors"`
	Permissions    []Check            `json:"permissions"`
	PlatformChecks []Check            `json:"platform_checks"`
	Dependencies   []DependencyCheck  `json:"dependencies"`
	RulePacks      []Check            `json:"rule_packs"`
	Summary        Summary            `json:"summary"`
}

type Options struct {
	ExplicitConfig      string
	LoadedConfigSources []string
	Offline             bool
	RefreshIntelligence bool
}

// Run performs read-only local diagnostics for Chimera's currently implemented
// collectors and runtime requirements. It never installs dependencies, changes
// privileges, refreshes intelligence, or mutates configuration.
func Run(ctx context.Context, opts Options) Result {
	at := time.Now().UTC()
	supported := supportedPlatform(runtime.GOOS)
	o := overview.Collect(ctx)

	result := Result{
		Schema:         SchemaVersion,
		CollectedAt:    at,
		Platform:       runtime.GOOS,
		Architecture:   runtime.GOARCH,
		Supported:      supported,
		Privilege:      o.Privilege,
		Config:         checkConfig(opts),
		Intelligence:   checkIntelligence(opts, at),
		Collectors:     collectorChecks(ctx, o, supported),
		Permissions:    permissionChecks(o, opts.LoadedConfigSources),
		PlatformChecks: platformChecks(supported),
		Dependencies:   dependencyChecks(runtime.GOOS),
		RulePacks:      rulePackChecks(),
	}

	checks := make([]Check, 0, len(result.Collectors)+len(result.Permissions)+len(result.PlatformChecks)+len(result.Dependencies)+len(result.RulePacks)+2)
	checks = append(checks, result.Collectors...)
	checks = append(checks, result.Permissions...)
	checks = append(checks, result.PlatformChecks...)
	checks = append(checks, result.RulePacks...)
	checks = append(checks, Check{ID: "config.active", Category: "config", Title: "Configuration validity", State: result.Config.State, Required: true, Detail: result.Config.Detail, Source: strings.Join(result.Config.Sources, ", ")})
	checks = append(checks, Check{ID: "intelligence.freshness", Category: "intelligence", Title: "Vulnerability intelligence freshness", State: result.Intelligence.State, Required: false, Detail: result.Intelligence.Detail, Source: result.Intelligence.Path})
	for _, d := range result.Dependencies {
		checks = append(checks, Check{ID: d.ID, Category: "dependency", Title: d.Purpose, State: d.State, Required: d.Required, Detail: d.Detail, Source: dependencySource(d)})
	}
	result.Summary = summarize(checks)
	result.State = overallState(result.Summary, supported)
	return result
}

func rulePackChecks() []Check {
	checks := make([]Check, 0, 20)

	if err := releasecontract.ValidateCore(); err != nil {
		checks = append(checks, Check{
			ID: "release.v1", Category: "release", Title: "Chimera v1 public contract",
			State: StateFail, Required: true, Detail: "release-contract validation failed: " + err.Error(),
			Source: releasecontract.ContractVersion,
			Remedy: "Treat this build as pre-release until the frozen v1 version, rule catalog, schemas, profile semantics, and category coverage validate cleanly.",
		})
	} else {
		c := releasecontract.Current()
		checks = append(checks, Check{
			ID: "release.v1", Category: "release", Title: "Chimera v1 public contract",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("v%s %s contract frozen: %d rules, %d categories, %d profiles, catalog digest %s", c.ReleaseVersion, c.Platform, c.RuleCount, len(c.RuleCategories), len(c.Profiles), c.CatalogDigest),
			Source: releasecontract.ContractVersion,
		})
	}

	if err := reliability.ValidateContract(); err != nil {
		checks = append(checks, Check{
			ID: "runtime.phase116", Category: "reliability", Title: "Enterprise reliability and safety boundary",
			State: StateFail, Required: true, Detail: "reliability contract validation failed: " + err.Error(),
			Source: reliability.EngineVersion,
			Remedy: "Treat this build as unhealthy until worker, evidence, collector-deadline, stable-read, and supported-build limits validate cleanly.",
		})
	} else {
		c := reliability.CurrentContract()
		checks = append(checks, Check{
			ID: "runtime.phase116", Category: "reliability", Title: "Enterprise reliability and safety boundary",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("bounds validated: workers<=%d evidence<=%d provider<=%d collector budgets=%s target=%s", c.MaxWorkers, c.MaxEvidenceObservations, c.MaxProviderEvidence, reliability.RuntimeCollectorBudgetSummary(), reliability.RuntimeTarget()),
			Source: reliability.EngineVersion,
		})
	}

	engineDefs := assessment.RuleEngineV2Definitions()
	if err := assessment.ValidateRuleEngineV2Catalog(engineDefs); err != nil {
		checks = append(checks, Check{
			ID: "rules.engine-v2", Category: "rules", Title: "Declarative rule engine v2",
			State: StateFail, Required: true, Detail: "declarative rule-engine validation failed: " + err.Error(),
			Source: assessment.RuleEngineVersion,
			Remedy: "Treat this build as unhealthy until the declarative rule schema, predicates, outcomes, and compiled rule metadata validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "rules.engine-v2", Category: "rules", Title: "Declarative rule engine v2",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d executable-free declarative rule definition(s) validated and compiled", len(engineDefs)),
			Source: assessment.RuleEngineVersion,
		})
	}

	serviceRules := assessment.ServiceSchedulerRulePack()
	if err := assessment.ValidateServiceSchedulerRulePack(serviceRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.service-scheduler", Category: "rules", Title: "Service & scheduler rule pack",
			State: StateFail, Required: true,
			Detail: "stable rule-pack contract validation failed: " + err.Error(),
			Source: assessment.ServiceSchedulerPackVersion,
			Remedy: "Treat this build as unhealthy until the frozen service/scheduler rule-ID contract is restored.",
		})
	} else {
		serviceCount, scheduledCount := 0, 0
		for _, rule := range serviceRules {
			switch rule.Category {
			case "service":
				serviceCount++
			case "scheduled":
				scheduledCount++
			}
		}
		checks = append(checks, Check{
			ID: "rules.service-scheduler", Category: "rules", Title: "Service & scheduler rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable rule(s) validated: %d service and %d scheduled-execution", len(serviceRules), serviceCount, scheduledCount),
			Source: assessment.ServiceSchedulerPackVersion,
		})
	}

	networkRules := assessment.NetworkExposureRulePack()
	if err := assessment.ValidateNetworkExposureRulePack(networkRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.network-firewall", Category: "rules", Title: "Network & firewall exposure rule pack",
			State: StateFail, Required: true,
			Detail: "stable rule-pack contract validation failed: " + err.Error(),
			Source: assessment.NetworkExposurePackVersion,
			Remedy: "Treat this build as unhealthy until the frozen network/firewall rule-ID contract is restored.",
		})
	} else {
		networkCount, firewallCount := 0, 0
		for _, rule := range networkRules {
			switch rule.Category {
			case "network":
				networkCount++
			case "firewall":
				firewallCount++
			}
		}
		checks = append(checks, Check{
			ID: "rules.network-firewall", Category: "rules", Title: "Network & firewall exposure rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable rule(s) validated: %d network and %d firewall", len(networkRules), networkCount, firewallCount),
			Source: assessment.NetworkExposurePackVersion,
		})
	}

	identityRules := assessment.IdentityAuthenticationRulePack()
	if err := assessment.ValidateIdentityAuthenticationRulePack(identityRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.identity-authentication", Category: "rules", Title: "Identity & authentication rule pack",
			State: StateFail, Required: true,
			Detail: "stable rule-pack contract validation failed: " + err.Error(),
			Source: assessment.IdentityAuthenticationPackVersion,
			Remedy: "Treat this build as unhealthy until the frozen identity/authentication rule-ID contract is restored.",
		})
	} else {
		checks = append(checks, Check{
			ID: "rules.identity-authentication", Category: "rules", Title: "Identity & authentication rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable CHM-ID rule(s) validated across local account and authentication posture", len(identityRules)),
			Source: assessment.IdentityAuthenticationPackVersion,
		})
	}

	filesystemStorageRules := assessment.FilesystemStorageRulePack()
	if err := assessment.ValidateFilesystemStorageRulePack(filesystemStorageRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.filesystem-storage", Category: "rules", Title: "Filesystem & storage rule pack",
			State: StateFail, Required: true,
			Detail: "stable rule-pack contract validation failed: " + err.Error(),
			Source: assessment.FilesystemStoragePackVersion,
			Remedy: "Treat this build as unhealthy until the frozen filesystem/storage rule-ID contract is restored.",
		})
	} else {
		filesystemCount, storageCount := 0, 0
		for _, rule := range filesystemStorageRules {
			switch rule.Category {
			case "filesystem":
				filesystemCount++
			case "storage":
				storageCount++
			}
		}
		checks = append(checks, Check{
			ID: "rules.filesystem-storage", Category: "rules", Title: "Filesystem & storage rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable rule(s) validated: %d filesystem and %d storage", len(filesystemStorageRules), filesystemCount, storageCount),
			Source: assessment.FilesystemStoragePackVersion,
		})
	}

	persistenceSecretRules := assessment.PersistenceSecretRulePack()
	if err := assessment.ValidatePersistenceSecretRulePack(persistenceSecretRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.persistence-secrets", Category: "rules", Title: "Persistence & secret-storage rule pack",
			State: StateFail, Required: true,
			Detail: "stable rule-pack contract validation failed: " + err.Error(),
			Source: assessment.PersistenceSecretPackVersion,
			Remedy: "Treat this build as unhealthy until the frozen persistence/secret-storage rule-ID contract is restored.",
		})
	} else {
		persistenceCount, secretCount := 0, 0
		for _, rule := range persistenceSecretRules {
			switch rule.Category {
			case "persistence":
				persistenceCount++
			case "secrets":
				secretCount++
			}
		}
		checks = append(checks, Check{
			ID: "rules.persistence-secrets", Category: "rules", Title: "Persistence & secret-storage rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable rule(s) validated: %d persistence and %d secret-storage", len(persistenceSecretRules), persistenceCount, secretCount),
			Source: assessment.PersistenceSecretPackVersion,
		})
	}

	crossDomainRules := assessment.CrossDomainCorrelationRules()
	if err := assessment.ValidateCrossDomainCorrelationRulePack(crossDomainRules); err != nil {
		checks = append(checks, Check{
			ID: "rules.cross-domain", Category: "rules", Title: "Cross-domain correlation rule pack",
			State: StateFail, Required: true,
			Detail: "stable correlation rule-pack contract validation failed: " + err.Error(),
			Source: assessment.CrossDomainCorrelationPackVersion,
			Remedy: "Treat this build as unhealthy until the frozen correlation rule-ID contract is restored.",
		})
	} else {
		checks = append(checks, Check{
			ID: "rules.cross-domain", Category: "rules", Title: "Cross-domain correlation rule pack",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d stable cross-domain correlation rule(s) validated across process, service, filesystem, network, and identity evidence", len(crossDomainRules)),
			Source: assessment.CrossDomainCorrelationPackVersion,
		})
	}

	if err := profile.ValidateEnterprisePolicyContract(assessment.ImplementedRules()); err != nil {
		checks = append(checks, Check{
			ID: "profiles.enterprise", Category: "rules", Title: "Custom enterprise profile engine",
			State: StateFail, Required: true, Detail: "enterprise-profile validation failed: " + err.Error(),
			Source: profile.EnterprisePolicyVersion,
			Remedy: "Treat this build as unhealthy until custom-profile inheritance, policy rule generation, and profile validation are deterministic.",
		})
	} else {
		checks = append(checks, Check{
			ID: "profiles.enterprise", Category: "rules", Title: "Custom enterprise profile engine",
			State: StatePass, Required: true,
			Detail: "custom-profile inheritance and generated expected-service/expected-port policy rules validated",
			Source: profile.EnterprisePolicyVersion,
		})
	}

	if err := cisalign.ValidateCatalog(assessment.ImplementedRules()); err != nil {
		checks = append(checks, Check{
			ID: "baseline.cis-inspired", Category: "rules", Title: "CIS-inspired control-concept mapping",
			State: StateFail, Required: true, Detail: "mapping validation failed: " + err.Error(),
			Source: cisalign.CatalogVersion,
			Remedy: "Treat this build as unhealthy until every selected security rule maps deterministically to a valid benchmark-neutral concept without certification claims.",
		})
	} else {
		checks = append(checks, Check{
			ID: "baseline.cis-inspired", Category: "rules", Title: "CIS-inspired control-concept mapping",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%d %s-mapped security rule(s) validated across %d benchmark-neutral concept(s); 5 observability-only core rules intentionally remain unmapped", len(cisalign.MappingsForPlatform(runtime.GOOS)), runtime.GOOS, len(cisalign.Concepts())),
			Source: cisalign.CatalogVersion,
		})
	}

	if err := suppression.ValidateEngineContract(assessment.ImplementedRules()); err != nil {
		checks = append(checks, Check{
			ID: "findings.suppressions", Category: "rules", Title: "Finding suppression policy engine",
			State: StateFail, Required: true, Detail: "suppression validation failed: " + err.Error(),
			Source: suppression.SchemaVersion,
			Remedy: "Treat this build as unhealthy until expiry, audit metadata, exact rule/object matching, and evidence-preservation semantics validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "findings.suppressions", Category: "rules", Title: "Finding suppression policy engine",
			State: StatePass, Required: true,
			Detail: "rule/object suppression, mandatory ownership/reason/expiry, audit ledger, and raw-evidence preservation validated",
			Source: suppression.SchemaVersion,
		})
	}

	if err := assessmentdiff.ValidateContract(); err != nil {
		checks = append(checks, Check{
			ID: "assessment.diff", Category: "rules", Title: "Assessment diff engine",
			State: StateFail, Required: true, Detail: "assessment-diff contract validation failed: " + err.Error(),
			Source: assessmentdiff.SchemaVersion,
			Remedy: "Treat this build as unhealthy until same-host validation, deterministic classification, scope tracking, suppression tracking, and evidence-change semantics validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "assessment.diff", Category: "rules", Title: "Assessment diff engine",
			State: StatePass, Required: true,
			Detail: "deterministic same-host assessment diff contract validated",
			Source: assessmentdiff.SchemaVersion,
		})
	}

	if err := prioritization.ValidateEngineContract(); err != nil {
		checks = append(checks, Check{
			ID: "assessment.prioritization", Category: "rules", Title: "Risk prioritization engine",
			State: StateFail, Required: true, Detail: "risk-prioritization contract validation failed: " + err.Error(),
			Source: prioritization.EngineVersion,
			Remedy: "Treat this build as unhealthy until deterministic scoring, context factors, raw-severity separation, and ranking semantics validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "assessment.prioritization", Category: "rules", Title: "Risk prioritization engine",
			State: StatePass, Required: true, Detail: "deterministic finding and vulnerability prioritization contract validated",
			Source: prioritization.EngineVersion,
		})
	}

	if err := remediation.ValidateEngineContract(); err != nil {
		checks = append(checks, Check{
			ID: "assessment.remediation", Category: "rules", Title: "Terminal remediation view",
			State: StateFail, Required: true, Detail: "remediation-view contract validation failed: " + err.Error(),
			Source: remediation.EngineVersion,
			Remedy: "Treat this build as unhealthy until priority/category/component grouping, suppression handling, UNKNOWN handling, and guidance preservation validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "assessment.remediation", Category: "rules", Title: "Terminal remediation view",
			State: StatePass, Required: true, Detail: "deterministic read-only remediation grouping and guidance contract validated",
			Source: remediation.EngineVersion,
		})
	}

	if reportErr, exportErr := report.ValidateEngineContract(), exporter.ValidateEngineContract(); reportErr != nil || exportErr != nil {
		detail := "report/export contract validation failed"
		if reportErr != nil {
			detail += ": report: " + reportErr.Error()
		}
		if exportErr != nil {
			detail += ": export: " + exportErr.Error()
		}
		checks = append(checks, Check{
			ID: "assessment.reporting", Category: "rules", Title: "Enterprise report and export",
			State: StateFail, Required: true, Detail: detail,
			Source: report.EngineVersion + "+" + exporter.EngineVersion,
			Remedy: "Treat this build as unhealthy until enterprise report provenance and JSON/text/CSV/SARIF export contracts validate cleanly.",
		})
	} else {
		checks = append(checks, Check{
			ID: "assessment.reporting", Category: "rules", Title: "Enterprise report and export",
			State: StatePass, Required: true, Detail: "enterprise report plus banner-free JSON, structured-text, CSV, and SARIF export contracts validated",
			Source: report.EngineVersion + "+" + exporter.EngineVersion,
		})
	}

	if err := baseline.ValidateEngineContract(); err != nil {
		checks = append(checks, Check{
			ID: "baseline.engine", Category: "rules", Title: "Profile-driven baseline engine",
			State: StateFail, Required: true, Detail: "baseline-engine contract validation failed: " + err.Error(),
			Source: baseline.EngineVersion,
			Remedy: "Treat this build as unhealthy until every built-in profile deterministically covers the complete implemented rule catalog.",
		})
	} else {
		checks = append(checks, Check{
			ID: "baseline.engine", Category: "rules", Title: "Profile-driven baseline engine",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("baseline contract validated across %d built-in profile(s) and %d implemented rule(s)", len(profile.Catalog()), len(assessment.ImplementedRules())),
			Source: baseline.EngineVersion,
		})
	}

	return checks
}

func supportedPlatform(goos string) bool {
	switch goos {
	case "linux", "windows", "darwin":
		return true
	default:
		return false
	}
}

func platformChecks(supported bool) []Check {
	if supported {
		return []Check{{
			ID: "platform.support", Category: "platform", Title: "Platform support",
			State: StatePass, Required: true,
			Detail: fmt.Sprintf("%s/%s has a native Chimera overview collector", runtime.GOOS, runtime.GOARCH),
			Source: "Go runtime + build-tagged collector",
		}}
	}
	return []Check{{
		ID: "platform.support", Category: "platform", Title: "Platform support",
		State: StateFail, Required: true,
		Detail: fmt.Sprintf("%s/%s does not have a native Chimera collector", runtime.GOOS, runtime.GOARCH),
		Source: "Go runtime + build-tagged collector", Remedy: "Run Chimera on Windows, Linux, or macOS.",
	}}
}

func collectorChecks(ctx context.Context, o overview.Overview, supported bool) []Check {
	_ = ctx
	checks := []Check{}
	if !supported {
		checks = append(checks, Check{ID: "collector.overview", Category: "collector", Title: "Live-host overview collector", State: StateFail, Required: true, Detail: "platform-specific overview collector is unsupported", Source: "internal/overview"})
		return checks
	}
	if err := evidence.ValidateAll(o.Evidence); err != nil {
		checks = append(checks, Check{ID: "collector.overview", Category: "collector", Title: "Live-host overview collector", State: StateFail, Required: true, Detail: "collector emitted an invalid normalized evidence batch: " + err.Error(), Source: "internal/overview", Remedy: "Treat this build as unhealthy until the collector/evidence contract mismatch is corrected."})
		return checks
	}
	state := StatePass
	detail := fmt.Sprintf("collector produced %d valid normalized observations", len(o.Evidence))
	if len(o.Degraded) > 0 {
		state = StateWarn
		detail += fmt.Sprintf(" with %d degradation reason(s): %s", len(o.Degraded), strings.Join(o.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.overview", Category: "collector", Title: "Live-host overview collector", State: state, Required: true, Detail: detail, Source: "internal/overview + chimera.evidence/v1"})

	sv := services.Collect(ctx)
	serviceState := StatePass
	serviceDetail := fmt.Sprintf("collector produced %d service record(s), %d provider status record(s), and %d valid normalized observations", len(sv.Services), len(sv.Sources), len(sv.Evidence))
	if err := sv.Validate(); err != nil {
		serviceState = StateFail
		serviceDetail = "service collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(sv.Degraded) > 0 {
		serviceState = StateWarn
		serviceDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(sv.Degraded), strings.Join(sv.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.services", Category: "collector", Title: "Service security inventory collector", State: serviceState, Required: true, Detail: serviceDetail, Source: "internal/services + chimera.services/v1 + chimera.evidence/v1"})

	sch := scheduled.Collect(ctx)
	scheduledState := StatePass
	scheduledDetail := fmt.Sprintf("collector produced %d scheduled-execution record(s), %d provider status record(s), and %d valid normalized observations", len(sch.Entries), len(sch.Sources), len(sch.Evidence))
	if err := sch.Validate(); err != nil {
		scheduledState = StateFail
		scheduledDetail = "scheduled-execution collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(sch.Degraded) > 0 {
		scheduledState = StateWarn
		scheduledDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(sch.Degraded), strings.Join(sch.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.scheduled", Category: "collector", Title: "Scheduled execution inventory collector", State: scheduledState, Required: true, Detail: scheduledDetail, Source: "internal/scheduled + chimera.scheduled/v2 + chimera.evidence/v1"})

	ac := accounts.Collect(ctx)
	per := persistence.CollectFrom(ctx, sv, sch, ac)
	persistenceState := StatePass
	persistenceDetail := fmt.Sprintf("collector composed %d persistence point(s), %d provider status record(s), and %d valid normalized observations", len(per.Entries), len(per.Sources), len(per.Evidence))
	if err := per.Validate(); err != nil {
		persistenceState = StateFail
		persistenceDetail = "persistence collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(per.Degraded) > 0 {
		persistenceState = StateWarn
		persistenceDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(per.Degraded), strings.Join(per.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.persistence", Category: "collector", Title: "Persistence inventory collector", State: persistenceState, Required: true, Detail: persistenceDetail, Source: "internal/persistence + chimera.persistence/v1 + chimera.evidence/v1"})

	sec := secretinv.Collect(ctx)
	secretState := StatePass
	secretDetail := fmt.Sprintf("collector produced %d secret-bearing path record(s), %d provider status record(s), and %d valid normalized observations with redacted plaintext indicators, private-key posture, and cloud/developer credential-file posture", len(sec.Records), len(sec.Sources), len(sec.Evidence))
	if err := sec.Validate(); err != nil {
		secretState = StateFail
		secretDetail = "secret-storage collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(sec.Degraded) > 0 {
		secretState = StateWarn
		secretDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(sec.Degraded), strings.Join(sec.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.secret-storage", Category: "collector", Title: "Secret-storage posture inventory collector", State: secretState, Required: true, Detail: secretDetail, Source: "internal/secrets + chimera.secrets/v1 + chimera.evidence/v1"})

	nv := netinv.Collect(ctx)
	networkState := StatePass
	networkDetail := fmt.Sprintf("collector produced %d listening/bound endpoint record(s), %d provider status record(s), and %d valid normalized observations", len(nv.Endpoints), len(nv.Sources), len(nv.Evidence))
	if err := nv.Validate(); err != nil {
		networkState = StateFail
		networkDetail = "network collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(nv.Degraded) > 0 {
		networkState = StateWarn
		networkDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(nv.Degraded), strings.Join(nv.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.network", Category: "collector", Title: "Local listener/exposure inventory collector", State: networkState, Required: true, Detail: networkDetail, Source: "internal/network + chimera.network/v1 + chimera.evidence/v1"})

	accountState := StatePass
	accountDetail := fmt.Sprintf("collector produced %d local account record(s), %d group record(s), %d provider status record(s), and %d valid normalized observations", len(ac.Accounts), len(ac.Groups), len(ac.Sources), len(ac.Evidence))
	if err := ac.Validate(); err != nil {
		accountState = StateFail
		accountDetail = "account collector emitted an invalid inventory/evidence contract: " + err.Error()
	} else if len(ac.Degraded) > 0 {
		accountState = StateWarn
		accountDetail += fmt.Sprintf(" with %d degradation reason(s): %s", len(ac.Degraded), strings.Join(ac.Degraded, "; "))
	}
	checks = append(checks, Check{ID: "collector.accounts", Category: "collector", Title: "Local account and authentication posture collector", State: accountState, Required: true, Detail: accountDetail, Source: "internal/accounts + chimera.accounts/v1 + chimera.evidence/v1"})
	return checks
}

func permissionChecks(o overview.Overview, sources []string) []Check {
	checks := []Check{}
	if strings.EqualFold(strings.TrimSpace(o.Privilege.Level), "unknown") || strings.TrimSpace(o.Privilege.Level) == "" {
		checks = append(checks, Check{ID: "permissions.execution-context", Category: "permissions", Title: "Execution privilege context", State: StateWarn, Required: true, Detail: "effective execution privilege could not be determined", Source: o.Privilege.DetectionSource})
	} else {
		detail := fmt.Sprintf("collection tier=%s; level=%s; elevated=%t", o.Privilege.CollectionTier, o.Privilege.Level, o.Privilege.Elevated)
		checks = append(checks, Check{ID: "permissions.execution-context", Category: "permissions", Title: "Execution privilege context", State: StatePass, Required: true, Detail: detail, Source: o.Privilege.DetectionSource})
	}

	denied := 0
	for _, obs := range o.Evidence {
		if obs.State == evidence.StateDenied {
			denied++
		}
	}
	if denied == 0 {
		checks = append(checks, Check{ID: "permissions.evidence-access", Category: "permissions", Title: "Current evidence access", State: StatePass, Required: false, Detail: "no normalized overview evidence was denied by current permissions", Source: "chimera.evidence/v1"})
	} else {
		checks = append(checks, Check{ID: "permissions.evidence-access", Category: "permissions", Title: "Current evidence access", State: StateWarn, Required: false, Detail: fmt.Sprintf("%d normalized overview observation(s) were denied by current permissions", denied), Source: "chimera.evidence/v1", Remedy: "Elevation is optional; use it only when deeper local evidence is required and authorized."})
	}

	if o.Privilege.DeeperEvidenceAvailable && !o.Privilege.Elevated {
		checks = append(checks, Check{ID: "permissions.deeper-evidence", Category: "permissions", Title: "Optional deeper evidence", State: StateWarn, Required: false, Detail: fmt.Sprintf("standard collection is supported; %d evidence class(es) may be deeper with authorized elevation", len(o.Privilege.DeeperEvidence)), Source: "chimera.privilege/v1", Remedy: "Re-run elevated only when the assessment requires those evidence classes; Chimera never elevates itself."})
	} else {
		checks = append(checks, Check{ID: "permissions.deeper-evidence", Category: "permissions", Title: "Optional deeper evidence", State: StatePass, Required: false, Detail: "current collection tier does not require a privilege warning", Source: "chimera.privilege/v1"})
	}

	for _, source := range uniqueSorted(sources) {
		state := StatePass
		detail := "loaded configuration source remains readable"
		remedy := ""
		f, err := os.Open(source)
		if err != nil {
			state = StateWarn
			detail = "loaded configuration source is no longer readable: " + err.Error()
			remedy = "Restore read access or select a readable configuration with --config."
		} else {
			_ = f.Close()
		}
		checks = append(checks, Check{ID: "permissions.config." + stablePathID(source), Category: "permissions", Title: "Configuration source access", State: state, Required: false, Detail: detail, Source: source, Remedy: remedy})
	}
	return checks
}

func checkConfig(opts Options) ConfigHealth {
	result, err := config.Load(opts.ExplicitConfig)
	if err != nil {
		return ConfigHealth{State: StateFail, Sources: append([]string(nil), opts.LoadedConfigSources...), Detail: "configuration validation failed: " + err.Error()}
	}
	sources := uniqueSorted(result.Sources)
	if len(sources) == 0 {
		return ConfigHealth{State: StatePass, Detail: "built-in defaults are valid; no configuration file is currently loaded"}
	}
	return ConfigHealth{State: StatePass, Sources: sources, Detail: fmt.Sprintf("%d configuration source(s) parsed with strict unknown-field and value validation", len(sources))}
}

func checkIntelligence(opts Options, now time.Time) IntelligenceHealth {
	mode := "local-pinned"
	if opts.Offline {
		mode = "offline-local-pinned"
	}
	if opts.RefreshIntelligence {
		mode = "refresh-requested-local-only"
	}

	session := intelligence.Open(intelligence.LoadOptions{Offline: opts.Offline, Now: now})
	if err := session.Error(); err != nil {
		path := strings.TrimSpace(os.Getenv(intelligence.EnvDirectory))
		if path != "" {
			if abs, absErr := filepath.Abs(path); absErr == nil {
				path = filepath.Join(abs, "manifest.json")
			}
		}
		return IntelligenceHealth{
			State: StateFail, Mode: mode, Path: path, Freshness: "UNAVAILABLE",
			Detail: "configured vulnerability-intelligence snapshot failed strict local validation: " + err.Error(),
		}
	}

	meta := session.Loaded.Metadata
	status := session.Status
	retrieved := meta.RetrievedAt.UTC()
	state := StatePass
	if status.Freshness == "STALE" {
		state = StateWarn
	}
	detail := fmt.Sprintf("validated %s intelligence snapshot %s with %d product mappings, %d vulnerability records, and %d lifecycle records; assessment policy is read-only and network-disabled", meta.State, meta.Version, meta.ProductCount, meta.VulnerabilityCount, meta.LifecycleCount)
	if opts.RefreshIntelligence {
		detail += "; refresh is maintenance-scoped and is only performed by the intelligence command"
	}
	return IntelligenceHealth{
		State: state, Mode: mode, Path: meta.Path, Version: meta.Version, Schema: meta.Schema,
		Digest: meta.Digest, RetrievedAt: &retrieved, Age: status.Age.Truncate(time.Second).String(), Freshness: status.Freshness,
		SourceCount: meta.SourceCount, ProductCount: meta.ProductCount, VulnerabilityCount: meta.VulnerabilityCount, LifecycleCount: meta.LifecycleCount, Detail: detail,
	}
}

type dependencySpec struct {
	ID       string
	Purpose  string
	Required bool
	AnyOf    []string
	Paths    []string
}

func dependencyChecks(goos string) []DependencyCheck {
	specs := dependencySpecs(goos)
	out := make([]DependencyCheck, 0, len(specs))
	for _, spec := range specs {
		providers := make([]Dependency, 0, len(spec.AnyOf)+len(spec.Paths))
		available := 0
		for _, name := range spec.AnyOf {
			p, err := exec.LookPath(name)
			ok := err == nil
			if ok {
				available++
			}
			providers = append(providers, Dependency{Name: name, Available: ok, Path: p})
		}
		for _, path := range spec.Paths {
			ok := executablePath(path)
			if ok {
				available++
			}
			providers = append(providers, Dependency{Name: filepath.Base(path), Available: ok, Path: path})
		}
		state := StatePass
		detail := fmt.Sprintf("%d/%d provider(s) available", available, len(providers))
		if available == 0 {
			if spec.Required {
				state = StateFail
				detail += "; required provider set is unavailable"
			} else {
				state = StateWarn
				detail += "; optional evidence will degrade"
			}
		}
		out = append(out, DependencyCheck{ID: spec.ID, Purpose: spec.Purpose, State: state, Required: spec.Required, Requirement: "at least one provider", Providers: providers, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func dependencySpecs(goos string) []dependencySpec {
	switch goos {
	case "linux":
		return []dependencySpec{
			{ID: "dependency.firewall-provider", Purpose: "Host firewall observation provider", AnyOf: []string{"nft", "iptables", "ufw", "firewall-cmd"}},
			{ID: "dependency.kernel-provider", Purpose: "Kernel version provider", AnyOf: []string{"uname"}},
			{ID: "dependency.service-manager", Purpose: "systemd runtime service metadata provider", AnyOf: []string{"systemctl"}},
		}
	case "darwin":
		return []dependencySpec{
			{ID: "dependency.core-os-provider", Purpose: "Core macOS metadata providers", Required: true, AnyOf: []string{"sw_vers", "sysctl"}},
			{ID: "dependency.security-control-provider", Purpose: "macOS security-control providers", AnyOf: []string{"csrutil", "spctl", "fdesetup"}, Paths: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw"}},
			{ID: "dependency.launchd-provider", Purpose: "launchd service definition/runtime providers", Required: true, AnyOf: []string{"launchctl", "plutil"}},
			{ID: "dependency.network-provider", Purpose: "Local listener/process socket metadata provider", Required: true, AnyOf: []string{"lsof"}},
		}
	case "windows":
		return []dependencySpec{
			{ID: "dependency.powershell", Purpose: "Windows CIM, token, firewall, and security-control provider", Required: true, AnyOf: []string{"powershell.exe"}},
		}
	default:
		return nil
	}
}

func executablePath(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0111 != 0
}

func dependencySource(d DependencyCheck) string {
	names := make([]string, 0, len(d.Providers))
	for _, p := range d.Providers {
		if p.Available {
			if p.Path != "" {
				names = append(names, p.Name+"="+p.Path)
			} else {
				names = append(names, p.Name)
			}
		}
	}
	if len(names) == 0 {
		return "local executable search path"
	}
	return strings.Join(names, ", ")
}

func summarize(checks []Check) Summary {
	s := Summary{Total: len(checks)}
	for _, c := range checks {
		switch c.State {
		case StatePass:
			s.Pass++
		case StateWarn:
			s.Warn++
		case StateFail:
			s.Fail++
		case StateNotApplicable:
			s.NotApplicable++
		}
	}
	return s
}

func overallState(s Summary, supported bool) string {
	if !supported {
		return "UNSUPPORTED"
	}
	if s.Fail > 0 {
		return "UNHEALTHY"
	}
	if s.Warn > 0 {
		return "DEGRADED"
	}
	return "HEALTHY"
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
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

func stablePathID(path string) string {
	s := strings.ToLower(filepath.Clean(path))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

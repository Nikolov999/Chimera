package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cli"
	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/filesystem"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/kernel"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/persistence"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/processes"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
	"github.com/Nikolov999/chimera/internal/scheduled"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/services"
	"github.com/Nikolov999/chimera/internal/software"
	"github.com/Nikolov999/chimera/internal/storage"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/updateposture"
	"github.com/Nikolov999/chimera/internal/version"
)

const SchemaVersion = "chimera.snapshot/v1"

const fingerprintAlgorithm = "sha256"

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type HostFingerprint struct {
	Algorithm string   `json:"algorithm"`
	Value     string   `json:"value"`
	Inputs    []string `json:"inputs"`
}

type ConfigProvenance struct {
	Digest  Digest   `json:"digest"`
	Sources []string `json:"sources,omitempty"`
}

type SuppressionProvenance struct {
	Schema             string `json:"schema"`
	Digest             Digest `json:"digest"`
	Total              int    `json:"total"`
	Applied            int    `json:"applied"`
	Expired            int    `json:"expired"`
	Unmatched          int    `json:"unmatched"`
	FindingsSuppressed int    `json:"findings_suppressed"`
}

type ProfileProvenance struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

type RuleSetProvenance struct {
	Schema        string `json:"schema"`
	Version       string `json:"version"`
	Digest        Digest `json:"digest"`
	RuleCount     int    `json:"rule_count"`
	SelectedCount int    `json:"selected_count"`
}

type IntelligenceProvenance struct {
	State              string    `json:"state"`
	Schema             string    `json:"schema,omitempty"`
	Version            string    `json:"version"`
	Source             string    `json:"source"`
	DigestAlgorithm    string    `json:"digest_algorithm,omitempty"`
	Digest             string    `json:"digest,omitempty"`
	RetrievedAt        time.Time `json:"retrieved_at,omitempty"`
	SourceCount        int       `json:"source_count,omitempty"`
	ProductCount       int       `json:"product_count,omitempty"`
	VulnerabilityCount int       `json:"vulnerability_count,omitempty"`
	LifecycleCount     int       `json:"lifecycle_count,omitempty"`
	Mode               string    `json:"mode,omitempty"`
	Freshness          string    `json:"freshness,omitempty"`
	AgeSeconds         int64     `json:"age_seconds,omitempty"`
	MaxAgeSeconds      int64     `json:"max_age_seconds,omitempty"`
	ReadOnly           bool      `json:"read_only"`
	NetworkAccess      bool      `json:"network_access"`
	Reason             string    `json:"reason,omitempty"`
}

type ProductNormalizationProvenance struct {
	State               string `json:"state"`
	Schema              string `json:"schema"`
	EngineVersion       string `json:"engine_version"`
	IntelligenceVersion string `json:"intelligence_version"`
	IntelligenceDigest  string `json:"intelligence_digest,omitempty"`
	CandidateCount      int    `json:"candidate_count"`
	MatchedCount        int    `json:"matched_count"`
	AmbiguousCount      int    `json:"ambiguous_count"`
	Reason              string `json:"reason,omitempty"`
}

type VulnerabilityCorrelationProvenance struct {
	State               string `json:"state"`
	Schema              string `json:"schema"`
	EngineVersion       string `json:"engine_version"`
	IntelligenceVersion string `json:"intelligence_version"`
	IntelligenceDigest  string `json:"intelligence_digest,omitempty"`
	EvaluationCount     int    `json:"evaluation_count"`
	AffectedCount       int    `json:"affected_count"`
	UnresolvedCount     int    `json:"unresolved_count"`
	Reason              string `json:"reason,omitempty"`
}

type VulnerabilityReachabilityProvenance struct {
	State                   string `json:"state"`
	Schema                  string `json:"schema"`
	CollectorVersion        string `json:"collector_version"`
	EvaluationCount         int    `json:"evaluation_count"`
	AffectedEvaluationCount int    `json:"affected_evaluation_count"`
	InstalledOnlyCount      int    `json:"installed_only_count"`
	RunningCount            int    `json:"running_count"`
	ServiceBackedCount      int    `json:"service_backed_count"`
	ListeningCount          int    `json:"listening_count"`
	PrivilegedCount         int    `json:"privileged_count"`
	UnknownCount            int    `json:"unknown_count"`
	Reason                  string `json:"reason,omitempty"`
}

type RiskPrioritizationProvenance struct {
	Schema                 string `json:"schema"`
	EngineVersion          string `json:"engine_version"`
	FindingCount           int    `json:"finding_count"`
	ActionableFindingCount int    `json:"actionable_finding_count"`
	VulnerabilityCount     int    `json:"vulnerability_count"`
	CriticalFindingCount   int    `json:"critical_finding_count"`
	HighFindingCount       int    `json:"high_finding_count"`
}

type LifecycleProvenance struct {
	State                 string `json:"state"`
	Schema                string `json:"schema"`
	EngineVersion         string `json:"engine_version"`
	IntelligenceVersion   string `json:"intelligence_version"`
	IntelligenceDigest    string `json:"intelligence_digest,omitempty"`
	CandidateCount        int    `json:"candidate_count"`
	WithIntelligenceCount int    `json:"with_intelligence_count"`
	SupportedCount        int    `json:"supported_count"`
	EndOfLifeCount        int    `json:"end_of_life_count"`
	UnsupportedCount      int    `json:"unsupported_count"`
	UnknownCount          int    `json:"unknown_count"`
	Reason                string `json:"reason,omitempty"`
}

type UpdatePostureProvenance struct {
	State                      string `json:"state"`
	Schema                     string `json:"schema"`
	CollectorVersion           string `json:"collector_version"`
	PendingCount               int    `json:"pending_count"`
	SecurityCount              int    `json:"security_count"`
	OtherCount                 int    `json:"other_count"`
	UnknownClassificationCount int    `json:"unknown_classification_count"`
	RebootRequired             bool   `json:"reboot_required"`
	FreshProviders             int    `json:"fresh_providers"`
	StaleProviders             int    `json:"stale_providers"`
	UnknownFreshnessProviders  int    `json:"unknown_freshness_providers"`
	Reason                     string `json:"reason,omitempty"`
}

type CollectorProvenance struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Schema         string `json:"schema"`
	EvidenceSchema string `json:"evidence_schema"`
	State          string `json:"state"`
}

type EvaluationProvenance struct {
	SelectedRules     int     `json:"selected_rules"`
	EvaluatedRules    int     `json:"evaluated_rules"`
	NotEvaluatedRules int     `json:"not_evaluated_rules"`
	Percent           float64 `json:"evaluation_percent"`
	Complete          bool    `json:"complete"`
}

type Snapshot struct {
	Schema                    string                              `json:"snapshot_schema"`
	AssessmentID              string                              `json:"assessment_id"`
	HostFingerprint           HostFingerprint                     `json:"host_fingerprint"`
	StartedAt                 time.Time                           `json:"started_at"`
	CollectedAt               time.Time                           `json:"collected_at"`
	AssessedAt                time.Time                           `json:"assessed_at"`
	CompletedAt               time.Time                           `json:"completed_at"`
	Tool                      version.Info                        `json:"tool"`
	Config                    ConfigProvenance                    `json:"config"`
	Suppressions              SuppressionProvenance               `json:"suppressions"`
	Profile                   ProfileProvenance                   `json:"profile"`
	Rules                     RuleSetProvenance                   `json:"rules"`
	Evaluation                EvaluationProvenance                `json:"evaluation"`
	Intelligence              IntelligenceProvenance              `json:"intelligence"`
	ProductNormalization      ProductNormalizationProvenance      `json:"product_normalization"`
	VulnerabilityCorrelation  VulnerabilityCorrelationProvenance  `json:"vulnerability_correlation"`
	VulnerabilityReachability VulnerabilityReachabilityProvenance `json:"vulnerability_reachability"`
	RiskPrioritization        RiskPrioritizationProvenance        `json:"risk_prioritization"`
	Lifecycle                 LifecycleProvenance                 `json:"lifecycle"`
	UpdatePosture             UpdatePostureProvenance             `json:"update_posture"`
	Collectors                []CollectorProvenance               `json:"collectors"`
}

type Input struct {
	StartedAt                 time.Time
	CollectedAt               time.Time
	AssessedAt                time.Time
	CompletedAt               time.Time
	Overview                  overview.Overview
	Kernel                    *kernel.Inventory
	Software                  *software.Inventory
	Processes                 *processes.Inventory
	Services                  *services.Inventory
	Scheduled                 *scheduled.Inventory
	Network                   *netinv.Inventory
	Firewall                  *firewall.Inventory
	RemoteManagement          *remotemgmt.Report
	Accounts                  *accounts.Inventory
	Filesystem                *filesystem.Inventory
	Storage                   *storage.Inventory
	Containers                *containerinv.Inventory
	Persistence               *persistence.Inventory
	Secrets                   *secretinv.Inventory
	Options                   cli.Options
	ConfigSources             []string
	Suppressions              suppression.Report
	Profile                   profile.Descriptor
	Rules                     []assessment.Rule
	Selection                 selection.Report
	Evaluation                EvaluationProvenance
	Tool                      version.Info
	Intelligence              *IntelligenceProvenance
	ProductNormalization      *ProductNormalizationProvenance
	VulnerabilityCorrelation  *VulnerabilityCorrelationProvenance
	VulnerabilityReachability *VulnerabilityReachabilityProvenance
	RiskPrioritization        *RiskPrioritizationProvenance
	Lifecycle                 *LifecycleProvenance
	UpdatePosture             *UpdatePostureProvenance
}

type assessmentConfig struct {
	TimeoutMS  int64    `json:"timeout_ms"`
	Profile    string   `json:"profile"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category,omitempty"`
	Include    []string `json:"include,omitempty"`
	Exclude    []string `json:"exclude,omitempty"`
	Offline    bool     `json:"offline"`
	Refresh    bool     `json:"refresh_intelligence"`
	MaxWorkers int      `json:"max_workers"`
}

type ruleDigestRecord struct {
	ID             string                                `json:"id"`
	Title          string                                `json:"title"`
	Category       string                                `json:"category"`
	Severity       assessment.Severity                   `json:"severity"`
	AffectedObject string                                `json:"affected_object"`
	ExpectedState  string                                `json:"expected_state"`
	Risk           string                                `json:"risk"`
	Remediation    string                                `json:"remediation"`
	References     []assessment.Reference                `json:"references,omitempty"`
	Definition     *assessment.DeclarativeRuleDefinition `json:"declarative_definition,omitempty"`
}

func Build(in Input) (Snapshot, error) {
	if in.StartedAt.IsZero() || in.CollectedAt.IsZero() || in.AssessedAt.IsZero() || in.CompletedAt.IsZero() {
		return Snapshot{}, fmt.Errorf("snapshot timestamps must all be set")
	}
	if in.CompletedAt.Before(in.StartedAt) {
		return Snapshot{}, fmt.Errorf("snapshot completion precedes start")
	}
	if strings.TrimSpace(in.Profile.Name) == "" {
		return Snapshot{}, fmt.Errorf("snapshot profile is required")
	}
	for _, r := range in.Rules {
		if err := r.Validate(); err != nil {
			return Snapshot{}, fmt.Errorf("snapshot rule set: %w", err)
		}
	}

	host, err := hostFingerprint(in.Overview)
	if err != nil {
		return Snapshot{}, err
	}
	configDigest, err := digestJSON(assessmentConfig{
		TimeoutMS:  in.Options.Timeout.Milliseconds(),
		Profile:    strings.ToLower(strings.TrimSpace(in.Options.Profile)),
		Severity:   strings.ToUpper(strings.TrimSpace(in.Options.Severity)),
		Category:   strings.ToLower(strings.TrimSpace(in.Options.Category)),
		Include:    normalizedStrings(in.Options.Include),
		Exclude:    normalizedStrings(in.Options.Exclude),
		Offline:    in.Options.Offline,
		Refresh:    in.Options.RefreshIntelligence,
		MaxWorkers: in.Options.MaxWorkers,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("digest effective assessment config: %w", err)
	}
	if in.Suppressions.Schema == "" {
		in.Suppressions = suppression.Report{Schema: suppression.SchemaVersion, AssessedAt: in.AssessedAt.UTC()}
	}
	if in.Suppressions.Schema != suppression.SchemaVersion {
		return Snapshot{}, fmt.Errorf("snapshot suppression schema %q is invalid", in.Suppressions.Schema)
	}
	suppressionDigest, err := digestJSON(in.Suppressions.Entries)
	if err != nil {
		return Snapshot{}, fmt.Errorf("digest suppression policy: %w", err)
	}
	suppressionProv := SuppressionProvenance{
		Schema: in.Suppressions.Schema, Digest: suppressionDigest,
		Total: in.Suppressions.Summary.Total, Applied: in.Suppressions.Summary.Applied,
		Expired: in.Suppressions.Summary.Expired, Unmatched: in.Suppressions.Summary.Unmatched,
		FindingsSuppressed: in.Suppressions.Summary.FindingsSuppressed,
	}

	profileDigest, err := digestJSON(in.Profile)
	if err != nil {
		return Snapshot{}, fmt.Errorf("digest profile: %w", err)
	}
	rulesDigest, err := digestRuleSet(in.Rules)
	if err != nil {
		return Snapshot{}, fmt.Errorf("digest rule set: %w", err)
	}

	collectors := []CollectorProvenance{{
		Name:           overview.CollectorName,
		Version:        overview.CollectorVersion,
		Schema:         overview.SchemaVersion,
		EvidenceSchema: in.Overview.EvidenceSchema,
		State:          collectorState(in.Overview),
	}}
	collectorIdentity := overview.CollectorVersion
	if in.Kernel != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: kernel.CollectorName, Version: kernel.CollectorVersion, Schema: kernel.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: kernelCollectorState(*in.Kernel),
		})
		collectorIdentity += "+" + kernel.CollectorVersion
	}
	if in.Software != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: software.CollectorName, Version: software.CollectorVersion, Schema: software.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: softwareCollectorState(*in.Software),
		})
		collectorIdentity += "+" + software.CollectorVersion
	}
	if in.Processes != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: processes.CollectorName, Version: processes.CollectorVersion, Schema: processes.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: processCollectorState(*in.Processes),
		})
		collectorIdentity += "+" + processes.CollectorVersion
	}
	if in.Services != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: services.CollectorName, Version: services.CollectorVersion, Schema: services.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: serviceCollectorState(*in.Services),
		})
		collectorIdentity += "+" + services.CollectorVersion
	}
	if in.Scheduled != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: scheduled.CollectorName, Version: scheduled.CollectorVersion, Schema: scheduled.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: scheduledCollectorState(*in.Scheduled),
		})
		collectorIdentity += "+" + scheduled.CollectorVersion
	}
	if in.Network != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: netinv.CollectorName, Version: netinv.CollectorVersion, Schema: netinv.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: networkCollectorState(*in.Network),
		})
		collectorIdentity += "+" + netinv.CollectorVersion
	}
	if in.Firewall != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: firewall.CollectorName, Version: firewall.CollectorVersion, Schema: firewall.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: firewallCollectorState(*in.Firewall),
		})
		collectorIdentity += "+" + firewall.CollectorVersion
	}
	if in.RemoteManagement != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: remotemgmt.CollectorName, Version: remotemgmt.CollectorVersion, Schema: remotemgmt.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: remoteManagementCollectorState(*in.RemoteManagement),
		})
		collectorIdentity += "+" + remotemgmt.CollectorVersion
	}
	if in.Accounts != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: accounts.CollectorName, Version: accounts.CollectorVersion, Schema: accounts.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: accountCollectorState(*in.Accounts),
		})
		collectorIdentity += "+" + accounts.CollectorVersion
	}
	if in.Filesystem != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: filesystem.CollectorName, Version: filesystem.CollectorVersion, Schema: filesystem.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: filesystemCollectorState(*in.Filesystem),
		})
		collectorIdentity += "+" + filesystem.CollectorVersion
	}
	if in.Storage != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: storage.CollectorName, Version: storage.CollectorVersion, Schema: storage.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: storageCollectorState(*in.Storage),
		})
		collectorIdentity += "+" + storage.CollectorVersion
	}
	if in.Containers != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: containerinv.CollectorName, Version: containerinv.CollectorVersion, Schema: containerinv.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: containerCollectorState(*in.Containers),
		})
		collectorIdentity += "+" + containerinv.CollectorVersion
	}
	if in.Persistence != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: persistence.CollectorName, Version: persistence.CollectorVersion, Schema: persistence.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: persistenceCollectorState(*in.Persistence),
		})
		collectorIdentity += "+" + persistence.CollectorVersion
	}
	if in.Secrets != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: secretinv.CollectorName, Version: secretinv.CollectorVersion, Schema: secretinv.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: secretCollectorState(*in.Secrets),
		})
		collectorIdentity += "+" + secretinv.CollectorVersion
	}
	if in.UpdatePosture != nil {
		collectors = append(collectors, CollectorProvenance{
			Name: "update-posture", Version: updateposture.CollectorVersion, Schema: updateposture.SchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: in.UpdatePosture.State,
		})
		collectorIdentity += "+" + updateposture.CollectorVersion
	}
	if in.Intelligence != nil {
		state := "COMPLETE"
		if in.Intelligence.State == "UNAVAILABLE" {
			state = "UNAVAILABLE"
		} else if in.Intelligence.Freshness == "STALE" {
			state = "DEGRADED"
		}
		collectors = append(collectors, CollectorProvenance{
			Name: "intelligence-snapshot", Version: "intelligence-session/phase031-v1", Schema: intelligence.AssessmentSchemaVersion,
			EvidenceSchema: evidence.SchemaVersion, State: state,
		})
		collectorIdentity += "+intelligence-session/phase031-v1"
	}

	intelligence := IntelligenceProvenance{
		State: "NOT_APPLICABLE", Version: "none", Source: "none",
		Reason: "no general vulnerability-intelligence provenance was supplied to this snapshot build",
	}
	if in.Kernel != nil && strings.TrimSpace(in.Kernel.DriverIntelligence.Version) != "" {
		intelligence = IntelligenceProvenance{
			State: "PINNED_LOCAL", Version: in.Kernel.DriverIntelligence.Version, Source: in.Kernel.DriverIntelligence.Source,
			Reason: "vulnerable-driver seed intelligence only",
		}
	}
	if in.Intelligence != nil {
		intelligence = *in.Intelligence
	}
	intelligenceIdentity := strings.Join([]string{intelligence.State, intelligence.Schema, intelligence.Version, intelligence.Source, intelligence.DigestAlgorithm, intelligence.Digest, intelligence.Mode, intelligence.Freshness, fmt.Sprint(intelligence.AgeSeconds), fmt.Sprint(intelligence.MaxAgeSeconds), fmt.Sprint(intelligence.ReadOnly), fmt.Sprint(intelligence.NetworkAccess)}, "|")
	normalization := ProductNormalizationProvenance{State: "NOT_APPLICABLE", Schema: "none", EngineVersion: "none", IntelligenceVersion: intelligence.Version, Reason: "no product-normalization provenance was supplied to this snapshot build"}
	if in.ProductNormalization != nil {
		normalization = *in.ProductNormalization
	}
	normalizationIdentity := strings.Join([]string{normalization.State, normalization.Schema, normalization.EngineVersion, normalization.IntelligenceVersion, normalization.IntelligenceDigest}, "|")
	correlation := VulnerabilityCorrelationProvenance{State: "NOT_APPLICABLE", Schema: "none", EngineVersion: "none", IntelligenceVersion: intelligence.Version, Reason: "no vulnerability-correlation provenance was supplied to this snapshot build"}
	if in.VulnerabilityCorrelation != nil {
		correlation = *in.VulnerabilityCorrelation
	}
	correlationIdentity := strings.Join([]string{correlation.State, correlation.Schema, correlation.EngineVersion, correlation.IntelligenceVersion, correlation.IntelligenceDigest, fmt.Sprint(correlation.EvaluationCount), fmt.Sprint(correlation.AffectedCount), fmt.Sprint(correlation.UnresolvedCount)}, "|")
	reachability := VulnerabilityReachabilityProvenance{State: "NOT_APPLICABLE", Schema: "none", CollectorVersion: "none", Reason: "no vulnerability-reachability provenance was supplied to this snapshot build"}
	if in.VulnerabilityReachability != nil {
		reachability = *in.VulnerabilityReachability
	}
	reachabilityIdentity := strings.Join([]string{reachability.State, reachability.Schema, reachability.CollectorVersion, fmt.Sprint(reachability.EvaluationCount), fmt.Sprint(reachability.AffectedEvaluationCount), fmt.Sprint(reachability.InstalledOnlyCount), fmt.Sprint(reachability.RunningCount), fmt.Sprint(reachability.ServiceBackedCount), fmt.Sprint(reachability.ListeningCount), fmt.Sprint(reachability.PrivilegedCount), fmt.Sprint(reachability.UnknownCount)}, "|")

	priority := RiskPrioritizationProvenance{Schema: prioritization.SchemaVersion, EngineVersion: prioritization.EngineVersion}
	if in.RiskPrioritization != nil {
		priority = *in.RiskPrioritization
	}
	priorityIdentity := strings.Join([]string{priority.Schema, priority.EngineVersion, fmt.Sprint(priority.FindingCount), fmt.Sprint(priority.ActionableFindingCount), fmt.Sprint(priority.VulnerabilityCount), fmt.Sprint(priority.CriticalFindingCount), fmt.Sprint(priority.HighFindingCount)}, "|")

	lifecycle := LifecycleProvenance{State: "NOT_APPLICABLE", Schema: "none", EngineVersion: "none", IntelligenceVersion: intelligence.Version, Reason: "no lifecycle provenance was supplied to this snapshot build"}
	if in.Lifecycle != nil {
		lifecycle = *in.Lifecycle
	}
	lifecycleIdentity := strings.Join([]string{lifecycle.State, lifecycle.Schema, lifecycle.EngineVersion, lifecycle.IntelligenceVersion, lifecycle.IntelligenceDigest, fmt.Sprint(lifecycle.CandidateCount), fmt.Sprint(lifecycle.WithIntelligenceCount), fmt.Sprint(lifecycle.SupportedCount), fmt.Sprint(lifecycle.EndOfLifeCount), fmt.Sprint(lifecycle.UnsupportedCount), fmt.Sprint(lifecycle.UnknownCount)}, "|")

	updatePosture := UpdatePostureProvenance{State: "NOT_APPLICABLE", Schema: "none", CollectorVersion: "none", Reason: "no update-posture provenance was supplied to this snapshot build"}
	if in.UpdatePosture != nil {
		updatePosture = *in.UpdatePosture
	}
	updatePostureIdentity := strings.Join([]string{updatePosture.State, updatePosture.Schema, updatePosture.CollectorVersion, fmt.Sprint(updatePosture.PendingCount), fmt.Sprint(updatePosture.SecurityCount), fmt.Sprint(updatePosture.OtherCount), fmt.Sprint(updatePosture.UnknownClassificationCount), fmt.Sprint(updatePosture.RebootRequired), fmt.Sprint(updatePosture.FreshProviders), fmt.Sprint(updatePosture.StaleProviders), fmt.Sprint(updatePosture.UnknownFreshnessProviders)}, "|")

	idDigest, err := digestJSON(struct {
		StartedAt                 string `json:"started_at"`
		Host                      string `json:"host"`
		Config                    string `json:"config"`
		Suppressions              string `json:"suppressions"`
		Profile                   string `json:"profile"`
		Rules                     string `json:"rules"`
		Evaluation                string `json:"evaluation"`
		Collector                 string `json:"collector"`
		Intelligence              string `json:"intelligence"`
		ProductNormalization      string `json:"product_normalization"`
		VulnerabilityCorrelation  string `json:"vulnerability_correlation"`
		VulnerabilityReachability string `json:"vulnerability_reachability"`
		RiskPrioritization        string `json:"risk_prioritization"`
		Lifecycle                 string `json:"lifecycle"`
		UpdatePosture             string `json:"update_posture"`
		ToolVersion               string `json:"tool_version"`
		ToolCommit                string `json:"tool_commit"`
		BuildDate                 string `json:"build_date"`
	}{
		StartedAt:                 in.StartedAt.UTC().Format(time.RFC3339Nano),
		Host:                      host.Value,
		Config:                    configDigest.Value,
		Suppressions:              suppressionDigest.Value,
		Profile:                   profileDigest.Value,
		Rules:                     rulesDigest.Value,
		Evaluation:                fmt.Sprintf("%d|%d|%d|%.6f|%t", in.Evaluation.SelectedRules, in.Evaluation.EvaluatedRules, in.Evaluation.NotEvaluatedRules, in.Evaluation.Percent, in.Evaluation.Complete),
		Collector:                 collectorIdentity,
		Intelligence:              intelligenceIdentity,
		ProductNormalization:      normalizationIdentity,
		VulnerabilityCorrelation:  correlationIdentity,
		VulnerabilityReachability: reachabilityIdentity,
		RiskPrioritization:        priorityIdentity,
		Lifecycle:                 lifecycleIdentity,
		UpdatePosture:             updatePostureIdentity,
		ToolVersion:               in.Tool.Version,
		ToolCommit:                in.Tool.Commit,
		BuildDate:                 in.Tool.BuildDate,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("derive assessment id: %w", err)
	}

	out := Snapshot{
		Schema:          SchemaVersion,
		AssessmentID:    "asm-" + idDigest.Value[:24],
		HostFingerprint: host,
		StartedAt:       in.StartedAt.UTC(),
		CollectedAt:     in.CollectedAt.UTC(),
		AssessedAt:      in.AssessedAt.UTC(),
		CompletedAt:     in.CompletedAt.UTC(),
		Tool:            in.Tool,
		Config:          ConfigProvenance{Digest: configDigest, Sources: normalizedPaths(in.ConfigSources)},
		Suppressions:    suppressionProv,
		Profile:         ProfileProvenance{Schema: in.Profile.Schema, Name: in.Profile.Name, Digest: profileDigest},
		Rules: RuleSetProvenance{
			Schema: assessment.SchemaVersion, Version: assessment.RuleSetVersion, Digest: rulesDigest,
			RuleCount: len(in.Rules), SelectedCount: selectedCount(in.Selection),
		},
		Evaluation:                in.Evaluation,
		Intelligence:              intelligence,
		ProductNormalization:      normalization,
		VulnerabilityCorrelation:  correlation,
		VulnerabilityReachability: reachability,
		RiskPrioritization:        priority,
		Lifecycle:                 lifecycle,
		UpdatePosture:             updatePosture,
		Collectors:                collectors,
	}
	if err := out.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("validate snapshot: %w", err)
	}
	return out, nil
}

func hostFingerprint(o overview.Overview) (HostFingerprint, error) {
	inputs := []string{"hostname", "os", "architecture", "cpu_model", "memory_total_bytes"}
	payload := struct {
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		CPUModel     string `json:"cpu_model"`
		MemoryBytes  uint64 `json:"memory_total_bytes"`
	}{
		Hostname:     strings.ToLower(strings.TrimSpace(o.Hostname)),
		OS:           strings.ToLower(strings.TrimSpace(o.OS)),
		Architecture: strings.ToLower(strings.TrimSpace(o.Architecture)),
		CPUModel:     strings.TrimSpace(o.CPUModel),
		MemoryBytes:  o.MemoryTotalBytes,
	}
	d, err := digestJSON(payload)
	if err != nil {
		return HostFingerprint{}, fmt.Errorf("derive host fingerprint: %w", err)
	}
	return HostFingerprint{Algorithm: d.Algorithm, Value: d.Value, Inputs: inputs}, nil
}

func digestRuleSet(rules []assessment.Rule) (Digest, error) {
	records := make([]ruleDigestRecord, 0, len(rules))
	for _, r := range rules {
		refs := append([]assessment.Reference(nil), r.References...)
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Title == refs[j].Title {
				return refs[i].URL < refs[j].URL
			}
			return refs[i].Title < refs[j].Title
		})
		var definition *assessment.DeclarativeRuleDefinition
		if r.Definition != nil {
			d := *r.Definition
			definition = &d
		}
		records = append(records, ruleDigestRecord{
			ID: r.ID, Title: r.Title, Category: r.Category, Severity: r.Severity,
			AffectedObject: r.AffectedObject, ExpectedState: r.ExpectedState, Risk: r.Risk,
			Remediation: r.Remediation, References: refs, Definition: definition,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return digestJSON(records)
}

func digestJSON(v any) (Digest, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Digest{}, err
	}
	sum := sha256.Sum256(b)
	return Digest{Algorithm: fingerprintAlgorithm, Value: hex.EncodeToString(sum[:])}, nil
}

func normalizedStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
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

func normalizedPaths(in []string) []string {
	seen := make(map[string]struct{}, len(in))
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

func (s Snapshot) Validate() error {
	if s.Schema != SchemaVersion {
		return fmt.Errorf("unexpected snapshot schema %q", s.Schema)
	}
	if !strings.HasPrefix(s.AssessmentID, "asm-") || len(s.AssessmentID) != 28 {
		return fmt.Errorf("invalid assessment id %q", s.AssessmentID)
	}
	if err := validateDigest("host fingerprint", Digest{Algorithm: s.HostFingerprint.Algorithm, Value: s.HostFingerprint.Value}); err != nil {
		return err
	}
	if len(s.HostFingerprint.Inputs) == 0 {
		return fmt.Errorf("host fingerprint inputs are required")
	}
	if s.StartedAt.IsZero() || s.CollectedAt.IsZero() || s.AssessedAt.IsZero() || s.CompletedAt.IsZero() {
		return fmt.Errorf("snapshot lifecycle timestamps are required")
	}
	if s.CompletedAt.Before(s.StartedAt) {
		return fmt.Errorf("snapshot completion precedes start")
	}
	if strings.TrimSpace(s.Tool.Product) == "" || strings.TrimSpace(s.Tool.Version) == "" {
		return fmt.Errorf("tool provenance is incomplete")
	}
	if err := validateDigest("config", s.Config.Digest); err != nil {
		return err
	}
	if s.Suppressions.Schema != suppression.SchemaVersion {
		return fmt.Errorf("suppression provenance schema %q is invalid", s.Suppressions.Schema)
	}
	if err := validateDigest("suppressions", s.Suppressions.Digest); err != nil {
		return err
	}
	if s.Suppressions.Total < 0 || s.Suppressions.Applied < 0 || s.Suppressions.Expired < 0 || s.Suppressions.Unmatched < 0 || s.Suppressions.FindingsSuppressed < 0 || s.Suppressions.Applied+s.Suppressions.Expired+s.Suppressions.Unmatched != s.Suppressions.Total {
		return fmt.Errorf("suppression provenance counts are invalid")
	}
	if strings.TrimSpace(s.Profile.Schema) == "" || strings.TrimSpace(s.Profile.Name) == "" {
		return fmt.Errorf("profile provenance is incomplete")
	}
	if err := validateDigest("profile", s.Profile.Digest); err != nil {
		return err
	}
	if strings.TrimSpace(s.Rules.Schema) == "" || strings.TrimSpace(s.Rules.Version) == "" || s.Rules.RuleCount < 0 || s.Rules.SelectedCount < 0 || s.Rules.SelectedCount > s.Rules.RuleCount {
		return fmt.Errorf("rule-set provenance is invalid")
	}
	if err := validateDigest("rule set", s.Rules.Digest); err != nil {
		return err
	}
	if s.Evaluation.SelectedRules < 0 || s.Evaluation.EvaluatedRules < 0 || s.Evaluation.NotEvaluatedRules < 0 || s.Evaluation.Percent < 0 || s.Evaluation.Percent > 100 {
		return fmt.Errorf("evaluation provenance is invalid")
	}
	if s.Evaluation.SelectedRules > 0 && s.Evaluation.EvaluatedRules+s.Evaluation.NotEvaluatedRules != s.Evaluation.SelectedRules {
		return fmt.Errorf("evaluation provenance does not account for selected rules")
	}
	if s.Evaluation.Complete && s.Evaluation.NotEvaluatedRules != 0 {
		return fmt.Errorf("evaluation provenance cannot be complete with NOT_EVALUATED rules")
	}
	if strings.TrimSpace(s.Intelligence.State) == "" || strings.TrimSpace(s.Intelligence.Version) == "" || strings.TrimSpace(s.Intelligence.Source) == "" {
		return fmt.Errorf("intelligence provenance is incomplete")
	}
	if strings.HasPrefix(s.Intelligence.State, "PINNED_") {
		if strings.TrimSpace(s.Intelligence.Schema) == "" || s.Intelligence.RetrievedAt.IsZero() {
			return fmt.Errorf("pinned intelligence provenance lacks schema or retrieval timestamp")
		}
		if s.Intelligence.DigestAlgorithm != "sha256" || len(s.Intelligence.Digest) != sha256.Size*2 {
			return fmt.Errorf("pinned intelligence digest is invalid")
		}
		if _, err := hex.DecodeString(s.Intelligence.Digest); err != nil {
			return fmt.Errorf("pinned intelligence digest is not hexadecimal: %w", err)
		}
		if s.Intelligence.SourceCount < 0 || s.Intelligence.ProductCount < 0 || s.Intelligence.VulnerabilityCount < 0 || s.Intelligence.LifecycleCount < 0 {
			return fmt.Errorf("pinned intelligence record counts are invalid")
		}
		if s.Intelligence.Mode != "LOCAL_PINNED" && s.Intelligence.Mode != "OFFLINE_PINNED" {
			return fmt.Errorf("pinned intelligence mode %q is invalid", s.Intelligence.Mode)
		}
		if s.Intelligence.Freshness != "CURRENT" && s.Intelligence.Freshness != "STALE" {
			return fmt.Errorf("pinned intelligence freshness %q is invalid", s.Intelligence.Freshness)
		}
		if s.Intelligence.AgeSeconds < 0 || s.Intelligence.MaxAgeSeconds <= 0 {
			return fmt.Errorf("pinned intelligence freshness ages are invalid")
		}
		if !s.Intelligence.ReadOnly || s.Intelligence.NetworkAccess {
			return fmt.Errorf("pinned intelligence must be read-only with network access disabled during assessment")
		}
	}
	if strings.TrimSpace(s.ProductNormalization.State) == "" || strings.TrimSpace(s.ProductNormalization.Schema) == "" || strings.TrimSpace(s.ProductNormalization.EngineVersion) == "" || strings.TrimSpace(s.ProductNormalization.IntelligenceVersion) == "" {
		return fmt.Errorf("product-normalization provenance is incomplete")
	}
	if s.ProductNormalization.CandidateCount < 0 || s.ProductNormalization.MatchedCount < 0 || s.ProductNormalization.AmbiguousCount < 0 || s.ProductNormalization.MatchedCount+s.ProductNormalization.AmbiguousCount > s.ProductNormalization.CandidateCount {
		return fmt.Errorf("product-normalization provenance counts are invalid")
	}
	if s.ProductNormalization.State == "COMPLETE" {
		if len(s.ProductNormalization.IntelligenceDigest) != sha256.Size*2 {
			return fmt.Errorf("product-normalization intelligence digest is invalid")
		}
		if _, err := hex.DecodeString(s.ProductNormalization.IntelligenceDigest); err != nil {
			return fmt.Errorf("product-normalization intelligence digest is not hexadecimal: %w", err)
		}
	}
	if strings.TrimSpace(s.VulnerabilityCorrelation.State) == "" || strings.TrimSpace(s.VulnerabilityCorrelation.Schema) == "" || strings.TrimSpace(s.VulnerabilityCorrelation.EngineVersion) == "" || strings.TrimSpace(s.VulnerabilityCorrelation.IntelligenceVersion) == "" {
		return fmt.Errorf("vulnerability-correlation provenance is incomplete")
	}
	if s.VulnerabilityCorrelation.EvaluationCount < 0 || s.VulnerabilityCorrelation.AffectedCount < 0 || s.VulnerabilityCorrelation.UnresolvedCount < 0 || s.VulnerabilityCorrelation.AffectedCount+s.VulnerabilityCorrelation.UnresolvedCount > s.VulnerabilityCorrelation.EvaluationCount {
		return fmt.Errorf("vulnerability-correlation provenance counts are invalid")
	}
	if s.VulnerabilityCorrelation.State == "COMPLETE" {
		if len(s.VulnerabilityCorrelation.IntelligenceDigest) != sha256.Size*2 {
			return fmt.Errorf("vulnerability-correlation intelligence digest is invalid")
		}
		if _, err := hex.DecodeString(s.VulnerabilityCorrelation.IntelligenceDigest); err != nil {
			return fmt.Errorf("vulnerability-correlation intelligence digest is not hexadecimal: %w", err)
		}
	}
	if strings.TrimSpace(s.VulnerabilityReachability.State) == "" || strings.TrimSpace(s.VulnerabilityReachability.Schema) == "" || strings.TrimSpace(s.VulnerabilityReachability.CollectorVersion) == "" {
		return fmt.Errorf("vulnerability-reachability provenance is incomplete")
	}
	vr := s.VulnerabilityReachability
	if vr.EvaluationCount < 0 || vr.AffectedEvaluationCount < 0 || vr.InstalledOnlyCount < 0 || vr.RunningCount < 0 || vr.ServiceBackedCount < 0 || vr.ListeningCount < 0 || vr.PrivilegedCount < 0 || vr.UnknownCount < 0 || vr.AffectedEvaluationCount > vr.EvaluationCount {
		return fmt.Errorf("vulnerability-reachability provenance counts are invalid")
	}
	if s.RiskPrioritization.Schema != prioritization.SchemaVersion || s.RiskPrioritization.EngineVersion != prioritization.EngineVersion {
		return fmt.Errorf("risk-prioritization provenance contract is invalid")
	}
	rp := s.RiskPrioritization
	if rp.FindingCount < 0 || rp.ActionableFindingCount < 0 || rp.VulnerabilityCount < 0 || rp.CriticalFindingCount < 0 || rp.HighFindingCount < 0 || rp.ActionableFindingCount > rp.FindingCount || rp.CriticalFindingCount+rp.HighFindingCount > rp.FindingCount {
		return fmt.Errorf("risk-prioritization provenance counts are invalid")
	}
	if strings.TrimSpace(s.Lifecycle.State) == "" || strings.TrimSpace(s.Lifecycle.Schema) == "" || strings.TrimSpace(s.Lifecycle.EngineVersion) == "" || strings.TrimSpace(s.Lifecycle.IntelligenceVersion) == "" {
		return fmt.Errorf("lifecycle provenance is incomplete")
	}
	if s.Lifecycle.CandidateCount < 0 || s.Lifecycle.WithIntelligenceCount < 0 || s.Lifecycle.SupportedCount < 0 || s.Lifecycle.EndOfLifeCount < 0 || s.Lifecycle.UnsupportedCount < 0 || s.Lifecycle.UnknownCount < 0 || s.Lifecycle.WithIntelligenceCount > s.Lifecycle.CandidateCount || s.Lifecycle.SupportedCount+s.Lifecycle.EndOfLifeCount+s.Lifecycle.UnsupportedCount+s.Lifecycle.UnknownCount != s.Lifecycle.WithIntelligenceCount {
		return fmt.Errorf("lifecycle provenance counts are invalid")
	}
	if s.Lifecycle.State == "COMPLETE" {
		if len(s.Lifecycle.IntelligenceDigest) != sha256.Size*2 {
			return fmt.Errorf("lifecycle intelligence digest is invalid")
		}
		if _, err := hex.DecodeString(s.Lifecycle.IntelligenceDigest); err != nil {
			return fmt.Errorf("lifecycle intelligence digest is not hexadecimal: %w", err)
		}
	}
	if strings.TrimSpace(s.UpdatePosture.State) == "" || strings.TrimSpace(s.UpdatePosture.Schema) == "" || strings.TrimSpace(s.UpdatePosture.CollectorVersion) == "" {
		return fmt.Errorf("update-posture provenance is incomplete")
	}
	u := s.UpdatePosture
	if u.PendingCount < 0 || u.SecurityCount < 0 || u.OtherCount < 0 || u.UnknownClassificationCount < 0 || u.FreshProviders < 0 || u.StaleProviders < 0 || u.UnknownFreshnessProviders < 0 || u.SecurityCount+u.OtherCount+u.UnknownClassificationCount != u.PendingCount {
		return fmt.Errorf("update-posture provenance counts are invalid")
	}
	if len(s.Collectors) == 0 {
		return fmt.Errorf("collector provenance is required")
	}
	for i, c := range s.Collectors {
		if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Version) == "" || strings.TrimSpace(c.Schema) == "" || strings.TrimSpace(c.EvidenceSchema) == "" || strings.TrimSpace(c.State) == "" {
			return fmt.Errorf("collector provenance %d is incomplete", i)
		}
	}
	return nil
}

func validateDigest(name string, d Digest) error {
	if d.Algorithm != fingerprintAlgorithm || len(d.Value) != sha256.Size*2 {
		return fmt.Errorf("%s digest is invalid", name)
	}
	if _, err := hex.DecodeString(d.Value); err != nil {
		return fmt.Errorf("%s digest is not hexadecimal: %w", name, err)
	}
	return nil
}

func accountCollectorState(a accounts.Inventory) string {
	if len(a.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range a.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func filesystemCollectorState(inv filesystem.Inventory) string {
	if len(inv.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, p := range inv.Paths {
		if p.State == evidence.StateDenied || p.State == evidence.StateUnavailable || p.State == evidence.StateDegraded {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func storageCollectorState(inv storage.Inventory) string {
	if len(inv.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range inv.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	for _, v := range inv.Volumes {
		if v.State == evidence.StateDenied || v.State == evidence.StateUnavailable || v.State == evidence.StateDegraded || v.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func secretCollectorState(inv secretinv.Inventory) string {
	if len(inv.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range inv.Sources {
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func persistenceCollectorState(inv persistence.Inventory) string {
	if len(inv.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range inv.Sources {
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func containerCollectorState(inv containerinv.Inventory) string {
	if len(inv.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range inv.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func processCollectorState(p processes.Inventory) string {
	if len(p.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range p.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func scheduledCollectorState(s scheduled.Inventory) string {
	if len(s.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range s.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func serviceCollectorState(s services.Inventory) string {
	if len(s.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range s.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func networkCollectorState(n netinv.Inventory) string {
	if len(n.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range n.Sources {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func remoteManagementCollectorState(r remotemgmt.Report) string {
	if len(r.Degraded) > 0 || r.Summary.ControlsUnavailable > 0 {
		return "DEGRADED"
	}
	return "COMPLETE"
}

func firewallCollectorState(f firewall.Inventory) string {
	if len(f.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, src := range f.Providers {
		if src.State == evidence.StateDenied || src.State == evidence.StateUnavailable || src.State == evidence.StateDegraded || src.State == evidence.StateUnsupported {
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func selectedCount(report selection.Report) int {
	count := 0
	for _, d := range report.Decisions {
		if d.Outcome == selection.OutcomeSelected {
			count++
		}
	}
	return count
}

func collectorState(o overview.Overview) string {
	if len(o.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, observation := range o.Evidence {
		switch observation.State {
		case evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported:
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}
func kernelCollectorState(k kernel.Inventory) string {
	if len(k.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, observation := range k.Evidence {
		switch observation.State {
		case evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported:
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

func softwareCollectorState(s software.Inventory) string {
	if len(s.Degraded) > 0 {
		return "DEGRADED"
	}
	for _, observation := range s.Evidence {
		switch observation.State {
		case evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported:
			return "DEGRADED"
		}
	}
	return "COMPLETE"
}

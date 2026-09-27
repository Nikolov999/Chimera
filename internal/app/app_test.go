package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/intelligence"
)

func TestVersionJSONIsMachineClean(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"version", "--json"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("json contains ANSI")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if v["command"] != "version" {
		t.Fatalf("unexpected command: %#v", v["command"])
	}
}

func TestPhase109BaselineJSONContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"baseline", "--json", "--timeout", "10s", "--max-workers", "2", "--category", "correlation", "--profile", "server"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("baseline json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema        string `json:"baseline_schema"`
			EngineVersion string `json:"engine_version"`
			RuleSet       string `json:"rule_set_version"`
			AssessmentID  string `json:"assessment_id"`
			State         string `json:"state"`
			Profile       struct {
				Name string `json:"name"`
			} `json:"profile"`
			Coverage struct {
				State    string `json:"state"`
				Selected int    `json:"selected_rules"`
				Total    int    `json:"total_rules"`
			} `json:"coverage"`
			Summary struct {
				Total int `json:"total"`
			} `json:"summary"`
			Categories []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"categories"`
			CISInspired struct {
				Schema         string `json:"schema"`
				CatalogVersion string `json:"catalog_version"`
				Framework      struct {
					OfficialBenchmark  bool `json:"official_benchmark"`
					CertificationClaim bool `json:"certification_claim"`
				} `json:"framework"`
				Summary struct {
					MappedRules     int `json:"mapped_rules"`
					UnmappedRules   int `json:"unmapped_rules"`
					MappedEvaluated int `json:"mapped_evaluated_rules"`
					Concepts        int `json:"concepts"`
				} `json:"summary"`
			} `json:"cis_inspired_mapping"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid baseline json: %v\n%s", err, out.String())
	}
	if v.Command != "baseline" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.baseline/v2" || v.Data.EngineVersion != "chimera.baseline-engine/v2-phase109" {
		t.Fatalf("unexpected baseline contract: %#v", v)
	}
	if v.Data.RuleSet == "" || v.Data.AssessmentID == "" || v.Data.State == "" || v.Data.Profile.Name != "server" {
		t.Fatalf("missing baseline provenance: %#v", v.Data)
	}
	if v.Data.Coverage.State != "PARTIAL" || v.Data.Coverage.Selected != 3 || v.Data.Coverage.Total <= v.Data.Coverage.Selected || v.Data.Summary.Total != v.Data.Coverage.Selected {
		t.Fatalf("unexpected baseline coverage: %#v", v.Data.Coverage)
	}
	if len(v.Data.Categories) != 1 || v.Data.Categories[0].Name != "correlation" || v.Data.Categories[0].State == "" {
		t.Fatalf("unexpected baseline category result: %#v", v.Data.Categories)
	}
	if v.Data.CISInspired.Schema != "chimera.cis-inspired-mapping/v1" || v.Data.CISInspired.CatalogVersion != "chimera.control-map/cis-inspired-v1-phase109" {
		t.Fatalf("missing CIS-inspired mapping contract: %#v", v.Data.CISInspired)
	}
	if v.Data.CISInspired.Framework.OfficialBenchmark || v.Data.CISInspired.Framework.CertificationClaim || v.Data.CISInspired.Summary.MappedRules <= 0 || v.Data.CISInspired.Summary.UnmappedRules != 5 || v.Data.CISInspired.Summary.MappedEvaluated != 3 || v.Data.CISInspired.Summary.Concepts != 17 {
		t.Fatalf("unexpected mapping semantics: %#v", v.Data.CISInspired)
	}
}

func TestScanJSONContainsPhase003OrchestrationContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--json", "--timeout", "30s", "--max-workers", "8"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("scan json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			ScanSchema string `json:"scan_schema"`
			Containers *struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
			} `json:"containers"`
			Persistence *struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
			} `json:"persistence"`
			Secrets *struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
			} `json:"secrets"`
			EvidenceSchema string `json:"evidence_schema"`
			FindingSchema  string `json:"finding_schema"`
			State          string `json:"state"`
			MaxWorkers     int    `json:"max_workers"`
			WorkersUsed    int    `json:"workers_used"`
			Categories     []struct {
				Name      string `json:"name"`
				State     string `json:"state"`
				RuleCount int    `json:"rule_count"`
			} `json:"categories"`
			Findings []struct {
				ID     string `json:"id"`
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if v.Command != "scan" || v.Data.ScanSchema != "chimera.scan/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.FindingSchema != "chimera.finding/v1" {
		t.Fatalf("unexpected scan contract: %#v", v)
	}
	if v.Data.Containers == nil || v.Data.Containers.Schema != "chimera.containers/v1" || v.Data.Containers.CollectorVersion != "containers/phase095-v1" {
		t.Fatalf("container/orchestration inventory missing from scan output: %#v", v.Data.Containers)
	}
	if v.Data.Persistence == nil || v.Data.Persistence.Schema != "chimera.persistence/v1" || v.Data.Persistence.CollectorVersion != "persistence/phase098-v1" {
		t.Fatalf("persistence inventory missing from scan output: %#v", v.Data.Persistence)
	}
	if v.Data.Secrets == nil || v.Data.Secrets.Schema != "chimera.secrets/v1" || v.Data.Secrets.CollectorVersion != "secrets/phase103-v1" {
		t.Fatalf("secret-storage inventory missing from scan output: %#v", v.Data.Secrets)
	}
	if v.Data.State == "" || v.Data.MaxWorkers != 8 || v.Data.WorkersUsed < 1 || v.Data.WorkersUsed > 8 {
		t.Fatalf("invalid orchestration metadata: %#v", v.Data)
	}
	if len(v.Data.Categories) == 0 || len(v.Data.Findings) == 0 {
		t.Fatalf("scan did not execute implemented categories: %#v", v.Data)
	}
	for i, c := range v.Data.Categories {
		if c.Name == "" || c.State == "" || c.RuleCount < 1 {
			t.Fatalf("incomplete category result: %#v", c)
		}
		if i > 0 && v.Data.Categories[i-1].Name > c.Name {
			t.Fatalf("categories are not deterministically ordered: %#v", v.Data.Categories)
		}
	}
	for _, f := range v.Data.Findings {
		if f.ID == "" || f.RuleID == "" {
			t.Fatalf("incomplete scan finding: %#v", f)
		}
	}
}

func TestScanJSONContainsPhase009DeterministicSnapshot(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--json", "--timeout", "20s", "--max-workers", "8", "--profile", "server"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Snapshot struct {
				Schema       string `json:"snapshot_schema"`
				AssessmentID string `json:"assessment_id"`
				Host         struct {
					Algorithm string   `json:"algorithm"`
					Value     string   `json:"value"`
					Inputs    []string `json:"inputs"`
				} `json:"host_fingerprint"`
				StartedAt   string `json:"started_at"`
				CollectedAt string `json:"collected_at"`
				AssessedAt  string `json:"assessed_at"`
				CompletedAt string `json:"completed_at"`
				Config      struct {
					Digest struct {
						Algorithm string `json:"algorithm"`
						Value     string `json:"value"`
					} `json:"digest"`
				} `json:"config"`
				Profile struct {
					Name   string `json:"name"`
					Digest struct {
						Value string `json:"value"`
					} `json:"digest"`
				} `json:"profile"`
				Rules struct {
					Version       string `json:"version"`
					RuleCount     int    `json:"rule_count"`
					SelectedCount int    `json:"selected_count"`
					Digest        struct {
						Value string `json:"value"`
					} `json:"digest"`
				} `json:"rules"`
				Intelligence struct {
					State   string `json:"state"`
					Schema  string `json:"schema"`
					Version string `json:"version"`
					Digest  string `json:"digest"`
				} `json:"intelligence"`
				ProductNormalization struct {
					State              string `json:"state"`
					Schema             string `json:"schema"`
					EngineVersion      string `json:"engine_version"`
					IntelligenceDigest string `json:"intelligence_digest"`
					CandidateCount     int    `json:"candidate_count"`
					MatchedCount       int    `json:"matched_count"`
				} `json:"product_normalization"`
				VulnerabilityCorrelation struct {
					State              string `json:"state"`
					Schema             string `json:"schema"`
					EngineVersion      string `json:"engine_version"`
					IntelligenceDigest string `json:"intelligence_digest"`
					EvaluationCount    int    `json:"evaluation_count"`
					AffectedCount      int    `json:"affected_count"`
					UnresolvedCount    int    `json:"unresolved_count"`
				} `json:"vulnerability_correlation"`
				VulnerabilityReachability struct {
					State                   string `json:"state"`
					Schema                  string `json:"schema"`
					CollectorVersion        string `json:"collector_version"`
					EvaluationCount         int    `json:"evaluation_count"`
					AffectedEvaluationCount int    `json:"affected_evaluation_count"`
					InstalledOnlyCount      int    `json:"installed_only_count"`
					RunningCount            int    `json:"running_count"`
					ListeningCount          int    `json:"listening_count"`
					PrivilegedCount         int    `json:"privileged_count"`
				} `json:"vulnerability_reachability"`
				Collectors []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Schema  string `json:"schema"`
					State   string `json:"state"`
				} `json:"collectors"`
			} `json:"snapshot"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	s := v.Data.Snapshot
	if s.Schema != "chimera.snapshot/v1" || !strings.HasPrefix(s.AssessmentID, "asm-") {
		t.Fatalf("unexpected snapshot identity: %#v", s)
	}
	if s.Host.Algorithm != "sha256" || len(s.Host.Value) != 64 || len(s.Host.Inputs) == 0 {
		t.Fatalf("invalid host fingerprint: %#v", s.Host)
	}
	if s.StartedAt == "" || s.CollectedAt == "" || s.AssessedAt == "" || s.CompletedAt == "" {
		t.Fatalf("snapshot timestamps incomplete: %#v", s)
	}
	if s.Config.Digest.Algorithm != "sha256" || len(s.Config.Digest.Value) != 64 {
		t.Fatalf("invalid config digest: %#v", s.Config)
	}
	if s.Profile.Name != "server" || len(s.Profile.Digest.Value) != 64 {
		t.Fatalf("invalid profile provenance: %#v", s.Profile)
	}
	if s.Rules.Version == "" || s.Rules.RuleCount < 1 || s.Rules.SelectedCount < 1 || len(s.Rules.Digest.Value) != 64 {
		t.Fatalf("invalid rule provenance: %#v", s.Rules)
	}
	if s.Intelligence.State != "PINNED_BUILTIN" || s.Intelligence.Schema != "chimera.intelligence/v1" || s.Intelligence.Version == "" || len(s.Intelligence.Digest) != 64 {
		t.Fatalf("missing vulnerability-intelligence provenance: %#v", s.Intelligence)
	}
	if s.ProductNormalization.State != "COMPLETE" || s.ProductNormalization.Schema != "chimera.product-normalization/v1" || s.ProductNormalization.EngineVersion != "productnorm/v1" || len(s.ProductNormalization.IntelligenceDigest) != 64 || s.ProductNormalization.CandidateCount < s.ProductNormalization.MatchedCount {
		t.Fatalf("missing product-normalization provenance: %#v", s.ProductNormalization)
	}
	if s.VulnerabilityCorrelation.State != "COMPLETE" || s.VulnerabilityCorrelation.Schema != "chimera.vulnerability-correlation/v1" || s.VulnerabilityCorrelation.EngineVersion != "vulncorrelator/v1" || len(s.VulnerabilityCorrelation.IntelligenceDigest) != 64 || s.VulnerabilityCorrelation.EvaluationCount < s.VulnerabilityCorrelation.AffectedCount+s.VulnerabilityCorrelation.UnresolvedCount {
		t.Fatalf("missing vulnerability-correlation provenance: %#v", s.VulnerabilityCorrelation)
	}
	if s.VulnerabilityReachability.State == "" || s.VulnerabilityReachability.Schema != "chimera.vulnerability-reachability/v1" || s.VulnerabilityReachability.CollectorVersion != "vulnreach/v1" || s.VulnerabilityReachability.EvaluationCount != s.VulnerabilityReachability.AffectedEvaluationCount {
		t.Fatalf("missing vulnerability-reachability provenance: %#v", s.VulnerabilityReachability)
	}
	if len(s.Collectors) != 17 {
		t.Fatalf("expected overview+kernel+software+processes+services+scheduled+network+firewall+remote-management+accounts+filesystem+storage+containers+persistence+secret-storage+update-posture+intelligence collector provenance: %#v", s.Collectors)
	}
	seenCollectors := map[string]bool{}
	for _, c := range s.Collectors {
		if c.Name == "" || c.Version == "" || c.Schema == "" || c.State == "" {
			t.Fatalf("invalid collector provenance: %#v", s.Collectors)
		}
		seenCollectors[c.Name] = true
	}
	if !seenCollectors["overview"] || !seenCollectors["kernel"] || !seenCollectors["software"] || !seenCollectors["processes"] || !seenCollectors["services"] || !seenCollectors["scheduled-execution"] || !seenCollectors["network-listeners"] || !seenCollectors["firewall"] || !seenCollectors["remote-management"] || !seenCollectors["accounts"] || !seenCollectors["filesystem-security"] || !seenCollectors["storage-encryption"] || !seenCollectors["container-runtime"] || !seenCollectors["persistence"] || !seenCollectors["secret-storage"] || !seenCollectors["update-posture"] || !seenCollectors["intelligence-snapshot"] {
		t.Fatalf("missing collector provenance: %#v", s.Collectors)
	}
}

func TestProcessesCommandPhase033Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"processes", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("processes json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			Schema           string `json:"schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Processes        []struct {
				PID         int `json:"pid"`
				CommandLine struct {
					Redacted bool `json:"redacted"`
				} `json:"command_line"`
			} `json:"processes"`
			RuntimePrivileges []struct {
				ProcessID         string `json:"process_id"`
				PID               int    `json:"pid"`
				State             string `json:"state"`
				PrivilegeSetState string `json:"privilege_set_state"`
			} `json:"runtime_privileges"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid processes json: %v\n%s", err, out.String())
	}
	if v.Command != "processes" || v.Data.Schema != "chimera.processes/v1" || v.Data.Collector != "processes" || v.Data.CollectorVersion != "processes/v1" {
		t.Fatalf("unexpected process contract: %#v", v)
	}
	for _, p := range v.Data.Processes {
		if p.PID <= 0 || !p.CommandLine.Redacted {
			t.Fatalf("invalid/redaction-unsafe process record: %#v", p)
		}
	}
}

func TestServicesCommandPhase043Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"services", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("services json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Services         []struct {
				ID                  string `json:"id"`
				Name                string `json:"name"`
				Manager             string `json:"manager"`
				Account             string `json:"account"`
				StartMode           string `json:"start_mode"`
				RuntimeState        string `json:"runtime_state"`
				PrivilegeContext    string `json:"privilege_context"`
				ConfigurationSource string `json:"configuration_source"`
				CollectionSource    string `json:"collection_source"`
				Confidence          string `json:"confidence"`
			} `json:"services"`
			Sources []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"sources"`
			Evidence []struct {
				Key string `json:"key"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid services json: %v\n%s", err, out.String())
	}
	if v.Command != "services" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.services/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "services" || v.Data.CollectorVersion != "services/phase048-v1" {
		t.Fatalf("unexpected service contract: %#v", v)
	}
	if len(v.Data.Sources) == 0 || len(v.Data.Evidence) < 4 {
		t.Fatalf("service inventory lacks provider/evidence provenance: %#v", v.Data)
	}
	for _, svc := range v.Data.Services {
		if svc.ID == "" || svc.Name == "" || svc.Manager == "" || svc.Account == "" || svc.StartMode == "" || svc.RuntimeState == "" || svc.PrivilegeContext == "" || svc.ConfigurationSource == "" || svc.CollectionSource == "" || svc.Confidence == "" {
			t.Fatalf("incomplete service record: %#v", svc)
		}
	}
}

func TestSoftwareCommandPhase024Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"software", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("software json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			Schema         string `json:"software_schema"`
			EvidenceSchema string `json:"evidence_schema"`
			Platform       string `json:"platform"`
			Architecture   string `json:"architecture"`
			Sources        []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"sources"`
			Items []struct {
				Product       string `json:"product"`
				Version       string `json:"version"`
				PackageSource string `json:"package_source"`
				SupportState  string `json:"support_state"`
			} `json:"items"`
			RuntimeSources []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"runtime_sources"`
			Runtimes []struct {
				ID         string `json:"id"`
				Family     string `json:"family"`
				Kind       string `json:"kind"`
				Product    string `json:"product"`
				Version    string `json:"version"`
				Executable string `json:"executable"`
			} `json:"runtimes"`
			InfrastructureSources []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"infrastructure_sources"`
			Infrastructure []struct {
				ID        string `json:"id"`
				Role      string `json:"role"`
				Family    string `json:"family"`
				Product   string `json:"product"`
				Version   string `json:"version"`
				Installed bool   `json:"installed"`
				Running   bool   `json:"running"`
			} `json:"infrastructure"`
			ClientSources []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"client_sources"`
			Browsers []struct {
				ID      string `json:"id"`
				Family  string `json:"family"`
				Product string `json:"product"`
				Version string `json:"version"`
				Channel string `json:"channel"`
			} `json:"browsers"`
			HighRiskClients []struct {
				ID              string   `json:"id"`
				Category        string   `json:"category"`
				Family          string   `json:"family"`
				Product         string   `json:"product"`
				Version         string   `json:"version"`
				ContentSurfaces []string `json:"content_surfaces"`
			} `json:"high_risk_clients"`
			AttributionSources []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"attribution_sources"`
			BinaryAttributions []struct {
				ID            string `json:"id"`
				Path          string `json:"path"`
				ResolvedPath  string `json:"resolved_path"`
				PathState     string `json:"path_state"`
				Ownership     string `json:"ownership"`
				Distribution  string `json:"distribution"`
				PackageID     string `json:"package_id"`
				Provider      string `json:"provider"`
				ProviderState string `json:"provider_state"`
				Method        string `json:"method"`
				Confidence    string `json:"confidence"`
				Targets       []struct {
					Kind string `json:"kind"`
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"targets"`
			} `json:"binary_attributions"`
			ProductNormalization struct {
				Schema              string `json:"schema"`
				EngineVersion       string `json:"engine_version"`
				State               string `json:"state"`
				IntelligenceVersion string `json:"intelligence_version"`
				IntelligenceDigest  string `json:"intelligence_digest"`
				Summary             struct {
					Candidates int `json:"candidates"`
					Matched    int `json:"matched"`
					Unmatched  int `json:"unmatched"`
					Ambiguous  int `json:"ambiguous"`
				} `json:"summary"`
			} `json:"product_normalization"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid software json: %v\n%s", err, out.String())
	}
	if v.Command != "software" || v.Data.Schema != "chimera.software/v5" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Platform == "" || v.Data.Architecture == "" {
		t.Fatalf("unexpected software contract: %#v", v)
	}
	if len(v.Data.Sources) == 0 {
		t.Fatal("software inventory did not report provider state")
	}
	if len(v.Data.RuntimeSources) == 0 {
		t.Fatal("runtime/framework inventory did not report provider state")
	}
	if len(v.Data.InfrastructureSources) == 0 {
		t.Fatal("server/infrastructure inventory did not report provider state")
	}
	if len(v.Data.ClientSources) == 0 {
		t.Fatal("browser/high-risk-client inventory did not report provider state")
	}
	if len(v.Data.AttributionSources) == 0 {
		t.Fatal("binary attribution did not report provider state")
	}
	if v.Data.ProductNormalization.Schema != "chimera.product-normalization/v1" || v.Data.ProductNormalization.EngineVersion != "productnorm/v1" || v.Data.ProductNormalization.State != "COMPLETE" || v.Data.ProductNormalization.IntelligenceVersion == "" || len(v.Data.ProductNormalization.IntelligenceDigest) != 64 {
		t.Fatalf("unexpected product normalization contract: %#v", v.Data.ProductNormalization)
	}
	if v.Data.ProductNormalization.Summary.Candidates != v.Data.ProductNormalization.Summary.Matched+v.Data.ProductNormalization.Summary.Unmatched+v.Data.ProductNormalization.Summary.Ambiguous {
		t.Fatalf("inconsistent normalization summary: %#v", v.Data.ProductNormalization.Summary)
	}
	for _, b := range v.Data.Browsers {
		if b.ID == "" || b.Family == "" || b.Product == "" || b.Version == "" || b.Channel == "" {
			t.Fatalf("incomplete browser record: %#v", b)
		}
	}
	for _, c := range v.Data.HighRiskClients {
		if c.ID == "" || c.Category == "" || c.Family == "" || c.Product == "" || c.Version == "" || len(c.ContentSurfaces) == 0 {
			t.Fatalf("incomplete high-risk client record: %#v", c)
		}
	}
	for _, item := range v.Data.Infrastructure {
		if item.ID == "" || item.Role == "" || item.Family == "" || item.Product == "" || item.Version == "" || (!item.Installed && !item.Running) {
			t.Fatalf("incomplete infrastructure record: %#v", item)
		}
	}
	for _, r := range v.Data.Runtimes {
		if r.ID == "" || r.Family == "" || r.Kind == "" || r.Product == "" || r.Version == "" || r.Executable == "" {
			t.Fatalf("incomplete runtime record: %#v", r)
		}
	}
	for _, a := range v.Data.BinaryAttributions {
		if a.ID == "" || a.Path == "" || a.ResolvedPath == "" || a.PathState == "" || a.Ownership == "" || a.Distribution == "" || a.PackageID == "" || a.Provider == "" || a.ProviderState == "" || a.Method == "" || a.Confidence == "" || len(a.Targets) == 0 {
			t.Fatalf("incomplete attribution record: %#v", a)
		}
	}
}

func TestVulnerabilitiesCommandPhase027Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"vulnerabilities", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("vulnerabilities json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Software struct {
				Schema string `json:"software_schema"`
			} `json:"software"`
			ProductNormalization struct {
				Schema string `json:"schema"`
				State  string `json:"state"`
			} `json:"product_normalization"`
			Correlation struct {
				Schema        string `json:"schema"`
				EngineVersion string `json:"engine_version"`
				State         string `json:"state"`
				Summary       struct {
					Evaluations int `json:"evaluations"`
					Affected    int `json:"affected"`
					NotAffected int `json:"not_affected"`
					Unresolved  int `json:"unresolved"`
				} `json:"summary"`
				Evaluations []struct {
					ID              string `json:"id"`
					VulnerabilityID string `json:"vulnerability_id"`
					CandidateRef    string `json:"candidate_ref"`
					State           string `json:"state"`
					Reason          string `json:"reason"`
				} `json:"evaluations"`
			} `json:"vulnerability_correlation"`
			Reachability struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
				State            string `json:"state"`
				RuntimeSnapshot  struct {
					Schema string `json:"schema"`
					State  string `json:"state"`
				} `json:"runtime_snapshot"`
				Summary struct {
					Evaluations   int `json:"evaluations"`
					InstalledOnly int `json:"installed_only"`
					Running       int `json:"running"`
					Listening     int `json:"listening"`
					Privileged    int `json:"privileged"`
				} `json:"summary"`
				Contexts []struct {
					CorrelationID string `json:"correlation_id"`
					Tier          string `json:"tier"`
				} `json:"contexts"`
			} `json:"vulnerability_reachability"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid vulnerabilities json: %v\n%s", err, out.String())
	}
	if v.Command != "vulnerabilities" || v.Version.Version != "1.0.0" || v.Data.Software.Schema != "chimera.software/v5" || v.Data.ProductNormalization.Schema != "chimera.product-normalization/v1" || v.Data.ProductNormalization.State != "COMPLETE" {
		t.Fatalf("unexpected vulnerabilities command prerequisites: %#v", v)
	}
	if v.Data.Correlation.Schema != "chimera.vulnerability-correlation/v1" || v.Data.Correlation.EngineVersion != "vulncorrelator/v1" || v.Data.Correlation.State != "COMPLETE" {
		t.Fatalf("unexpected correlation contract: %#v", v.Data.Correlation)
	}
	if v.Data.Correlation.Summary.Evaluations != v.Data.Correlation.Summary.Affected+v.Data.Correlation.Summary.NotAffected+v.Data.Correlation.Summary.Unresolved || v.Data.Correlation.Summary.Evaluations != len(v.Data.Correlation.Evaluations) {
		t.Fatalf("inconsistent correlation summary: %#v", v.Data.Correlation)
	}
	for _, ev := range v.Data.Correlation.Evaluations {
		if ev.ID == "" || ev.VulnerabilityID == "" || ev.CandidateRef == "" || ev.State == "" || ev.Reason == "" {
			t.Fatalf("incomplete correlation record: %#v", ev)
		}
	}
	if v.Data.Reachability.Schema != "chimera.vulnerability-reachability/v1" || v.Data.Reachability.CollectorVersion != "vulnreach/v1" || v.Data.Reachability.State == "" || v.Data.Reachability.RuntimeSnapshot.Schema != "chimera.vulnerability-reachability/v1/runtime" || v.Data.Reachability.RuntimeSnapshot.State == "" {
		t.Fatalf("unexpected reachability contract: %#v", v.Data.Reachability)
	}
	if v.Data.Reachability.Summary.Evaluations != len(v.Data.Reachability.Contexts) {
		t.Fatalf("inconsistent reachability summary: %#v", v.Data.Reachability)
	}
	for _, c := range v.Data.Reachability.Contexts {
		if c.CorrelationID == "" || c.Tier == "" {
			t.Fatalf("incomplete reachability context: %#v", c)
		}
	}
}

func TestKernelJSONPhase016Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"kernel", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("kernel json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema         string `json:"kernel_schema"`
			EvidenceSchema string `json:"evidence_schema"`
			Platform       string `json:"platform"`
			KernelRelease  string `json:"kernel_release"`
			SecureBoot     struct {
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"secure_boot"`
			IntegrityControls []struct {
				ID              string `json:"id"`
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"integrity_controls"`
			MemoryMitigations []struct {
				ID              string `json:"id"`
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"memory_mitigations"`
			DebugExposure []struct {
				ID              string `json:"id"`
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"debug_exposure"`
			UnprivilegedFeatures []struct {
				ID              string `json:"id"`
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"unprivileged_kernel_features"`
			LoadedModules []struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				CollectionState string `json:"collection_state"`
				LoadState       string `json:"load_state"`
				SignatureState  string `json:"signature_state"`
				TrustState      string `json:"trust_state"`
				BackingState    string `json:"backing_state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"loaded_modules"`
			DriverIntelligence struct {
				Schema          string `json:"schema"`
				Version         string `json:"version"`
				Source          string `json:"source"`
				PlatformEntries int    `json:"platform_entries"`
				CandidateCount  int    `json:"candidate_count"`
				MatchCount      int    `json:"match_count"`
			} `json:"driver_intelligence"`
			VulnerableDrivers []struct {
				ID              string `json:"id"`
				InstalledState  string `json:"installed_state"`
				LoadState       string `json:"load_state"`
				ExposureState   string `json:"exposure_state"`
				ResolutionState string `json:"resolution_state"`
			} `json:"vulnerable_drivers"`
			MandatoryAccess []struct {
				ID              string `json:"id"`
				Framework       string `json:"framework"`
				CollectionState string `json:"collection_state"`
				State           string `json:"state"`
				Provider        string `json:"provider"`
				Source          string `json:"source"`
				Confidence      string `json:"confidence"`
			} `json:"mandatory_access_controls"`
			Capabilities []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"hardening_capabilities"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid kernel json: %v\n%s", err, out.String())
	}
	if v.Command != "kernel" || v.Data.Schema != "chimera.kernel/v9" || v.Data.EvidenceSchema != "chimera.evidence/v1" {
		t.Fatalf("unexpected kernel contract: %#v", v)
	}
	if v.Data.Platform == "" || v.Data.KernelRelease == "" || v.Data.SecureBoot.CollectionState == "" || v.Data.SecureBoot.State == "" || v.Data.SecureBoot.Provider == "" || v.Data.SecureBoot.Source == "" || v.Data.SecureBoot.Confidence == "" || len(v.Data.IntegrityControls) == 0 || v.Data.IntegrityControls[0].ID == "" || v.Data.IntegrityControls[0].CollectionState == "" || v.Data.IntegrityControls[0].State == "" || v.Data.IntegrityControls[0].Provider == "" || v.Data.IntegrityControls[0].Source == "" || v.Data.IntegrityControls[0].Confidence == "" || len(v.Data.MemoryMitigations) == 0 || v.Data.MemoryMitigations[0].ID == "" || v.Data.MemoryMitigations[0].CollectionState == "" || v.Data.MemoryMitigations[0].State == "" || v.Data.MemoryMitigations[0].Provider == "" || v.Data.MemoryMitigations[0].Source == "" || v.Data.MemoryMitigations[0].Confidence == "" || len(v.Data.DebugExposure) == 0 || v.Data.DebugExposure[0].ID == "" || v.Data.DebugExposure[0].CollectionState == "" || v.Data.DebugExposure[0].State == "" || v.Data.DebugExposure[0].Provider == "" || v.Data.DebugExposure[0].Source == "" || v.Data.DebugExposure[0].Confidence == "" || len(v.Data.UnprivilegedFeatures) == 0 || v.Data.UnprivilegedFeatures[0].ID == "" || v.Data.UnprivilegedFeatures[0].CollectionState == "" || v.Data.UnprivilegedFeatures[0].State == "" || v.Data.UnprivilegedFeatures[0].Provider == "" || v.Data.UnprivilegedFeatures[0].Source == "" || v.Data.UnprivilegedFeatures[0].Confidence == "" || len(v.Data.LoadedModules) == 0 || v.Data.LoadedModules[0].ID == "" || v.Data.LoadedModules[0].Name == "" || v.Data.LoadedModules[0].CollectionState == "" || v.Data.LoadedModules[0].LoadState == "" || v.Data.LoadedModules[0].SignatureState == "" || v.Data.LoadedModules[0].TrustState == "" || v.Data.LoadedModules[0].BackingState == "" || v.Data.LoadedModules[0].Provider == "" || v.Data.LoadedModules[0].Source == "" || v.Data.LoadedModules[0].Confidence == "" || v.Data.DriverIntelligence.Schema != "chimera.driver-intelligence/v1" || v.Data.DriverIntelligence.Version == "" || v.Data.DriverIntelligence.Source == "" || len(v.Data.MandatoryAccess) == 0 || v.Data.MandatoryAccess[0].ID == "" || v.Data.MandatoryAccess[0].Framework == "" || v.Data.MandatoryAccess[0].CollectionState == "" || v.Data.MandatoryAccess[0].State == "" || v.Data.MandatoryAccess[0].Provider == "" || v.Data.MandatoryAccess[0].Source == "" || v.Data.MandatoryAccess[0].Confidence == "" || len(v.Data.Capabilities) == 0 || len(v.Data.Evidence) == 0 {
		t.Fatalf("incomplete kernel inventory: %#v", v.Data)
	}
	if v.Version.Version != "1.0.0" {
		t.Fatalf("unexpected version %q", v.Version.Version)
	}
}

func TestOverviewJSONContainsPhase001EvidenceContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"overview", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			EvidenceSchema string `json:"evidence_schema"`
			Evidence       []struct {
				Key        string `json:"key"`
				State      string `json:"state"`
				Source     string `json:"source"`
				Confidence string `json:"confidence"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if v.Command != "overview" {
		t.Fatalf("unexpected command %q", v.Command)
	}
	if v.Data.EvidenceSchema != "chimera.evidence/v1" {
		t.Fatalf("unexpected evidence schema %q", v.Data.EvidenceSchema)
	}
	if len(v.Data.Evidence) == 0 {
		t.Fatal("missing evidence observations")
	}
	for _, e := range v.Data.Evidence {
		if e.Key == "" || e.State == "" || e.Source == "" || e.Confidence == "" {
			t.Fatalf("incomplete evidence observation: %#v", e)
		}
	}
}

func TestFindingsJSONContainsPhase002Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("findings json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			FindingSchema  string `json:"finding_schema"`
			EvidenceSchema string `json:"evidence_schema"`
			Findings       []struct {
				ID            string `json:"id"`
				RuleID        string `json:"rule_id"`
				Status        string `json:"status"`
				Severity      string `json:"severity"`
				Confidence    string `json:"confidence"`
				Observed      string `json:"observed_state"`
				Expected      string `json:"expected_state"`
				Remediation   string `json:"remediation"`
				Applicability string `json:"applicability"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if v.Command != "findings" || v.Data.FindingSchema != "chimera.finding/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" {
		t.Fatalf("unexpected contract: %#v", v)
	}
	if len(v.Data.Findings) == 0 {
		t.Fatal("no findings returned")
	}
	for _, f := range v.Data.Findings {
		if f.ID == "" || f.RuleID == "" || f.Status == "" || f.Severity == "" || f.Confidence == "" || f.Observed == "" || f.Expected == "" || f.Remediation == "" || f.Applicability == "" {
			t.Fatalf("incomplete finding: %#v", f)
		}
	}
}

func TestFocusedFindingCommandsPhase004(t *testing.T) {
	var findingsOut, errOut bytes.Buffer
	if err := Run([]string{"findings", "--json", "--timeout", "10s"}, &findingsOut, &errOut); err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Data struct {
			Findings []struct {
				ID string `json:"id"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(findingsOut.Bytes(), &listing); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(listing.Data.Findings) == 0 || listing.Data.Findings[0].ID == "" {
		t.Fatal("no stable finding id available for focused inspection")
	}
	id := listing.Data.Findings[0].ID

	for _, command := range []string{"finding", "explain", "evidence"} {
		var out bytes.Buffer
		if err := Run([]string{command, id, "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
			t.Fatalf("%s failed: %v", command, err)
		}
		if strings.Contains(out.String(), "\x1b[") {
			t.Fatalf("%s json contains ANSI", command)
		}
		var env struct {
			Command string         `json:"command"`
			Data    map[string]any `json:"data"`
		}
		if err := json.Unmarshal(out.Bytes(), &env); err != nil {
			t.Fatalf("%s invalid json: %v\n%s", command, err, out.String())
		}
		if env.Command != command {
			t.Fatalf("%s returned command %q", command, env.Command)
		}
		if env.Data["inspection_schema"] != "chimera.finding-inspection/v1" {
			t.Fatalf("%s missing phase 004 inspection schema: %#v", command, env.Data)
		}
		repro, ok := env.Data["reproducibility"].(map[string]any)
		if !ok || repro["evidence_digest"] == "" || repro["derived_finding_id"] != id || repro["matches_finding_id"] != true {
			t.Fatalf("%s missing reproducibility metadata: %#v", command, repro)
		}
	}
}

func TestFocusedFindingRequiresExactlyOneID(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"finding", "--json"}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "requires <id>") {
		t.Fatalf("expected missing-id usage error, got %v", err)
	}
	if err := Run([]string{"explain", "one", "two", "--json"}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "at most 1") {
		t.Fatalf("expected extra-argument error, got %v", err)
	}
}

func TestFocusedFindingRejectsUnknownID(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"evidence", "CHM-F-0000000000000000", "--json", "--timeout", "10s"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected current-snapshot not-found error, got %v", err)
	}
}

func TestProfilesJSONPhase005CatalogAndPolicy(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"profiles", "--profile", "high-security", "--json"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("profiles json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			Schema string `json:"profile_schema"`
			Active struct {
				Name string `json:"name"`
			} `json:"active"`
			Catalog []struct {
				Name string `json:"name"`
			} `json:"catalog"`
			RuleDecisions []struct {
				RuleID            string `json:"rule_id"`
				Applicable        bool   `json:"applicable"`
				BaseSeverity      string `json:"base_severity"`
				EffectiveSeverity string `json:"effective_severity"`
			} `json:"rule_decisions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid profiles json: %v\n%s", err, out.String())
	}
	if v.Command != "profiles" || v.Data.Schema != "chimera.profile/v2" || v.Data.Active.Name != "high-security" {
		t.Fatalf("unexpected profile contract: %#v", v)
	}
	want := map[string]bool{"default": true, "workstation": true, "server": true, "developer": true, "high-security": true, "minimal": true}
	for _, p := range v.Data.Catalog {
		delete(want, p.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing required profiles: %#v", want)
	}
	if len(v.Data.RuleDecisions) == 0 {
		t.Fatal("missing active profile rule decisions")
	}
	raised := false
	for _, d := range v.Data.RuleDecisions {
		if d.RuleID == "" || d.BaseSeverity == "" || d.EffectiveSeverity == "" {
			t.Fatalf("incomplete rule decision: %#v", d)
		}
		if d.BaseSeverity != d.EffectiveSeverity {
			raised = true
		}
	}
	if !raised {
		t.Fatal("high-security profile did not raise any current core severity")
	}
}

func TestProfilesJSONPhase110CustomEnterpriseProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "chimera.json")
	data := []byte(`{
  "profile":"prod-web",
  "custom_profiles":[{
    "name":"prod-web",
    "extends":"server",
    "description":"Production web host",
    "disabled_rules":["CHM-CTR-023"],
    "severity_overrides":{"CHM-NET-008":"HIGH"},
    "environment":{"environment":"production","role":"web"},
    "port_policy_mode":"required",
    "expected_ports":[{"protocol":"TCP","port":443,"binding":"EXTERNAL","required":true}]
  }]
}`)
	if err := os.WriteFile(cfg, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := Run([]string{"profiles", "--config", cfg, "--json"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema string `json:"profile_schema"`
			Active struct {
				Name          string `json:"name"`
				Custom        bool   `json:"custom"`
				Extends       string `json:"extends"`
				Behavior      string `json:"behavior_profile"`
				PolicyVersion string `json:"policy_version"`
			} `json:"active"`
			Catalog []struct {
				Name   string `json:"name"`
				Custom bool   `json:"custom"`
			} `json:"catalog"`
			RuleDecisions []struct {
				RuleID            string `json:"rule_id"`
				Applicable        bool   `json:"applicable"`
				EffectiveSeverity string `json:"effective_severity"`
			} `json:"rule_decisions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid profiles json: %v\n%s", err, out.String())
	}
	if v.Command != "profiles" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.profile/v2" {
		t.Fatalf("unexpected profile envelope: %#v", v)
	}
	if v.Data.Active.Name != "prod-web" || !v.Data.Active.Custom || v.Data.Active.Extends != "server" || v.Data.Active.Behavior != "server" || v.Data.Active.PolicyVersion != "chimera.enterprise-policy/v1-phase110" {
		t.Fatalf("custom profile not resolved correctly: %#v", v.Data.Active)
	}
	foundCatalog, foundDisabled, foundOverride, foundEnterprise := false, false, false, false
	for _, item := range v.Data.Catalog {
		if item.Name == "prod-web" && item.Custom {
			foundCatalog = true
		}
	}
	for _, d := range v.Data.RuleDecisions {
		switch d.RuleID {
		case "CHM-CTR-023":
			foundDisabled = !d.Applicable
		case "CHM-NET-008":
			foundOverride = d.EffectiveSeverity == "HIGH"
		case "CHM-ENT-002":
			foundEnterprise = d.Applicable
		}
	}
	if !foundCatalog || !foundDisabled || !foundOverride || !foundEnterprise {
		t.Fatalf("custom profile policy incomplete: catalog=%t disabled=%t override=%t enterprise=%t", foundCatalog, foundDisabled, foundOverride, foundEnterprise)
	}
}

func TestMinimalProfileKeepsRulesVisibleAsNotApplicable(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--profile", "minimal", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Profile struct {
				Name string `json:"name"`
			} `json:"profile"`
			Findings []struct {
				RuleID        string `json:"rule_id"`
				Applicability string `json:"applicability"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid findings json: %v\n%s", err, out.String())
	}
	if v.Data.Profile.Name != "minimal" {
		t.Fatalf("unexpected active profile %q", v.Data.Profile.Name)
	}
	byRule := map[string]string{}
	for _, f := range v.Data.Findings {
		byRule[f.RuleID] = f.Applicability
	}
	if byRule["CHM-CORE-004"] != "NOT_APPLICABLE" || byRule["CHM-CORE-005"] != "NOT_APPLICABLE" {
		t.Fatalf("minimal profile did not retain identity/network findings as N/A: %#v", byRule)
	}
	if byRule["CHM-CORE-001"] == "NOT_APPLICABLE" || byRule["CHM-CORE-002"] == "NOT_APPLICABLE" || byRule["CHM-CORE-003"] == "NOT_APPLICABLE" {
		t.Fatalf("minimal profile incorrectly disabled core collection/inventory: %#v", byRule)
	}
}

func TestUnknownProfileFailsClosed(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"scan", "--profile", "not-a-profile", "--json"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown assessment profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

func TestScanJSONCarriesActiveProfilePhase005(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--profile", "server", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Profile struct {
				Descriptor struct {
					Name string `json:"name"`
				} `json:"descriptor"`
				RuleDecisions []struct {
					RuleID string `json:"rule_id"`
				} `json:"rule_decisions"`
			} `json:"profile"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	if v.Data.Profile.Descriptor.Name != "server" || len(v.Data.Profile.RuleDecisions) == 0 {
		t.Fatalf("missing profile metadata: %#v", v.Data.Profile)
	}
}

func TestFindingsJSONPhase006RuleSelectionLedger(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--include", "network", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Selection struct {
				Schema  string `json:"selection_schema"`
				Summary struct {
					Total      int `json:"total"`
					Selected   int `json:"selected"`
					Skipped    int `json:"skipped"`
					Suppressed int `json:"suppressed"`
				} `json:"summary"`
				Decisions []struct {
					RuleID  string `json:"rule_id"`
					Outcome string `json:"outcome"`
					Reason  string `json:"reason"`
				} `json:"decisions"`
			} `json:"selection"`
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid findings json: %v\n%s", err, out.String())
	}
	totalRules := len(assessment.ImplementedRules())
	networkRules := 0
	for _, r := range assessment.ImplementedRules() {
		if r.Category == "network" {
			networkRules++
		}
	}
	if v.Data.Selection.Schema != "chimera.selection/v1" || v.Data.Selection.Summary.Total != totalRules || v.Data.Selection.Summary.Selected != networkRules || v.Data.Selection.Summary.Skipped != totalRules-networkRules || v.Data.Selection.Summary.Suppressed != 0 {
		t.Fatalf("unexpected selection summary: %#v", v.Data.Selection)
	}
	if len(v.Data.Findings) != networkRules {
		t.Fatalf("include category did not constrain findings to network rules: %#v", v.Data.Findings)
	}
	wantNetwork := map[string]bool{}
	for _, r := range assessment.ImplementedRules() {
		if r.Category == "network" {
			wantNetwork[r.ID] = false
		}
	}
	for _, f := range v.Data.Findings {
		if _, ok := wantNetwork[f.RuleID]; !ok {
			t.Fatalf("unexpected network finding %s", f.RuleID)
		}
		wantNetwork[f.RuleID] = true
	}
	for id, seen := range wantNetwork {
		if !seen {
			t.Fatalf("missing selected network rule %s", id)
		}
	}
	for _, d := range v.Data.Selection.Decisions {
		if d.RuleID == "" || d.Outcome == "" || d.Reason == "" {
			t.Fatalf("incomplete selection decision: %#v", d)
		}
	}
}

func TestScanJSONPhase006ExcludeAndSeveritySelection(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--profile", "high-security", "--severity", "LOW", "--exclude", "network", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Selection struct {
				Summary struct {
					Selected   int `json:"selected"`
					Skipped    int `json:"skipped"`
					Suppressed int `json:"suppressed"`
				} `json:"summary"`
				Decisions []struct {
					RuleID            string `json:"rule_id"`
					EffectiveSeverity string `json:"effective_severity"`
					Outcome           string `json:"outcome"`
				} `json:"decisions"`
			} `json:"selection"`
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	networkRules := 0
	for _, r := range assessment.ImplementedRules() {
		if r.Category == "network" {
			networkRules++
		}
	}
	if v.Data.Selection.Summary.Selected != len(assessment.ImplementedRules())-networkRules || v.Data.Selection.Summary.Suppressed != networkRules || v.Data.Selection.Summary.Skipped != 0 {
		t.Fatalf("unexpected selection summary: %#v", v.Data.Selection.Summary)
	}
	for _, f := range v.Data.Findings {
		if f.RuleID == "CHM-CORE-005" || strings.HasPrefix(f.RuleID, "CHM-NET-") {
			t.Fatal("excluded network rule was evaluated")
		}
	}
	suppressed := map[string]bool{}
	for _, d := range v.Data.Selection.Decisions {
		if d.RuleID == "CHM-CORE-005" || strings.HasPrefix(d.RuleID, "CHM-NET-") {
			suppressed[d.RuleID] = d.Outcome == "SUPPRESSED"
		}
	}
	if len(suppressed) != networkRules {
		t.Fatalf("missing network suppression ledger entries: %#v", v.Data.Selection.Decisions)
	}
	for id, ok := range suppressed {
		if !ok {
			t.Fatalf("network rule %s was not suppressed", id)
		}
	}
}

func TestPhase006UnknownSelectionFailsClosed(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"findings", "--category", "not-a-real-category", "--json"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown category") {
		t.Fatalf("expected fail-closed category error, got %v", err)
	}
	err = Run([]string{"scan", "--include", "not-a-real-rule", "--json"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown selector") {
		t.Fatalf("expected fail-closed include error, got %v", err)
	}
}

func TestPhase006SeverityThresholdCanSelectNoRulesWithoutInventingFindings(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--profile", "default", "--severity", "MEDIUM", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Selection struct {
				Summary struct {
					Selected int `json:"selected"`
					Skipped  int `json:"skipped"`
				} `json:"summary"`
			} `json:"selection"`
			Findings []any `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid findings json: %v\n%s", err, out.String())
	}
	if v.Data.Selection.Summary.Selected == 0 || v.Data.Selection.Summary.Selected != len(v.Data.Findings) || v.Data.Selection.Summary.Selected+v.Data.Selection.Summary.Skipped != len(assessment.ImplementedRules()) {
		t.Fatalf("severity threshold should select only the implemented MEDIUM+ rules: %#v", v.Data)
	}
}

func TestOverviewJSONContainsPhase007PrivilegeContext(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"overview", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("overview json contains ANSI")
	}
	var v struct {
		Data struct {
			PrivilegeSchema string `json:"privilege_schema"`
			Privilege       struct {
				Schema                  string `json:"schema"`
				Level                   string `json:"level"`
				CollectionTier          string `json:"collection_tier"`
				ElevationNote           string `json:"elevation_note"`
				DeeperEvidenceAvailable bool   `json:"deeper_evidence_available"`
			} `json:"privilege"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid overview json: %v\n%s", err, out.String())
	}
	if v.Data.PrivilegeSchema != "chimera.privilege/v1" || v.Data.Privilege.Schema != "chimera.privilege/v1" {
		t.Fatalf("missing phase 007 privilege schema: %#v", v.Data)
	}
	if v.Data.Privilege.Level == "" || v.Data.Privilege.CollectionTier == "" || v.Data.Privilege.ElevationNote == "" {
		t.Fatalf("incomplete privilege context: %#v", v.Data.Privilege)
	}
	seen := map[string]bool{
		"host.privilege":                           false,
		"host.privilege.elevated":                  false,
		"host.privilege.collection_tier":           false,
		"host.privilege.deeper_evidence_available": false,
		"host.privilege.elevation_note":            false,
	}
	for _, e := range v.Data.Evidence {
		if _, ok := seen[e.Key]; ok {
			seen[e.Key] = e.State != ""
		}
	}
	for key, ok := range seen {
		if !ok {
			t.Fatalf("missing phase 007 evidence key %q", key)
		}
	}
}

func TestDoctorJSONPhase008Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"doctor", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("doctor json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema       string `json:"doctor_schema"`
			State        string `json:"state"`
			Platform     string `json:"platform"`
			Architecture string `json:"architecture"`
			Collectors   []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"collectors"`
			Permissions []struct {
				ID string `json:"id"`
			} `json:"permissions"`
			Summary struct {
				Total int `json:"total"`
			} `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid doctor json: %v\n%s", err, out.String())
	}
	if v.Command != "doctor" || v.Data.Schema != "chimera.doctor/v1" {
		t.Fatalf("unexpected doctor contract: %#v", v)
	}
	if v.Version.Version != "1.0.0" {
		t.Fatalf("unexpected version %q", v.Version.Version)
	}
	if v.Data.State == "" || v.Data.Platform == "" || v.Data.Architecture == "" || len(v.Data.Collectors) == 0 || len(v.Data.Permissions) == 0 || v.Data.Summary.Total == 0 {
		t.Fatalf("incomplete doctor result: %#v", v.Data)
	}
}

func TestDoctorDiagnosesInvalidActiveConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "chimera.json"), []byte(`{"unknown_phase008_key":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	var out, errOut bytes.Buffer
	if err := Run([]string{"doctor", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatalf("doctor should diagnose invalid config instead of failing before diagnostics: %v", err)
	}
	var v struct {
		Data struct {
			Config struct {
				State  string `json:"state"`
				Detail string `json:"detail"`
			} `json:"config"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Data.Config.State != "FAIL" || !strings.Contains(v.Data.Config.Detail, "unknown field") {
		t.Fatalf("expected invalid-config doctor finding, got %#v", v.Data.Config)
	}
}

func TestIntelligenceJSONPhase025Contract(t *testing.T) {
	t.Setenv("CHIMERA_INTELLIGENCE_DIR", "")
	var out, errOut bytes.Buffer
	if err := Run([]string{"intelligence", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("intelligence json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Metadata struct {
				Schema             string `json:"schema"`
				Version            string `json:"version"`
				State              string `json:"state"`
				Digest             string `json:"digest"`
				ProductCount       int    `json:"product_count"`
				VulnerabilityCount int    `json:"vulnerability_count"`
			} `json:"metadata"`
			Store struct {
				Products []struct {
					ID string `json:"id"`
				} `json:"products"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Affected []struct {
						ProductID string `json:"product_id"`
						Ranges    []struct {
							Kind string `json:"kind"`
						} `json:"ranges"`
					} `json:"affected"`
				} `json:"vulnerabilities"`
			} `json:"store"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid intelligence json: %v\n%s", err, out.String())
	}
	if v.Command != "intelligence" || v.Version.Version != "1.0.0" || v.Data.Metadata.Schema != "chimera.intelligence/v1" || v.Data.Metadata.State != "PINNED_BUILTIN" || len(v.Data.Metadata.Digest) != 64 {
		t.Fatalf("unexpected intelligence contract: %#v", v)
	}
	if v.Data.Metadata.ProductCount != len(v.Data.Store.Products) || v.Data.Metadata.VulnerabilityCount != len(v.Data.Store.Vulnerabilities) || len(v.Data.Store.Products) == 0 || len(v.Data.Store.Vulnerabilities) == 0 {
		t.Fatalf("incomplete intelligence store: %#v", v.Data)
	}
	for _, vuln := range v.Data.Store.Vulnerabilities {
		if vuln.ID == "" || len(vuln.Affected) == 0 || vuln.Affected[0].ProductID == "" || len(vuln.Affected[0].Ranges) == 0 || vuln.Affected[0].Ranges[0].Kind == "" {
			t.Fatalf("vulnerability lacks product/range contract: %#v", vuln)
		}
	}
}

func TestSoftwareCommandPhase029LifecycleContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"software", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Lifecycle struct {
				Schema              string `json:"schema"`
				EngineVersion       string `json:"engine_version"`
				State               string `json:"state"`
				IntelligenceVersion string `json:"intelligence_version"`
				IntelligenceDigest  string `json:"intelligence_digest"`
				Summary             struct {
					Candidates       int `json:"candidates"`
					WithIntelligence int `json:"with_intelligence"`
					Supported        int `json:"supported"`
					EndOfLife        int `json:"end_of_life"`
					Unsupported      int `json:"unsupported"`
					Unknown          int `json:"unknown"`
					NoIntelligence   int `json:"no_intelligence"`
				} `json:"summary"`
				Evaluations []struct {
					ID           string `json:"id"`
					CandidateRef string `json:"candidate_ref"`
					Status       string `json:"status"`
					Reason       string `json:"reason"`
				} `json:"evaluations"`
			} `json:"lifecycle"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid software json: %v\n%s", err, out.String())
	}
	life := v.Data.Lifecycle
	if v.Command != "software" || v.Version.Version != "1.0.0" || life.Schema != "chimera.lifecycle/v1" || life.EngineVersion != "lifecycle/v1" || life.State != "COMPLETE" || life.IntelligenceVersion == "" || len(life.IntelligenceDigest) != 64 {
		t.Fatalf("unexpected lifecycle contract: %#v", v)
	}
	if life.Summary.WithIntelligence+life.Summary.NoIntelligence != life.Summary.Candidates || life.Summary.Supported+life.Summary.EndOfLife+life.Summary.Unsupported+life.Summary.Unknown != life.Summary.WithIntelligence || len(life.Evaluations) != life.Summary.WithIntelligence {
		t.Fatalf("inconsistent lifecycle summary: %#v", life.Summary)
	}
	for _, ev := range life.Evaluations {
		if ev.ID == "" || ev.CandidateRef == "" || ev.Status == "" || ev.Reason == "" {
			t.Fatalf("incomplete lifecycle evaluation: %#v", ev)
		}
	}
}

func TestScanSnapshotIncludesPhase029LifecycleProvenance(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			Lifecycle struct {
				Schema        string `json:"schema"`
				EngineVersion string `json:"engine_version"`
				State         string `json:"state"`
			} `json:"lifecycle"`
			Snapshot struct {
				Lifecycle struct {
					Schema                string `json:"schema"`
					EngineVersion         string `json:"engine_version"`
					State                 string `json:"state"`
					IntelligenceDigest    string `json:"intelligence_digest"`
					CandidateCount        int    `json:"candidate_count"`
					WithIntelligenceCount int    `json:"with_intelligence_count"`
					SupportedCount        int    `json:"supported_count"`
					EndOfLifeCount        int    `json:"end_of_life_count"`
					UnsupportedCount      int    `json:"unsupported_count"`
					UnknownCount          int    `json:"unknown_count"`
				} `json:"lifecycle"`
			} `json:"snapshot"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	if v.Data.Lifecycle.Schema != "chimera.lifecycle/v1" || v.Data.Lifecycle.EngineVersion != "lifecycle/v1" || v.Data.Lifecycle.State != "COMPLETE" {
		t.Fatalf("scan omitted lifecycle result: %#v", v.Data.Lifecycle)
	}
	p := v.Data.Snapshot.Lifecycle
	if p.Schema != "chimera.lifecycle/v1" || p.EngineVersion != "lifecycle/v1" || p.State != "COMPLETE" || len(p.IntelligenceDigest) != 64 || p.WithIntelligenceCount > p.CandidateCount || p.SupportedCount+p.EndOfLifeCount+p.UnsupportedCount+p.UnknownCount != p.WithIntelligenceCount {
		t.Fatalf("scan snapshot omitted lifecycle provenance: %#v", p)
	}
}

func TestSoftwareCommandPhase030UpdatePostureContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"software", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			UpdatePosture struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
				State            string `json:"state"`
				Summary          struct {
					Pending  int `json:"pending"`
					Security int `json:"security"`
					Other    int `json:"other"`
					Unknown  int `json:"unknown_classification"`
				} `json:"summary"`
				Updates []struct {
					ID             string `json:"id"`
					Product        string `json:"product"`
					Classification string `json:"classification"`
					Source         string `json:"source"`
				} `json:"updates"`
				Providers []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					Freshness string `json:"freshness"`
				} `json:"providers"`
			} `json:"update_posture"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid software json: %v\n%s", err, out.String())
	}
	u := v.Data.UpdatePosture
	if v.Command != "software" || v.Version.Version != "1.0.0" || u.Schema != "chimera.update-posture/v1" || u.CollectorVersion != "update-posture/phase030-v1" || u.State == "" {
		t.Fatalf("unexpected update posture contract: %#v", v)
	}
	if u.Summary.Pending != len(u.Updates) || u.Summary.Security+u.Summary.Other+u.Summary.Unknown != u.Summary.Pending {
		t.Fatalf("inconsistent update summary: %#v", u.Summary)
	}
	for _, x := range u.Updates {
		if x.ID == "" || x.Product == "" || x.Classification == "" || x.Source == "" {
			t.Fatalf("incomplete update: %#v", x)
		}
	}
}

func TestScanSnapshotIncludesPhase030UpdatePostureProvenance(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			UpdatePosture struct {
				Schema           string `json:"schema"`
				CollectorVersion string `json:"collector_version"`
				State            string `json:"state"`
				Summary          struct {
					Pending  int `json:"pending"`
					Security int `json:"security"`
					Other    int `json:"other"`
					Unknown  int `json:"unknown_classification"`
				} `json:"summary"`
			} `json:"update_posture"`
			Snapshot struct {
				UpdatePosture struct {
					State            string `json:"state"`
					Schema           string `json:"schema"`
					CollectorVersion string `json:"collector_version"`
					Pending          int    `json:"pending_count"`
					Security         int    `json:"security_count"`
					Other            int    `json:"other_count"`
					Unknown          int    `json:"unknown_classification_count"`
				} `json:"update_posture"`
			} `json:"snapshot"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	u, p := v.Data.UpdatePosture, v.Data.Snapshot.UpdatePosture
	if u.Schema != "chimera.update-posture/v1" || u.CollectorVersion != "update-posture/phase030-v1" || u.State == "" {
		t.Fatalf("scan omitted update result: %#v", u)
	}
	if p.Schema != u.Schema || p.CollectorVersion != u.CollectorVersion || p.State != u.State || p.Pending != u.Summary.Pending || p.Security != u.Summary.Security || p.Other != u.Summary.Other || p.Unknown != u.Summary.Unknown {
		t.Fatalf("scan snapshot update provenance mismatch: result=%#v provenance=%#v", u, p)
	}
}

func TestScanOfflinePhase031ReportsStalePinnedIntelligenceFinding(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	builtin, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	store := builtin.Store
	store.Version = "phase031-stale-scan-test"
	store.RetrievedAt = time.Now().UTC().Add(-31 * 24 * time.Hour)
	for i := range store.Sources {
		store.Sources[i].RetrievedAt = store.RetrievedAt
	}
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(intelligence.EnvDirectory, dir)

	var out, errOut bytes.Buffer
	if err := Run([]string{"scan", "--json", "--offline", "--timeout", "10s", "--max-workers", "2"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data struct {
			State    string `json:"state"`
			Snapshot struct {
				Intelligence struct {
					Mode          string `json:"mode"`
					Freshness     string `json:"freshness"`
					ReadOnly      bool   `json:"read_only"`
					NetworkAccess bool   `json:"network_access"`
				} `json:"intelligence"`
			} `json:"snapshot"`
			Findings []struct {
				RuleID string `json:"rule_id"`
				Status string `json:"status"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scan json: %v\n%s", err, out.String())
	}
	intel := v.Data.Snapshot.Intelligence
	if intel.Mode != "OFFLINE_PINNED" || intel.Freshness != "STALE" || !intel.ReadOnly || intel.NetworkAccess {
		t.Fatalf("offline provenance mismatch: %#v", intel)
	}
	found := false
	for _, f := range v.Data.Findings {
		if f.RuleID == "CHM-INTEL-002" {
			found = true
			if f.Status != "WARN" {
				t.Fatalf("stale intelligence finding status=%q", f.Status)
			}
		}
	}
	if !found {
		t.Fatalf("stale intelligence finding missing: %#v", v.Data.Findings)
	}
	if v.Data.State != "DEGRADED" {
		t.Fatalf("stale intelligence should degrade full scan state, got %q", v.Data.State)
	}
}

func TestPhase032RefreshFlagIsMaintenanceScoped(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"scan", "--refresh-intelligence", "--timeout", "2s"}, &out, &errOut)
	if err == nil {
		t.Fatal("expected refresh flag to be rejected outside intelligence maintenance")
	}
	if !strings.Contains(err.Error(), "only valid with the intelligence maintenance command") {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("assessment began before refresh flag was rejected: %q", out.String())
	}
}

func TestPhase032IntelligenceRejectsUnknownAction(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"intelligence", "unexpected-action"}, &out, &errOut)
	if err == nil {
		t.Fatal("expected unknown intelligence action to fail")
	}
	if !strings.Contains(err.Error(), "supported positional action: rollback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFindingsCommandPhase034ProcessTrustRules(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--category", "process", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("process findings json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Findings []struct {
				RuleID        string `json:"rule_id"`
				Category      string `json:"category"`
				Status        string `json:"status"`
				Applicability string `json:"applicability"`
				ObservedState string `json:"observed_state"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid findings json: %v\n%s", err, out.String())
	}
	if v.Command != "findings" || v.Version.Version != "1.0.0" {
		t.Fatalf("unexpected findings envelope: %#v", v)
	}
	seen := map[string]bool{}
	for _, f := range v.Data.Findings {
		if f.Category != "process" || f.Status == "" || f.Applicability == "" || f.ObservedState == "" {
			t.Fatalf("invalid process finding: %#v", f)
		}
		seen[f.RuleID] = true
	}
	for _, id := range []string{"CHM-PRC-001", "CHM-PRC-002", "CHM-PRC-003", "CHM-PRC-004", "CHM-PRC-005", "CHM-PRC-006", "CHM-PRC-007", "CHM-PRC-008", "CHM-PRC-009", "CHM-PRC-010", "CHM-PRC-011", "CHM-PRC-012", "CHM-PRC-013"} {
		if !seen[id] {
			t.Fatalf("missing implemented process rule %s: %#v", id, v.Data.Findings)
		}
	}
}

func TestScheduledCommandPhase050Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"scheduled", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("scheduled json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Entries          []struct {
				ID          string `json:"id"`
				RunLevel    string `json:"run_level"`
				LogonType   string `json:"logon_type"`
				HiddenState string `json:"hidden_state"`
				ActionPath  struct {
					State string `json:"state"`
				} `json:"action_path"`
				ActionDirectory struct {
					State string `json:"state"`
				} `json:"action_directory_posture"`
			} `json:"entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scheduled json: %v\n%s", err, out.String())
	}
	if v.Command != "scheduled" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.scheduled/v2" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "scheduled-execution" || v.Data.CollectorVersion != "scheduled/phase050-v1" {
		t.Fatalf("unexpected scheduled contract: %#v", v)
	}
	for _, e := range v.Data.Entries {
		if e.ID == "" || e.RunLevel == "" || e.LogonType == "" || e.HiddenState == "" || e.ActionPath.State == "" || e.ActionDirectory.State == "" {
			t.Fatalf("incomplete scheduled record: %#v", e)
		}
	}
}

func TestFindingsCommandPhase050ScheduledRules(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"findings", "--category", "scheduled", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			Findings []struct {
				RuleID   string `json:"rule_id"`
				Category string `json:"category"`
				Status   string `json:"status"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid scheduled findings json: %v\n%s", err, out.String())
	}
	if v.Command != "findings" {
		t.Fatalf("unexpected command: %#v", v)
	}
	seen := map[string]bool{}
	for _, f := range v.Data.Findings {
		if f.Category != "scheduled" || f.Status == "" {
			t.Fatalf("invalid scheduled finding: %#v", f)
		}
		seen[f.RuleID] = true
	}
	for _, id := range []string{"CHM-SCH-001", "CHM-SCH-002", "CHM-SCH-003", "CHM-SCH-004", "CHM-SCH-005"} {
		if !seen[id] {
			t.Fatalf("missing scheduled rule %s: %#v", id, v.Data.Findings)
		}
	}
}

func TestFirewallCommandPhase058Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"firewall", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("firewall json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Providers        []struct {
				ID      string `json:"id"`
				State   string `json:"state"`
				Enabled string `json:"enabled"`
				Source  string `json:"source"`
			} `json:"providers"`
			Policies []struct {
				ID       string `json:"id"`
				Provider string `json:"provider"`
				Scope    string `json:"scope"`
				Enabled  string `json:"enabled"`
				Source   string `json:"source"`
			} `json:"policies"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid firewall json: %v\n%s", err, out.String())
	}
	if v.Command != "firewall" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.firewall/v2" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "firewall" || v.Data.CollectorVersion != "firewall/phase058-v1" {
		t.Fatalf("unexpected firewall contract: %#v", v)
	}
	if len(v.Data.Providers) == 0 || len(v.Data.Evidence) < 2 {
		t.Fatalf("firewall inventory lacks provider/evidence provenance: %#v", v.Data)
	}
	for _, p := range v.Data.Providers {
		if p.ID == "" || p.State == "" || p.Enabled == "" || p.Source == "" {
			t.Fatalf("incomplete firewall provider: %#v", p)
		}
	}
	for _, p := range v.Data.Policies {
		if p.ID == "" || p.Provider == "" || p.Scope == "" || p.Enabled == "" || p.Source == "" {
			t.Fatalf("incomplete firewall policy: %#v", p)
		}
	}
}

func TestNetworkCommandPhase052Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"network", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("network json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Endpoints        []struct {
				ID             string `json:"id"`
				Protocol       string `json:"protocol"`
				TransportState string `json:"transport_state"`
				AddressFamily  string `json:"address_family"`
				LocalAddress   string `json:"local_address"`
				LocalPort      uint16 `json:"local_port"`
				Binding        struct {
					Class string `json:"class"`
				} `json:"interface_binding"`
				Owner struct {
					State string `json:"state"`
				} `json:"owner"`
			} `json:"endpoints"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid network json: %v\n%s", err, out.String())
	}
	if v.Command != "network" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.network/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "network-listeners" || v.Data.CollectorVersion != "network/phase052-v1" {
		t.Fatalf("unexpected network contract: %#v", v)
	}
	for _, e := range v.Data.Endpoints {
		if e.ID == "" || (e.Protocol != "TCP" && e.Protocol != "UDP") || (e.TransportState != "LISTEN" && e.TransportState != "BOUND") || (e.AddressFamily != "IPV4" && e.AddressFamily != "IPV6") || e.LocalAddress == "" || e.LocalPort == 0 || e.Binding.Class == "" || e.Owner.State == "" {
			t.Fatalf("incomplete endpoint: %#v", e)
		}
	}
}

func TestAccountsCommandPhase064Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("accounts json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Accounts         []struct {
				ID              string   `json:"id"`
				Name            string   `json:"name"`
				EnabledState    string   `json:"enabled_state"`
				LoginCapability string   `json:"login_capability"`
				Groups          []string `json:"groups"`
				Authentication  struct {
					State         string `json:"state"`
					PasswordState string `json:"password_state"`
				} `json:"authentication"`
			} `json:"accounts"`
			Groups []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"groups"`
			Evidence []struct {
				Key string `json:"key"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.accounts/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "accounts" || v.Data.CollectorVersion != "accounts/phase072-v1" {
		t.Fatalf("unexpected account contract: %#v", v)
	}
	for _, a := range v.Data.Accounts {
		if a.ID == "" || a.Name == "" || a.EnabledState == "" || a.LoginCapability == "" || a.Authentication.State == "" || a.Authentication.PasswordState == "" {
			t.Fatalf("incomplete account record: %#v", a)
		}
	}
	for _, g := range v.Data.Groups {
		if g.ID == "" || g.Name == "" {
			t.Fatalf("incomplete group record: %#v", g)
		}
	}
	if len(v.Data.Evidence) == 0 {
		t.Fatal("account inventory emitted no normalized evidence")
	}
}

func TestAccountsCommandPhase067SecurityPolicyContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			SecurityPolicy struct {
				State    string `json:"state"`
				Source   string `json:"source"`
				Controls []struct {
					ID    string `json:"id"`
					State string `json:"state"`
					Value string `json:"value"`
				} `json:"controls"`
			} `json:"security_policy"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.SecurityPolicy.State == "" || v.Data.SecurityPolicy.Source == "" {
		t.Fatalf("missing security policy contract: %#v", v.Data.SecurityPolicy)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.policy.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("policy provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.policy.provider evidence missing")
	}
}

func TestAccountsCommandPhase068CredentialProtectionContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			CredentialProtection struct {
				State    string `json:"state"`
				Source   string `json:"source"`
				Controls []struct {
					ID    string `json:"id"`
					State string `json:"state"`
					Value string `json:"value"`
				} `json:"controls"`
			} `json:"credential_protection"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.CredentialProtection.State == "" || v.Data.CredentialProtection.Source == "" {
		t.Fatalf("missing credential-protection contract: %#v", v.Data.CredentialProtection)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.credential_protection.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("credential-protection provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.credential_protection.provider evidence missing")
	}
}

func TestAccountsCommandPhase069SudoPostureContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			SudoPosture struct {
				State   string `json:"state"`
				Source  string `json:"source"`
				Summary struct {
					ParsedFiles int `json:"parsed_files"`
				} `json:"summary"`
			} `json:"sudo_posture"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.SudoPosture.State == "" || v.Data.SudoPosture.Source == "" {
		t.Fatalf("missing sudo posture contract: %#v", v.Data.SudoPosture)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.sudo.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("sudo provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.sudo.provider evidence missing")
	}
}

func TestAccountsCommandPhase070LinuxAuthPostureContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			CollectorVersion string `json:"collector_version"`
			LinuxAuthPosture struct {
				State   string `json:"state"`
				Source  string `json:"source"`
				Summary struct {
					ParsedFiles int `json:"parsed_files"`
					PAMRules    int `json:"pam_rules"`
				} `json:"summary"`
			} `json:"linux_auth_posture"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.CollectorVersion != "accounts/phase072-v1" || v.Data.LinuxAuthPosture.State == "" || v.Data.LinuxAuthPosture.Source == "" {
		t.Fatalf("missing Linux auth posture contract: %#v", v.Data.LinuxAuthPosture)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.linux_auth.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("Linux auth provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.linux_auth.provider evidence missing")
	}
}

func TestAccountsCommandPhase071MacOSAuthorizationContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			CollectorVersion          string `json:"collector_version"`
			MacOSAuthorizationPosture struct {
				State     string `json:"state"`
				Source    string `json:"source"`
				FileVault struct {
					State string `json:"state"`
				} `json:"filevault"`
			} `json:"macos_authorization_posture"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.CollectorVersion != "accounts/phase072-v1" || v.Data.MacOSAuthorizationPosture.State == "" || v.Data.MacOSAuthorizationPosture.Source == "" || v.Data.MacOSAuthorizationPosture.FileVault.State == "" {
		t.Fatalf("missing macOS authorization contract: %#v", v.Data.MacOSAuthorizationPosture)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.macos_authorization.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("macOS authorization provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.macos_authorization.provider evidence missing")
	}
}

func TestAccountsCommandPhase072SSHKeyPostureContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"accounts", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Command string `json:"command"`
		Data    struct {
			CollectorVersion string `json:"collector_version"`
			SSHKeyPosture    struct {
				State   string `json:"state"`
				Source  string `json:"source"`
				Summary struct {
					SSHDirectories       int `json:"ssh_directories"`
					AuthorizedKeysFiles  int `json:"authorized_keys_files"`
					PrivateKeyCandidates int `json:"private_key_candidates"`
				} `json:"summary"`
				Records []struct {
					ID         string `json:"id"`
					Principal  string `json:"principal"`
					Path       string `json:"path"`
					Kind       string `json:"kind"`
					State      string `json:"state"`
					OwnerMatch string `json:"owner_match"`
				} `json:"records"`
			} `json:"ssh_key_posture"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid accounts json: %v\n%s", err, out.String())
	}
	if v.Command != "accounts" || v.Data.CollectorVersion != "accounts/phase072-v1" || v.Data.SSHKeyPosture.State == "" || v.Data.SSHKeyPosture.Source == "" {
		t.Fatalf("missing SSH key posture contract: %#v", v.Data.SSHKeyPosture)
	}
	foundProvider := false
	for _, e := range v.Data.Evidence {
		if e.Key == "account.ssh_key.provider" {
			foundProvider = true
			if e.State == "" {
				t.Fatal("SSH key provider evidence has empty state")
			}
		}
	}
	if !foundProvider {
		t.Fatal("account.ssh_key.provider evidence missing")
	}
	for _, r := range v.Data.SSHKeyPosture.Records {
		if r.ID == "" || r.Principal == "" || r.Path == "" || r.Kind == "" || r.State == "" || r.OwnerMatch == "" {
			t.Fatalf("incomplete SSH path record: %#v", r)
		}
	}
}

func TestFilesystemCommandPhase085Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"filesystem", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("filesystem json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema               string `json:"schema"`
			EvidenceSchema       string `json:"evidence_schema"`
			Collector            string `json:"collector"`
			CollectorVersion     string `json:"collector_version"`
			PermissionCapability struct {
				State string `json:"state"`
				Model string `json:"model"`
			} `json:"permission_capability"`
			Paths []struct {
				ID    string `json:"id"`
				Kind  string `json:"kind"`
				Path  string `json:"path"`
				State string `json:"state"`
			} `json:"paths"`
			Mounts []struct {
				ID              string `json:"id"`
				Path            string `json:"path"`
				State           string `json:"state"`
				BackingSource   string `json:"backing_source"`
				Filesystem      string `json:"filesystem"`
				AccessMode      string `json:"access_mode"`
				Classification  string `json:"classification"`
				EncryptionState string `json:"encryption_state"`
			} `json:"mount_boundaries"`
			NetworkShares []struct {
				ID               string `json:"id"`
				Direction        string `json:"direction"`
				Protocol         string `json:"protocol"`
				LocalPath        string `json:"local_path"`
				AccessMode       string `json:"access_mode"`
				State            string `json:"state"`
				CollectionSource string `json:"collection_source"`
				Confidence       string `json:"confidence"`
			} `json:"network_shares"`
			SearchPaths []struct {
				ID       string   `json:"id"`
				Path     string   `json:"path"`
				State    string   `json:"state"`
				Contexts []string `json:"contexts"`
			} `json:"search_paths"`
			SensitiveFiles []struct {
				ID           string `json:"id"`
				Kind         string `json:"kind"`
				Path         string `json:"path"`
				State        string `json:"state"`
				AccessPolicy string `json:"access_policy"`
				OwnerState   string `json:"owner_state"`
			} `json:"sensitive_files"`
			ACLBoundaries []struct {
				ID       string   `json:"id"`
				Path     string   `json:"path"`
				State    string   `json:"state"`
				ACLModel string   `json:"acl_model"`
				Contexts []string `json:"contexts"`
			} `json:"acl_boundaries"`
			TempDirectories []struct {
				ID              string `json:"id"`
				Path            string `json:"path"`
				Scope           string `json:"scope"`
				State           string `json:"state"`
				PermissionModel string `json:"permission_model"`
			} `json:"temp_directories"`
			PrivilegedFiles []struct {
				ID             string   `json:"id"`
				Path           string   `json:"path"`
				State          string   `json:"state"`
				SetUID         bool     `json:"setuid"`
				SetGID         bool     `json:"setgid"`
				Capabilities   []string `json:"capabilities"`
				Classification string   `json:"classification"`
			} `json:"privileged_files"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid filesystem json: %v\n%s", err, out.String())
	}
	if v.Command != "filesystem" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.filesystem/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "filesystem-security" || v.Data.CollectorVersion != "filesystem/phase085-v1" {
		t.Fatalf("unexpected filesystem contract: %#v", v)
	}
	if v.Data.PermissionCapability.State == "" || v.Data.PermissionCapability.Model == "" || len(v.Data.Paths) == 0 || len(v.Data.Evidence) == 0 {
		t.Fatalf("filesystem inventory is incomplete: %#v", v.Data)
	}
	foundExecutableSource := false
	foundSearchSource := false
	foundPrivilegedSource := false
	foundSensitiveSource := false
	foundACLSource := false
	foundTempSource := false
	foundMountedShareSource := false
	foundNFSExportSource := false
	for _, o := range v.Data.Evidence {
		if o.Key == "filesystem.source.executable-permissions" {
			foundExecutableSource = true
		}
		if o.Key == "filesystem.source.privileged-search-paths" {
			foundSearchSource = true
		}
		if o.Key == "filesystem.source.linux-privileged-files" {
			foundPrivilegedSource = true
		}
		if o.Key == "filesystem.source.sensitive-file-permissions" {
			foundSensitiveSource = true
		}
		if o.Key == "filesystem.source.acl-boundaries" {
			foundACLSource = true
		}
		if o.Key == "filesystem.source.temporary-directory-security" {
			foundTempSource = true
		}
		if o.Key == "filesystem.source.network-mounted-shares" {
			foundMountedShareSource = true
		}
		if o.Key == "filesystem.source.nfs-exports" {
			foundNFSExportSource = true
		}
	}
	if !foundExecutableSource {
		t.Fatal("executable-permission source evidence missing")
	}
	if !foundSearchSource {
		t.Fatal("privileged-search-path source evidence missing")
	}
	if !foundPrivilegedSource {
		t.Fatal("Linux privileged-file source evidence missing")
	}
	if !foundSensitiveSource {
		t.Fatal("sensitive-file permission source evidence missing")
	}
	if !foundACLSource {
		t.Fatal("ACL boundary source evidence missing")
	}
	if !foundTempSource {
		t.Fatal("temporary-directory source evidence missing")
	}
	if !foundMountedShareSource || !foundNFSExportSource {
		t.Fatalf("network-share source evidence missing: mounted=%t nfs_exports=%t", foundMountedShareSource, foundNFSExportSource)
	}
	for _, sf := range v.Data.SensitiveFiles {
		if sf.ID == "" || sf.Kind == "" || sf.Path == "" || sf.State == "" || sf.AccessPolicy == "" || sf.OwnerState == "" {
			t.Fatalf("incomplete sensitive-file record: %#v", sf)
		}
	}
	for _, acl := range v.Data.ACLBoundaries {
		if acl.ID == "" || acl.Path == "" || acl.State == "" || acl.ACLModel == "" || len(acl.Contexts) == 0 {
			t.Fatalf("incomplete ACL boundary record: %#v", acl)
		}
	}
	for _, td := range v.Data.TempDirectories {
		if td.ID == "" || td.Path == "" || td.Scope == "" || td.State == "" || td.PermissionModel == "" {
			t.Fatalf("incomplete temporary-directory record: %#v", td)
		}
	}
	for _, m := range v.Data.Mounts {
		if m.ID == "" || m.Path == "" || m.State == "" || m.BackingSource == "" || m.AccessMode == "" || m.Classification == "" || m.EncryptionState == "" {
			t.Fatalf("incomplete mount/volume record: %#v", m)
		}
	}
	for _, sh := range v.Data.NetworkShares {
		if sh.ID == "" || sh.Direction == "" || sh.Protocol == "" || sh.AccessMode == "" || sh.State == "" || sh.CollectionSource == "" || sh.Confidence == "" {
			t.Fatalf("incomplete network-share record: %#v", sh)
		}
	}
	for _, sp := range v.Data.SearchPaths {
		if sp.ID == "" || sp.Path == "" || sp.State == "" || len(sp.Contexts) == 0 {
			t.Fatalf("incomplete search path: %#v", sp)
		}
	}
	for _, pf := range v.Data.PrivilegedFiles {
		if pf.ID == "" || pf.Path == "" || pf.State == "" || pf.Classification == "" {
			t.Fatalf("incomplete privileged executable: %#v", pf)
		}
	}
	for _, p := range v.Data.Paths {
		if p.ID == "" || p.Kind == "" || p.Path == "" || p.State == "" {
			t.Fatalf("incomplete filesystem path: %#v", p)
		}
	}
}

func TestStorageCommandPhase084Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"storage", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("storage json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Platform         string `json:"platform"`
			Architecture     string `json:"architecture"`
			Volumes          []struct {
				ID              string `json:"id"`
				EncryptionState string `json:"encryption_state"`
				ProtectionState string `json:"protection_state"`
				LockState       string `json:"lock_state"`
				State           string `json:"state"`
				Source          string `json:"collection_source"`
			} `json:"volumes"`
			SwapAreas []struct {
				ID              string `json:"id"`
				Path            string `json:"path"`
				EncryptionState string `json:"encryption_state"`
				State           string `json:"state"`
				Source          string `json:"collection_source"`
			} `json:"swap_areas"`
			Hibernation struct {
				SupportState       string `json:"support_state"`
				ConfigurationState string `json:"configuration_state"`
				ExposureState      string `json:"exposure_state"`
				EncryptionState    string `json:"encryption_state"`
				State              string `json:"state"`
				Source             string `json:"collection_source"`
			} `json:"hibernation"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid storage json: %v\n%s", err, out.String())
	}
	if v.Command != "storage" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.storage/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "storage-encryption" || v.Data.CollectorVersion != "storage/phase084-v1" {
		t.Fatalf("unexpected storage contract: %#v", v)
	}
	if v.Data.Platform == "" || v.Data.Architecture == "" || len(v.Data.Evidence) == 0 {
		t.Fatalf("storage inventory identity/evidence incomplete: %#v", v.Data)
	}
	foundSummary := false
	foundSource := false
	foundHibernation := false
	for _, o := range v.Data.Evidence {
		if o.Key == "storage.summary" {
			foundSummary = true
		}
		if strings.HasPrefix(o.Key, "storage.source.") {
			foundSource = true
		}
		if o.Key == "storage.hibernation" {
			foundHibernation = true
		}
	}
	if !foundSummary || !foundSource || !foundHibernation {
		t.Fatalf("storage summary/provider/hibernation evidence missing: %#v", v.Data.Evidence)
	}
	for _, volume := range v.Data.Volumes {
		if volume.ID == "" || volume.EncryptionState == "" || volume.ProtectionState == "" || volume.LockState == "" || volume.State == "" || volume.Source == "" {
			t.Fatalf("incomplete storage volume: %#v", volume)
		}
	}
	for _, area := range v.Data.SwapAreas {
		if area.ID == "" || area.Path == "" || area.EncryptionState == "" || area.State == "" || area.Source == "" {
			t.Fatalf("incomplete swap/pagefile area: %#v", area)
		}
	}
	if v.Data.Hibernation.SupportState == "" || v.Data.Hibernation.ConfigurationState == "" || v.Data.Hibernation.ExposureState == "" || v.Data.Hibernation.EncryptionState == "" || v.Data.Hibernation.State == "" || v.Data.Hibernation.Source == "" {
		t.Fatalf("incomplete hibernation posture: %#v", v.Data.Hibernation)
	}
}

func TestContainersCommandPhase095Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"containers", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("containers json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Platform         string `json:"platform"`
			Architecture     string `json:"architecture"`
			Runtimes         []struct {
				ID                string `json:"id"`
				Name              string `json:"name"`
				InstallationState string `json:"installation_state"`
				RuntimeState      string `json:"runtime_state"`
				Accessibility     string `json:"accessibility"`
				RootlessState     string `json:"rootless_state"`
				Source            string `json:"collection_source"`
			} `json:"runtimes"`
			Security []struct {
				ID                            string `json:"id"`
				Runtime                       string `json:"runtime"`
				RuntimeContainerID            string `json:"runtime_container_id"`
				PrivilegedState               string `json:"privileged_state"`
				RootExecutionState            string `json:"root_execution_state"`
				PIDNamespace                  string `json:"pid_namespace"`
				NetworkNamespace              string `json:"network_namespace"`
				UserNamespace                 string `json:"user_namespace"`
				CapabilityAssessmentState     string `json:"capability_assessment_state"`
				CapabilityBoundingState       string `json:"capability_bounding_state"`
				SeccompState                  string `json:"seccomp_state"`
				MandatoryAccessControlState   string `json:"mandatory_access_control_state"`
				ReadOnlyRootFSState           string `json:"read_only_rootfs_state"`
				NoNewPrivilegesState          string `json:"no_new_privileges_state"`
				UnrestrictedDeviceAccessState string `json:"unrestricted_device_access_state"`
				MountAssessmentState          string `json:"mount_assessment_state"`
				HostRootMountState            string `json:"host_root_mount_state"`
				RuntimeSocketMountState       string `json:"runtime_socket_mount_state"`
				CredentialMountState          string `json:"credential_mount_state"`
				DeviceMountState              string `json:"device_mount_state"`
				SensitiveHostPathMountState   string `json:"sensitive_host_path_mount_state"`
			} `json:"security"`
			RuntimeEndpoints []struct {
				ID                        string `json:"id"`
				Runtime                   string `json:"runtime"`
				Endpoint                  string `json:"endpoint"`
				EndpointKind              string `json:"endpoint_kind"`
				PermissionAssessmentState string `json:"permission_assessment_state"`
				WorldWritableState        string `json:"world_writable_state"`
				LocalTransportState       string `json:"local_transport_state"`
			} `json:"runtime_endpoints"`
			Kubernetes struct {
				ID                string `json:"id"`
				State             string `json:"state"`
				InstallationState string `json:"installation_state"`
				Applicability     string `json:"applicability"`
				Source            string `json:"collection_source"`
			} `json:"kubernetes"`
			Kubeconfigs []struct {
				ID                        string `json:"id"`
				Path                      string `json:"path"`
				Scope                     string `json:"scope"`
				State                     string `json:"state"`
				PermissionAssessmentState string `json:"permission_assessment_state"`
				EmbeddedCredentialState   string `json:"embedded_credential_state"`
			} `json:"kubeconfigs"`
			KubernetesCredentialPaths []struct {
				ID                        string `json:"id"`
				KubeconfigID              string `json:"kubeconfig_id"`
				Kind                      string `json:"kind"`
				Path                      string `json:"path"`
				State                     string `json:"state"`
				PermissionAssessmentState string `json:"permission_assessment_state"`
			} `json:"kubernetes_credential_paths"`
			Hypervisors []struct {
				ID                string `json:"id"`
				Name              string `json:"name"`
				Kind              string `json:"kind"`
				State             string `json:"state"`
				InstallationState string `json:"installation_state"`
				RuntimeState      string `json:"runtime_state"`
				ServiceState      string `json:"service_state"`
				LocalAccessState  string `json:"local_access_state"`
			} `json:"hypervisors"`
			HypervisorInterfaces []struct {
				ID                        string `json:"id"`
				Hypervisor                string `json:"hypervisor"`
				Kind                      string `json:"kind"`
				Endpoint                  string `json:"endpoint"`
				PermissionAssessmentState string `json:"permission_assessment_state"`
				WorldWritableState        string `json:"world_writable_state"`
				LocalAccessState          string `json:"local_access_state"`
			} `json:"hypervisor_management_interfaces"`
			DeveloperSurfaces []struct {
				ID              string `json:"id"`
				Kind            string `json:"kind"`
				Product         string `json:"product"`
				State           string `json:"state"`
				ActivationState string `json:"activation_state"`
				ListenerState   string `json:"listener_state"`
				BindingState    string `json:"binding_state"`
				ExposureState   string `json:"exposure_state"`
				Source          string `json:"collection_source"`
			} `json:"developer_surfaces"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid containers json: %v\n%s", err, out.String())
	}
	if v.Command != "containers" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.containers/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "container-runtime" || v.Data.CollectorVersion != "containers/phase095-v1" {
		t.Fatalf("unexpected containers contract: %#v", v)
	}
	if v.Data.Platform == "" || v.Data.Architecture == "" || len(v.Data.Runtimes) != 3 || len(v.Data.Evidence) == 0 {
		t.Fatalf("container inventory identity/evidence incomplete: %#v", v.Data)
	}
	seenSummary := false
	seenRuntime := map[string]bool{}
	seenSecuritySource := map[string]bool{}
	seenEndpointSource := false
	seenKubernetes := false
	seenKubeconfigSource := false
	seenKubeCredentialSource := false
	seenHypervisorSource := false
	seenHypervisorEvidence := false
	seenDeveloperProcessSource := false
	seenDeveloperListenerSource := false
	seenDeveloperSurfaceSource := false
	for _, o := range v.Data.Evidence {
		if o.Key == "container.summary" {
			seenSummary = true
		}
		if strings.HasPrefix(o.Key, "container.runtime.") {
			seenRuntime[strings.TrimPrefix(o.Key, "container.runtime.")] = true
		}
		if strings.HasPrefix(o.Key, "container.source.") && strings.HasSuffix(o.Key, "-security") {
			seenSecuritySource[strings.TrimPrefix(o.Key, "container.source.")] = true
		}
		if o.Key == "container.source.runtime-endpoint-permissions" {
			seenEndpointSource = true
		}
		if o.Key == "container.orchestration.kubernetes" {
			seenKubernetes = true
		}
		if o.Key == "container.source.kubernetes-kubeconfig" {
			seenKubeconfigSource = true
		}
		if o.Key == "container.source.kubernetes-credential-paths" {
			seenKubeCredentialSource = true
		}
		if o.Key == "container.source.virtualization-hypervisors" {
			seenHypervisorSource = true
		}
		if strings.HasPrefix(o.Key, "container.virtualization.hypervisor.") {
			seenHypervisorEvidence = true
		}
		if o.Key == "container.source.developer-process-metadata" {
			seenDeveloperProcessSource = true
		}
		if o.Key == "container.source.developer-listener-correlation" {
			seenDeveloperListenerSource = true
		}
		if o.Key == "container.source.developer-surfaces" {
			seenDeveloperSurfaceSource = true
		}
	}
	if !seenSummary || !seenRuntime["docker"] || !seenRuntime["containerd"] || !seenRuntime["podman"] || !seenSecuritySource["docker-security"] || !seenSecuritySource["containerd-security"] || !seenSecuritySource["podman-security"] || !seenEndpointSource || !seenKubernetes || !seenKubeconfigSource || !seenKubeCredentialSource || !seenHypervisorSource || !seenHypervisorEvidence || !seenDeveloperProcessSource || !seenDeveloperListenerSource || !seenDeveloperSurfaceSource {
		t.Fatalf("container/orchestration/virtualization/developer evidence missing: %#v", v.Data.Evidence)
	}
	for _, r := range v.Data.Runtimes {
		if r.ID == "" || r.Name == "" || r.InstallationState == "" || r.RuntimeState == "" || r.Accessibility == "" || r.RootlessState == "" || r.Source == "" {
			t.Fatalf("incomplete runtime record: %#v", r)
		}
	}
	for _, c := range v.Data.Security {
		if c.ID == "" || c.Runtime == "" || c.RuntimeContainerID == "" || c.PrivilegedState == "" || c.RootExecutionState == "" || c.PIDNamespace == "" || c.NetworkNamespace == "" || c.UserNamespace == "" || c.CapabilityAssessmentState == "" || c.CapabilityBoundingState == "" || c.SeccompState == "" || c.MandatoryAccessControlState == "" || c.ReadOnlyRootFSState == "" || c.NoNewPrivilegesState == "" || c.UnrestrictedDeviceAccessState == "" || c.MountAssessmentState == "" || c.HostRootMountState == "" || c.RuntimeSocketMountState == "" || c.CredentialMountState == "" || c.DeviceMountState == "" || c.SensitiveHostPathMountState == "" {
			t.Fatalf("incomplete security posture: %#v", c)
		}
	}
	for _, ep := range v.Data.RuntimeEndpoints {
		if ep.ID == "" || ep.Runtime == "" || ep.Endpoint == "" || ep.EndpointKind == "" || ep.PermissionAssessmentState == "" || ep.WorldWritableState == "" || ep.LocalTransportState == "" {
			t.Fatalf("incomplete runtime endpoint posture: %#v", ep)
		}
	}
	if v.Data.Kubernetes.ID == "" || v.Data.Kubernetes.State == "" || v.Data.Kubernetes.InstallationState == "" || v.Data.Kubernetes.Applicability == "" || v.Data.Kubernetes.Source == "" {
		t.Fatalf("incomplete Kubernetes posture: %#v", v.Data.Kubernetes)
	}
	for _, cfg := range v.Data.Kubeconfigs {
		if cfg.ID == "" || cfg.Path == "" || cfg.Scope == "" || cfg.State == "" || cfg.PermissionAssessmentState == "" || cfg.EmbeddedCredentialState == "" {
			t.Fatalf("incomplete kubeconfig posture: %#v", cfg)
		}
	}
	for _, cred := range v.Data.KubernetesCredentialPaths {
		if cred.ID == "" || cred.KubeconfigID == "" || cred.Kind == "" || cred.Path == "" || cred.State == "" || cred.PermissionAssessmentState == "" {
			t.Fatalf("incomplete Kubernetes credential path posture: %#v", cred)
		}
	}
	for _, h := range v.Data.Hypervisors {
		if h.ID == "" || h.Name == "" || h.Kind == "" || h.State == "" || h.InstallationState == "" || h.RuntimeState == "" || h.ServiceState == "" || h.LocalAccessState == "" {
			t.Fatalf("incomplete hypervisor posture: %#v", h)
		}
	}
	for _, h := range v.Data.HypervisorInterfaces {
		if h.ID == "" || h.Hypervisor == "" || h.Kind == "" || h.Endpoint == "" || h.PermissionAssessmentState == "" || h.WorldWritableState == "" || h.LocalAccessState == "" {
			t.Fatalf("incomplete hypervisor interface posture: %#v", h)
		}
	}
	for _, d := range v.Data.DeveloperSurfaces {
		if d.ID == "" || d.Kind == "" || d.Product == "" || d.State == "" || d.ActivationState == "" || d.ListenerState == "" || d.BindingState == "" || d.ExposureState == "" || d.Source == "" {
			t.Fatalf("incomplete developer surface posture: %#v", d)
		}
	}
}

func TestPersistenceJSONPhase098Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"persistence", "--json", "--timeout", "8s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("persistence json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Platform         string `json:"platform"`
			Architecture     string `json:"architecture"`
			Entries          []struct {
				ID               string `json:"id"`
				Mechanism        string `json:"mechanism"`
				EnabledState     string `json:"enabled_state"`
				RuntimeState     string `json:"runtime_state"`
				CollectionSource string `json:"collection_source"`
				PathIntegrity    struct {
					State          string `json:"state"`
					PrivilegeBasis string `json:"privilege_basis"`
				} `json:"path_integrity"`
			} `json:"entries"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid persistence json: %v\n%s", err, out.String())
	}
	if v.Command != "persistence" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.persistence/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "persistence" || v.Data.CollectorVersion != "persistence/phase098-v1" {
		t.Fatalf("unexpected persistence contract: %#v", v)
	}
	if v.Data.Platform == "" || v.Data.Architecture == "" || len(v.Data.Evidence) == 0 {
		t.Fatalf("persistence identity/evidence incomplete: %#v", v.Data)
	}
	seenSummary := false
	for _, o := range v.Data.Evidence {
		if o.Key == "persistence.summary" && o.State == "OBSERVED" {
			seenSummary = true
		}
	}
	if !seenSummary {
		t.Fatalf("persistence.summary evidence missing: %#v", v.Data.Evidence)
	}
	for _, e := range v.Data.Entries {
		if e.ID == "" || e.Mechanism == "" || e.EnabledState == "" || e.RuntimeState == "" || e.CollectionSource == "" || e.PathIntegrity.State == "" || e.PathIntegrity.PrivilegeBasis == "" {
			t.Fatalf("incomplete persistence entry: %#v", e)
		}
	}
}

func TestSecretsCommandPhase103Contract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"secrets", "--json", "--timeout", "10s"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("secrets json contains ANSI")
	}
	var v struct {
		Command string `json:"command"`
		Version struct {
			Version string `json:"version"`
		} `json:"version"`
		Data struct {
			Schema           string `json:"schema"`
			EvidenceSchema   string `json:"evidence_schema"`
			Collector        string `json:"collector"`
			CollectorVersion string `json:"collector_version"`
			Platform         string `json:"platform"`
			Architecture     string `json:"architecture"`
			Summary          struct {
				Records                   int `json:"records"`
				ContentInspected          int `json:"content_inspected"`
				FilesWithSecretIndicators int `json:"files_with_secret_indicators"`
				SecretIndicators          int `json:"secret_indicators"`
				PrivateKeys               int `json:"private_keys"`
			} `json:"summary"`
			PrivateKeyPermissions struct {
				AssessmentState       string `json:"assessment_state"`
				Keys                  int    `json:"keys"`
				PermissionAssessed    int    `json:"permission_assessed"`
				ReadExposed           int    `json:"read_exposed"`
				WriteExposed          int    `json:"write_exposed"`
				SystemOwnerUnexpected int    `json:"system_owner_unexpected"`
			} `json:"private_key_permissions"`
			CredentialFilePosture struct {
				AssessmentState   string `json:"assessment_state"`
				Files             int    `json:"files"`
				CredentialBearing int    `json:"credential_bearing"`
				ReadExposed       int    `json:"read_exposed"`
				WriteExposed      int    `json:"write_exposed"`
			} `json:"credential_file_posture"`
			Records []struct {
				ID                     string `json:"id"`
				Kind                   string `json:"kind"`
				Path                   string `json:"path"`
				PermissionState        string `json:"permission_state"`
				ContentInspected       bool   `json:"content_inspected"`
				ContentInspectionState string `json:"content_inspection_state"`
				SecretIndicatorCount   int    `json:"secret_indicator_count"`
				RedactionApplied       bool   `json:"redaction_applied"`
				CollectionSource       string `json:"collection_source"`
			} `json:"records"`
			Evidence []struct {
				Key   string `json:"key"`
				State string `json:"state"`
			} `json:"evidence"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid secrets json: %v\n%s", err, out.String())
	}
	if v.Command != "secrets" || v.Version.Version != "1.0.0" || v.Data.Schema != "chimera.secrets/v1" || v.Data.EvidenceSchema != "chimera.evidence/v1" || v.Data.Collector != "secret-storage" || v.Data.CollectorVersion != "secrets/phase103-v1" {
		t.Fatalf("unexpected secrets contract: %#v", v)
	}
	if v.Data.Platform == "" || v.Data.Architecture == "" || len(v.Data.Evidence) == 0 {
		t.Fatalf("secret-storage identity/evidence incomplete: %#v", v.Data)
	}
	seenSummary, seenRisk, seenPrivateKeys, seenCredentialFiles := false, false, false, false
	for _, o := range v.Data.Evidence {
		if o.Key == "secret_storage.summary" && o.State == "OBSERVED" {
			seenSummary = true
		}
		if o.Key == "secret_storage.plaintext_risk" && o.State == "OBSERVED" {
			seenRisk = true
		}
		if o.Key == "secret_storage.private_key_permissions" && o.State == "OBSERVED" {
			seenPrivateKeys = true
		}
		if o.Key == "secret_storage.credential_file_posture" && o.State == "OBSERVED" {
			seenCredentialFiles = true
		}
	}
	if !seenSummary || !seenRisk || !seenPrivateKeys || !seenCredentialFiles {
		t.Fatalf("secret-storage evidence missing: %#v", v.Data.Evidence)
	}
	if v.Data.PrivateKeyPermissions.AssessmentState == "" || v.Data.PrivateKeyPermissions.Keys != v.Data.Summary.PrivateKeys {
		t.Fatalf("private-key permission posture mismatch: %#v %#v", v.Data.PrivateKeyPermissions, v.Data.Summary)
	}
	if v.Data.CredentialFilePosture.AssessmentState == "" {
		t.Fatalf("credential-file posture missing: %#v", v.Data.CredentialFilePosture)
	}
	for _, r := range v.Data.Records {
		if r.ID == "" || r.Kind == "" || r.Path == "" || r.PermissionState == "" || r.ContentInspectionState == "" || r.CollectionSource == "" {
			t.Fatalf("incomplete secret-storage record: %#v", r)
		}
		if r.SecretIndicatorCount > 0 && !r.RedactionApplied {
			t.Fatalf("plaintext-secret indicator is not marked redacted: %#v", r)
		}
	}
}

func TestPhase112DiffCommandContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"diff", "--help"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"chimera diff <before.json> <after.json>", "chimera.assessment-diff/v1", "cross-host comparisons fail closed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("diff help missing %q:\n%s", want, text)
		}
	}

	out.Reset()
	if err := Run([]string{"diff", "only-one.json"}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "requires <before.json> <after.json>") {
		t.Fatalf("expected exact two-argument validation, got %v", err)
	}
}

func TestPhase114RemediationCommandRegistered(t *testing.T) {
	cmd, ok := commandRegistry()["remediation"]
	if !ok {
		t.Fatal("remediation command is not registered")
	}
	if cmd.Lane != "Report" || cmd.Run == nil || cmd.Help.Usage != "chimera remediation [global options]" {
		t.Fatalf("unexpected remediation command contract: %#v", cmd)
	}
}

func TestPhase115ReportAndExportCommandsRegistered(t *testing.T) {
	r := commandRegistry()
	reportCmd, ok := r["report"]
	if !ok || reportCmd.Lane != "Report" || reportCmd.Run == nil || reportCmd.Help.Usage != "chimera report [assessment.json] [global options]" || reportCmd.MaxArgs != 1 {
		t.Fatalf("unexpected report command contract: %#v", reportCmd)
	}
	exportCmd, ok := r["export"]
	if !ok || exportCmd.Lane != "Report" || exportCmd.Run == nil || exportCmd.MinArgs != 1 || exportCmd.MaxArgs != 1 || exportCmd.ArgSyntax != "<json|text|csv|sarif>" {
		t.Fatalf("unexpected export command contract: %#v", exportCmd)
	}
}

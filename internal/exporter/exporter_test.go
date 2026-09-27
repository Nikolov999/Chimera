package exporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidencequality"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/report"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/snapshot"
	"github.com/Nikolov999/chimera/internal/version"
)

func minimalReport(t *testing.T) report.Result {
	t.Helper()
	p := prioritization.Compute(nil, nil)
	rem, err := remediation.Build(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1700000000, 0).UTC()
	return report.Result{
		Schema: report.SchemaVersion, EngineVersion: report.EngineVersion, GeneratedAt: at,
		Tool:            version.Info{Product: "IRONCLAD Chimera", Version: "1.0.0", Commit: "test", BuildDate: "test"},
		Host:            report.Host{Hostname: "host-a", CurrentUser: "tester", Platform: "linux", Architecture: "amd64", CollectionTier: "standard", Fingerprint: "abcdef"},
		Assessment:      report.Assessment{ID: "assessment-1", State: scan.StateComplete, StartedAt: at.Add(-time.Second), CompletedAt: at, DurationMS: 1000, Profile: "default"},
		EvidenceQuality: report.EvidenceQuality{State: scan.StateComplete, Counts: scan.EvidenceCounts{}, UnknownAudit: evidencequality.UnknownAudit{Schema: evidencequality.UnknownAuditSchemaVersion}},
		Snapshot:        snapshot.Snapshot{AssessmentID: "assessment-1"},
		RuleSet:         snapshot.RuleSetProvenance{Schema: "rules/v1", Version: "rules-1", Digest: snapshot.Digest{Algorithm: "sha256", Value: "rulesdigest"}},
		Intelligence:    snapshot.IntelligenceProvenance{State: "PINNED", Version: "intel-1", Source: "local", ReadOnly: true},
		Prioritization:  p, Remediation: rem,
		Findings:    report.Findings{Summary: scan.FindingCounts{}, Items: nil},
		Limitations: []string{}, Safety: "read only",
	}
}

func TestFormatsSerializeWithoutBannerOrANSI(t *testing.T) {
	r := minimalReport(t)
	for _, f := range []Format{FormatJSON, FormatText, FormatCSV, FormatSARIF} {
		var b bytes.Buffer
		if err := Write(&b, f, r); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out := b.String()
		if strings.Contains(out, "\x1b[") || strings.Contains(out, "______") {
			t.Fatalf("%s output contains terminal decoration: %q", f, out)
		}
		if strings.TrimSpace(out) == "" {
			t.Fatalf("%s output is empty", f)
		}
	}
}

func TestSARIFIsJSONAndCSVHasAssessmentColumns(t *testing.T) {
	r := minimalReport(t)
	var sarif bytes.Buffer
	if err := Write(&sarif, FormatSARIF, r); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %#v", doc["version"])
	}

	var csv bytes.Buffer
	if err := Write(&csv, FormatCSV, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csv.String(), "assessment_id,host_fingerprint") {
		t.Fatalf("missing CSV provenance header: %q", csv.String())
	}
}

func TestMachineJSONExportsAreCompact(t *testing.T) {
	r := minimalReport(t)
	for _, f := range []Format{FormatJSON, FormatSARIF} {
		var b bytes.Buffer
		if err := Write(&b, f, r); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out := b.String()
		if strings.Contains(out, "\n  ") || strings.Contains(out, "\n    ") {
			t.Fatalf("%s unexpectedly contains pretty-print indentation", f)
		}
		var doc any
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatalf("%s compact output is invalid JSON: %v", f, err)
		}
	}
}

func TestParseAndEngineContract(t *testing.T) {
	if _, err := ParseFormat("sarif"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFormat("bogus"); err == nil {
		t.Fatal("expected invalid format")
	}
	if err := ValidateEngineContract(); err != nil {
		t.Fatal(err)
	}
}

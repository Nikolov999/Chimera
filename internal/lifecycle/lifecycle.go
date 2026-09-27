package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/software"
)

const (
	SchemaVersion = "chimera.lifecycle/v1"
	EngineVersion = "lifecycle/v1"
)

type Status string

const (
	StatusSupported   Status = "SUPPORTED"
	StatusEOL         Status = "EOL"
	StatusUnsupported Status = "UNSUPPORTED"
	StatusUnknown     Status = "UNKNOWN"
)

type Evaluation struct {
	ID            string              `json:"id"`
	RecordID      string              `json:"record_id"`
	CandidateRef  string              `json:"candidate_ref"`
	CandidateKind string              `json:"candidate_kind"`
	Product       string              `json:"product"`
	Version       string              `json:"version"`
	Family        string              `json:"family,omitempty"`
	Status        Status              `json:"status"`
	EndOfSupport  time.Time           `json:"end_of_support"`
	AssessedAt    time.Time           `json:"assessed_at"`
	SourceID      string              `json:"source_id"`
	Reference     string              `json:"reference"`
	Confidence    evidence.Confidence `json:"confidence"`
	MatchEvidence []string            `json:"match_evidence"`
	Reason        string              `json:"reason"`
}

type Summary struct {
	Candidates       int `json:"candidates"`
	WithIntelligence int `json:"with_intelligence"`
	Supported        int `json:"supported"`
	EndOfLife        int `json:"end_of_life"`
	Unsupported      int `json:"unsupported"`
	Unknown          int `json:"unknown"`
	NoIntelligence   int `json:"no_intelligence"`
}

type Result struct {
	Schema              string       `json:"schema"`
	EngineVersion       string       `json:"engine_version"`
	State               string       `json:"state"`
	Reason              string       `json:"reason,omitempty"`
	EvaluatedAt         time.Time    `json:"evaluated_at"`
	IntelligenceVersion string       `json:"intelligence_version"`
	IntelligenceDigest  string       `json:"intelligence_digest"`
	Summary             Summary      `json:"summary"`
	Evaluations         []Evaluation `json:"evaluations"`
}

type candidate struct {
	Ref        string
	Kind       string
	Product    string
	PackageID  string
	Version    string
	Family     string
	Confidence evidence.Confidence
}

// Evaluate correlates local OS/software/runtime/browser identities with the
// pinned lifecycle records. Matching is deliberately exact/anchored; it does
// not infer support from a substring-only package name or from a CVE record.
func Evaluate(o overview.Overview, inv software.Inventory, loaded intelligence.Loaded) Result {
	at := inv.CollectedAt.UTC()
	if at.IsZero() {
		at = o.CollectedAt.UTC()
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	out := Result{
		Schema: SchemaVersion, EngineVersion: EngineVersion, State: "COMPLETE", EvaluatedAt: at,
		IntelligenceVersion: loaded.Metadata.Version, IntelligenceDigest: loaded.Metadata.Digest,
		Evaluations: make([]Evaluation, 0),
	}
	candidates := inventoryCandidates(o, inv)
	out.Summary.Candidates = len(candidates)

	for _, c := range candidates {
		matches := matchingRecords(c, loaded.Store.Lifecycles)
		if len(matches) == 0 {
			out.Summary.NoIntelligence++
			continue
		}
		// A candidate can only have one applicable lifecycle series. If a
		// malformed/custom store makes multiple series applicable, preserve
		// uncertainty rather than arbitrarily selecting one.
		if len(matches) > 1 {
			ev := Evaluation{
				ID: stableID(c.Ref, "ambiguous"), RecordID: "AMBIGUOUS", CandidateRef: c.Ref,
				CandidateKind: c.Kind, Product: c.Product, Version: normalizedVersion(c.Version), Family: c.Family,
				Status: StatusUnknown, AssessedAt: at, SourceID: "multiple", Reference: "multiple lifecycle records",
				Confidence: evidence.ConfidenceLow, MatchEvidence: []string{"multiple applicable lifecycle records"},
				Reason: "multiple lifecycle records match this exact local identity/version series; support state is not guessed",
			}
			out.Evaluations = append(out.Evaluations, ev)
			out.Summary.WithIntelligence++
			out.Summary.Unknown++
			continue
		}
		rec := matches[0]
		status := Status(rec.StatusAfterEnd)
		if status == "" {
			status = StatusEOL
		}
		reason := "support end date has passed according to pinned lifecycle intelligence"
		if supportDateIncludes(rec.EndOfSupport, at) {
			status = StatusSupported
			reason = "support remains active through the published end-of-support date according to pinned lifecycle intelligence"
		}
		ev := Evaluation{
			ID: stableID(c.Ref, rec.ID), RecordID: rec.ID, CandidateRef: c.Ref, CandidateKind: c.Kind,
			Product: c.Product, Version: normalizedVersion(c.Version), Family: c.Family, Status: status,
			EndOfSupport: rec.EndOfSupport.UTC(), AssessedAt: at, SourceID: rec.SourceID,
			Reference: rec.Reference, Confidence: minConfidence(c.Confidence, evidence.ConfidenceHigh),
			MatchEvidence: matchEvidence(c, rec), Reason: reason,
		}
		out.Evaluations = append(out.Evaluations, ev)
		out.Summary.WithIntelligence++
		switch status {
		case StatusSupported:
			out.Summary.Supported++
		case StatusEOL:
			out.Summary.EndOfLife++
		case StatusUnsupported:
			out.Summary.Unsupported++
		default:
			out.Summary.Unknown++
		}
	}
	sort.Slice(out.Evaluations, func(i, j int) bool {
		if out.Evaluations[i].CandidateRef != out.Evaluations[j].CandidateRef {
			return out.Evaluations[i].CandidateRef < out.Evaluations[j].CandidateRef
		}
		return out.Evaluations[i].ID < out.Evaluations[j].ID
	})
	return out
}

// supportDateIncludes treats lifecycle end-of-support values as calendar dates,
// not midnight instants. Vendor lifecycle tables publish an inclusive final
// support date, so a product remains supported for that entire UTC date and
// becomes EOL/unsupported at the start of the following day.
func supportDateIncludes(endOfSupport, assessedAt time.Time) bool {
	end := endOfSupport.UTC()
	endExclusive := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	return assessedAt.UTC().Before(endExclusive)
}

func Unavailable(at time.Time, version, digest, reason string) Result {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(version) == "" {
		version = "unknown"
	}
	return Result{Schema: SchemaVersion, EngineVersion: EngineVersion, State: "UNAVAILABLE", Reason: strings.TrimSpace(reason), EvaluatedAt: at.UTC(), IntelligenceVersion: version, IntelligenceDigest: strings.TrimSpace(digest), Evaluations: []Evaluation{}}
}

func inventoryCandidates(o overview.Overview, inv software.Inventory) []candidate {
	out := make([]candidate, 0, 1+len(inv.Items)+len(inv.Runtimes)+len(inv.Browsers))
	if strings.TrimSpace(o.OS) != "" && strings.TrimSpace(o.OSVersion) != "" {
		out = append(out, candidate{Ref: "host.os", Kind: "os", Product: o.OS, Version: o.OSVersion, Family: platformFamily(o.OS), Confidence: evidence.ConfidenceExact})
	}
	for _, x := range inv.Items {
		out = append(out, candidate{Ref: "software.item." + x.ID, Kind: "installed-software", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Confidence: x.Confidence})
	}
	for _, x := range inv.Runtimes {
		out = append(out, candidate{Ref: "software.runtime." + x.ID, Kind: "runtime", Product: x.Product, Version: x.Version, Family: x.Family, Confidence: x.Confidence})
	}
	for _, x := range inv.Browsers {
		out = append(out, candidate{Ref: "software.browser." + x.ID, Kind: "browser", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Family: x.Family, Confidence: x.Confidence})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func matchingRecords(c candidate, records []intelligence.LifecycleRecord) []intelligence.LifecycleRecord {
	out := make([]intelligence.LifecycleRecord, 0, 1)
	for _, r := range records {
		if !containsFold(r.TargetKinds, c.Kind) {
			continue
		}
		if r.Family != "" && normalize(r.Family) != normalize(c.Family) {
			continue
		}
		if !identityMatches(c, r) {
			continue
		}
		if !seriesMatches(c.Version, r.VersionSeries) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func identityMatches(c candidate, r intelligence.LifecycleRecord) bool {
	product := normalize(c.Product)
	packageID := normalizePackage(c.PackageID)
	for _, name := range append([]string{r.Product}, r.Aliases...) {
		n := normalize(name)
		if n != "" && (product == n || packageID == n) {
			return true
		}
	}
	if c.Kind == "os" {
		for _, marker := range r.NameContains {
			m := normalize(marker)
			if m != "" && containsTokenPhrase(product, m) {
				return true
			}
		}
	}
	return false
}

func seriesMatches(version, series string) bool {
	version = strings.TrimSpace(strings.ToLower(version))
	series = strings.TrimSpace(strings.ToLower(series))
	if version == "" || series == "" || version == "unknown" {
		return false
	}
	if version == series {
		return true
	}
	if !strings.HasPrefix(version, series) {
		return false
	}
	if len(version) == len(series) {
		return true
	}
	next := version[len(series)]
	switch next {
	case '.', '-', '+', '_', ':':
		return true
	}
	// Some version lines append a patch letter directly (for example
	// OpenSSL 1.1.1w). A numeric continuation is never accepted because
	// that would make series 3.9 incorrectly match 3.90.
	return next >= 'a' && next <= 'z'
}

func matchEvidence(c candidate, r intelligence.LifecycleRecord) []string {
	out := []string{"target_kind=" + c.Kind, "version_series=" + r.VersionSeries}
	if r.Family != "" {
		out = append(out, "family="+r.Family)
	}
	out = append(out, "identity="+c.Product)
	return out
}

func platformFamily(name string) string {
	n := normalize(name)
	switch {
	case strings.Contains(n, "windows"):
		return "windows"
	case strings.Contains(n, "ubuntu"):
		return "ubuntu"
	case strings.Contains(n, "debian"):
		return "debian"
	case strings.Contains(n, "macos"), strings.Contains(n, "mac os"):
		return "macos"
	default:
		return "unknown"
	}
}

func containsTokenPhrase(haystack, needle string) bool {
	h := " " + strings.Join(strings.Fields(haystack), " ") + " "
	n := " " + strings.Join(strings.Fields(needle), " ") + " "
	return strings.Contains(h, n)
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
			continue
		}
		if !space && b.Len() > 0 {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
}

func normalizePackage(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.LastIndex(s, ":"); i > 0 {
		switch s[i+1:] {
		case "amd64", "arm64", "i386", "386", "x86", "x86_64", "all", "armhf", "armel":
			s = s[:i]
		}
	}
	return normalize(s)
}

func normalizedVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func containsFold(items []string, want string) bool {
	for _, x := range items {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
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
		default:
			return 1
		}
	}
	if rank(a) <= rank(b) {
		if a == "" {
			return evidence.ConfidenceLow
		}
		return a
	}
	return b
}

func stableID(ref, record string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(ref)) + "\x00" + strings.ToLower(strings.TrimSpace(record))))
	return "lc-" + hex.EncodeToString(sum[:10])
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion || r.EngineVersion != EngineVersion {
		return fmt.Errorf("unexpected lifecycle contract %q / %q", r.Schema, r.EngineVersion)
	}
	if strings.TrimSpace(r.State) == "" || r.EvaluatedAt.IsZero() || strings.TrimSpace(r.IntelligenceVersion) == "" {
		return fmt.Errorf("lifecycle provenance is incomplete")
	}
	if r.State == "COMPLETE" && len(r.IntelligenceDigest) != sha256.Size*2 {
		return fmt.Errorf("complete lifecycle result requires intelligence digest")
	}
	if r.State == "UNAVAILABLE" {
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("unavailable lifecycle result requires reason")
		}
		return nil
	}
	if r.State != "COMPLETE" {
		return fmt.Errorf("invalid lifecycle state %q", r.State)
	}
	if r.Summary.Candidates < 0 || r.Summary.WithIntelligence < 0 || r.Summary.NoIntelligence < 0 || r.Summary.WithIntelligence+r.Summary.NoIntelligence != r.Summary.Candidates {
		return fmt.Errorf("lifecycle candidate accounting is inconsistent")
	}
	if r.Summary.Supported+r.Summary.EndOfLife+r.Summary.Unsupported+r.Summary.Unknown != r.Summary.WithIntelligence || len(r.Evaluations) != r.Summary.WithIntelligence {
		return fmt.Errorf("lifecycle status accounting is inconsistent")
	}
	seen := map[string]struct{}{}
	for i, ev := range r.Evaluations {
		if ev.ID == "" || ev.RecordID == "" || ev.CandidateRef == "" || ev.CandidateKind == "" || ev.Product == "" || ev.Version == "" || ev.Status == "" || ev.AssessedAt.IsZero() || ev.SourceID == "" || ev.Reference == "" || ev.Confidence == "" || ev.Reason == "" {
			return fmt.Errorf("lifecycle evaluation %d is incomplete", i)
		}
		if _, ok := seen[ev.ID]; ok {
			return fmt.Errorf("duplicate lifecycle evaluation id %q", ev.ID)
		}
		seen[ev.ID] = struct{}{}
		if ev.Status != StatusUnknown && ev.EndOfSupport.IsZero() {
			return fmt.Errorf("lifecycle evaluation %q lacks end-of-support date", ev.ID)
		}
		switch ev.Status {
		case StatusSupported, StatusEOL, StatusUnsupported, StatusUnknown:
		default:
			return fmt.Errorf("invalid lifecycle status %q", ev.Status)
		}
	}
	return nil
}

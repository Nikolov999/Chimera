package updateposture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.update-posture/v1"
	CollectorVersion = "update-posture/phase030-v1"
	maxUpdates       = 10000
)

type State string

const (
	StateComplete    State = "COMPLETE"
	StateDegraded    State = "DEGRADED"
	StateUnavailable State = "UNAVAILABLE"
	StateUnsupported State = "UNSUPPORTED"
)

type Classification string

const (
	ClassificationSecurity Classification = "SECURITY"
	ClassificationOther    Classification = "OTHER"
	ClassificationUnknown  Classification = "UNKNOWN"
)

type Freshness string

const (
	FreshnessFresh   Freshness = "FRESH"
	FreshnessStale   Freshness = "STALE"
	FreshnessUnknown Freshness = "UNKNOWN"
)

type Update struct {
	ID               string              `json:"id"`
	Product          string              `json:"product"`
	PackageID        string              `json:"package_id"`
	InstalledVersion string              `json:"installed_version,omitempty"`
	CandidateVersion string              `json:"candidate_version,omitempty"`
	Architecture     string              `json:"architecture,omitempty"`
	Classification   Classification      `json:"classification"`
	AdvisoryID       string              `json:"advisory_id,omitempty"`
	RebootRequired   bool                `json:"reboot_required,omitempty"`
	Source           string              `json:"source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason"`
}

type ProviderStage struct {
	ID               string         `json:"id"`
	State            evidence.State `json:"state"`
	Command          string         `json:"command,omitempty"`
	ExitCode         *int           `json:"exit_code,omitempty"`
	ElapsedMS        int64          `json:"elapsed_ms,omitempty"`
	ExceptionType    string         `json:"exception_type,omitempty"`
	ExceptionMessage string         `json:"exception_message,omitempty"`
	Stderr           string         `json:"stderr,omitempty"`
	ItemCount        int            `json:"item_count,omitempty"`
	Reason           string         `json:"reason,omitempty"`
}

type Provider struct {
	ID            string          `json:"id"`
	State         evidence.State  `json:"state"`
	Source        string          `json:"source"`
	ItemCount     int             `json:"item_count"`
	SecurityCount int             `json:"security_count"`
	MetadataTime  time.Time       `json:"metadata_time,omitempty"`
	Freshness     Freshness       `json:"freshness"`
	Partial       bool            `json:"partial,omitempty"`
	Stages        []ProviderStage `json:"stages,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

type Summary struct {
	Providers                 int  `json:"providers"`
	Pending                   int  `json:"pending"`
	Security                  int  `json:"security"`
	Other                     int  `json:"other"`
	UnknownClassification     int  `json:"unknown_classification"`
	RebootRequired            bool `json:"reboot_required"`
	FreshProviders            int  `json:"fresh_providers"`
	StaleProviders            int  `json:"stale_providers"`
	UnknownFreshnessProviders int  `json:"unknown_freshness_providers"`
}

type Result struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	CollectorVersion string                 `json:"collector_version"`
	State            State                  `json:"state"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Summary          Summary                `json:"summary"`
	RebootRequired   bool                   `json:"reboot_required"`
	Updates          []Update               `json:"updates"`
	Providers        []Provider             `json:"providers"`
	Evidence         []evidence.Observation `json:"evidence"`
	Limitations      []string               `json:"limitations,omitempty"`
}

func Collect(ctx context.Context) Result {
	now := time.Now().UTC()
	r := Result{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, CollectorVersion: CollectorVersion, State: StateComplete, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: now, Updates: []Update{}, Providers: []Provider{}, Evidence: []evidence.Observation{}, Limitations: []string{}}
	collectPlatform(ctx, &r)
	normalize(&r)
	r.Evidence = buildEvidence(r)
	return r
}

func Unavailable(at time.Time, reason string) Result {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "update posture provider unavailable"
	}
	r := Result{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, CollectorVersion: CollectorVersion,
		State: StateUnavailable, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at.UTC(),
		Updates: []Update{}, Providers: []Provider{}, Limitations: []string{reason},
	}
	r.Evidence = []evidence.Observation{evidence.NewState("updates.provider.health", evidence.StateUnavailable, "provider guard", at.UTC(), evidence.ConfidenceExact, reason)}
	return r
}

func normalize(r *Result) {
	if r.Schema == "" {
		r.Schema = SchemaVersion
	}
	if r.EvidenceSchema == "" {
		r.EvidenceSchema = evidence.SchemaVersion
	}
	if r.CollectorVersion == "" {
		r.CollectorVersion = CollectorVersion
	}
	if r.CollectedAt.IsZero() {
		r.CollectedAt = time.Now().UTC()
	}
	if r.Updates == nil {
		r.Updates = []Update{}
	}
	if r.Providers == nil {
		r.Providers = []Provider{}
	}
	if r.Evidence == nil {
		r.Evidence = []evidence.Observation{}
	}
	if r.Limitations == nil {
		r.Limitations = []string{}
	}

	seen := map[string]Update{}
	for _, u := range r.Updates {
		u.Product = strings.TrimSpace(u.Product)
		u.PackageID = strings.TrimSpace(u.PackageID)
		if u.Product == "" {
			u.Product = u.PackageID
		}
		if u.PackageID == "" {
			u.PackageID = u.Product
		}
		if u.Product == "" {
			continue
		}
		if u.Classification == "" {
			u.Classification = ClassificationUnknown
		}
		if u.Source == "" {
			u.Source = "native local update metadata"
		}
		if u.Confidence == "" {
			u.Confidence = evidence.ConfidenceMedium
		}
		if strings.TrimSpace(u.Reason) == "" {
			u.Reason = "native local update metadata reports a pending candidate"
		}
		u.ID = stableID(u)
		key := strings.ToLower(strings.Join([]string{u.PackageID, u.InstalledVersion, u.CandidateVersion, string(u.Classification), u.AdvisoryID, u.Source}, "\x00"))
		if old, ok := seen[key]; !ok || confidenceRank(u.Confidence) > confidenceRank(old.Confidence) {
			seen[key] = u
		}
	}
	r.Updates = r.Updates[:0]
	for _, u := range seen {
		r.Updates = append(r.Updates, u)
	}
	sort.Slice(r.Updates, func(i, j int) bool {
		a, b := r.Updates[i], r.Updates[j]
		if classRank(a.Classification) != classRank(b.Classification) {
			return classRank(a.Classification) < classRank(b.Classification)
		}
		if strings.ToLower(a.Product) != strings.ToLower(b.Product) {
			return strings.ToLower(a.Product) < strings.ToLower(b.Product)
		}
		if a.CandidateVersion != b.CandidateVersion {
			return a.CandidateVersion < b.CandidateVersion
		}
		return a.ID < b.ID
	})
	if len(r.Updates) > maxUpdates {
		r.Updates = r.Updates[:maxUpdates]
		r.Limitations = append(r.Limitations, fmt.Sprintf("pending update inventory truncated at %d records", maxUpdates))
	}
	sort.Slice(r.Providers, func(i, j int) bool { return r.Providers[i].ID < r.Providers[j].ID })
	r.Limitations = uniqueSorted(r.Limitations)
	r.Summary = Summary{Providers: len(r.Providers)}
	for _, p := range r.Providers {
		switch p.Freshness {
		case FreshnessFresh:
			r.Summary.FreshProviders++
		case FreshnessStale:
			r.Summary.StaleProviders++
		default:
			r.Summary.UnknownFreshnessProviders++
		}
	}
	for _, u := range r.Updates {
		r.Summary.Pending++
		switch u.Classification {
		case ClassificationSecurity:
			r.Summary.Security++
		case ClassificationOther:
			r.Summary.Other++
		default:
			r.Summary.UnknownClassification++
		}
		if u.RebootRequired {
			r.Summary.RebootRequired = true
		}
	}
	r.Summary.RebootRequired = r.Summary.RebootRequired || r.RebootRequired
	r.RebootRequired = r.Summary.RebootRequired
	if len(r.Providers) == 0 {
		r.State = StateUnavailable
		r.Limitations = append(r.Limitations, "no supported native local update metadata provider was available")
	}
	anyObserved := false
	degraded := false
	for _, p := range r.Providers {
		if p.State == evidence.StateObserved {
			anyObserved = true
		}
		if p.Partial || p.State == evidence.StateDenied || p.State == evidence.StateDegraded || p.State == evidence.StateUnavailable {
			degraded = true
		}
	}
	if !anyObserved {
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			r.State = StateUnsupported
		} else {
			r.State = StateUnavailable
		}
	} else if degraded || r.Summary.StaleProviders > 0 || r.Summary.UnknownFreshnessProviders > 0 {
		r.State = StateDegraded
	} else {
		r.State = StateComplete
	}
	if r.Summary.StaleProviders > 0 {
		r.Limitations = uniqueSorted(append(r.Limitations, "one or more update metadata caches are stale; pending-update results may under-report current available fixes"))
	}
	if r.Summary.UnknownFreshnessProviders > 0 {
		r.Limitations = uniqueSorted(append(r.Limitations, "update metadata freshness could not be established for one or more providers; an empty pending-update set is not proof that no fixes are available"))
	}
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion {
		return fmt.Errorf("unexpected update posture schema %q", r.Schema)
	}
	if r.EvidenceSchema != evidence.SchemaVersion || strings.TrimSpace(r.CollectorVersion) == "" || strings.TrimSpace(r.Platform) == "" || strings.TrimSpace(r.Architecture) == "" || r.CollectedAt.IsZero() {
		return fmt.Errorf("update posture provenance is incomplete")
	}
	switch r.State {
	case StateComplete, StateDegraded, StateUnavailable, StateUnsupported:
	default:
		return fmt.Errorf("invalid update posture state %q", r.State)
	}
	if r.Updates == nil || r.Providers == nil || r.Evidence == nil {
		return fmt.Errorf("update posture arrays must be non-nil")
	}
	for _, p := range r.Providers {
		if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Source) == "" {
			return fmt.Errorf("incomplete update provider %#v", p)
		}
		switch p.State {
		case evidence.StateObserved, evidence.StateDenied, evidence.StateDegraded, evidence.StateUnavailable, evidence.StateNotApplicable:
		default:
			return fmt.Errorf("invalid update provider state %q", p.State)
		}
		stageIDs := map[string]struct{}{}
		for _, st := range p.Stages {
			if strings.TrimSpace(st.ID) == "" {
				return fmt.Errorf("update provider %q has a stage without an id", p.ID)
			}
			if _, ok := stageIDs[st.ID]; ok {
				return fmt.Errorf("update provider %q has duplicate stage %q", p.ID, st.ID)
			}
			stageIDs[st.ID] = struct{}{}
			switch st.State {
			case evidence.StateObserved, evidence.StateDenied, evidence.StateDegraded, evidence.StateUnavailable, evidence.StateNotApplicable:
			default:
				return fmt.Errorf("update provider %q has invalid stage state %q", p.ID, st.State)
			}
		}
	}
	if r.Summary.Pending != len(r.Updates) {
		return fmt.Errorf("pending summary does not match update records")
	}
	counts := map[Classification]int{}
	reboot := false
	ids := map[string]struct{}{}
	for _, u := range r.Updates {
		if !strings.HasPrefix(u.ID, "upd-") || strings.TrimSpace(u.Product) == "" || strings.TrimSpace(u.PackageID) == "" || strings.TrimSpace(u.Source) == "" || strings.TrimSpace(u.Reason) == "" {
			return fmt.Errorf("incomplete update record %#v", u)
		}
		if _, ok := ids[u.ID]; ok {
			return fmt.Errorf("duplicate update id %q", u.ID)
		}
		ids[u.ID] = struct{}{}
		switch u.Classification {
		case ClassificationSecurity, ClassificationOther, ClassificationUnknown:
		default:
			return fmt.Errorf("invalid update classification %q", u.Classification)
		}
		counts[u.Classification]++
		reboot = reboot || u.RebootRequired
	}
	if counts[ClassificationSecurity] != r.Summary.Security || counts[ClassificationOther] != r.Summary.Other || counts[ClassificationUnknown] != r.Summary.UnknownClassification || (reboot || r.RebootRequired) != r.Summary.RebootRequired {
		return fmt.Errorf("update posture summary is inconsistent")
	}
	if err := evidence.ValidateAll(r.Evidence); err != nil {
		return fmt.Errorf("update posture evidence: %w", err)
	}
	return nil
}

func buildEvidence(r Result) []evidence.Observation {
	at := r.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("updates.platform", r.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("updates.pending.count", r.Summary.Pending, "normalized native update metadata", at, evidence.ConfidenceExact),
		evidence.NewObserved("updates.security.count", r.Summary.Security, "normalized native update metadata", at, evidence.ConfidenceExact),
		evidence.NewObserved("updates.reboot_required", r.Summary.RebootRequired, "native servicing/update metadata", at, evidence.ConfidenceHigh),
	}
	for _, p := range r.Providers {
		key := "updates.provider." + slug(p.ID)
		if p.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, p, p.Source, at, evidence.ConfidenceHigh))
		} else {
			st := p.State
			if st == "" {
				st = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(p.Reason)
			if reason == "" {
				reason = "native update metadata provider did not return usable state"
			}
			out = append(out, evidence.NewState(key, st, p.Source, at, evidence.ConfidenceLow, reason))
		}
	}
	for _, u := range r.Updates {
		out = append(out, evidence.NewObserved("updates.item."+u.ID, u, u.Source, at, u.Confidence))
	}
	return out
}

func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func stableID(u Update) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join([]string{u.PackageID, u.InstalledVersion, u.CandidateVersion, string(u.Classification), u.AdvisoryID, u.Source}, "\x00"))))
	return "upd-" + hex.EncodeToString(sum[:10])
}
func confidenceRank(c evidence.Confidence) int {
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
func classRank(c Classification) int {
	switch c {
	case ClassificationSecurity:
		return 0
	case ClassificationUnknown:
		return 1
	default:
		return 2
	}
}
func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

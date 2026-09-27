package intelligence

import (
	"fmt"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	AssessmentSchemaVersion = "chimera.intelligence-assessment/v1"
	DefaultMaxAge           = 30 * 24 * time.Hour
)

type LoadOptions struct {
	Offline bool
	Now     time.Time
	MaxAge  time.Duration
}

type AssessmentStatus struct {
	Schema          string        `json:"schema"`
	Mode            string        `json:"mode"`
	State           string        `json:"state"`
	Freshness       string        `json:"freshness"`
	Age             time.Duration `json:"-"`
	AgeSeconds      int64         `json:"age_seconds"`
	MaxAgeSeconds   int64         `json:"max_age_seconds"`
	Available       bool          `json:"available"`
	ReadOnly        bool          `json:"read_only"`
	NetworkAccess   bool          `json:"network_access"`
	SnapshotVersion string        `json:"snapshot_version,omitempty"`
	SnapshotDigest  string        `json:"snapshot_digest,omitempty"`
	SnapshotSource  string        `json:"snapshot_source,omitempty"`
	Reason          string        `json:"reason,omitempty"`
}

type Session struct {
	Loaded   Loaded                 `json:"loaded"`
	Status   AssessmentStatus       `json:"status"`
	Evidence []evidence.Observation `json:"evidence"`
	err      error
}

// Open pins one immutable local intelligence snapshot for the lifetime of an
// assessment session. It performs no network access and never refreshes or
// mutates intelligence. refresh is an explicit maintenance path and is never called by Open.
func Open(opts LoadOptions) Session {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	mode := "LOCAL_PINNED"
	if opts.Offline {
		mode = "OFFLINE_PINNED"
	}

	loaded, err := Load()
	if err != nil {
		reason := strings.TrimSpace(err.Error())
		status := AssessmentStatus{
			Schema: AssessmentSchemaVersion, Mode: mode, State: "MISSING", Freshness: "UNAVAILABLE",
			MaxAgeSeconds: int64(maxAge / time.Second), Available: false, ReadOnly: true, NetworkAccess: false,
			Reason: reason,
		}
		return Session{Loaded: Loaded{}, Status: status, Evidence: unavailableEvidence(now, mode, reason), err: err}
	}

	age := now.Sub(loaded.Metadata.RetrievedAt.UTC())
	if age < 0 {
		age = 0
	}
	freshness := "CURRENT"
	state := "READY"
	if age > maxAge {
		freshness = "STALE"
		state = "STALE"
	}
	status := AssessmentStatus{
		Schema: AssessmentSchemaVersion, Mode: mode, State: state, Freshness: freshness,
		Age: age, AgeSeconds: int64(age / time.Second), MaxAgeSeconds: int64(maxAge / time.Second),
		Available: true, ReadOnly: true, NetworkAccess: false,
		SnapshotVersion: loaded.Metadata.Version, SnapshotDigest: loaded.Metadata.Digest, SnapshotSource: loaded.Metadata.Source,
	}
	if freshness == "STALE" {
		status.Reason = fmt.Sprintf("pinned intelligence snapshot is older than %s", maxAge)
	}
	return Session{Loaded: loaded, Status: status, Evidence: statusEvidence(now, loaded, status)}
}

func (s Session) Error() error { return s.err }

func (s Session) DegradationReasons() []string {
	if s.err != nil {
		return []string{"pinned vulnerability intelligence unavailable: " + s.err.Error()}
	}
	if s.Status.Freshness == "STALE" {
		return []string{fmt.Sprintf("pinned vulnerability intelligence is stale: age=%s max_age=%s", s.Status.Age.Truncate(time.Second), time.Duration(s.Status.MaxAgeSeconds)*time.Second)}
	}
	return nil
}

func statusEvidence(at time.Time, loaded Loaded, status AssessmentStatus) []evidence.Observation {
	src := loaded.Metadata.Source
	out := []evidence.Observation{
		evidence.NewObserved("intelligence.snapshot.available", true, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.mode", status.Mode, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.freshness", status.Freshness, src, at, evidence.ConfidenceHigh),
		evidence.NewObserved("intelligence.snapshot.version", loaded.Metadata.Version, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.digest", loaded.Metadata.Digest, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.read_only", true, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.network_access", false, src, at, evidence.ConfidenceExact),
	}
	return out
}

func unavailableEvidence(at time.Time, mode, reason string) []evidence.Observation {
	const src = "local vulnerability intelligence loader"
	return []evidence.Observation{
		evidence.NewState("intelligence.snapshot.available", evidence.StateUnavailable, src, at, evidence.ConfidenceExact, reason),
		evidence.NewObserved("intelligence.snapshot.mode", mode, src, at, evidence.ConfidenceExact),
		evidence.NewState("intelligence.snapshot.freshness", evidence.StateUnavailable, src, at, evidence.ConfidenceLow, "freshness cannot be determined because no valid pinned snapshot is available"),
		evidence.NewObserved("intelligence.snapshot.read_only", true, src, at, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.network_access", false, src, at, evidence.ConfidenceExact),
	}
}

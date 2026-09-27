package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidencequality"
)

const (
	AssessmentSnapshotSchemaVersion       = "chimera.assessment-snapshot/v1"
	maxAssessmentSnapshotBytes      int64 = 256 << 20
)

// AssessmentSnapshot is the Fix52 immutable normalized-assessment boundary.
// It freezes the exact scan result that produced findings and carries the
// evidence-quality identities needed by report/export consumers so they never
// need to recollect the host merely to render the same assessment.
type AssessmentSnapshot struct {
	Schema                 string                       `json:"schema"`
	AssessmentID           string                       `json:"assessment_id"`
	CapturedAt             time.Time                    `json:"captured_at"`
	DigestAlgorithm        string                       `json:"digest_algorithm"`
	Digest                 string                       `json:"digest"`
	CollectionState        State                        `json:"collection_state"`
	CollectionEvidence     EvidenceCounts               `json:"collection_evidence"`
	ProviderStates         []AssessmentProviderState    `json:"provider_states"`
	RawLimitations         []string                     `json:"raw_limitations,omitempty"`
	LimitationRootCauseIDs []string                     `json:"limitation_root_cause_ids,omitempty"`
	UnknownAudit           evidencequality.UnknownAudit `json:"unknown_audit"`
	Timing                 Timing                       `json:"timing"`
	FindingCount           int                          `json:"finding_count"`
	Assessment             Result                       `json:"assessment"`
}

type AssessmentProviderState struct {
	Name       string         `json:"name"`
	State      State          `json:"state"`
	Evidence   EvidenceCounts `json:"evidence"`
	DurationMS float64        `json:"duration_ms"`
}

type scanEnvelope struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data"`
}

// FreezeAssessmentSnapshot deep-clones a completed scan through JSON before
// returning it. Callers therefore receive an immutable value boundary rather
// than aliases to mutable slices/maps owned by the live assessment pipeline.
func FreezeAssessmentSnapshot(in Result) (AssessmentSnapshot, error) {
	if err := validateAssessmentSnapshotInput(in); err != nil {
		return AssessmentSnapshot{}, err
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("encode normalized assessment: %w", err)
	}
	var frozen Result
	if err := json.Unmarshal(encoded, &frozen); err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("clone normalized assessment: %w", err)
	}

	h := sha256.Sum256(encoded)
	providers := make([]AssessmentProviderState, 0, len(frozen.Collection.Providers))
	for _, provider := range frozen.Collection.Providers {
		providers = append(providers, AssessmentProviderState{
			Name: provider.Name, State: provider.State, Evidence: provider.Evidence,
			DurationMS: provider.Timing.DurationMS,
		})
	}
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })

	rawLimitations := assessmentSnapshotLimitations(frozen)
	classified, _ := evidencequality.ClassifyAll(rawLimitations)
	roots := make([]string, 0, len(classified))
	seenRoots := map[string]struct{}{}
	for _, item := range classified {
		root := strings.TrimSpace(item.RootCauseID)
		if root == "" {
			root = strings.TrimSpace(item.CanonicalKey)
		}
		if root == "" {
			continue
		}
		if _, ok := seenRoots[root]; ok {
			continue
		}
		seenRoots[root] = struct{}{}
		roots = append(roots, root)
	}
	sort.Strings(roots)

	out := AssessmentSnapshot{
		Schema:                 AssessmentSnapshotSchemaVersion,
		AssessmentID:           frozen.Snapshot.AssessmentID,
		CapturedAt:             frozen.Timing.CompletedAt,
		DigestAlgorithm:        "sha256",
		Digest:                 hex.EncodeToString(h[:]),
		CollectionState:        frozen.Collection.State,
		CollectionEvidence:     frozen.Collection.Evidence,
		ProviderStates:         providers,
		RawLimitations:         rawLimitations,
		LimitationRootCauseIDs: roots,
		UnknownAudit:           frozen.Summary.UnknownAudit,
		Timing:                 frozen.Timing,
		FindingCount:           len(frozen.Findings),
		Assessment:             frozen,
	}
	if err := out.Validate(); err != nil {
		return AssessmentSnapshot{}, err
	}
	return out, nil
}

// LoadAssessmentSnapshotFile accepts either an ordinary `chimera scan --json`
// envelope or a raw scan result, freezes it, and validates its deterministic
// snapshot before it is allowed to feed report generation.
func LoadAssessmentSnapshotFile(path string) (AssessmentSnapshot, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return AssessmentSnapshot{}, fmt.Errorf("assessment snapshot path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return AssessmentSnapshot{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return AssessmentSnapshot{}, err
	}
	if !st.Mode().IsRegular() {
		return AssessmentSnapshot{}, fmt.Errorf("%q is not a regular file", path)
	}
	if st.Size() > maxAssessmentSnapshotBytes {
		return AssessmentSnapshot{}, fmt.Errorf("%q exceeds %d-byte assessment snapshot limit", path, maxAssessmentSnapshotBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAssessmentSnapshotBytes+1))
	if err != nil {
		return AssessmentSnapshot{}, err
	}
	if int64(len(b)) > maxAssessmentSnapshotBytes {
		return AssessmentSnapshot{}, fmt.Errorf("%q exceeds %d-byte assessment snapshot limit", path, maxAssessmentSnapshotBytes)
	}
	b, err = normalizeAssessmentSnapshotJSON(b)
	if err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("normalize assessment snapshot text encoding: %w", err)
	}
	if int64(len(b)) > maxAssessmentSnapshotBytes {
		return AssessmentSnapshot{}, fmt.Errorf("decoded %q exceeds %d-byte assessment snapshot limit", path, maxAssessmentSnapshotBytes)
	}

	var env scanEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("decode assessment snapshot JSON: %w", err)
	}
	var result Result
	if len(env.Data) > 0 {
		if env.Command != "scan" {
			return AssessmentSnapshot{}, fmt.Errorf("JSON envelope command is %q, expected scan", env.Command)
		}
		if err := json.Unmarshal(env.Data, &result); err != nil {
			return AssessmentSnapshot{}, fmt.Errorf("decode scan envelope data: %w", err)
		}
	} else if err := json.Unmarshal(b, &result); err != nil {
		return AssessmentSnapshot{}, fmt.Errorf("decode scan result: %w", err)
	}
	return FreezeAssessmentSnapshot(result)
}

// normalizeAssessmentSnapshotJSON makes saved scan artifacts portable across
// the native-output encodings used by Windows PowerShell 5.1 and newer shells.
// JSON is decoded to UTF-8 before the normal schema/identity validation runs.
func normalizeAssessmentSnapshotJSON(in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("assessment snapshot file is empty")
	}

	// UTF-8 BOM. Go's encoding/json intentionally rejects it, while Windows
	// tooling may add it when persisting otherwise valid UTF-8 JSON.
	if bytes.HasPrefix(in, []byte{0xEF, 0xBB, 0xBF}) {
		in = in[3:]
	}

	// Windows PowerShell 5.1 commonly persists redirected native output as
	// UTF-16. Accept both BOM forms and a conservative BOM-less JSON heuristic
	// so a valid Chimera scan cannot become unreadable merely because of the
	// shell that wrote it.
	switch {
	case bytes.HasPrefix(in, []byte{0xFF, 0xFE}):
		return decodeAssessmentSnapshotUTF16(in[2:], true)
	case bytes.HasPrefix(in, []byte{0xFE, 0xFF}):
		return decodeAssessmentSnapshotUTF16(in[2:], false)
	case looksLikeUTF16LEJSON(in):
		return decodeAssessmentSnapshotUTF16(in, true)
	case looksLikeUTF16BEJSON(in):
		return decodeAssessmentSnapshotUTF16(in, false)
	default:
		return in, nil
	}
}

func decodeAssessmentSnapshotUTF16(in []byte, littleEndian bool) ([]byte, error) {
	if len(in)%2 != 0 {
		return nil, fmt.Errorf("UTF-16 assessment snapshot has odd byte length %d", len(in))
	}
	words := make([]uint16, len(in)/2)
	for i := range words {
		j := i * 2
		if littleEndian {
			words[i] = uint16(in[j]) | uint16(in[j+1])<<8
		} else {
			words[i] = uint16(in[j])<<8 | uint16(in[j+1])
		}
	}
	decoded := string(utf16.Decode(words))
	decoded = strings.TrimPrefix(decoded, "\uFEFF")
	return []byte(decoded), nil
}

func looksLikeUTF16LEJSON(in []byte) bool {
	if len(in) < 4 {
		return false
	}
	// JSON artifacts start with optional ASCII whitespace followed by '{'.
	for i := 0; i+1 < len(in) && i < 64; i += 2 {
		if in[i+1] != 0 {
			return false
		}
		switch in[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

func looksLikeUTF16BEJSON(in []byte) bool {
	if len(in) < 4 {
		return false
	}
	for i := 0; i+1 < len(in) && i < 64; i += 2 {
		if in[i] != 0 {
			return false
		}
		switch in[i+1] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

func (s AssessmentSnapshot) Validate() error {
	if s.Schema != AssessmentSnapshotSchemaVersion {
		return fmt.Errorf("unexpected assessment snapshot schema %q", s.Schema)
	}
	if strings.TrimSpace(s.AssessmentID) == "" || s.AssessmentID != s.Assessment.Snapshot.AssessmentID {
		return fmt.Errorf("assessment snapshot identity mismatch")
	}
	if s.CapturedAt.IsZero() || s.DigestAlgorithm != "sha256" || len(s.Digest) != sha256.Size*2 {
		return fmt.Errorf("assessment snapshot digest/timestamp is incomplete")
	}
	if s.FindingCount != len(s.Assessment.Findings) {
		return fmt.Errorf("assessment snapshot finding count mismatch")
	}
	if err := s.UnknownAudit.Validate(s.Assessment.Summary.Findings.Unknown); err != nil {
		return fmt.Errorf("validate assessment snapshot UNKNOWN audit: %w", err)
	}
	if s.UnknownAudit.Summary != s.Assessment.Summary.UnknownAudit.Summary {
		return fmt.Errorf("assessment snapshot UNKNOWN audit does not match scan summary")
	}
	if s.CollectionState != s.Assessment.Collection.State || s.CollectionEvidence != s.Assessment.Collection.Evidence {
		return fmt.Errorf("assessment snapshot collection state/evidence mismatch")
	}
	if err := validateAssessmentSnapshotInput(s.Assessment); err != nil {
		return err
	}
	encoded, err := json.Marshal(s.Assessment)
	if err != nil {
		return fmt.Errorf("re-encode assessment snapshot: %w", err)
	}
	h := sha256.Sum256(encoded)
	if hex.EncodeToString(h[:]) != s.Digest {
		return fmt.Errorf("assessment snapshot digest mismatch")
	}
	return nil
}

func (s AssessmentSnapshot) ResultCopy() (Result, error) {
	if err := s.Validate(); err != nil {
		return Result{}, err
	}
	b, err := json.Marshal(s.Assessment)
	if err != nil {
		return Result{}, err
	}
	var out Result
	if err := json.Unmarshal(b, &out); err != nil {
		return Result{}, err
	}
	return out, nil
}

func validateAssessmentSnapshotInput(in Result) error {
	if in.Schema != SchemaVersion {
		return fmt.Errorf("unsupported scan schema %q", in.Schema)
	}
	if strings.TrimSpace(in.Snapshot.AssessmentID) == "" {
		return fmt.Errorf("assessment snapshot identity is missing")
	}
	if err := in.Snapshot.Validate(); err != nil {
		return fmt.Errorf("validate deterministic assessment provenance: %w", err)
	}
	if err := assessment.ValidateAll(in.Findings); err != nil {
		return fmt.Errorf("validate assessment findings: %w", err)
	}
	if err := in.Summary.UnknownAudit.Validate(in.Summary.Findings.Unknown); err != nil {
		return fmt.Errorf("validate scan UNKNOWN audit: %w", err)
	}
	return nil
}

func assessmentSnapshotLimitations(s Result) []string {
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		seen[v] = struct{}{}
	}
	if s.TimedOut {
		add("assessment reached its configured timeout; some evidence or categories may be incomplete")
	}
	for _, v := range s.Collection.DegradationReasons {
		add(v)
	}
	for _, c := range s.Categories {
		if c.Reason != "" {
			add(c.Name + ": " + c.Reason)
		}
		for _, v := range c.DegradationReasons {
			add(c.Name + ": " + v)
		}
	}
	if s.Snapshot.Intelligence.Reason != "" {
		add("intelligence: " + s.Snapshot.Intelligence.Reason)
	}
	if s.Overview.Privilege.ElevationNote != "" {
		add("privilege: " + s.Overview.Privilege.ElevationNote)
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

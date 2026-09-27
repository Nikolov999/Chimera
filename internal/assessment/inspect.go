package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const InspectionSchemaVersion = "chimera.finding-inspection/v1"

type RuleDescriptor struct {
	ID             string      `json:"id"`
	Title          string      `json:"title"`
	Category       string      `json:"category"`
	Severity       Severity    `json:"severity"`
	AffectedObject string      `json:"affected_object"`
	ExpectedState  string      `json:"expected_state"`
	Risk           string      `json:"risk"`
	Remediation    string      `json:"remediation"`
	References     []Reference `json:"references,omitempty"`
}

type Reproducibility struct {
	Algorithm      string   `json:"algorithm"`
	RuleID         string   `json:"rule_id"`
	AffectedObject string   `json:"affected_object"`
	EvidenceKeys   []string `json:"evidence_keys"`
	EvidenceDigest string   `json:"evidence_digest"`
	DerivedID      string   `json:"derived_finding_id"`
	MatchesID      bool     `json:"matches_finding_id"`
}

type FindingInspection struct {
	Schema         string          `json:"inspection_schema"`
	FindingSchema  string          `json:"finding_schema"`
	EvidenceSchema string          `json:"evidence_schema"`
	Finding        Finding         `json:"finding"`
	Rule           RuleDescriptor  `json:"rule"`
	Provenance     []EvidenceRef   `json:"provenance"`
	Reproducible   Reproducibility `json:"reproducibility"`
}

// InspectFinding re-evaluates the supplied rules exclusively from the supplied
// normalized evidence snapshot and returns a focused finding plus the exact
// evidence provenance that produced it. No host collection occurs here.
func InspectFinding(rules []Rule, observations []evidence.Observation, assessedAt time.Time, findingID string) (FindingInspection, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return FindingInspection{}, fmt.Errorf("finding id is required")
	}

	findings, err := EvaluateRules(rules, observations, assessedAt)
	if err != nil {
		return FindingInspection{}, err
	}
	var found *Finding
	for i := range findings {
		if strings.EqualFold(findings[i].ID, findingID) {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		return FindingInspection{}, fmt.Errorf("finding %q not found in the current assessment snapshot", findingID)
	}

	var rule *Rule
	for i := range rules {
		if rules[i].ID == found.RuleID {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		return FindingInspection{}, fmt.Errorf("rule %q for finding %q is unavailable", found.RuleID, found.ID)
	}

	provenance := append([]EvidenceRef(nil), found.Evidence...)
	sort.SliceStable(provenance, func(i, j int) bool { return provenance[i].Key < provenance[j].Key })
	keys := make([]string, 0, len(provenance))
	for _, p := range provenance {
		keys = append(keys, p.Key)
	}
	digest, err := evidenceDigest(*rule, provenance)
	if err != nil {
		return FindingInspection{}, fmt.Errorf("compute reproducibility digest: %w", err)
	}
	derived := StableFindingID(rule.ID, rule.AffectedObject)

	return FindingInspection{
		Schema:         InspectionSchemaVersion,
		FindingSchema:  SchemaVersion,
		EvidenceSchema: evidence.SchemaVersion,
		Finding:        *found,
		Rule: RuleDescriptor{
			ID: rule.ID, Title: rule.Title, Category: rule.Category, Severity: rule.Severity,
			AffectedObject: rule.AffectedObject, ExpectedState: rule.ExpectedState,
			Risk: rule.Risk, Remediation: rule.Remediation, References: append([]Reference(nil), rule.References...),
		},
		Provenance: provenance,
		Reproducible: Reproducibility{
			Algorithm:      "sha256(rule_id + affected_object + normalized evidence key/state/value/source/confidence/reason)",
			RuleID:         rule.ID,
			AffectedObject: rule.AffectedObject,
			EvidenceKeys:   keys,
			EvidenceDigest: digest,
			DerivedID:      derived,
			MatchesID:      derived == found.ID,
		},
	}, nil
}

type digestObservation struct {
	Key        string              `json:"key"`
	State      evidence.State      `json:"state"`
	Value      any                 `json:"value,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Reason     string              `json:"reason,omitempty"`
}

type digestInput struct {
	RuleID         string              `json:"rule_id"`
	AffectedObject string              `json:"affected_object"`
	Evidence       []digestObservation `json:"evidence"`
}

func evidenceDigest(rule Rule, provenance []EvidenceRef) (string, error) {
	items := make([]digestObservation, 0, len(provenance))
	for _, p := range provenance {
		items = append(items, digestObservation{
			Key: p.Key, State: p.State, Value: p.Value, Source: p.Source,
			Confidence: p.Confidence, Reason: p.Reason,
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	b, err := json.Marshal(digestInput{RuleID: rule.ID, AffectedObject: rule.AffectedObject, Evidence: items})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

package evidencequality

import (
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

type UnknownCauseClass string

const (
	UnknownMissingRequiredEvidence UnknownCauseClass = "MISSING_REQUIRED_EVIDENCE"
	UnknownProductDefect           UnknownCauseClass = "PROVIDER_PRODUCT_DEFECT"
	UnknownDeadlineBudget          UnknownCauseClass = "DEADLINE_BUDGET"
	UnknownPermissionRestriction   UnknownCauseClass = "PERMISSION_RESTRICTION"
	UnknownExpectedEnvironment     UnknownCauseClass = "EXPECTED_ENVIRONMENT"
	UnknownOptionalProvider        UnknownCauseClass = "OPTIONAL_PROVIDER"
	UnknownUnsupportedSafe         UnknownCauseClass = "UNSUPPORTED_SAFE_COLLECTION"
	UnknownNotApplicable           UnknownCauseClass = "NOT_APPLICABLE"
	UnknownDegradedEvidence        UnknownCauseClass = "DEGRADED_EVIDENCE"
	UnknownOther                   UnknownCauseClass = "OTHER"
)

type UnknownCause struct {
	Class   UnknownCauseClass `json:"class"`
	Count   int               `json:"count"`
	RuleIDs []string          `json:"rule_ids,omitempty"`
}

type UnknownSummary struct {
	Total                   int `json:"total"`
	MissingRequiredEvidence int `json:"missing_required_evidence"`
	ProductDefect           int `json:"provider_product_defect"`
	DeadlineBudget          int `json:"deadline_budget"`
	PermissionRestriction   int `json:"permission_restriction"`
	ExpectedEnvironment     int `json:"expected_environment"`
	OptionalProvider        int `json:"optional_provider"`
	UnsupportedSafe         int `json:"unsupported_safe_collection"`
	NotApplicable           int `json:"not_applicable"`
	DegradedEvidence        int `json:"degraded_evidence"`
	Other                   int `json:"other"`
}

// ClassifyUnknownFindings explains UNKNOWN findings without changing their
// assessment status. Fix33 uses this only for evidence-quality auditability;
// missing evidence is never promoted to PASS.
func ClassifyUnknownFindings(findings []assessment.Finding) ([]UnknownCause, UnknownSummary) {
	byClass := map[UnknownCauseClass][]string{}
	var summary UnknownSummary
	for _, finding := range findings {
		if finding.Status != assessment.StatusUnknown {
			continue
		}
		class := classifyUnknownFinding(finding)
		byClass[class] = append(byClass[class], finding.RuleID)
		summary.Total++
		switch class {
		case UnknownMissingRequiredEvidence:
			summary.MissingRequiredEvidence++
		case UnknownProductDefect:
			summary.ProductDefect++
		case UnknownDeadlineBudget:
			summary.DeadlineBudget++
		case UnknownPermissionRestriction:
			summary.PermissionRestriction++
		case UnknownExpectedEnvironment:
			summary.ExpectedEnvironment++
		case UnknownOptionalProvider:
			summary.OptionalProvider++
		case UnknownUnsupportedSafe:
			summary.UnsupportedSafe++
		case UnknownNotApplicable:
			summary.NotApplicable++
		case UnknownDegradedEvidence:
			summary.DegradedEvidence++
		default:
			summary.Other++
		}
	}

	classes := make([]UnknownCauseClass, 0, len(byClass))
	for class := range byClass {
		classes = append(classes, class)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	out := make([]UnknownCause, 0, len(classes))
	for _, class := range classes {
		rules := uniqueSortedStrings(byClass[class])
		out = append(out, UnknownCause{Class: class, Count: len(rules), RuleIDs: rules})
	}
	return out, summary
}

func classifyUnknownFinding(f assessment.Finding) UnknownCauseClass {
	best := UnknownOther
	bestRank := unknownRank(best)
	for _, ref := range f.Evidence {
		candidate := classifyUnknownEvidence(ref)
		if rank := unknownRank(candidate); rank > bestRank {
			best, bestRank = candidate, rank
		}
	}
	if best != UnknownOther {
		return best
	}

	text := strings.ToLower(strings.TrimSpace(f.ObservedState))
	switch {
	case containsAny(text, "context deadline", "deadline", "timed out", "budget"):
		return UnknownDeadlineBudget
	case containsAny(text, "permission", "access-restricted", "access denied", "denied"):
		return UnknownPermissionRestriction
	case containsAny(text, "intentionally does not", "unsupported safe", "safe collection"):
		return UnknownUnsupportedSafe
	case containsAny(text, "not applicable", "not_applicable"):
		return UnknownNotApplicable
	case containsAny(text, "degraded", "unresolved", "incomplete"):
		return UnknownDegradedEvidence
	case containsAny(text, "missing", "unavailable", "no usable", "required evidence", "provider evidence"):
		return UnknownMissingRequiredEvidence
	default:
		return UnknownOther
	}
}

func classifyUnknownEvidence(ref assessment.EvidenceRef) UnknownCauseClass {
	reason := strings.TrimSpace(ref.Reason)
	if reason != "" {
		lim := Classify(reason)
		switch lim.Class {
		case ClassProductDefect:
			return UnknownProductDefect
		case ClassDeadlineBudget:
			return UnknownDeadlineBudget
		case ClassPermission:
			return UnknownPermissionRestriction
		case ClassExpectedEnvironment:
			return UnknownExpectedEnvironment
		case ClassOptionalProvider:
			return UnknownOptionalProvider
		case ClassNotApplicable:
			return UnknownNotApplicable
		}
	}

	switch ref.State {
	case evidence.StateDenied:
		return UnknownPermissionRestriction
	case evidence.StateUnsupported:
		return UnknownUnsupportedSafe
	case evidence.StateNotApplicable:
		return UnknownNotApplicable
	case evidence.StateDegraded:
		return UnknownDegradedEvidence
	case evidence.StateUnavailable:
		return UnknownMissingRequiredEvidence
	default:
		return UnknownOther
	}
}

func unknownRank(class UnknownCauseClass) int {
	switch class {
	case UnknownProductDefect:
		return 100
	case UnknownDeadlineBudget:
		return 90
	case UnknownPermissionRestriction:
		return 80
	case UnknownExpectedEnvironment:
		return 70
	case UnknownOptionalProvider:
		return 60
	case UnknownUnsupportedSafe:
		return 50
	case UnknownNotApplicable:
		return 40
	case UnknownDegradedEvidence:
		return 30
	case UnknownMissingRequiredEvidence:
		return 20
	default:
		return 0
	}
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

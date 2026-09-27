package evidencequality

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
)

const UnknownAuditSchemaVersion = "chimera.unknown-audit/v1"

type UnknownPrimaryClass string

const (
	UnknownRequiredEvidenceMissing UnknownPrimaryClass = "REQUIRED_EVIDENCE_MISSING"
	UnknownPrimaryProductDefect    UnknownPrimaryClass = "PRODUCT_DEFECT"
	UnknownPrimaryPermission       UnknownPrimaryClass = "PERMISSION_RESTRICTION"
	UnknownPrimaryOptionalAbsent   UnknownPrimaryClass = "OPTIONAL_PROVIDER_ABSENT"
	UnknownEnvironmentalAbsence    UnknownPrimaryClass = "ENVIRONMENTAL_ABSENCE"
	UnknownSafeCollectionBoundary  UnknownPrimaryClass = "SAFE_COLLECTION_BOUNDARY"
	UnknownUnsupportedState        UnknownPrimaryClass = "UNSUPPORTED_STATE"
	UnknownPrimaryNotApplicable    UnknownPrimaryClass = "NON_APPLICABLE"
	UnknownTemporalRace            UnknownPrimaryClass = "TEMPORAL_RACE"
	UnknownOtherExplained          UnknownPrimaryClass = "OTHER_EXPLAINED"
)

type UnknownAuditEntry struct {
	RuleID               string              `json:"rule_id"`
	RuleFamily           string              `json:"rule_family"`
	Category             string              `json:"category"`
	EvidenceDependencies []string            `json:"evidence_dependencies"`
	RootCauseID          string              `json:"root_cause_id"`
	Classification       UnknownPrimaryClass `json:"classification"`
	FindingCount         int                 `json:"finding_count"`
	AffectedCount        int                 `json:"affected_count"`
	Reason               string              `json:"reason"`
}

type UnknownAuditSummary struct {
	Total                   int `json:"total"`
	RequiredEvidenceMissing int `json:"required_evidence_missing"`
	ProductDefect           int `json:"product_defect"`
	PermissionRestriction   int `json:"permission_restriction"`
	OptionalProviderAbsent  int `json:"optional_provider_absent"`
	EnvironmentalAbsence    int `json:"environmental_absence"`
	SafeCollectionBoundary  int `json:"safe_collection_boundary"`
	UnsupportedState        int `json:"unsupported_state"`
	NonApplicable           int `json:"non_applicable"`
	TemporalRace            int `json:"temporal_race"`
	OtherExplained          int `json:"other_explained"`
}

type UnknownAudit struct {
	Schema  string              `json:"schema"`
	Summary UnknownAuditSummary `json:"summary"`
	Entries []UnknownAuditEntry `json:"entries"`
}

type unknownCandidate struct {
	class  UnknownPrimaryClass
	reason string
	rank   int
}

var (
	unknownOfTotalRE = regexp.MustCompile(`(?i)\b([0-9]+)\s+of\s+[0-9]+\b`)
	unknownForRE     = regexp.MustCompile(`(?i)\bfor\s+([0-9]+)\s+(?:of\s+[0-9]+\s+)?`)
	unknownCountRE   = regexp.MustCompile(`(?i)\b([0-9]+)\s+(?:[a-z0-9_/-]+\s+){0,4}(?:record|records|endpoint|endpoints|service|services|setting|settings|account|accounts|state|states|process|processes)(?:\(s\))?\b`)
)

// AuditUnknownFindings produces the Fix42 machine-readable UNKNOWN audit. It
// explains UNKNOWN; it never mutates rule status or promotes incomplete
// evidence to PASS.
func AuditUnknownFindings(findings []assessment.Finding) UnknownAudit {
	type group struct {
		entry UnknownAuditEntry
	}
	groups := map[string]*group{}
	order := make([]string, 0)
	var summary UnknownAuditSummary

	for _, finding := range findings {
		if finding.Status != assessment.StatusUnknown {
			continue
		}
		classification, reason := classifyUnknownPrimary(finding)
		dependencies := unknownEvidenceDependencies(finding)
		rootCauseID := unknownRootCauseID(classification, reason)
		family := unknownRuleFamily(finding.RuleID)
		affected := unknownAffectedCount(finding)
		if affected < 1 {
			affected = 1
		}
		key := strings.Join([]string{
			strings.ToUpper(strings.TrimSpace(finding.RuleID)),
			string(classification),
			rootCauseID,
			strings.Join(dependencies, ","),
		}, "\x00")
		if existing := groups[key]; existing != nil {
			existing.entry.FindingCount++
			existing.entry.AffectedCount += affected
		} else {
			groups[key] = &group{entry: UnknownAuditEntry{
				RuleID: strings.TrimSpace(finding.RuleID), RuleFamily: family,
				Category: strings.TrimSpace(finding.Category), EvidenceDependencies: dependencies,
				RootCauseID: rootCauseID, Classification: classification,
				FindingCount: 1, AffectedCount: affected, Reason: conciseUnknownReason(reason),
			}}
			order = append(order, key)
		}
		summary.Total++
		incrementUnknownPrimarySummary(&summary, classification)
	}

	entries := make([]UnknownAuditEntry, 0, len(order))
	for _, key := range order {
		entries = append(entries, groups[key].entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].RuleFamily != entries[j].RuleFamily {
			return entries[i].RuleFamily < entries[j].RuleFamily
		}
		if entries[i].RuleID != entries[j].RuleID {
			return entries[i].RuleID < entries[j].RuleID
		}
		if entries[i].Classification != entries[j].Classification {
			return entries[i].Classification < entries[j].Classification
		}
		return entries[i].RootCauseID < entries[j].RootCauseID
	})
	return UnknownAudit{Schema: UnknownAuditSchemaVersion, Summary: summary, Entries: entries}
}

func (a UnknownAudit) Validate(expectedUnknown int) error {
	if a.Schema != UnknownAuditSchemaVersion {
		return fmt.Errorf("unexpected UNKNOWN audit schema %q", a.Schema)
	}
	if a.Summary.Total != expectedUnknown {
		return fmt.Errorf("UNKNOWN audit total=%d does not match findings=%d", a.Summary.Total, expectedUnknown)
	}
	classified := a.Summary.RequiredEvidenceMissing + a.Summary.ProductDefect + a.Summary.PermissionRestriction +
		a.Summary.OptionalProviderAbsent + a.Summary.EnvironmentalAbsence + a.Summary.SafeCollectionBoundary +
		a.Summary.UnsupportedState + a.Summary.NonApplicable + a.Summary.TemporalRace + a.Summary.OtherExplained
	if classified != a.Summary.Total {
		return fmt.Errorf("UNKNOWN audit classification total=%d does not match total=%d", classified, a.Summary.Total)
	}
	findingCount := 0
	seen := map[string]struct{}{}
	for i, entry := range a.Entries {
		if strings.TrimSpace(entry.RuleID) == "" || strings.TrimSpace(entry.RuleFamily) == "" || strings.TrimSpace(entry.Category) == "" {
			return fmt.Errorf("UNKNOWN audit entry %d is missing rule identity/category", i)
		}
		if !validUnknownPrimaryClass(entry.Classification) {
			return fmt.Errorf("UNKNOWN audit entry %d has invalid classification %q", i, entry.Classification)
		}
		if strings.TrimSpace(entry.RootCauseID) == "" || strings.TrimSpace(entry.Reason) == "" {
			return fmt.Errorf("UNKNOWN audit entry %d is missing root cause/reason", i)
		}
		if entry.FindingCount < 1 || entry.AffectedCount < 1 {
			return fmt.Errorf("UNKNOWN audit entry %d has invalid finding/affected counts", i)
		}
		if len(entry.EvidenceDependencies) == 0 {
			return fmt.Errorf("UNKNOWN audit entry %d has no evidence dependency", i)
		}
		key := strings.ToLower(strings.Join([]string{entry.RuleID, string(entry.Classification), entry.RootCauseID, strings.Join(entry.EvidenceDependencies, ",")}, "\x00"))
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate UNKNOWN audit group for %q", entry.RuleID)
		}
		seen[key] = struct{}{}
		findingCount += entry.FindingCount
	}
	if findingCount != a.Summary.Total {
		return fmt.Errorf("UNKNOWN audit grouped finding count=%d does not match total=%d", findingCount, a.Summary.Total)
	}
	return nil
}

func validUnknownPrimaryClass(class UnknownPrimaryClass) bool {
	switch class {
	case UnknownRequiredEvidenceMissing, UnknownPrimaryProductDefect, UnknownPrimaryPermission,
		UnknownPrimaryOptionalAbsent, UnknownEnvironmentalAbsence, UnknownSafeCollectionBoundary,
		UnknownUnsupportedState, UnknownPrimaryNotApplicable, UnknownTemporalRace, UnknownOtherExplained:
		return true
	default:
		return false
	}
}

func incrementUnknownPrimarySummary(summary *UnknownAuditSummary, class UnknownPrimaryClass) {
	switch class {
	case UnknownRequiredEvidenceMissing:
		summary.RequiredEvidenceMissing++
	case UnknownPrimaryProductDefect:
		summary.ProductDefect++
	case UnknownPrimaryPermission:
		summary.PermissionRestriction++
	case UnknownPrimaryOptionalAbsent:
		summary.OptionalProviderAbsent++
	case UnknownEnvironmentalAbsence:
		summary.EnvironmentalAbsence++
	case UnknownSafeCollectionBoundary:
		summary.SafeCollectionBoundary++
	case UnknownUnsupportedState:
		summary.UnsupportedState++
	case UnknownPrimaryNotApplicable:
		summary.NonApplicable++
	case UnknownTemporalRace:
		summary.TemporalRace++
	default:
		summary.OtherExplained++
	}
}

func classifyUnknownPrimary(f assessment.Finding) (UnknownPrimaryClass, string) {
	candidates := make([]unknownCandidate, 0, len(f.Evidence)+1)
	for _, ref := range f.Evidence {
		if reason := strings.TrimSpace(ref.Reason); reason != "" {
			class, rank := unknownPrimaryFromText(reason)
			candidates = append(candidates, unknownCandidate{class: class, reason: reason, rank: rank})
		}
		for _, reason := range supplementalUnknownEvidenceReasons(f.RuleID, ref) {
			class, rank := unknownPrimaryFromText(reason)
			candidates = append(candidates, unknownCandidate{class: class, reason: reason, rank: rank})
		}
	}
	observed := strings.TrimSpace(f.ObservedState)
	if observed != "" {
		class, rank := unknownPrimaryFromText(observed)
		candidates = append(candidates, unknownCandidate{class: class, reason: observed, rank: rank})
	}
	if len(candidates) == 0 {
		return UnknownRequiredEvidenceMissing, "UNKNOWN finding has no direct evidence reason; required normalized evidence is missing"
	}
	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.rank > best.rank {
			best = candidate
		}
	}
	if best.class == "" {
		best.class = UnknownOtherExplained
	}
	if strings.TrimSpace(best.reason) == "" {
		best.reason = "UNKNOWN remains explained by incomplete or ambiguous normalized evidence"
	}
	return best.class, best.reason
}

func supplementalUnknownEvidenceReasons(ruleID string, ref assessment.EvidenceRef) []string {
	ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
	key := strings.ToLower(strings.TrimSpace(ref.Key))
	paths := [][]string{}
	switch {
	case (ruleID == "CHM-PRC-002" || ruleID == "CHM-PRC-003" || ruleID == "CHM-PRC-004") && strings.HasPrefix(key, "process.item."):
		paths = append(paths, []string{"trust", "reason"})
	case (ruleID == "CHM-PRC-008" || ruleID == "CHM-PRC-009" || ruleID == "CHM-PRC-010") && strings.HasPrefix(key, "process.permission."):
		return collectJSONReasonFields(ref.Value, 32)
	case (ruleID == "CHM-PRC-019" || ruleID == "CHM-PRC-020" || ruleID == "CHM-PRC-021") && strings.HasPrefix(key, "process.environment."):
		paths = append(paths, []string{"reason"})
	case ruleID == "CHM-ID-005" && strings.HasPrefix(key, "account.item."):
		paths = append(paths, []string{"authentication", "reason"})
	case ruleID == "CHM-CTR-018" && strings.HasPrefix(key, "container.runtime_endpoint."):
		paths = append(paths, []string{"reason"})
	default:
		return nil
	}

	root, ok := jsonObject(ref.Value)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if reason := jsonPathString(root, path...); reason != "" {
			out = appendUniqueSorted(out, reason)
		}
	}
	return out
}

func jsonObject(value any) (map[string]any, bool) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, false
	}
	return root, true
}

func jsonPathString(root map[string]any, path ...string) string {
	var current any = root
	for _, part := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[part]
		if !ok {
			return ""
		}
	}
	value, _ := current.(string)
	return strings.TrimSpace(value)
}

func collectJSONReasonFields(value any, limit int) []string {
	b, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var root any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil
	}
	out := []string{}
	var walk func(any, int)
	walk = func(v any, depth int) {
		if depth > 8 || len(out) >= limit {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := x[key]
				if strings.EqualFold(key, "reason") {
					if reason, ok := child.(string); ok && strings.TrimSpace(reason) != "" {
						out = appendUniqueSorted(out, strings.TrimSpace(reason))
					}
				}
				walk(child, depth+1)
			}
		case []any:
			for _, child := range x {
				walk(child, depth+1)
			}
		}
	}
	walk(root, 0)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func unknownPrimaryFromText(reason string) (UnknownPrimaryClass, int) {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return UnknownOtherExplained, 1
	}
	// A process disappearing while it is being observed is a temporal race,
	// not a provider defect and not a reason to infer a safe state.
	if containsAny(r, "process exited during collection", "exited during collection", "removed during collection", "disappeared during collection", "no longer exists during collection") {
		return UnknownTemporalRace, 95
	}
	// Normal-assessment provider/schema/deadline failures are engineering
	// defects. Deliberate short-timeout scans do not reach the enterprise report
	// release audit as complete normal assessments.
	if containsAny(r,
		"context deadline exceeded", "collector deadline reached", "collection deadline reached", "reserved collection budget",
		"invalid provider json", "provider json is invalid", "json: cannot unmarshal", "json: cannot decode",
		"candidate contract failed", "candidate correlation failed", "structural validation failed", "typed inventory validation failed",
		"provider launch failed", "provider invocation failed", "provider stage failed", "provider panic", "panic contained",
		"unexpected zero-result contract", "zero-result contract violation", "impossible provider", "impossible schema",
		"quarantined", "unmatched or malformed", "malformed provider") ||
		((strings.Contains(r, "exit status ") || strings.Contains(r, "exit code ")) && !containsAny(r, "docker", "podman", "containerd")) {
		return UnknownPrimaryProductDefect, 100
	}
	if containsAny(r, "permission denied", "access is denied", "access denied", "permission-restricted", "access-restricted", "protected process", "requires elevation", "requires administrator") {
		return UnknownPrimaryPermission, 90
	}
	if containsAny(r, "docker cli is unavailable", "podman cli is unavailable", "containerd instance enumeration", "optional provider is unavailable", "optional cli is unavailable") {
		return UnknownPrimaryOptionalAbsent, 80
	}
	if containsAny(r,
		"not safely observable", "cannot be safely observed", "intentionally not retrieved", "intentionally does not read",
		"safe collection boundary", "not provided by this local endpoint metadata collector", "without reading process memory",
		"credential material is not", "password value/state is intentionally") {
		return UnknownSafeCollectionBoundary, 75
	}
	if containsAny(r,
		"registry value is absent; no deterministic windows default is inferred", "setting was not exposed by the local provider",
		"configuration file are unavailable", "configuration file is unavailable", "local configuration file are unavailable",
		"local configuration file is unavailable", "configuration is absent", "not installed", "not configured on this host") {
		return UnknownEnvironmentalAbsence, 70
	}
	if containsAny(r, "not applicable", "not_applicable") {
		return UnknownPrimaryNotApplicable, 65
	}
	if containsAny(r,
		"cannot be determined defensibly", "cannot be classified defensibly", "unsupported state", "unsupported value",
		"unrecognized state", "unrecognised state", "mode unknown", "state is unknown", "configuration state is unresolved: unknown") {
		return UnknownUnsupportedState, 60
	}
	if containsAny(r, "unsupported safe", "provider is not implemented", "unsupported platform") {
		return UnknownUnsupportedState, 55
	}
	if containsAny(r,
		"required evidence", "provider evidence", "no usable records", "no records were returned", "inventory is incomplete",
		"metadata unavailable", "metadata is unavailable", "state(s) unresolved", "state unresolved", "posture is unresolved",
		"posture unresolved", "unresolved for", "is incomplete", "provider state unavailable", "settings are unavailable",
		"controls are unavailable", "policy is unavailable", "result unavailable across", "unavailable or contained no usable records") {
		return UnknownRequiredEvidenceMissing, 50
	}
	if containsAny(r, "lack a reliable last-logon", "lacks a reliable last-logon", "reliable last-logon timestamp") {
		return UnknownOtherExplained, 45
	}
	if containsAny(r, "unavailable", "unresolved", "incomplete", "unknown") {
		return UnknownRequiredEvidenceMissing, 40
	}
	return UnknownOtherExplained, 10
}

func unknownRuleFamily(ruleID string) string {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(ruleID)), "-")
	if len(parts) >= 3 && parts[0] == "CHM" {
		return parts[0] + "-" + parts[1]
	}
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	if strings.TrimSpace(ruleID) == "" {
		return "UNKNOWN-RULE-FAMILY"
	}
	return strings.ToUpper(strings.TrimSpace(ruleID))
}

func unknownEvidenceDependencies(f assessment.Finding) []string {
	set := map[string]struct{}{}
	for _, ref := range f.Evidence {
		key := normalizeUnknownDependency(ref.Key)
		if key != "" {
			set[key] = struct{}{}
		}
	}
	if len(set) == 0 {
		set["required.normalized_evidence"] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func normalizeUnknownDependency(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return key
	}
	last := strings.ToLower(parts[len(parts)-1])
	for _, prefix := range []string{"proc-", "svc-", "acct-", "net-", "per-", "sch-", "smbs-", "ctr-", "vol-", "fw-", "fs-", "sec-"} {
		if strings.HasPrefix(last, prefix) {
			parts[len(parts)-1] = "*"
			return strings.Join(parts, ".")
		}
	}
	return key
}

func unknownRootCauseID(class UnknownPrimaryClass, reason string) string {
	r := strings.TrimSpace(reason)
	if class == UnknownPrimaryProductDefect {
		lim := Classify(r)
		if lim.ReleaseBlocker && strings.TrimSpace(lim.RootCauseID) != "" {
			return lim.RootCauseID
		}
	}
	key := compactKey(strings.ToLower(r))
	if key == "" {
		key = "explained-unknown"
	}
	if len(key) > 120 {
		key = key[:120]
	}
	return "UNKNOWN:" + string(class) + ":" + key
}

func unknownAffectedCount(f assessment.Finding) int {
	text := strings.TrimSpace(f.ObservedState)
	for _, re := range []*regexp.Regexp{unknownOfTotalRE, unknownForRE, unknownCountRE} {
		if match := re.FindStringSubmatch(text); len(match) == 2 {
			if n, err := strconv.Atoi(match[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	set := map[string]struct{}{}
	for _, ref := range f.Evidence {
		key := strings.TrimSpace(ref.Key)
		if key == "" {
			continue
		}
		if normalizeUnknownDependency(key) != key {
			set[key] = struct{}{}
		}
	}
	if len(set) > 0 {
		return len(set)
	}
	if len(f.Evidence) > 0 {
		return 1
	}
	return 1
}

func conciseUnknownReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "UNKNOWN remains explained by incomplete or ambiguous normalized evidence"
	}
	if len(reason) > 512 {
		return reason[:512]
	}
	return reason
}

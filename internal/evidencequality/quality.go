package evidencequality

import (
	"sort"
	"strings"
)

// LimitationClass provides a stable, machine-readable reason family for
// evidence limitations without changing the underlying provider reason text.
type LimitationClass string

const (
	ClassExpectedEnvironment LimitationClass = "EXPECTED_ENVIRONMENT"
	ClassPermission          LimitationClass = "PERMISSION"
	ClassOptionalProvider    LimitationClass = "OPTIONAL_PROVIDER"
	ClassProductDefect       LimitationClass = "PRODUCT_DEFECT"
	ClassDeadlineBudget      LimitationClass = "DEADLINE_BUDGET"
	ClassNotApplicable       LimitationClass = "NOT_APPLICABLE"
	ClassOther               LimitationClass = "OTHER"
)

// Limitation is the canonical evidence-quality representation used by reports.
// Occurrences records how many raw limitation strings collapsed into this root
// cause. AffectedRecords counts distinct record-scoped identities when the
// source limitation names a stable object/evidence id.
type Limitation struct {
	Reason             string          `json:"reason"`
	Class              LimitationClass `json:"class"`
	ReleaseBlocker     bool            `json:"release_blocker"`
	CanonicalKey       string          `json:"canonical_key,omitempty"`
	RootCauseID        string          `json:"root_cause_id,omitempty"`
	Provider           string          `json:"provider,omitempty"`
	Stage              string          `json:"stage,omitempty"`
	Platform           string          `json:"platform,omitempty"`
	ErrorCode          string          `json:"error_code,omitempty"`
	Message            string          `json:"message,omitempty"`
	Occurrences        int             `json:"occurrences,omitempty"`
	AffectedRecords    int             `json:"affected_records,omitempty"`
	AffectedRecordIDs  []string        `json:"affected_record_ids,omitempty"`
	AffectedCategories []string        `json:"affected_categories,omitempty"`
	Aliases            []string        `json:"aliases,omitempty"`
}

type Summary struct {
	ExpectedEnvironment   int `json:"expected_environment"`
	Permission            int `json:"permission"`
	OptionalProvider      int `json:"optional_provider"`
	ProductDefect         int `json:"product_defect"`
	DeadlineBudget        int `json:"deadline_budget"`
	NotApplicable         int `json:"not_applicable"`
	Other                 int `json:"other"`
	ReleaseBlockers       int `json:"release_blockers"`
	UniqueReleaseBlockers int `json:"unique_release_blockers"`
	TotalOccurrences      int `json:"total_occurrences,omitempty"`
	UniqueLimitations     int `json:"unique_limitations,omitempty"`
	AffectedRecords       int `json:"affected_records,omitempty"`
}

func Classify(reason string) Limitation {
	r := strings.ToLower(strings.TrimSpace(reason))
	out := Limitation{Reason: strings.TrimSpace(reason), Class: ClassOther, Occurrences: 1}

	switch {
	case r == "":
		return out
	case containsAny(r,
		"reserved collection budget", "context deadline exceeded", "collector deadline reached",
		"collection deadline reached", "assessment reached its configured timeout", "stopped at the reserved collection budget",
		"class=deadline"):
		out.Class, out.ReleaseBlocker = ClassDeadlineBudget, true
	case containsAny(r, "process exited during collection", "exited during collection"):
		out.Class = ClassExpectedEnvironment
	case containsAny(r, "permission denied", "access is denied", "access denied", "requires elevation", "requires administrator", "permission-restricted", "access-restricted", "protected process"):
		out.Class = ClassPermission
	case containsAny(r,
		"typed inventory validation failed", "record 0 is incomplete", "record 1 is incomplete",
		"provider panic", "panic contained", "unexpected internal", "invariant failed", "impossible provider", "impossible schema",
		"invalid provider json", "invalid windows smb provider json", "provider json is invalid",
		"json: cannot unmarshal", "json: cannot decode", "decode windows smb provider output",
		"candidate contract failed", "candidate correlation failed", "structural validation failed",
		"provider launch failed", "provider invocation failed", "provider stage failed",
		"unexpected zero-result contract", "zero-result contract violation",
		"class=provider_failure", "class=provider_decode", "class=input_contract"):
		out.Class, out.ReleaseBlocker = ClassProductDefect, true
	case (strings.Contains(r, "exit status ") || strings.Contains(r, "exit code ")) && !containsAny(r, "docker", "podman", "containerd"):
		out.Class, out.ReleaseBlocker = ClassProductDefect, true
	case containsAny(r, "not applicable", "not_applicable", "linux-only", "windows-only", "macos-only"):
		out.Class = ClassNotApplicable
	case containsAny(r,
		"docker cli is unavailable", "podman cli is unavailable", "containerd instance enumeration",
		"virtualization technology was observed but no safely inspectable", "no safely inspectable local management socket/device",
		"class=module_unavailable"):
		out.Class = ClassOptionalProvider
	case containsAny(r,
		"registry value is absent; no deterministic windows default is inferred",
		"intentionally does not read process memory", "ordinary chimera scans never contact windows update",
		"update metadata freshness could not be established"):
		out.Class = ClassExpectedEnvironment
	case containsAny(r, "no supported local firewall provider was observable"):
		// On a supported Windows 11 release target the host firewall provider is
		// core assessment evidence, so this remains a release blocker. The gate
		// may still permit it on non-Windows platforms through platform policy.
		out.Class, out.ReleaseBlocker = ClassProductDefect, true
	}
	out.CanonicalKey = CanonicalLimitationKey(out.Reason, out.Class, out.ReleaseBlocker)
	populateLimitationMetadata(&out)
	return out
}

// CanonicalReleaseBlockerKey collapses duplicate renderings of the same
// underlying product defect/deadline into one stable release-gate identity.
func CanonicalReleaseBlockerKey(reason string, class LimitationClass) string {
	return releaseRootCause(reason, class).ID
}

// CanonicalLimitationKey creates a stable root-cause identity for every
// limitation, not only release blockers. This prevents provider/category/
// normalized-evidence aliases and per-record repetitions from flooding the
// enterprise report while leaving the original evidence records untouched.
func CanonicalLimitationKey(reason string, class LimitationClass, releaseBlocker bool) string {
	if releaseBlocker {
		return CanonicalReleaseBlockerKey(reason, class)
	}
	r := stripGenericAliases(strings.ToLower(strings.TrimSpace(reason)))
	if r == "" {
		return ""
	}

	if prefix, body, ok := splitReasonPrefix(r); ok {
		if _, scope := recordIdentity(prefix); scope != "" {
			return string(class) + ":" + scope + ":" + compactKey(body)
		}
	}

	if provider := explicitWindowsProvider(r); provider != "" {
		body := reasonBody(r)
		if body == "" {
			body = r
		}
		return string(class) + ":" + provider + ":" + compactKey(body)
	}

	return string(class) + ":" + compactKey(r)
}

// ClassifyAll returns one structured limitation per canonical root cause.
// Existing summary class counters intentionally continue to count raw
// occurrences for backward-compatible telemetry; UniqueLimitations and
// Occurrences expose the new Fix33 aggregation explicitly.
func ClassifyAll(reasons []string) ([]Limitation, Summary) {
	groups := map[string]int{}
	recordSets := map[string]map[string]struct{}{}
	items := make([]Limitation, 0, len(reasons))
	var s Summary
	seenReleaseBlockers := map[string]struct{}{}

	for _, reason := range reasons {
		item := Classify(reason)
		if item.Reason == "" {
			continue
		}
		s.TotalOccurrences++
		switch item.Class {
		case ClassExpectedEnvironment:
			s.ExpectedEnvironment++
		case ClassPermission:
			s.Permission++
		case ClassOptionalProvider:
			s.OptionalProvider++
		case ClassProductDefect:
			s.ProductDefect++
		case ClassDeadlineBudget:
			s.DeadlineBudget++
		case ClassNotApplicable:
			s.NotApplicable++
		default:
			s.Other++
		}
		if item.ReleaseBlocker {
			key := item.CanonicalKey
			if key == "" {
				key = strings.ToLower(strings.TrimSpace(item.Reason))
			}
			if _, ok := seenReleaseBlockers[key]; !ok {
				seenReleaseBlockers[key] = struct{}{}
				s.ReleaseBlockers++
			}
		}

		key := item.CanonicalKey
		if key == "" {
			key = string(item.Class) + ":" + compactKey(item.Reason)
		}
		recordID, _ := recordIdentityFromReason(reason)
		if idx, ok := groups[key]; ok {
			items[idx].Occurrences++
			items[idx].Aliases = appendUniqueSorted(items[idx].Aliases, strings.TrimSpace(reason))
			items[idx].AffectedCategories = appendUniqueSorted(items[idx].AffectedCategories, limitationCategories(reason)...)
			if recordID != "" {
				if recordSets[key] == nil {
					recordSets[key] = map[string]struct{}{}
				}
				recordSets[key][recordID] = struct{}{}
				items[idx].AffectedRecords = len(recordSets[key])
				items[idx].AffectedRecordIDs = sortedStringSet(recordSets[key])
			}
			continue
		}

		item.Reason = displayReason(reason)
		item.Occurrences = 1
		item.Aliases = appendUniqueSorted(nil, strings.TrimSpace(reason))
		item.AffectedCategories = appendUniqueSorted(nil, limitationCategories(reason)...)
		if recordID != "" {
			recordSets[key] = map[string]struct{}{recordID: {}}
			item.AffectedRecords = 1
			item.AffectedRecordIDs = []string{recordID}
		}
		groups[key] = len(items)
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Class != items[j].Class {
			return items[i].Class < items[j].Class
		}
		return items[i].CanonicalKey < items[j].CanonicalKey
	})
	s.UniqueLimitations = len(items)
	s.UniqueReleaseBlockers = s.ReleaseBlockers
	for _, item := range items {
		s.AffectedRecords += item.AffectedRecords
	}
	return items, s
}

func appendUniqueSorted(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst)+len(values))
	for _, value := range dst {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func explicitWindowsProvider(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ':', '(', ')', '[', ']', ',', ';':
			return true
		default:
			return false
		}
	})
	for _, f := range fields {
		n := compactKey(f)
		if strings.HasPrefix(n, "windows-") && n != "windows-smb-provider-json" && n != "windows-smb-provider" {
			return n
		}
	}
	return ""
}

func providerIdentity(s string) string {
	parts := strings.Split(s, ":")
	for i := len(parts) - 2; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" || genericPrefix(p) {
			continue
		}
		if idx := strings.LastIndex(p, ".source."); idx >= 0 {
			p = p[idx+len(".source."):]
		}
		if strings.HasPrefix(p, "provider ") {
			p = strings.TrimSpace(strings.TrimPrefix(p, "provider "))
			if cut := strings.IndexByte(p, ' '); cut >= 0 {
				p = p[:cut]
			}
		}
		if key := compactKey(p); key != "" {
			return key
		}
	}
	if strings.HasPrefix(s, "provider ") {
		p := strings.TrimPrefix(s, "provider ")
		if cut := strings.IndexByte(p, ' '); cut >= 0 {
			p = p[:cut]
		}
		return compactKey(p)
	}
	return ""
}

func blockerCause(s string, class LimitationClass) string {
	switch class {
	case ClassDeadlineBudget:
		return "deadline-budget"
	case ClassProductDefect:
		switch {
		case strings.Contains(s, "class=provider_decode"):
			return "provider-json"
		case strings.Contains(s, "class=input_contract"):
			return "candidate-contract"
		case strings.Contains(s, "class=provider_failure"):
			return "provider-stage"
		case strings.Contains(s, "exit status "), strings.Contains(s, "exit code "), strings.Contains(s, "exit_code="):
			return "provider-exit"
		case containsAny(s, "invalid provider json", "invalid windows smb provider json", "provider json is invalid", "json: cannot unmarshal", "json: cannot decode", "decode windows smb provider output"):
			return "provider-json"
		case containsAny(s, "typed inventory validation failed", "record 0 is incomplete", "record 1 is incomplete", "structural validation failed"):
			return "inventory-validation"
		case containsAny(s, "candidate contract failed", "candidate correlation failed"):
			return "candidate-contract"
		case containsAny(s, "unexpected zero-result contract", "zero-result contract violation"):
			return "zero-result-contract"
		case containsAny(s, "provider launch failed", "provider invocation failed"):
			return "provider-launch"
		case containsAny(s, "provider stage failed"):
			return "provider-stage"
		case containsAny(s, "provider panic", "panic contained"):
			return "provider-panic"
		case containsAny(s, "unexpected internal", "invariant failed", "impossible provider", "impossible schema"):
			return "internal-invariant"
		case containsAny(s, "no supported local firewall provider was observable"):
			return "provider-unavailable"
		}
	}
	return ""
}

func genericPrefix(s string) bool {
	switch compactKey(s) {
	case "process", "services", "service", "filesystem", "network", "firewall", "accounts", "account", "identity", "persistence", "containers", "container", "software", "infrastructure":
		return true
	default:
		return false
	}
}

func stripGenericAliases(s string) string {
	s = strings.TrimSpace(s)
	for {
		prefix, body, ok := splitReasonPrefix(s)
		if !ok || !genericPrefix(prefix) {
			return s
		}
		s = strings.TrimSpace(body)
	}
}

func splitReasonPrefix(s string) (string, string, bool) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
}

func reasonBody(s string) string {
	_, body, ok := splitReasonPrefix(stripGenericAliases(s))
	if !ok {
		return ""
	}
	return body
}

func recordIdentityFromReason(reason string) (string, string) {
	r := stripGenericAliases(strings.ToLower(strings.TrimSpace(reason)))
	prefix, _, ok := splitReasonPrefix(r)
	if !ok {
		return "", ""
	}
	return recordIdentity(prefix)
}

func recordIdentity(prefix string) (string, string) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return "", ""
	}
	parts := strings.Split(prefix, ".")
	last := parts[len(parts)-1]
	dash := strings.LastIndex(last, "-")
	if dash <= 0 || dash == len(last)-1 {
		return "", ""
	}
	tail := last[dash+1:]
	if len(tail) < 8 || !allHex(tail) {
		return "", ""
	}
	scopeParts := parts[:len(parts)-1]
	base := last[:dash]
	if len(scopeParts) == 0 {
		scopeParts = []string{base}
	} else {
		scopeParts = append(scopeParts, base)
	}
	scope := compactKey(strings.Join(scopeParts, "-"))
	if strings.HasPrefix(scope, "persistence-privilege-per") || strings.HasPrefix(scope, "persistence-privilege") {
		scope = "persistence-privilege-correlation"
	}
	return prefix, scope
}

func displayReason(reason string) string {
	r := stripGenericAliases(strings.TrimSpace(reason))
	prefix, body, ok := splitReasonPrefix(r)
	if !ok {
		return r
	}
	if _, scope := recordIdentity(prefix); scope != "" {
		return strings.ReplaceAll(scope, "-", " ") + ": " + strings.TrimSpace(body)
	}
	return r
}

func allHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func compactKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		alphaNum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if alphaNum {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func containsAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

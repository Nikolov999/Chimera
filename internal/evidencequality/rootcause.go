package evidencequality

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type rootCauseDescriptor struct {
	ID        string
	Provider  string
	Stage     string
	Platform  string
	ErrorCode string
	Message   string
}

var (
	windowsProviderTokenRE = regexp.MustCompile(`(?i)windows[-_][a-z0-9_-]+`)
	providerPrefixRE       = regexp.MustCompile(`(?i)\bprovider\s+([a-z0-9._-]+)\b`)
	exitCodeRE             = regexp.MustCompile(`(?i)\bexit(?:_|\s)(?:status|code)\s*[=:]?\s*\(?(-?[0-9]+)\)?`)
	chimeraStageRE         = regexp.MustCompile(`(?i)\[chimera-stage:([a-z0-9._-]+)\]`)
	explicitProviderRE     = regexp.MustCompile(`(?i)\bprovider=([a-z0-9._-]+)\b`)
	explicitStageRE        = regexp.MustCompile(`(?i)\bstage=([a-z0-9._-]+)\b`)
)

// populateLimitationMetadata turns the textual compatibility reason into the
// structured Fix40 root-cause contract. CanonicalKey remains available for
// existing consumers; RootCauseID is the preferred release/report identity.
func populateLimitationMetadata(item *Limitation) {
	if item == nil || strings.TrimSpace(item.Reason) == "" {
		return
	}
	if item.ReleaseBlocker {
		d := releaseRootCause(item.Reason, item.Class)
		item.RootCauseID = d.ID
		item.CanonicalKey = d.ID
		item.Provider = d.Provider
		item.Stage = d.Stage
		item.Platform = d.Platform
		item.ErrorCode = d.ErrorCode
		item.Message = d.Message
		return
	}
	item.RootCauseID = item.CanonicalKey
	provider, stage := inferProviderStage(strings.ToLower(item.Reason))
	item.Provider = provider
	item.Stage = stage
	item.Platform = inferPlatform(item.Reason, provider)
	item.ErrorCode = inferErrorCode(strings.ToLower(item.Reason), item.Class)
	item.Message = canonicalMessage(item.Reason, item.Class)
}

func releaseRootCause(reason string, class LimitationClass) rootCauseDescriptor {
	raw := strings.TrimSpace(reason)
	r := strings.ToLower(raw)
	if r == "" {
		return rootCauseDescriptor{}
	}

	// Preserve the stable Fix27 SMB identity while enriching its metadata.
	if containsAny(r, "invalid windows smb provider json", "decode windows smb provider output") ||
		(strings.Contains(r, "json: cannot unmarshal") && strings.Contains(r, "smb")) {
		return rootCauseDescriptor{
			ID:        string(class) + ":windows-smb-provider-json",
			Provider:  "windows-smb",
			Stage:     "json-contract",
			Platform:  "windows",
			ErrorCode: "invalid-provider-json",
			Message:   canonicalMessage(raw, class),
		}
	}

	provider, stage := inferProviderStage(r)
	if provider == "" {
		provider = "assessment"
	}
	cause := blockerCause(r, class)
	if cause == "" {
		cause = compactKey(r)
	}
	id := string(class) + ":" + provider
	if stage != "" {
		id += ":" + compactKey(stage)
	}
	id += ":" + cause
	return rootCauseDescriptor{
		ID:        id,
		Provider:  provider,
		Stage:     stage,
		Platform:  inferPlatform(raw, provider),
		ErrorCode: inferErrorCode(r, class),
		Message:   canonicalMessage(raw, class),
	}
}

// inferProviderStage deliberately selects the deepest provider token in a
// propagated reason chain. For example:
//
// windows-service-account-security: windows-service-security-enrichment:
// context deadline exceeded
//
// is rooted at windows-service-security/enrichment, not at the account-security
// alias that merely propagated it.
func inferProviderStage(r string) (string, string) {
	// Propagated limitations can contain several structured provider/stage
	// segments. The deepest (last) segment is the actual originating stage;
	// outer entries are category/dependency aliases.
	if matches := explicitProviderRE.FindAllStringSubmatch(r, -1); len(matches) > 0 {
		provider := compactKey(matches[len(matches)-1][1])
		stage := ""
		if stages := explicitStageRE.FindAllStringSubmatch(r, -1); len(stages) > 0 {
			stage = compactKey(stages[len(stages)-1][1])
		}
		return provider, stage
	}
	if m := chimeraStageRE.FindAllStringSubmatch(r, -1); len(m) > 0 {
		return normalizeProviderStage(m[len(m)-1][1])
	}

	tokens := windowsProviderTokenRE.FindAllString(r, -1)
	if len(tokens) > 0 {
		return normalizeProviderStage(tokens[len(tokens)-1])
	}

	if matches := providerPrefixRE.FindAllStringSubmatch(r, -1); len(matches) > 0 {
		provider := compactKey(matches[len(matches)-1][1])
		stage := ""
		if strings.Contains(r, "collector deadline") || strings.Contains(r, "collection deadline") {
			stage = "collector"
		}
		return provider, stage
	}

	switch {
	case strings.Contains(r, "service path-integrity collection deadline reached"):
		return "service-path-integrity", "collection"
	case strings.Contains(r, "assessment reached its configured timeout"):
		return "assessment", "evaluation"
	}
	if p := providerIdentity(r); p != "" {
		return p, ""
	}
	return "", ""
}

func normalizeProviderStage(token string) (string, string) {
	t := compactKey(token)
	if t == "" {
		return "", ""
	}
	// These stage suffixes are emitted by bounded Windows providers. Keeping the
	// stage separate lets two genuinely independent executions remain distinct.
	for _, suffix := range []string{"enumeration", "enrichment", "collection", "decode", "validation", "launch"} {
		needle := "-" + suffix
		if strings.HasSuffix(t, needle) && len(t) > len(needle) {
			return strings.TrimSuffix(t, needle), suffix
		}
	}
	return t, ""
}

func inferPlatform(reason, provider string) string {
	r := strings.ToLower(reason)
	if strings.HasPrefix(provider, "windows-") || strings.Contains(r, "windows") || strings.Contains(r, "win32_") || strings.Contains(r, "hkey_local_machine") {
		return "windows"
	}
	if strings.Contains(r, "linux") {
		return "linux"
	}
	if strings.Contains(r, "macos") || strings.Contains(r, "darwin") {
		return "macos"
	}
	return ""
}

func inferErrorCode(r string, class LimitationClass) string {
	if strings.Contains(r, "context deadline exceeded") {
		return "context-deadline-exceeded"
	}
	if containsAny(r, "reserved collection budget", "collector deadline reached", "collection deadline reached", "configured timeout") {
		return "deadline-budget-exhausted"
	}
	if m := exitCodeRE.FindStringSubmatch(r); len(m) == 2 {
		if _, err := strconv.Atoi(m[1]); err == nil {
			return "exit-code-" + m[1]
		}
	}
	switch {
	case strings.Contains(r, "class=provider_decode"):
		return "invalid-provider-json"
	case strings.Contains(r, "class=input_contract"):
		return "candidate-contract"
	case strings.Contains(r, "class=provider_failure"):
		return "provider-stage-failed"
	case containsAny(r, "invalid provider json", "provider json is invalid", "json: cannot unmarshal", "json: cannot decode", "decode windows smb provider output"):
		return "invalid-provider-json"
	case containsAny(r, "typed inventory validation failed", "structural validation failed", "record 0 is incomplete", "record 1 is incomplete"):
		return "structural-inventory-validation"
	case containsAny(r, "candidate contract failed", "candidate correlation failed"):
		return "candidate-contract"
	case containsAny(r, "provider panic", "panic contained"):
		return "provider-panic"
	case containsAny(r, "provider launch failed", "provider invocation failed"):
		return "provider-launch-failed"
	case containsAny(r, "unexpected zero-result contract", "zero-result contract violation"):
		return "zero-result-contract"
	case containsAny(r, "unexpected internal", "invariant failed", "impossible provider", "impossible schema"):
		return "internal-invariant"
	case class == ClassPermission:
		return "access-restricted"
	}
	return ""
}

func canonicalMessage(reason string, class LimitationClass) string {
	r := strings.TrimSpace(reason)
	lower := strings.ToLower(r)
	if strings.Contains(lower, "context deadline exceeded") {
		return "context deadline exceeded"
	}
	if class == ClassDeadlineBudget {
		return "provider or assessment deadline/budget exhausted"
	}
	if m := exitCodeRE.FindStringSubmatch(lower); len(m) == 2 {
		return fmt.Sprintf("provider exited with code/status %s", m[1])
	}
	if strings.Contains(lower, "class=provider_decode") {
		return "provider JSON contract is invalid"
	}
	if strings.Contains(lower, "class=input_contract") {
		return "provider input contract failed"
	}
	if strings.Contains(lower, "class=provider_failure") {
		return "provider stage failed"
	}
	if containsAny(lower, "invalid provider json", "provider json is invalid", "json: cannot unmarshal", "json: cannot decode", "decode windows smb provider output") {
		return "provider JSON contract is invalid"
	}
	if containsAny(lower, "candidate contract failed", "candidate correlation failed") {
		return "provider candidate contract failed"
	}
	if containsAny(lower, "typed inventory validation failed", "structural validation failed") {
		return "provider inventory structural validation failed"
	}
	if len(r) > 512 {
		return r[:512]
	}
	return r
}

func limitationCategories(reason string) []string {
	r := strings.ToLower(strings.TrimSpace(reason))
	set := map[string]struct{}{}
	add := func(v string) {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	checks := []struct {
		name   string
		values []string
	}{
		{"processes", []string{"process.", "process:", "windows-loaded-modules", "windows-process-"}},
		{"services", []string{"service.", "services:", "provider services", "windows-service-", "service path-integrity"}},
		{"network", []string{"network.", "network:", "provider network", "windows-smb", "firewall"}},
		{"filesystem", []string{"filesystem.", "filesystem:", "temporary-directory", "executable-dacl"}},
		{"accounts", []string{"accounts.", "accounts:", "account.", "identity."}},
		{"persistence", []string{"persistence.", "persistence:"}},
		{"software", []string{"software.", "software:"}},
		{"infrastructure", []string{"infrastructure.", "infrastructure:"}},
		{"containers", []string{"container.", "containers:"}},
	}
	for _, check := range checks {
		for _, needle := range check.values {
			if strings.Contains(r, needle) {
				add(check.name)
				break
			}
		}
	}
	out := make([]string, 0, len(set))
	for category := range set {
		out = append(out, category)
	}
	sort.Strings(out)
	return out
}

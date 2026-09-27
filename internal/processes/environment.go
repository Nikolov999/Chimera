package processes

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxEnvironmentBytes      = 256 * 1024
	maxEnvironmentIndicators = 64
)

// EnvironmentIndicator is a redacted observation about a
// security-relevant environment setting. Values are intentionally never kept.
// Only the variable name and bounded classification metadata are retained.
type EnvironmentIndicator struct {
	Name                string   `json:"name"`
	Category            string   `json:"category"`
	RiskClass           string   `json:"risk_class"`
	NonEmpty            bool     `json:"non_empty"`
	ComponentCount      int      `json:"component_count,omitempty"`
	RelativeComponents  int      `json:"relative_components,omitempty"`
	EmptyComponents     int      `json:"empty_components,omitempty"`
	TemporaryComponents int      `json:"temporary_components,omitempty"`
	PatternClasses      []string `json:"pattern_classes,omitempty"`
}

// RuntimeEnvironmentContext records dangerous/weak runtime environment
// configuration without retaining environment values. It is evidence only;
// is responsible for the consolidated runtime-security rule pack.
type RuntimeEnvironmentContext struct {
	ProcessID          string                 `json:"process_id"`
	PID                int                    `json:"pid"`
	Platform           string                 `json:"platform"`
	State              string                 `json:"state"`
	Posture            string                 `json:"posture"`
	VariablesObserved  int                    `json:"variables_observed"`
	RelevantVariables  int                    `json:"relevant_variables"`
	LoaderOverrides    int                    `json:"loader_overrides"`
	LoaderHooks        int                    `json:"loader_hooks"`
	RuntimeSearchPaths int                    `json:"runtime_search_paths"`
	StartupHooks       int                    `json:"startup_hooks"`
	DebugControls      int                    `json:"debug_controls"`
	ProxyOverrides     int                    `json:"proxy_overrides"`
	TLSKeyLogging      bool                   `json:"tls_key_logging"`
	HighRiskIndicators int                    `json:"high_risk_indicators"`
	ValuesRedacted     bool                   `json:"values_redacted"`
	Indicators         []EnvironmentIndicator `json:"indicators,omitempty"`
	Signals            []string               `json:"signals,omitempty"`
	Source             string                 `json:"source"`
	Confidence         evidence.Confidence    `json:"confidence"`
	Reason             string                 `json:"reason,omitempty"`
}

type environmentProviderStats struct {
	ID      string
	State   evidence.State
	Source  string
	Count   int
	Denied  int
	Missing int
	Reason  string
}

func collectRuntimeEnvironment(ctx context.Context, items []Process, platform string) ([]RuntimeEnvironmentContext, SourceStatus) {
	raw, stats := collectRuntimeEnvironmentPlatform(ctx, items)
	byPID := make(map[int]RuntimeEnvironmentContext, len(raw))
	for _, c := range raw {
		if c.PID <= 0 {
			continue
		}
		c.Platform = fallback(strings.ToLower(strings.TrimSpace(c.Platform)), strings.ToLower(strings.TrimSpace(platform)))
		c.State = strings.ToUpper(fallback(c.State, "UNKNOWN"))
		c.Posture = strings.ToUpper(fallback(c.Posture, "UNKNOWN"))
		c.Source = fallback(c.Source, "platform process environment metadata")
		c.Reason = strings.TrimSpace(c.Reason)
		c.ValuesRedacted = true
		c.Indicators = normalizeEnvironmentIndicators(c.Indicators)
		recomputeEnvironmentCounters(&c)
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceLow
		}
		if old, ok := byPID[c.PID]; !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) {
			byPID[c.PID] = c
		}
	}

	out := make([]RuntimeEnvironmentContext, 0, len(items))
	for _, p := range items {
		c, ok := byPID[p.PID]
		if !ok {
			c = RuntimeEnvironmentContext{
				PID: p.PID, Platform: strings.ToLower(strings.TrimSpace(platform)), State: "UNKNOWN", Posture: "UNKNOWN",
				ValuesRedacted: true, Source: "platform process environment metadata", Confidence: evidence.ConfidenceLow,
				Reason: "process environment metadata unavailable for observed process",
			}
		}
		c.ProcessID = p.ID
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ProcessID < out[j].ProcessID
	})

	state := stats.State
	if state == "" {
		state = evidence.StateUnavailable
	}
	reason := strings.TrimSpace(stats.Reason)
	if reason == "" && (stats.Denied > 0 || stats.Missing > 0) {
		parts := []string{}
		if stats.Denied > 0 {
			parts = append(parts, itoa(stats.Denied)+" process environment record(s) permission-restricted")
		}
		if stats.Missing > 0 {
			parts = append(parts, itoa(stats.Missing)+" process environment record(s) unavailable or exited during collection")
		}
		reason = strings.Join(parts, "; ")
		if stats.Count > 0 {
			state = evidence.StateDegraded
		} else if stats.Denied > 0 {
			state = evidence.StateDenied
		}
	}
	return out, SourceStatus{ID: stats.ID, State: state, Source: fallback(stats.Source, "platform process environment metadata"), ItemCount: stats.Count, Reason: reason}
}

func inspectEnvironmentEntries(entries []string, platform, source string) RuntimeEnvironmentContext {
	c := RuntimeEnvironmentContext{
		Platform: strings.ToLower(strings.TrimSpace(platform)), State: "OBSERVED", Posture: "NONE",
		ValuesRedacted: true, Source: source, Confidence: evidence.ConfidenceHigh,
	}
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		c.VariablesObserved++
		if ind, ok := classifyEnvironmentVariable(name, value, platform); ok {
			c.Indicators = append(c.Indicators, ind)
			c.Signals = append(c.Signals, strings.ToLower(ind.Category)+":"+ind.Name)
			switch ind.Category {
			case "LOADER_PATH":
				c.LoaderOverrides++
			case "LOADER_HOOK":
				c.LoaderHooks++
			case "RUNTIME_SEARCH_PATH":
				c.RuntimeSearchPaths++
			case "STARTUP_HOOK":
				c.StartupHooks++
			case "DEBUG_CONTROL":
				c.DebugControls++
			case "PROXY_OVERRIDE":
				c.ProxyOverrides++
			case "TLS_KEY_LOGGING":
				c.TLSKeyLogging = true
			}
			if ind.RiskClass == "HIGH" {
				c.HighRiskIndicators++
			}
		}
	}
	c.Indicators = normalizeEnvironmentIndicators(c.Indicators)
	recomputeEnvironmentCounters(&c)
	return c
}

func recomputeEnvironmentCounters(c *RuntimeEnvironmentContext) {
	c.RelevantVariables = len(c.Indicators)
	c.LoaderOverrides = 0
	c.LoaderHooks = 0
	c.RuntimeSearchPaths = 0
	c.StartupHooks = 0
	c.DebugControls = 0
	c.ProxyOverrides = 0
	c.TLSKeyLogging = false
	c.HighRiskIndicators = 0
	c.Signals = nil
	for _, ind := range c.Indicators {
		c.Signals = append(c.Signals, strings.ToLower(ind.Category)+":"+ind.Name)
		switch ind.Category {
		case "LOADER_PATH":
			c.LoaderOverrides++
		case "LOADER_HOOK":
			c.LoaderHooks++
		case "RUNTIME_SEARCH_PATH":
			c.RuntimeSearchPaths++
		case "STARTUP_HOOK":
			c.StartupHooks++
		case "DEBUG_CONTROL":
			c.DebugControls++
		case "PROXY_OVERRIDE":
			c.ProxyOverrides++
		case "TLS_KEY_LOGGING":
			c.TLSKeyLogging = true
		}
		if ind.RiskClass == "HIGH" {
			c.HighRiskIndicators++
		}
	}
	c.Signals = normalizedList(c.Signals)
	if c.State == "UNKNOWN" || c.State == "DENIED" || c.State == "UNSUPPORTED" {
		c.Posture = "UNKNOWN"
	} else if c.HighRiskIndicators > 0 {
		c.Posture = "HIGH_RISK_HOOKS_PRESENT"
	} else if c.RelevantVariables > 0 {
		c.Posture = "OVERRIDES_PRESENT"
	} else {
		c.Posture = "NONE"
	}
}

func classifyEnvironmentVariable(name, value, platform string) (EnvironmentIndicator, bool) {
	n := strings.ToUpper(strings.TrimSpace(name))
	v := strings.TrimSpace(value)
	ind := EnvironmentIndicator{Name: n, NonEmpty: v != "", RiskClass: "CONTEXTUAL"}
	if v == "" {
		return EnvironmentIndicator{}, false
	}

	switch n {
	case "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH":
		ind.Category = "LOADER_PATH"
		addPathMetadata(&ind, v, platform, false)
		if ind.RelativeComponents > 0 || ind.EmptyComponents > 0 || ind.TemporaryComponents > 0 {
			ind.RiskClass = "HIGH"
		}
	case "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES":
		ind.Category = "LOADER_HOOK"
		ind.RiskClass = "HIGH"
		addPathMetadata(&ind, v, platform, true)
	case "PYTHONPATH", "NODE_PATH", "PERL5LIB", "RUBYLIB", "CLASSPATH":
		ind.Category = "RUNTIME_SEARCH_PATH"
		addPathMetadata(&ind, v, platform, false)
		if ind.RelativeComponents > 0 || ind.EmptyComponents > 0 || ind.TemporaryComponents > 0 {
			ind.RiskClass = "HIGH"
		}
	case "PYTHONSTARTUP", "BASH_ENV", "ENV", "DOTNET_STARTUP_HOOKS", "COR_PROFILER", "CORECLR_PROFILER", "COR_PROFILER_PATH", "CORECLR_PROFILER_PATH":
		ind.Category = "STARTUP_HOOK"
		ind.RiskClass = "HIGH"
		addPathMetadata(&ind, v, platform, false)
	case "COR_ENABLE_PROFILING", "CORECLR_ENABLE_PROFILING":
		if !truthyEnvironmentValue(v) {
			return EnvironmentIndicator{}, false
		}
		ind.Category = "STARTUP_HOOK"
		ind.RiskClass = "HIGH"
		ind.PatternClasses = []string{"PROFILING_ENABLED"}
	case "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_PROFILE":
		ind.Category = "DEBUG_CONTROL"
		ind.RiskClass = "CONTEXTUAL"
	case "PYTHONINSPECT":
		if !truthyEnvironmentValue(v) {
			return EnvironmentIndicator{}, false
		}
		ind.Category = "DEBUG_CONTROL"
		ind.RiskClass = "CONTEXTUAL"
		ind.PatternClasses = []string{"INTERACTIVE_DEBUG_ENABLED"}
	case "PYTHONBREAKPOINT":
		if strings.EqualFold(v, "0") {
			return EnvironmentIndicator{}, false
		}
		ind.Category = "DEBUG_CONTROL"
		ind.RiskClass = "CONTEXTUAL"
		ind.PatternClasses = []string{"CUSTOM_BREAKPOINT_HOOK"}
	case "NODE_OPTIONS":
		patterns := matchTokenPatterns(v, map[string]string{
			"--inspect": "REMOTE_DEBUG_OPTION", "--debug": "DEBUG_OPTION", "--require": "MODULE_PRELOAD_OPTION", "--import": "MODULE_IMPORT_HOOK", "--loader": "CUSTOM_LOADER_OPTION",
		})
		if len(patterns) == 0 {
			return EnvironmentIndicator{}, false
		}
		ind.Category = "DEBUG_CONTROL"
		ind.PatternClasses = patterns
		if containsAny(patterns, "MODULE_PRELOAD_OPTION", "MODULE_IMPORT_HOOK", "CUSTOM_LOADER_OPTION") {
			ind.RiskClass = "HIGH"
		}
	case "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS":
		patterns := matchTokenPatterns(v, map[string]string{
			"-agentlib": "AGENT_LIBRARY", "-agentpath": "AGENT_PATH", "-javaagent": "JAVA_AGENT", "-xdebug": "DEBUG_OPTION", "jdwp": "DEBUG_WIRE_PROTOCOL",
		})
		if len(patterns) == 0 {
			return EnvironmentIndicator{}, false
		}
		ind.Category = "DEBUG_CONTROL"
		ind.PatternClasses = patterns
		ind.RiskClass = "HIGH"
	case "PERL5OPT", "RUBYOPT":
		ind.Category = "STARTUP_HOOK"
		ind.RiskClass = "CONTEXTUAL"
		ind.PatternClasses = []string{"RUNTIME_OPTION_OVERRIDE"}
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
		ind.Category = "PROXY_OVERRIDE"
		ind.RiskClass = "CONTEXTUAL"
	case "SSLKEYLOGFILE":
		ind.Category = "TLS_KEY_LOGGING"
		ind.RiskClass = "HIGH"
		ind.PatternClasses = []string{"TLS_SESSION_KEY_LOGGING"}
	default:
		return EnvironmentIndicator{}, false
	}
	ind.PatternClasses = normalizedList(ind.PatternClasses)
	return ind, true
}

func addPathMetadata(ind *EnvironmentIndicator, value, platform string, splitWhitespace bool) {
	parts := splitEnvironmentPath(value, platform, splitWhitespace)
	ind.ComponentCount = len(parts)
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			ind.EmptyComponents++
			ind.RelativeComponents++
			continue
		}
		if isRelativeEnvironmentPath(trimmed, platform) {
			ind.RelativeComponents++
		}
		if isTemporaryEnvironmentPath(trimmed, platform) {
			ind.TemporaryComponents++
		}
	}
}

func splitEnvironmentPath(value, platform string, splitWhitespace bool) []string {
	sep := ':'
	if strings.EqualFold(platform, "windows") {
		sep = ';'
	}
	if splitWhitespace {
		return strings.FieldsFunc(value, func(r rune) bool { return r == sep || r == ' ' || r == '\t' })
	}
	return strings.Split(value, string(sep))
}

func isRelativeEnvironmentPath(p, platform string) bool {
	p = strings.TrimSpace(p)
	if p == "" || p == "." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, ".\\") {
		return true
	}
	if strings.EqualFold(platform, "windows") {
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `/`) {
			return false
		}
		return !(len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
	}
	return !strings.HasPrefix(p, "/")
}

func isTemporaryEnvironmentPath(p, platform string) bool {
	low := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	if strings.EqualFold(platform, "windows") {
		return strings.Contains(low, "/appdata/local/temp/") || strings.HasSuffix(low, "/appdata/local/temp") || strings.Contains(low, "/windows/temp/") || strings.HasSuffix(low, "/windows/temp") || strings.Contains(low, "%temp%") || strings.Contains(low, "%tmp%")
	}
	return low == "/tmp" || strings.HasPrefix(low, "/tmp/") || low == "/var/tmp" || strings.HasPrefix(low, "/var/tmp/") || low == "/private/tmp" || strings.HasPrefix(low, "/private/tmp/")
}

func truthyEnvironmentValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func matchTokenPatterns(value string, patterns map[string]string) []string {
	low := strings.ToLower(value)
	out := []string{}
	for needle, class := range patterns {
		if strings.Contains(low, strings.ToLower(needle)) {
			out = append(out, class)
		}
	}
	return normalizedList(out)
}

func containsAny(in []string, wanted ...string) bool {
	set := map[string]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	for _, v := range wanted {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func normalizeEnvironmentIndicators(in []EnvironmentIndicator) []EnvironmentIndicator {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]EnvironmentIndicator{}
	for _, ind := range in {
		ind.Name = strings.ToUpper(strings.TrimSpace(ind.Name))
		ind.Category = strings.ToUpper(strings.TrimSpace(ind.Category))
		ind.RiskClass = strings.ToUpper(fallback(ind.RiskClass, "CONTEXTUAL"))
		ind.PatternClasses = normalizedList(ind.PatternClasses)
		if ind.Name == "" || ind.Category == "" {
			continue
		}
		seen[ind.Name+"\x00"+ind.Category] = ind
	}
	out := make([]EnvironmentIndicator, 0, len(seen))
	for _, ind := range seen {
		out = append(out, ind)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Category < out[j].Category
	})
	if len(out) > maxEnvironmentIndicators {
		out = out[:maxEnvironmentIndicators]
	}
	return out
}

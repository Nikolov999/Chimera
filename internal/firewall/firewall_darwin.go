//go:build darwin

package firewall

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectPF(ctx, inv)
	collectApplicationFirewall(ctx, inv)
}
func collectPF(ctx context.Context, inv *Inventory) {
	path, err := exec.LookPath("pfctl")
	if err != nil {
		addProvider(inv, ProviderStatus{ID: "pf", Name: "pf", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "executable search path", Reason: "pfctl is not installed"})
		return
	}
	out, state, reason := runDarwin(ctx, path, "-s", "info")
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: "pf", Name: "pf", State: state, Enabled: "UNKNOWN", Source: path + " -s info", Reason: reason})
		return
	}
	enabled, attributes := parsePFInfo(out)
	rules, rs, rr := runDarwin(ctx, path, "-sr")
	known := rs == evidence.StateObserved
	count := 0
	if known {
		for _, l := range strings.Split(rules, "\n") {
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
	} else if rs == evidence.StateDenied {
		inv.Degraded = append(inv.Degraded, "pf rules: "+rr)
	}
	addProvider(inv, ProviderStatus{ID: "pf", Name: "pf", State: evidence.StateObserved, Enabled: enabled, Source: path + " -s info", RuleCount: count, RuleCountKnown: known})
	addPolicy(inv, Policy{Provider: "pf", Scope: "global", Enabled: enabled, RuleCount: count, RuleCountKnown: known, Source: path + " local metadata", Confidence: evidence.ConfidenceHigh, Attributes: attributes})
	if known {
		for _, r := range parsePFRestrictions(rules) {
			r.Provider = "pf"
			r.Source = path + " -sr"
			addRestriction(inv, r)
		}
	}
}
func parsePFInfo(out string) (string, []Attribute) {
	enabled := "UNKNOWN"
	a := []Attribute{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if strings.EqualFold(k, "Status") {
			fields := strings.Fields(v)
			if len(fields) > 0 {
				enabled = normalizeEnabled(fields[0])
			}
		}
		if strings.EqualFold(k, "Debug") || strings.EqualFold(k, "Hostid") || strings.EqualFold(k, "Since") {
			a = append(a, Attribute{Name: k, Value: v})
		}
	}
	return enabled, a
}
func collectApplicationFirewall(ctx context.Context, inv *Inventory) {
	path := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		addProvider(inv, ProviderStatus{ID: "macos-application-firewall", Name: "macOS Application Firewall", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: path, Reason: "socketfilterfw is not available"})
		return
	}
	global, state, reason := runDarwin(ctx, path, "--getglobalstate")
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: "macos-application-firewall", Name: "macOS Application Firewall", State: state, Enabled: "UNKNOWN", Source: path + " --getglobalstate", Reason: reason})
		return
	}
	enabled := parseSocketFilterEnabled(global)
	attrsOut := []Attribute{}
	for _, spec := range []struct{ name, arg string }{{"block_all", "--getblockall"}, {"stealth_mode", "--getstealthmode"}, {"allow_signed", "--getallowsigned"}, {"allow_signed_app", "--getallowsignedapp"}} {
		o, s, _ := runDarwin(ctx, path, spec.arg)
		if s == evidence.StateObserved {
			attrsOut = append(attrsOut, Attribute{Name: spec.name, Value: compactDarwin(o)})
		}
	}
	addProvider(inv, ProviderStatus{ID: "macos-application-firewall", Name: "macOS Application Firewall", State: evidence.StateObserved, Enabled: enabled, Source: path + " local state"})
	addPolicy(inv, Policy{Provider: "macos-application-firewall", Scope: "global", Enabled: enabled, Source: path + " local state", Confidence: evidence.ConfidenceHigh, Attributes: attrsOut})
}

var pfActionExpr = regexp.MustCompile(`(?i)^(pass|block)(?:\s+\w+)*\s+in\b`)
var pfProtoExpr = regexp.MustCompile(`(?i)\bproto\s+(tcp|udp)\b`)
var pfFromExpr = regexp.MustCompile(`(?i)\bfrom\s+([^\s]+)`)
var pfToExpr = regexp.MustCompile(`(?i)\bto\s+([^\s]+)`)
var pfPortExpr = regexp.MustCompile(`(?i)\bport\s+(?:=|==)?\s*([0-9]+(?:\s*[:\-]\s*[0-9]+)?)`)
var pfInterfaceExpr = regexp.MustCompile(`(?i)\bon\s+([^\s]+)`)

func parsePFRestrictions(out string) []RestrictionRule {
	rules := []RestrictionRule{}
	order := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		m := pfActionExpr.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		order++
		action := "ALLOW"
		if strings.EqualFold(m[1], "block") {
			action = "BLOCK"
		}
		r := RestrictionRule{Scope: "global", Direction: "INBOUND", Action: action, Protocol: "ANY", Enabled: "ENABLED", Order: order, Confidence: evidence.ConfidenceHigh}
		if pm := pfProtoExpr.FindStringSubmatch(line); len(pm) > 1 {
			r.Protocol = strings.ToUpper(pm[1])
		}
		if fm := pfFromExpr.FindStringSubmatch(line); len(fm) > 1 {
			if !strings.EqualFold(fm[1], "any") {
				r.RemoteAddresses = []string{fm[1]}
			} else {
				r.RemoteAddresses = []string{"ANY"}
			}
		}
		if tm := pfToExpr.FindStringSubmatch(line); len(tm) > 1 {
			if !strings.EqualFold(tm[1], "any") {
				r.LocalAddresses = []string{tm[1]}
			}
		}
		if pm := pfPortExpr.FindStringSubmatch(line); len(pm) > 1 {
			r.LocalPorts = parsePortSpec(strings.ReplaceAll(pm[1], ":", "-"))
		}
		if im := pfInterfaceExpr.FindStringSubmatch(line); len(im) > 1 {
			r.Interfaces = []string{im[1]}
		}
		rules = append(rules, r)
	}
	return rules
}

func parseSocketFilterEnabled(out string) string {
	low := strings.ToLower(out)
	if strings.Contains(low, "state = 1") || strings.Contains(low, "enabled") {
		return "ENABLED"
	}
	if strings.Contains(low, "state = 0") || strings.Contains(low, "disabled") {
		return "DISABLED"
	}
	return "UNKNOWN"
}
func runDarwin(ctx context.Context, path string, args ...string) (string, evidence.State, string) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	b, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(b))
	if err == nil {
		return out, evidence.StateObserved, ""
	}
	msg := strings.TrimSpace(out + " " + err.Error())
	low := strings.ToLower(msg)
	if strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted") || strings.Contains(low, "root") || strings.Contains(low, "permission") {
		return out, evidence.StateDenied, msg
	}
	return out, evidence.StateUnavailable, msg
}
func compactDarwin(v string) string { return strings.Join(strings.Fields(v), " ") }

var _ = strconv.Itoa

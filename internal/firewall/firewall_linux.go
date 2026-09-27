//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

var nftHook = regexp.MustCompile(`(?i)hook\s+(input|output|forward)\b`)
var nftPolicy = regexp.MustCompile(`(?i)policy\s+(accept|drop|reject)\b`)

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectNFT(ctx, inv)
	collectIPTables(ctx, inv, "iptables", "ipv4")
	collectIPTables(ctx, inv, "ip6tables", "ipv6")
	collectFirewalld(ctx, inv)
	collectUFW(ctx, inv)
}

func collectNFT(ctx context.Context, inv *Inventory) {
	path, err := exec.LookPath("nft")
	if err != nil {
		addProvider(inv, ProviderStatus{ID: "nftables", Name: "nftables", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "executable search path", Reason: "nft command is not installed"})
		return
	}
	out, state, reason := runLocal(ctx, path, "list", "ruleset")
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: "nftables", Name: "nftables", State: state, Enabled: "UNKNOWN", Source: path + " list ruleset", Reason: reason})
		return
	}
	policies, tableCount, chainCount, ruleCount := parseNFTRuleset(out)
	enabled := "DISABLED"
	if tableCount > 0 {
		enabled = "ENABLED"
	}
	addProvider(inv, ProviderStatus{ID: "nftables", Name: "nftables", State: evidence.StateObserved, Enabled: enabled, Source: path + " list ruleset", RuleCount: ruleCount, RuleCountKnown: true})
	for _, p := range policies {
		p.Provider = "nftables"
		p.Source = path + " list ruleset"
		p.Attributes = append(p.Attributes, attrs("table_count", strconv.Itoa(tableCount), "chain_count", strconv.Itoa(chainCount))...)
		addPolicy(inv, p)
	}
	for _, r := range parseNFTRestrictions(out) {
		r.Provider = "nftables"
		r.Source = path + " list ruleset"
		addRestriction(inv, r)
	}
}

func parseNFTRuleset(out string) ([]Policy, int, int, int) {
	lines := strings.Split(out, "\n")
	tableCount, chainCount, ruleCount := 0, 0, 0
	family, table, chain := "", "", ""
	policies := []Policy{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "table" && strings.HasSuffix(line, "{") {
			tableCount++
			family = f[1]
			table = f[2]
			continue
		}
		if len(f) >= 2 && f[0] == "chain" && strings.HasSuffix(line, "{") {
			chainCount++
			chain = f[1]
			continue
		}
		if strings.Contains(line, " hook ") || strings.HasPrefix(line, "type ") {
			m := nftHook.FindStringSubmatch(line)
			if len(m) > 0 {
				hook := strings.ToLower(m[1])
				action := "UNKNOWN"
				if pm := nftPolicy.FindStringSubmatch(line); len(pm) > 1 {
					action = strings.ToUpper(pm[1])
				}
				p := Policy{Scope: strings.Join([]string{family, table, chain}, "/"), Enabled: "ENABLED", Source: "nft list ruleset", Confidence: evidence.ConfidenceHigh, Attributes: attrs("hook", hook)}
				switch hook {
				case "input":
					p.DefaultInbound = action
				case "output":
					p.DefaultOutbound = action
				case "forward":
					p.DefaultForward = action
				}
				policies = append(policies, p)
			}
			continue
		}
		if line == "{" || line == "}" || strings.HasPrefix(line, "type ") {
			continue
		}
		if chain != "" && !strings.HasPrefix(line, "chain ") {
			ruleCount++
		}
	}
	return policies, tableCount, chainCount, ruleCount
}

func collectIPTables(ctx context.Context, inv *Inventory, binary, scope string) {
	path, err := exec.LookPath(binary)
	id := binary
	name := binary
	if err != nil {
		addProvider(inv, ProviderStatus{ID: id, Name: name, State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "executable search path", Reason: binary + " command is not installed"})
		return
	}
	out, state, reason := runLocal(ctx, path, "-S")
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: id, Name: name, State: state, Enabled: "UNKNOWN", Source: path + " -S", Reason: reason})
		return
	}
	inb, outb, fwd, rules, seen := parseIPTables(out)
	enabled := "DISABLED"
	if seen || rules > 0 {
		enabled = "ENABLED"
	}
	addProvider(inv, ProviderStatus{ID: id, Name: name, State: evidence.StateObserved, Enabled: enabled, Source: path + " -S", RuleCount: rules, RuleCountKnown: true})
	if seen || rules > 0 {
		addPolicy(inv, Policy{Provider: id, Scope: scope, Enabled: enabled, DefaultInbound: inb, DefaultOutbound: outb, DefaultForward: fwd, RuleCount: rules, RuleCountKnown: true, Source: path + " -S", Confidence: evidence.ConfidenceExact})
	}
	for _, r := range parseIPTablesRestrictions(out, id, scope) {
		r.Source = path + " -S"
		addRestriction(inv, r)
	}
}
func parseIPTables(out string) (string, string, string, int, bool) {
	inb, outb, fwd := "UNKNOWN", "UNKNOWN", "UNKNOWN"
	rules := 0
	seen := false
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(raw))
		if len(f) >= 3 && f[0] == "-P" {
			seen = true
			switch strings.ToUpper(f[1]) {
			case "INPUT":
				inb = strings.ToUpper(f[2])
			case "OUTPUT":
				outb = strings.ToUpper(f[2])
			case "FORWARD":
				fwd = strings.ToUpper(f[2])
			}
		} else if len(f) > 0 && f[0] == "-A" {
			rules++
		}
	}
	return inb, outb, fwd, rules, seen
}

func collectFirewalld(ctx context.Context, inv *Inventory) {
	path, err := exec.LookPath("firewall-cmd")
	if err != nil {
		addProvider(inv, ProviderStatus{ID: "firewalld", Name: "firewalld", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "executable search path", Reason: "firewall-cmd is not installed"})
		return
	}
	out, state, reason := runLocal(ctx, path, "--state")
	low := strings.ToLower(strings.TrimSpace(out + " " + reason))
	if state != evidence.StateObserved && strings.Contains(low, "not running") {
		state = evidence.StateObserved
		out = "not running"
		reason = ""
	}
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: "firewalld", Name: "firewalld", State: state, Enabled: "UNKNOWN", Source: path + " --state", Reason: reason})
		return
	}
	enabled := normalizeEnabled(out)
	addProvider(inv, ProviderStatus{ID: "firewalld", Name: "firewalld", State: evidence.StateObserved, Enabled: enabled, Source: path + " --state"})
	if enabled != "ENABLED" {
		return
	}
	zone, _, _ := runLocal(ctx, path, "--get-default-zone")
	active, _, _ := runLocal(ctx, path, "--get-active-zones")
	zones := parseActiveFirewalldZones(active)
	defaultZone := strings.TrimSpace(zone)
	if len(zones) == 0 && defaultZone != "" {
		zones = append(zones, defaultZone)
	}
	if len(zones) == 0 {
		zones = append(zones, "default-zone")
	}
	for _, z := range zones {
		target, targetState, targetReason := runLocal(ctx, path, "--zone="+z, "--get-target")
		defaultInbound := "UNKNOWN"
		targetValue := strings.TrimSpace(target)
		if targetState == evidence.StateObserved {
			switch strings.ToUpper(targetValue) {
			case "ACCEPT", "DROP", "REJECT":
				defaultInbound = strings.ToUpper(targetValue)
			}
		} else if targetReason != "" {
			inv.Degraded = append(inv.Degraded, "firewalld zone "+z+" target: "+targetReason)
		}
		addPolicy(inv, Policy{Provider: "firewalld", Scope: z, Enabled: "ENABLED", DefaultInbound: defaultInbound, Source: path + " local zone metadata", Confidence: evidence.ConfidenceHigh, Attributes: attrs("default_zone", defaultZone, "active_zones", compactLines(active), "zone_target", fallback(targetValue, "UNKNOWN"))})
	}
}

func parseActiveFirewalldZones(out string) []string {
	zones := []string{}
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(out, "\n") {
		if strings.TrimSpace(raw) == "" || len(raw) == 0 || raw[0] == ' ' || raw[0] == '	' {
			continue
		}
		z := strings.TrimSpace(raw)
		if strings.Contains(z, ":") {
			continue
		}
		if _, ok := seen[z]; ok {
			continue
		}
		seen[z] = struct{}{}
		zones = append(zones, z)
	}
	sort.Strings(zones)
	return zones
}

func collectUFW(ctx context.Context, inv *Inventory) {
	path, err := exec.LookPath("ufw")
	if err != nil {
		addProvider(inv, ProviderStatus{ID: "ufw", Name: "UFW", State: evidence.StateNotApplicable, Enabled: "NOT_APPLICABLE", Source: "executable search path", Reason: "ufw command is not installed"})
		return
	}
	out, state, reason := runLocal(ctx, path, "status", "verbose")
	if state != evidence.StateObserved {
		addProvider(inv, ProviderStatus{ID: "ufw", Name: "UFW", State: state, Enabled: "UNKNOWN", Source: path + " status verbose", Reason: reason})
		return
	}
	enabled, inb, outb, fwd, logging := parseUFW(out)
	addProvider(inv, ProviderStatus{ID: "ufw", Name: "UFW", State: evidence.StateObserved, Enabled: enabled, Source: path + " status verbose"})
	addPolicy(inv, Policy{Provider: "ufw", Scope: "global", Enabled: enabled, DefaultInbound: inb, DefaultOutbound: outb, DefaultForward: fwd, Logging: logging, Source: path + " status verbose", Confidence: evidence.ConfidenceHigh})
	if enabled == "ENABLED" {
		rulesOut, rs, rr := runLocal(ctx, path, "status", "numbered")
		if rs == evidence.StateObserved {
			for _, r := range parseUFWRestrictions(rulesOut) {
				r.Source = path + " status numbered"
				addRestriction(inv, r)
			}
		} else if rr != "" {
			inv.Degraded = append(inv.Degraded, "ufw rule correlation: "+rr)
		}
	}
}
func parseUFW(out string) (string, string, string, string, string) {
	enabled, inb, outb, fwd, logging := "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "status:") {
			enabled = normalizeEnabled(strings.TrimSpace(strings.TrimPrefix(low, "status:")))
		}
		if strings.HasPrefix(low, "logging:") {
			logging = strings.TrimSpace(strings.TrimPrefix(line, "Logging:"))
		}
		if strings.HasPrefix(low, "default:") {
			v := strings.TrimSpace(strings.TrimPrefix(low, "default:"))
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				fields := strings.Fields(part)
				if len(fields) < 2 {
					continue
				}
				action := strings.ToUpper(fields[0])
				switch {
				case strings.Contains(part, "incoming"):
					inb = action
				case strings.Contains(part, "outgoing"):
					outb = action
				case strings.Contains(part, "routed"):
					fwd = action
				}
			}
		}
	}
	return enabled, inb, outb, fwd, logging
}

var nftPortExpr = regexp.MustCompile(`(?i)\b(tcp|udp)\s+dport\s+(\{[^}]+\}|[0-9]+(?:\s*[-:]\s*[0-9]+)?)`)
var nftSAddrExpr = regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+saddr\s+(\{[^}]+\}|[^\s]+)`)
var nftDAddrExpr = regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+daddr\s+(\{[^}]+\}|[^\s]+)`)
var nftIIFExpr = regexp.MustCompile(`(?i)\biifname\s+("[^"]+"|[^\s]+)`)

func parseNFTRestrictions(out string) []RestrictionRule {
	family, table, chain, hook := "", "", "", ""
	order := 0
	rules := []RestrictionRule{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "table" && strings.HasSuffix(line, "{") {
			family, table = f[1], f[2]
			chain, hook = "", ""
			continue
		}
		if len(f) >= 2 && f[0] == "chain" && strings.HasSuffix(line, "{") {
			chain, hook = f[1], ""
			continue
		}
		if m := nftHook.FindStringSubmatch(line); len(m) > 1 {
			hook = strings.ToLower(m[1])
			continue
		}
		if line == "}" {
			chain, hook = "", ""
			continue
		}
		if hook != "input" || chain == "" {
			continue
		}
		action := ""
		low := strings.ToLower(line)
		for _, v := range []string{"accept", "drop", "reject"} {
			if regexp.MustCompile(`\b` + v + `\b`).MatchString(low) {
				action = strings.ToUpper(v)
			}
		}
		if action == "" {
			continue
		}
		order++
		r := RestrictionRule{Scope: strings.Join([]string{family, table, chain}, "/"), Direction: "INBOUND", Action: action, Protocol: "ANY", Enabled: "ENABLED", Order: order, Confidence: evidence.ConfidenceHigh}
		if m := nftPortExpr.FindStringSubmatch(line); len(m) > 2 {
			r.Protocol = strings.ToUpper(m[1])
			spec := strings.Trim(strings.ReplaceAll(m[2], ":", "-"), "{} ")
			r.LocalPorts = parsePortSpec(spec)
		}
		if m := nftSAddrExpr.FindStringSubmatch(line); len(m) > 1 {
			r.RemoteAddresses = splitNFTSelector(m[1])
		}
		if m := nftDAddrExpr.FindStringSubmatch(line); len(m) > 1 {
			r.LocalAddresses = splitNFTSelector(m[1])
		}
		if m := nftIIFExpr.FindStringSubmatch(line); len(m) > 1 {
			r.Interfaces = []string{strings.Trim(m[1], `"`)}
		}
		rules = append(rules, r)
	}
	return rules
}

func splitNFTSelector(v string) []string {
	v = strings.Trim(strings.TrimSpace(v), "{}")
	return normalizeSelectorList(strings.FieldsFunc(v, func(r rune) bool { return r == ',' }))
}

func parseIPTablesRestrictions(out, provider, scope string) []RestrictionRule {
	rules := []RestrictionRule{}
	order := 0
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(raw))
		if len(f) < 3 || f[0] != "-A" || strings.ToUpper(f[1]) != "INPUT" {
			continue
		}
		order++
		r := RestrictionRule{Provider: provider, Scope: scope + "/INPUT", Direction: "INBOUND", Protocol: "ANY", Enabled: "ENABLED", Order: order, Confidence: evidence.ConfidenceExact}
		for i := 2; i < len(f); i++ {
			switch f[i] {
			case "-p", "--protocol":
				if i+1 < len(f) {
					i++
					r.Protocol = normalizeProtocol(f[i])
				}
			case "--dport", "--destination-port":
				if i+1 < len(f) {
					i++
					r.LocalPorts = parsePortSpec(strings.ReplaceAll(f[i], ":", "-"))
				}
			case "-d", "--destination":
				if i+1 < len(f) {
					i++
					r.LocalAddresses = []string{f[i]}
				}
			case "-s", "--source":
				if i+1 < len(f) {
					i++
					r.RemoteAddresses = []string{f[i]}
				}
			case "-i", "--in-interface":
				if i+1 < len(f) {
					i++
					r.Interfaces = []string{f[i]}
				}
			case "-j", "--jump":
				if i+1 < len(f) {
					i++
					r.Action = strings.ToUpper(f[i])
				}
			}
		}
		if inboundActionClass(r.Action) == "UNKNOWN" {
			continue
		}
		rules = append(rules, r)
	}
	return rules
}

var ufwRuleLine = regexp.MustCompile(`^\[\s*[0-9]+\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.+)$`)

func parseUFWRestrictions(out string) []RestrictionRule {
	rules := []RestrictionRule{}
	order := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		m := ufwRuleLine.FindStringSubmatch(line)
		if len(m) != 5 || strings.ToUpper(m[3]) != "IN" {
			continue
		}
		order++
		target := strings.TrimSpace(m[1])
		from := strings.TrimSpace(m[4])
		proto := "ANY"
		portSpec := target
		if idx := strings.LastIndex(target, "/"); idx > 0 {
			proto = strings.ToUpper(target[idx+1:])
			portSpec = target[:idx]
		}
		action := strings.ToUpper(m[2])
		if action == "LIMIT" {
			action = "ALLOW"
		}
		r := RestrictionRule{Provider: "ufw", Scope: "global", Direction: "INBOUND", Action: action, Protocol: proto, LocalPorts: parsePortSpec(portSpec), Enabled: "ENABLED", Order: order, Confidence: evidence.ConfidenceHigh}
		if from != "" && !strings.EqualFold(from, "Anywhere") {
			r.RemoteAddresses = []string{strings.Fields(from)[0]}
		} else {
			r.RemoteAddresses = []string{"ANY"}
		}
		rules = append(rules, r)
	}
	return rules
}

func runLocal(ctx context.Context, path string, args ...string) (string, evidence.State, string) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	b, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(b))
	if err == nil {
		return out, evidence.StateObserved, ""
	}
	msg := strings.TrimSpace(out + " " + err.Error())
	low := strings.ToLower(msg)
	for _, needle := range []string{"permission denied", "operation not permitted", "must be root", "need to be root", "requires root", "permission-restricted", "access denied"} {
		if strings.Contains(low, needle) {
			return out, evidence.StateDenied, msg
		}
	}
	return out, evidence.StateUnavailable, msg
}
func compactLines(v string) string {
	parts := []string{}
	for _, l := range strings.Split(v, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, " | ")
}

var _ = fmt.Sprintf

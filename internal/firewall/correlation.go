package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
)

const (
	CoveragePresent       = "PRESENT"
	CoverageAbsent        = "ABSENT"
	CoverageAmbiguous     = "AMBIGUOUS"
	CoverageUnavailable   = "UNAVAILABLE"
	CoverageNotApplicable = "NOT_APPLICABLE"
)

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type RestrictionRule struct {
	ID              string              `json:"id"`
	Provider        string              `json:"provider"`
	Scope           string              `json:"scope,omitempty"`
	Direction       string              `json:"direction"`
	Action          string              `json:"action"`
	Protocol        string              `json:"protocol"`
	LocalPorts      []PortRange         `json:"local_ports,omitempty"`
	LocalAddresses  []string            `json:"local_addresses,omitempty"`
	RemoteAddresses []string            `json:"remote_addresses,omitempty"`
	Interfaces      []string            `json:"interfaces,omitempty"`
	Application     string              `json:"application,omitempty"`
	Service         string              `json:"service,omitempty"`
	Enabled         string              `json:"enabled"`
	Order           int                 `json:"order,omitempty"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
}

type ListenerCoverage struct {
	ID             string              `json:"id"`
	EndpointID     string              `json:"endpoint_id"`
	Protocol       string              `json:"protocol"`
	LocalAddress   string              `json:"local_address"`
	LocalPort      uint16              `json:"local_port"`
	BindingClass   string              `json:"binding_class"`
	ProcessName    string              `json:"process_name,omitempty"`
	ServiceName    string              `json:"service_name,omitempty"`
	State          string              `json:"state"`
	ProviderIDs    []string            `json:"provider_ids,omitempty"`
	PolicyIDs      []string            `json:"policy_ids,omitempty"`
	RestrictionIDs []string            `json:"restriction_ids,omitempty"`
	Basis          string              `json:"basis"`
	Source         string              `json:"source"`
	Confidence     evidence.Confidence `json:"confidence"`
}

func addRestriction(inv *Inventory, r RestrictionRule) {
	r.Provider = slug(r.Provider)
	r.Scope = strings.TrimSpace(r.Scope)
	r.Direction = strings.ToUpper(strings.TrimSpace(r.Direction))
	r.Action = normalizeAction(r.Action)
	r.Protocol = normalizeProtocol(r.Protocol)
	r.Enabled = normalizeEnabled(r.Enabled)
	r.LocalPorts = normalizePortRanges(r.LocalPorts)
	r.LocalAddresses = normalizeSelectorList(r.LocalAddresses)
	r.RemoteAddresses = normalizeSelectorList(r.RemoteAddresses)
	r.Interfaces = uniqueSorted(r.Interfaces)
	r.Application = strings.TrimSpace(r.Application)
	r.Service = strings.TrimSpace(r.Service)
	r.Source = strings.TrimSpace(r.Source)
	if r.Source == "" {
		r.Source = "local firewall rule metadata"
	}
	if r.Confidence == "" {
		r.Confidence = evidence.ConfidenceHigh
	}
	if r.Direction == "" {
		r.Direction = "UNKNOWN"
	}
	if r.Action == "" {
		r.Action = "UNKNOWN"
	}
	if r.Protocol == "" {
		r.Protocol = "ANY"
	}
	if r.Enabled == "UNKNOWN" {
		r.Enabled = "ENABLED"
	}
	r.ID = stableRestrictionID(r)
	inv.Restrictions = append(inv.Restrictions, r)
}

func normalizeRestrictions(in []RestrictionRule) []RestrictionRule {
	out := make([]RestrictionRule, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r.Provider = slug(r.Provider)
		r.Scope = strings.TrimSpace(r.Scope)
		r.Direction = strings.ToUpper(strings.TrimSpace(r.Direction))
		r.Action = normalizeAction(r.Action)
		r.Protocol = normalizeProtocol(r.Protocol)
		r.Enabled = normalizeEnabled(r.Enabled)
		r.LocalPorts = normalizePortRanges(r.LocalPorts)
		r.LocalAddresses = normalizeSelectorList(r.LocalAddresses)
		r.RemoteAddresses = normalizeSelectorList(r.RemoteAddresses)
		r.Interfaces = uniqueSorted(r.Interfaces)
		r.Application = strings.TrimSpace(r.Application)
		r.Service = strings.TrimSpace(r.Service)
		if r.Source == "" {
			r.Source = "local firewall rule metadata"
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceHigh
		}
		if r.Protocol == "" {
			r.Protocol = "ANY"
		}
		r.ID = stableRestrictionID(r)
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxRestrictions {
		out = out[:maxRestrictions]
	}
	return out
}

func stableRestrictionID(r RestrictionRule) string {
	ports := make([]string, 0, len(r.LocalPorts))
	for _, p := range r.LocalPorts {
		ports = append(ports, fmt.Sprintf("%d-%d", p.Start, p.End))
	}
	basis := strings.Join([]string{r.Provider, r.Scope, r.Direction, r.Action, r.Protocol, strings.Join(ports, ","), strings.Join(r.LocalAddresses, ","), strings.Join(r.RemoteAddresses, ","), strings.Join(r.Interfaces, ","), r.Application, r.Service}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return "fwr-" + hex.EncodeToString(sum[:10])
}

func normalizeProtocol(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if strings.Contains(v, ",") {
		parts := normalizeSelectorList([]string{v})
		if len(parts) == 1 {
			v = strings.ToUpper(parts[0])
		} else if len(parts) > 1 {
			first := normalizeProtocol(parts[0])
			same := true
			for _, p := range parts[1:] {
				if normalizeProtocol(p) != first {
					same = false
					break
				}
			}
			if same {
				return first
			}
			return "ANY"
		}
	}
	switch v {
	case "6", "TCP":
		return "TCP"
	case "17", "UDP":
		return "UDP"
	case "", "ANY", "ALL", "*", "256":
		return "ANY"
	default:
		return v
	}
}

func normalizePortRanges(in []PortRange) []PortRange {
	out := make([]PortRange, 0, len(in))
	seen := map[string]struct{}{}
	for _, p := range in {
		if p.Start == 0 {
			continue
		}
		if p.End == 0 {
			p.End = p.Start
		}
		if p.End < p.Start {
			p.Start, p.End = p.End, p.Start
		}
		k := fmt.Sprintf("%d-%d", p.Start, p.End)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start == out[j].Start {
			return out[i].End < out[j].End
		}
		return out[i].Start < out[j].Start
	})
	return out
}

func normalizeSelectorList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool { return r == ',' || r == ';' }) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upper := strings.ToUpper(part)
			if upper == "*" || upper == "ANY" || upper == "0.0.0.0/0" || upper == "::/0" {
				part = "ANY"
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	sort.Strings(out)
	return out
}

// WithListenerCoverage derives listener-to-firewall correlation from
// immutable network evidence and the local firewall inventory. It
// performs no network probes and does not alter firewall configuration.
func (inv Inventory) WithListenerCoverage(net netinv.Inventory) Inventory {
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	inv.ListenerCoverage = correlateListenerCoverage(net.Endpoints, inv)
	inv.Summary = summarize(inv.Providers, inv.Policies, inv.Restrictions, inv.ListenerCoverage)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func correlateListenerCoverage(endpoints []netinv.Endpoint, inv Inventory) []ListenerCoverage {
	providers := map[string]ProviderStatus{}
	for _, p := range inv.Providers {
		providers[p.ID] = p
	}
	policies := map[string][]Policy{}
	for _, p := range inv.Policies {
		policies[p.Provider] = append(policies[p.Provider], p)
	}
	rules := map[string][]RestrictionRule{}
	for _, r := range inv.Restrictions {
		rules[r.Provider] = append(rules[r.Provider], r)
	}
	out := make([]ListenerCoverage, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.InterfaceBinding.Class == "LOOPBACK" {
			continue
		}
		c := correlateEndpoint(ep, providers, policies, rules)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EndpointID < out[j].EndpointID })
	return out
}

func correlateEndpoint(ep netinv.Endpoint, providers map[string]ProviderStatus, policies map[string][]Policy, rules map[string][]RestrictionRule) ListenerCoverage {
	c := ListenerCoverage{
		EndpointID: ep.ID, Protocol: ep.Protocol, LocalAddress: ep.LocalAddress, LocalPort: ep.LocalPort,
		BindingClass: ep.InterfaceBinding.Class, ProcessName: ep.Owner.ProcessName, ServiceName: ep.Owner.ServiceName,
		Source: "listener + /058 local firewall evidence", Confidence: evidence.ConfidenceLow,
	}
	c.ID = stableCoverageID(ep)

	enabled := make([]ProviderStatus, 0)
	uncertainProviders := make([]ProviderStatus, 0)
	disabled := make([]ProviderStatus, 0)
	unavailable := false
	for _, p := range providers {
		switch p.State {
		case evidence.StateObserved:
			switch p.Enabled {
			case "ENABLED":
				enabled = append(enabled, p)
			case "DISABLED", "NOT_APPLICABLE":
				disabled = append(disabled, p)
			default:
				uncertainProviders = append(uncertainProviders, p)
			}
		case evidence.StateDenied, evidence.StateUnavailable, evidence.StateDegraded, evidence.StateUnsupported:
			unavailable = true
		}
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })
	if len(enabled) == 0 {
		if len(uncertainProviders) > 0 || unavailable {
			c.State = CoverageUnavailable
			c.Basis = "no enabled local firewall provider could be confirmed; one or more provider states are unresolved"
			c.Confidence = evidence.ConfidenceLow
			return c
		}
		if len(disabled) > 0 {
			ids := make([]string, 0, len(disabled))
			for _, p := range disabled {
				ids = append(ids, p.ID)
			}
			c.ProviderIDs = uniqueSorted(ids)
			c.State = CoverageAbsent
			c.Basis = "all observable local firewall providers are disabled"
			c.Confidence = evidence.ConfidenceHigh
			return c
		}
		c.State = CoverageUnavailable
		c.Basis = "no observable local firewall provider can be correlated to this listener"
		return c
	}

	type decision struct {
		provider string
		state    string
		policy   []string
		rules    []string
		basis    string
		conf     evidence.Confidence
	}
	decisions := make([]decision, 0, len(enabled))
	for _, p := range enabled {
		d := correlateProvider(ep, p, policies[p.ID], rules[p.ID])
		decisions = append(decisions, decision(d))
	}

	for _, d := range decisions {
		c.ProviderIDs = append(c.ProviderIDs, d.provider)
		c.PolicyIDs = append(c.PolicyIDs, d.policy...)
		c.RestrictionIDs = append(c.RestrictionIDs, d.rules...)
	}
	c.ProviderIDs = uniqueSorted(c.ProviderIDs)
	c.PolicyIDs = uniqueSorted(c.PolicyIDs)
	c.RestrictionIDs = uniqueSorted(c.RestrictionIDs)

	present, absent, ambiguous := 0, 0, 0
	basis := make([]string, 0, len(decisions))
	conf := evidence.ConfidenceExact
	for _, d := range decisions {
		switch d.state {
		case CoveragePresent:
			present++
		case CoverageAbsent:
			absent++
		default:
			ambiguous++
		}
		basis = append(basis, d.provider+": "+d.basis)
		conf = lowerConfidence(conf, d.conf)
	}
	// One confirmed active restriction is sufficient to establish that a local
	// firewall boundary exists for the listener. Ambiguity matters only when no
	// active provider can be shown to restrict it.
	switch {
	case present > 0:
		c.State = CoveragePresent
	case ambiguous > 0 || unavailable || len(uncertainProviders) > 0:
		c.State = CoverageAmbiguous
		if unavailable || len(uncertainProviders) > 0 {
			basis = append(basis, "additional firewall provider state is unresolved")
		}
	case absent > 0:
		c.State = CoverageAbsent
	default:
		c.State = CoverageUnavailable
	}
	c.Basis = strings.Join(basis, "; ")
	c.Confidence = conf
	return c
}

func correlateProvider(ep netinv.Endpoint, provider ProviderStatus, policies []Policy, rules []RestrictionRule) struct {
	provider string
	state    string
	policy   []string
	rules    []string
	basis    string
	conf     evidence.Confidence
} {
	d := struct {
		provider string
		state    string
		policy   []string
		rules    []string
		basis    string
		conf     evidence.Confidence
	}{provider: provider.ID, state: CoverageAmbiguous, conf: evidence.ConfidenceLow}

	matched, uncertain := matchRestrictionRules(ep, rules, policies)
	for _, r := range matched {
		d.rules = append(d.rules, r.ID)
	}
	if len(matched) > 0 {
		restrictive, permissive, sourceScoped := 0, 0, 0
		for _, r := range matched {
			switch inboundActionClass(r.Action) {
			case "RESTRICTIVE":
				restrictive++
			case "PERMISSIVE":
				permissive++
				if selectorIsRestricted(r.RemoteAddresses) {
					sourceScoped++
				}
			}
		}
		switch {
		case restrictive > 0 && permissive > 0 && provider.ID == "windows-defender-firewall":
			// Windows Defender Firewall explicit block rules take precedence over
			// conflicting allow rules for the same traffic.
			d.state, d.basis, d.conf = CoveragePresent, "matching Windows inbound rules include an explicit block; block precedence restricts the listener", evidence.ConfidenceHigh
			return d
		case restrictive > 0 && permissive > 0:
			d.state, d.basis, d.conf = CoverageAmbiguous, "matching inbound rules contain both restrictive and permissive actions", evidence.ConfidenceMedium
			return d
		case restrictive > 0:
			d.state, d.basis, d.conf = CoveragePresent, "matching inbound rule explicitly restricts the listener", evidence.ConfidenceHigh
			return d
		case permissive > 0 && sourceScoped == permissive:
			d.state, d.basis, d.conf = CoveragePresent, "matching inbound allow rule restricts remote source scope", evidence.ConfidenceHigh
			return d
		case permissive > 0:
			d.state, d.basis, d.conf = CoverageAbsent, "matching inbound allow rule permits an unrestricted remote source scope", evidence.ConfidenceHigh
			return d
		}
	}
	if uncertain {
		d.state, d.basis, d.conf = CoverageAmbiguous, "one or more inbound rules could apply but their listener selectors are not specific enough to resolve safely", evidence.ConfidenceLow
		return d
	}

	enabledPolicies := make([]Policy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled != "ENABLED" {
			continue
		}
		if provider.ID == "windows-defender-firewall" {
			active := policyAttribute(p, "active_state")
			if active == "INACTIVE" {
				continue
			}
		}
		enabledPolicies = append(enabledPolicies, p)
		d.policy = append(d.policy, p.ID)
	}
	if len(enabledPolicies) == 0 {
		d.state, d.basis, d.conf = CoverageAmbiguous, "enabled provider exposes no enabled policy scope that can be mapped to the listener", evidence.ConfidenceLow
		return d
	}
	restrictive, permissive, unknown := 0, 0, 0
	for _, p := range enabledPolicies {
		switch policyInboundClass(p.DefaultInbound) {
		case "RESTRICTIVE":
			restrictive++
		case "PERMISSIVE":
			permissive++
		default:
			unknown++
		}
	}
	switch {
	case unknown > 0 || (restrictive > 0 && permissive > 0):
		d.state, d.basis, d.conf = CoverageAmbiguous, "enabled policy scopes do not agree on a defensible inbound default for this listener", evidence.ConfidenceLow
	case restrictive > 0:
		if provider.ID == "windows-defender-firewall" && provider.RestrictionSetComplete {
			d.state, d.basis, d.conf = CoveragePresent, "effective restrictive Windows inbound default applies and the complete enabled inbound rule set contains no matching allow exception", evidence.ConfidenceHigh
		} else if provider.RuleCountKnown && provider.RuleCount == 0 {
			d.state, d.basis, d.conf = CoveragePresent, "restrictive inbound default applies and provider reports no exception rules", evidence.ConfidenceHigh
		} else {
			d.state, d.basis, d.conf = CoverageAmbiguous, "restrictive inbound default exists but uncorrelated exception rules may apply to this listener", evidence.ConfidenceMedium
		}
	case permissive > 0:
		if provider.ID == "windows-defender-firewall" && provider.RestrictionSetComplete {
			d.state, d.basis, d.conf = CoverageAbsent, "effective permissive Windows inbound default applies and the complete enabled inbound rule set contains no matching restrictive rule", evidence.ConfidenceHigh
		} else if provider.RuleCountKnown && provider.RuleCount == 0 {
			d.state, d.basis, d.conf = CoverageAbsent, "permissive inbound default applies and provider reports no filtering rules", evidence.ConfidenceHigh
		} else {
			d.state, d.basis, d.conf = CoverageAmbiguous, "permissive inbound default exists but uncorrelated filtering rules may apply to this listener", evidence.ConfidenceMedium
		}
	default:
		d.state, d.basis, d.conf = CoverageUnavailable, "provider policy does not expose inbound restriction semantics", evidence.ConfidenceLow
	}
	return d
}

func matchRestrictionRules(ep netinv.Endpoint, rules []RestrictionRule, policies []Policy) (matched []RestrictionRule, uncertain bool) {
	for _, r := range rules {
		if r.Enabled != "ENABLED" || r.Direction != "INBOUND" {
			continue
		}
		if r.Protocol != "ANY" && r.Protocol != ep.Protocol {
			continue
		}
		if len(r.Interfaces) > 0 {
			interfaces := make([]string, 0, len(r.Interfaces))
			for _, name := range r.Interfaces {
				if name != "" && !strings.EqualFold(name, "Any") {
					interfaces = append(interfaces, name)
				}
			}
			if len(interfaces) > 0 {
				if ep.InterfaceBinding.IsWildcard {
					uncertain = true
					continue
				}
				if len(ep.InterfaceBinding.Interfaces) == 0 {
					uncertain = true
					continue
				}
				if !stringSetsIntersect(interfaces, ep.InterfaceBinding.Interfaces) {
					continue
				}
			}
		}
		if len(r.LocalPorts) > 0 && !portMatches(ep.LocalPort, r.LocalPorts) {
			continue
		}
		if len(r.LocalAddresses) > 0 {
			match, unknown := addressSelectorMatch(ep.LocalAddress, r.LocalAddresses)
			if unknown {
				uncertain = true
			}
			if !match {
				continue
			}
		}
		if r.Application != "" {
			if ep.Owner.Executable == "" {
				uncertain = true
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(r.Application), strings.TrimSpace(ep.Owner.Executable)) {
				continue
			}
		}
		if r.Service != "" {
			if ep.Owner.ServiceName == "" {
				uncertain = true
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(r.Service), strings.TrimSpace(ep.Owner.ServiceName)) {
				continue
			}
		}
		if r.Provider == "windows-defender-firewall" {
			applies, unknown := windowsRuleProfileApplies(r.Scope, policies, ep)
			if unknown {
				uncertain = true
				continue
			}
			if !applies {
				continue
			}
		}
		matched = append(matched, r)
	}
	return matched, uncertain
}

func policyAttribute(p Policy, name string) string {
	name = slug(name)
	for _, a := range p.Attributes {
		if a.Name == name {
			return strings.ToUpper(strings.TrimSpace(a.Value))
		}
	}
	return ""
}

func windowsRuleProfileApplies(scope string, policies []Policy, ep netinv.Endpoint) (bool, bool) {
	scope = strings.TrimSpace(scope)
	if scope == "" || strings.EqualFold(scope, "Any") {
		return true, false
	}
	wanted := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(scope, func(r rune) bool { return r == ',' || r == ';' || r == '|' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			wanted[strings.ToLower(part)] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return true, false
	}

	activeKnown := false
	activeMatched := false
	for _, p := range policies {
		if p.Provider != "windows-defender-firewall" || p.Enabled != "ENABLED" {
			continue
		}
		active := policyAttribute(p, "active_state")
		if active == "UNKNOWN" || active == "" {
			continue
		}
		activeKnown = true
		if active != "ACTIVE" {
			continue
		}
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(p.Scope))]; !ok {
			continue
		}
		// If this listener is tied to known interfaces, use the connection
		// profile's interface aliases to avoid applying a profile from another
		// interface. Wildcard listeners legitimately span active profiles.
		if !ep.InterfaceBinding.IsWildcard && len(ep.InterfaceBinding.Interfaces) > 0 {
			aliases := strings.FieldsFunc(policyAttribute(p, "active_interfaces"), func(r rune) bool { return r == ',' || r == ';' })
			if len(aliases) > 0 && !stringSetsIntersect(aliases, ep.InterfaceBinding.Interfaces) {
				continue
			}
		}
		activeMatched = true
	}
	if !activeKnown {
		return false, true
	}
	return activeMatched, false
}

func stringSetsIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(y)) {
				return true
			}
		}
	}
	return false
}

func portMatches(port uint16, ranges []PortRange) bool {
	for _, r := range ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

func addressSelectorMatch(address string, selectors []string) (bool, bool) {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(address), "[]"))
	unknown := false
	for _, s := range selectors {
		s = strings.TrimSpace(s)
		if strings.EqualFold(s, "ANY") || strings.EqualFold(s, address) {
			return true, unknown
		}
		if _, network, err := net.ParseCIDR(s); err == nil {
			if ip != nil && network.Contains(ip) {
				return true, unknown
			}
			continue
		}
		if parsed := net.ParseIP(strings.Trim(s, "[]")); parsed != nil {
			if ip != nil && parsed.Equal(ip) {
				return true, unknown
			}
			continue
		}
		unknown = true
	}
	return false, unknown
}

func selectorIsRestricted(selectors []string) bool {
	if len(selectors) == 0 {
		return false
	}
	for _, s := range selectors {
		if strings.EqualFold(strings.TrimSpace(s), "ANY") {
			return false
		}
	}
	return true
}

func policyInboundClass(action string) string {
	switch normalizeAction(action) {
	case "BLOCK", "DENY", "DROP", "REJECT":
		return "RESTRICTIVE"
	case "ALLOW", "ACCEPT":
		return "PERMISSIVE"
	}
	return "UNKNOWN"
}

func inboundActionClass(action string) string {
	switch normalizeAction(action) {
	case "BLOCK", "DENY", "DROP", "REJECT":
		return "RESTRICTIVE"
	case "ALLOW", "ACCEPT":
		return "PERMISSIVE"
	}
	return "UNKNOWN"
}

func parsePortSpec(v string) []PortRange {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "any") || v == "*" {
		return nil
	}
	out := []PortRange{}
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			a, errA := strconv.Atoi(strings.TrimSpace(ab[0]))
			b, errB := strconv.Atoi(strings.TrimSpace(ab[1]))
			if errA == nil && errB == nil && a > 0 && a <= 65535 && b > 0 && b <= 65535 {
				out = append(out, PortRange{Start: uint16(a), End: uint16(b)})
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err == nil && n > 0 && n <= 65535 {
			out = append(out, PortRange{Start: uint16(n), End: uint16(n)})
		}
	}
	return normalizePortRanges(out)
}

func stableCoverageID(ep netinv.Endpoint) string {
	sum := sha256.Sum256([]byte(ep.ID + "\x00" + ep.Protocol + "\x00" + ep.LocalAddress + "\x00" + strconv.Itoa(int(ep.LocalPort))))
	return "fwcov-" + hex.EncodeToString(sum[:10])
}

func lowerConfidence(a, b evidence.Confidence) evidence.Confidence {
	rank := map[evidence.Confidence]int{evidence.ConfidenceLow: 1, evidence.ConfidenceMedium: 2, evidence.ConfidenceHigh: 3, evidence.ConfidenceExact: 4}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

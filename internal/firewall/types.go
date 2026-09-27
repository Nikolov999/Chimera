package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.firewall/v2"
	CollectorName    = "firewall"
	CollectorVersion = "firewall/phase058-v1"
	maxPolicies      = 512
	maxRestrictions  = 8192
)

type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ProviderStatus struct {
	ID                     string         `json:"id"`
	Name                   string         `json:"name"`
	State                  evidence.State `json:"state"`
	Enabled                string         `json:"enabled"`
	Source                 string         `json:"source"`
	PolicyCount            int            `json:"policy_count"`
	RuleCount              int            `json:"rule_count,omitempty"`
	RuleCountKnown         bool           `json:"rule_count_known"`
	RestrictionCount       int            `json:"restriction_rule_count,omitempty"`
	RestrictionCountKnown  bool           `json:"restriction_rule_count_known"`
	RestrictionSetComplete bool           `json:"restriction_set_complete"`
	Reason                 string         `json:"reason,omitempty"`
}

type Policy struct {
	ID              string              `json:"id"`
	Provider        string              `json:"provider"`
	Scope           string              `json:"scope"`
	Enabled         string              `json:"enabled"`
	DefaultInbound  string              `json:"default_inbound,omitempty"`
	DefaultOutbound string              `json:"default_outbound,omitempty"`
	DefaultForward  string              `json:"default_forward,omitempty"`
	RuleCount       int                 `json:"rule_count,omitempty"`
	RuleCountKnown  bool                `json:"rule_count_known"`
	Logging         string              `json:"logging,omitempty"`
	Attributes      []Attribute         `json:"attributes,omitempty"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
}

type Summary struct {
	Providers              int `json:"providers"`
	ObservedProviders      int `json:"observed_providers"`
	EnabledProviders       int `json:"enabled_providers"`
	DisabledProviders      int `json:"disabled_providers"`
	MixedProviders         int `json:"mixed_providers"`
	DeniedProviders        int `json:"denied_providers"`
	UnavailableProviders   int `json:"unavailable_providers"`
	NotApplicableProviders int `json:"not_applicable_providers"`
	Policies               int `json:"policies"`
	KnownRules             int `json:"known_rules"`
	RestrictionRules       int `json:"restriction_rules"`
	ListenerCoverage       int `json:"listener_coverage"`
	CoveragePresent        int `json:"coverage_present"`
	CoverageAbsent         int `json:"coverage_absent"`
	CoverageAmbiguous      int `json:"coverage_ambiguous"`
	CoverageUnavailable    int `json:"coverage_unavailable"`
}

type Inventory struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Providers        []ProviderStatus       `json:"providers"`
	Policies         []Policy               `json:"policies"`
	Restrictions     []RestrictionRule      `json:"restriction_rules,omitempty"`
	ListenerCoverage []ListenerCoverage     `json:"listener_coverage,omitempty"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at}
	collectPlatform(ctx, &inv)
	inv.Policies = normalizePolicies(inv.Policies)
	inv.Restrictions = normalizeRestrictions(inv.Restrictions)
	inv.Providers = normalizeProviders(inv.Providers, inv.Policies)
	observedProviders := 0
	for _, p := range inv.Providers {
		if p.State == evidence.StateObserved {
			observedProviders++
		}
	}
	if observedProviders == 0 && (inv.Platform == "linux" || inv.Platform == "windows" || inv.Platform == "darwin") {
		inv.Degraded = append(inv.Degraded, "no supported local firewall provider was observable; host firewall posture cannot be confirmed")
	}
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Providers, inv.Policies, inv.Restrictions, inv.ListenerCoverage)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected firewall collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("firewall inventory identity is incomplete")
	}
	if len(inv.Policies) > maxPolicies {
		return fmt.Errorf("firewall policy inventory exceeds maximum record count")
	}
	if len(inv.Restrictions) > maxRestrictions {
		return fmt.Errorf("firewall restriction inventory exceeds maximum record count")
	}
	seenProviders := map[string]struct{}{}
	last := ""
	for i, p := range inv.Providers {
		if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Source) == "" || !validProviderState(p.State) || !validEnabled(p.Enabled) {
			return fmt.Errorf("firewall provider %d is incomplete", i)
		}
		if p.State != evidence.StateObserved && p.State != evidence.StateNotApplicable && strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("firewall provider %q requires a degradation reason", p.ID)
		}
		if _, ok := seenProviders[p.ID]; ok {
			return fmt.Errorf("duplicate firewall provider id %q", p.ID)
		}
		seenProviders[p.ID] = struct{}{}
		if last != "" && p.ID < last {
			return fmt.Errorf("firewall providers are not deterministically ordered")
		}
		last = p.ID
	}
	seenPolicies := map[string]struct{}{}
	last = ""
	for i, p := range inv.Policies {
		if p.ID == "" || p.Provider == "" || p.Scope == "" || !validEnabled(p.Enabled) || p.Source == "" || p.Confidence == "" {
			return fmt.Errorf("firewall policy %d is incomplete", i)
		}
		if _, ok := seenProviders[p.Provider]; !ok {
			return fmt.Errorf("firewall policy %q references unknown provider %q", p.ID, p.Provider)
		}
		if _, ok := seenPolicies[p.ID]; ok {
			return fmt.Errorf("duplicate firewall policy id %q", p.ID)
		}
		seenPolicies[p.ID] = struct{}{}
		k := policySortKey(p)
		if last != "" && k < last {
			return fmt.Errorf("firewall policies are not deterministically ordered")
		}
		last = k
		prev := ""
		for _, a := range p.Attributes {
			if strings.TrimSpace(a.Name) == "" {
				return fmt.Errorf("firewall policy %q has empty attribute name", p.ID)
			}
			if prev != "" && a.Name < prev {
				return fmt.Errorf("firewall policy %q attributes are not ordered", p.ID)
			}
			prev = a.Name
		}
	}
	seenRestrictions := map[string]struct{}{}
	last = ""
	for i, r := range inv.Restrictions {
		if r.ID == "" || r.Provider == "" || r.Direction == "" || r.Action == "" || r.Protocol == "" || r.Enabled == "" || r.Source == "" || r.Confidence == "" {
			return fmt.Errorf("firewall restriction %d is incomplete", i)
		}
		if _, ok := seenProviders[r.Provider]; !ok {
			return fmt.Errorf("firewall restriction %q references unknown provider %q", r.ID, r.Provider)
		}
		if _, ok := seenRestrictions[r.ID]; ok {
			return fmt.Errorf("duplicate firewall restriction id %q", r.ID)
		}
		seenRestrictions[r.ID] = struct{}{}
		k := r.Provider + "\x00" + fmt.Sprintf("%08d", r.Order) + "\x00" + r.ID
		if last != "" && k < last {
			return fmt.Errorf("firewall restrictions are not deterministically ordered")
		}
		last = k
	}
	seenCoverage := map[string]struct{}{}
	last = ""
	for i, c := range inv.ListenerCoverage {
		if c.ID == "" || c.EndpointID == "" || c.Protocol == "" || c.LocalAddress == "" || c.LocalPort == 0 || c.BindingClass == "" || c.State == "" || c.Basis == "" || c.Source == "" || c.Confidence == "" {
			return fmt.Errorf("firewall listener coverage %d is incomplete", i)
		}
		switch c.State {
		case CoveragePresent, CoverageAbsent, CoverageAmbiguous, CoverageUnavailable, CoverageNotApplicable:
		default:
			return fmt.Errorf("firewall listener coverage %q has invalid state %q", c.ID, c.State)
		}
		if _, ok := seenCoverage[c.ID]; ok {
			return fmt.Errorf("duplicate firewall listener coverage id %q", c.ID)
		}
		seenCoverage[c.ID] = struct{}{}
		if last != "" && c.EndpointID < last {
			return fmt.Errorf("firewall listener coverage is not deterministically ordered")
		}
		last = c.EndpointID
	}
	if inv.Summary != summarize(inv.Providers, inv.Policies, inv.Restrictions, inv.ListenerCoverage) {
		return fmt.Errorf("firewall summary does not match records")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func addProvider(inv *Inventory, p ProviderStatus) {
	p.ID = slug(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Source = strings.TrimSpace(p.Source)
	p.Reason = strings.TrimSpace(p.Reason)
	p.Enabled = normalizeEnabled(p.Enabled)
	if p.State == "" {
		p.State = evidence.StateUnavailable
	}
	if p.Source == "" {
		p.Source = "local firewall provider"
	}
	inv.Providers = append(inv.Providers, p)
	switch p.State {
	case evidence.StateDenied, evidence.StateUnavailable, evidence.StateDegraded, evidence.StateUnsupported:
		if p.Reason != "" {
			inv.Degraded = append(inv.Degraded, p.ID+": "+p.Reason)
		}
	}
}

func addPolicy(inv *Inventory, p Policy) {
	p.Provider = slug(p.Provider)
	p.Scope = strings.TrimSpace(p.Scope)
	p.Enabled = normalizeEnabled(p.Enabled)
	p.DefaultInbound = normalizeAction(p.DefaultInbound)
	p.DefaultOutbound = normalizeAction(p.DefaultOutbound)
	p.DefaultForward = normalizeAction(p.DefaultForward)
	p.Logging = strings.TrimSpace(p.Logging)
	p.Source = strings.TrimSpace(p.Source)
	if p.Confidence == "" {
		p.Confidence = evidence.ConfidenceHigh
	}
	if p.Source == "" {
		p.Source = "local firewall provider"
	}
	p.Attributes = normalizeAttributes(p.Attributes)
	p.ID = stablePolicyID(p)
	inv.Policies = append(inv.Policies, p)
}

func normalizeProviders(in []ProviderStatus, policies []Policy) []ProviderStatus {
	out := append([]ProviderStatus(nil), in...)
	by := map[string][]Policy{}
	for _, p := range policies {
		by[p.Provider] = append(by[p.Provider], p)
	}
	for i := range out {
		out[i].PolicyCount = len(by[out[i].ID])
		if out[i].RuleCount < 0 {
			out[i].RuleCount = 0
		}
		out[i].Enabled = normalizeEnabled(out[i].Enabled)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func normalizePolicies(in []Policy) []Policy {
	out := make([]Policy, 0, len(in))
	seen := map[string]struct{}{}
	for _, p := range in {
		p.Provider = slug(p.Provider)
		p.Scope = strings.TrimSpace(p.Scope)
		p.Enabled = normalizeEnabled(p.Enabled)
		p.DefaultInbound = normalizeAction(p.DefaultInbound)
		p.DefaultOutbound = normalizeAction(p.DefaultOutbound)
		p.DefaultForward = normalizeAction(p.DefaultForward)
		p.Attributes = normalizeAttributes(p.Attributes)
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceHigh
		}
		p.ID = stablePolicyID(p)
		if _, ok := seen[p.ID]; ok {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return policySortKey(out[i]) < policySortKey(out[j]) })
	if len(out) > maxPolicies {
		out = out[:maxPolicies]
	}
	return out
}
func normalizeAttributes(in []Attribute) []Attribute {
	out := make([]Attribute, 0, len(in))
	seen := map[string]struct{}{}
	for _, a := range in {
		a.Name = slug(a.Name)
		a.Value = strings.TrimSpace(a.Value)
		if a.Name == "" || a.Value == "" {
			continue
		}
		key := a.Name + "\x00" + a.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Value < out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	return out
}
func stablePolicyID(p Policy) string {
	basis := strings.Join([]string{p.Provider, p.Scope, p.DefaultInbound, p.DefaultOutbound, p.DefaultForward}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return "fw-" + hex.EncodeToString(sum[:10])
}
func policySortKey(p Policy) string {
	return p.Provider + "\x00" + strings.ToLower(p.Scope) + "\x00" + p.ID
}
func summarize(providers []ProviderStatus, policies []Policy, restrictions []RestrictionRule, coverage []ListenerCoverage) Summary {
	s := Summary{Providers: len(providers), Policies: len(policies), RestrictionRules: len(restrictions), ListenerCoverage: len(coverage)}
	for _, p := range providers {
		switch p.State {
		case evidence.StateObserved:
			s.ObservedProviders++
		case evidence.StateDenied:
			s.DeniedProviders++
		case evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateDegraded:
			s.UnavailableProviders++
		case evidence.StateNotApplicable:
			s.NotApplicableProviders++
		}
		switch p.Enabled {
		case "ENABLED":
			s.EnabledProviders++
		case "DISABLED":
			s.DisabledProviders++
		case "MIXED":
			s.MixedProviders++
		}
		if p.RuleCountKnown {
			s.KnownRules += p.RuleCount
		}
	}
	for _, c := range coverage {
		switch c.State {
		case CoveragePresent:
			s.CoveragePresent++
		case CoverageAbsent:
			s.CoverageAbsent++
		case CoverageAmbiguous:
			s.CoverageAmbiguous++
		case CoverageUnavailable:
			s.CoverageUnavailable++
		}
	}
	return s
}
func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{evidence.NewObserved("firewall.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact), evidence.NewObserved("firewall.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact)}
	for _, p := range inv.Providers {
		key := "firewall.provider." + p.ID
		if p.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, p, p.Source, at, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState(key, p.State, p.Source, at, evidence.ConfidenceLow, fallback(p.Reason, "firewall provider state unavailable")))
		}
	}
	for _, p := range inv.Policies {
		out = append(out, evidence.NewObserved("firewall.policy."+p.ID, p, p.Source, at, p.Confidence))
	}
	for _, r := range inv.Restrictions {
		out = append(out, evidence.NewObserved("firewall.restriction."+r.ID, r, r.Source, at, r.Confidence))
	}
	for _, c := range inv.ListenerCoverage {
		out = append(out, evidence.NewObserved("firewall.listener_coverage."+c.EndpointID, c, c.Source, at, c.Confidence))
	}
	if inv.Summary.ObservedProviders == 0 {
		out = append(out, evidence.NewState("firewall.provider.available", evidence.StateUnavailable, "platform firewall provider set", at, evidence.ConfidenceLow, "no supported local firewall provider was observable; host firewall posture cannot be confirmed"))
	}
	return out
}
func validProviderState(s evidence.State) bool {
	switch s {
	case evidence.StateObserved, evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateNotApplicable:
		return true
	}
	return false
}
func validEnabled(v string) bool {
	switch normalizeEnabled(v) {
	case "ENABLED", "DISABLED", "MIXED", "UNKNOWN", "NOT_APPLICABLE":
		return true
	}
	return false
}
func normalizeEnabled(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "TRUE", "YES", "ON", "ACTIVE", "RUNNING", "1":
		return "ENABLED"
	case "FALSE", "NO", "OFF", "INACTIVE", "NOT RUNNING", "0":
		return "DISABLED"
	case "ENABLED", "DISABLED", "MIXED", "UNKNOWN", "NOT_APPLICABLE":
		return v
	default:
		return "UNKNOWN"
	}
}
func normalizeAction(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "ALLOW", "ACCEPT", "BLOCK", "DENY", "DROP", "REJECT", "NOT_CONFIGURED", "NOTCONFIGURED", "UNKNOWN", "DISABLED":
		if v == "NOTCONFIGURED" {
			return "NOT_CONFIGURED"
		}
		return v
	case "":
		return ""
	}
	return strings.ReplaceAll(v, " ", "_")
}
func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func fallback(v, f string) string {
	if strings.TrimSpace(v) == "" {
		return f
	}
	return strings.TrimSpace(v)
}
func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	dash := false
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
func attrs(kv ...string) []Attribute {
	out := []Attribute{}
	for i := 0; i+1 < len(kv); i += 2 {
		if strings.TrimSpace(kv[i+1]) != "" {
			out = append(out, Attribute{Name: kv[i], Value: kv[i+1]})
		}
	}
	return out
}
func boolString(v bool) string { return strconv.FormatBool(v) }

package prioritization

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/vulnerability"
)

const (
	SchemaVersion = "chimera.risk-prioritization/v1"
	EngineVersion = "risk-priority/post117-fix04-v1"
)

type Band string

const (
	BandNone     Band = "NONE"
	BandLow      Band = "LOW"
	BandMedium   Band = "MEDIUM"
	BandHigh     Band = "HIGH"
	BandCritical Band = "CRITICAL"
)

type Factor struct {
	Name    string   `json:"name"`
	Points  int      `json:"points"`
	Reason  string   `json:"reason"`
	Sources []string `json:"sources,omitempty"`
}

type FindingPriority struct {
	FindingID      string              `json:"finding_id"`
	RuleID         string              `json:"rule_id"`
	Severity       assessment.Severity `json:"severity"`
	Status         assessment.Status   `json:"status"`
	Score          int                 `json:"score"`
	Band           Band                `json:"band"`
	Rank           int                 `json:"rank"`
	Actionable     bool                `json:"actionable"`
	Suppressed     bool                `json:"suppressed"`
	FactorCount    int                 `json:"factor_count"`
	Factors        []Factor            `json:"factors"`
	PriorityReason string              `json:"priority_reason"`
}

type VulnerabilityPriority struct {
	CorrelationID   string   `json:"correlation_id"`
	VulnerabilityID string   `json:"vulnerability_id"`
	CandidateRef    string   `json:"candidate_ref"`
	Score           int      `json:"score"`
	Band            Band     `json:"band"`
	Rank            int      `json:"rank"`
	Factors         []Factor `json:"factors"`
	PriorityReason  string   `json:"priority_reason"`
}

type Summary struct {
	Findings                int `json:"findings"`
	ActionableFindings      int `json:"actionable_findings"`
	SuppressedFindings      int `json:"suppressed_findings"`
	CriticalFindings        int `json:"critical_findings"`
	HighFindings            int `json:"high_findings"`
	MediumFindings          int `json:"medium_findings"`
	LowFindings             int `json:"low_findings"`
	UnprioritizedFindings   int `json:"unprioritized_findings"`
	Vulnerabilities         int `json:"vulnerabilities"`
	CriticalVulnerabilities int `json:"critical_vulnerabilities"`
	HighVulnerabilities     int `json:"high_vulnerabilities"`
}

type Result struct {
	Schema          string                  `json:"schema"`
	EngineVersion   string                  `json:"engine_version"`
	ScoringModel    string                  `json:"scoring_model"`
	Summary         Summary                 `json:"summary"`
	Findings        []FindingPriority       `json:"findings"`
	Vulnerabilities []VulnerabilityPriority `json:"vulnerabilities"`
}

// Compute applies a deterministic, additive, bounded priority model to normalized
// findings and affected vulnerability reachability contexts. Raw severity is
// preserved as an independent input and is never rewritten by the priority score.
func Compute(findings []assessment.Finding, reach *vulnerability.ReachabilityResult) Result {
	out := Result{
		Schema:          SchemaVersion,
		EngineVersion:   EngineVersion,
		ScoringModel:    "bounded additive score 0-100 over severity, status, confidence, exploitability context, runtime presence, privilege, non-loopback network exposure, listener-to-firewall control weakness, and other control weakness; raw severity remains independent",
		Findings:        make([]FindingPriority, 0, len(findings)),
		Vulnerabilities: []VulnerabilityPriority{},
	}
	for _, f := range findings {
		p := prioritizeFinding(f)
		out.Findings = append(out.Findings, p)
		out.Summary.Findings++
		if p.Actionable {
			out.Summary.ActionableFindings++
		}
		if p.Suppressed {
			out.Summary.SuppressedFindings++
		}
		switch p.Band {
		case BandCritical:
			out.Summary.CriticalFindings++
		case BandHigh:
			out.Summary.HighFindings++
		case BandMedium:
			out.Summary.MediumFindings++
		case BandLow:
			out.Summary.LowFindings++
		case BandNone:
			out.Summary.UnprioritizedFindings++
		}
	}
	sortFindingPriorities(out.Findings)
	assignFindingRanks(out.Findings)

	if reach != nil {
		coverage := vulnerabilityFirewallCoverage(findings)
		for _, c := range reach.Contexts {
			p := prioritizeVulnerability(c, coverage)
			out.Vulnerabilities = append(out.Vulnerabilities, p)
			out.Summary.Vulnerabilities++
			switch p.Band {
			case BandCritical:
				out.Summary.CriticalVulnerabilities++
			case BandHigh:
				out.Summary.HighVulnerabilities++
			}
		}
		sortVulnerabilityPriorities(out.Vulnerabilities)
		for i := range out.Vulnerabilities {
			out.Vulnerabilities[i].Rank = i + 1
		}
	}
	return out
}

func prioritizeFinding(f assessment.Finding) FindingPriority {
	p := FindingPriority{
		FindingID:  f.ID,
		RuleID:     f.RuleID,
		Severity:   f.Severity,
		Status:     f.Status,
		Suppressed: f.Suppression == assessment.SuppressionSuppressed,
		Factors:    []Factor{},
	}
	if f.Applicability == assessment.NotApplicable || f.Status == assessment.StatusPass {
		p.Band = BandNone
		p.PriorityReason = "finding is not an active adverse state"
		return p
	}

	p.Actionable = f.Suppression != assessment.SuppressionSuppressed
	p.Factors = append(p.Factors, Factor{Name: "severity", Points: severityPoints(f.Severity), Reason: "raw finding severity contributes the base risk weight"})
	if pts := statusPoints(f.Status); pts > 0 {
		p.Factors = append(p.Factors, Factor{Name: "status", Points: pts, Reason: "confirmed FAIL/WARN state increases remediation priority"})
	}
	if pts := confidencePoints(f.Confidence); pts > 0 {
		p.Factors = append(p.Factors, Factor{Name: "confidence", Points: pts, Reason: "stronger evidence confidence increases certainty of the priority", Sources: evidenceSources(f.Evidence)})
	}

	keys := evidenceKeys(f.Evidence)
	if pts, sources := exploitabilityContext(f, keys); pts > 0 {
		p.Factors = append(p.Factors, Factor{Name: "exploitability_context", Points: pts, Reason: "the rule represents a vulnerability or compound weakness with a defensible path to material host impact", Sources: sources})
	}
	if sources := matchingSources(keys, runtimeKey); len(sources) > 0 {
		p.Factors = append(p.Factors, Factor{Name: "runtime_presence", Points: 8, Reason: "the affected component is represented by live process, service, scheduled, persistence, or container evidence", Sources: sources})
	}
	if privilegeContext(f, keys) {
		p.Factors = append(p.Factors, Factor{Name: "privilege_context", Points: 10, Reason: "the affected boundary carries elevated/root/SYSTEM/admin-equivalent execution context", Sources: matchingSources(keys, privilegeKey)})
	}
	if networkContext(f, keys) {
		p.Factors = append(p.Factors, Factor{Name: "network_exposure", Points: 12, Reason: "the affected boundary is tied to listener, remote-management, or external-bind evidence", Sources: matchingSources(keys, networkKey)})
	}
	if sources := matchingSources(keys, controlWeaknessKey); len(sources) > 0 {
		p.Factors = append(p.Factors, Factor{Name: "control_weakness", Points: 5, Reason: "the finding includes an observed security-control or trust-boundary weakness", Sources: sources})
	}

	for _, factor := range p.Factors {
		p.Score += factor.Points
	}
	if p.Score > 100 {
		p.Score = 100
	}
	p.Band = bandForScore(p.Score)
	p.FactorCount = len(p.Factors)
	p.PriorityReason = priorityReason(p.Score, p.Band, p.Factors, p.Suppressed)
	return p
}

func prioritizeVulnerability(c vulnerability.ReachabilityContext, coverage map[string]firewall.ListenerCoverage) VulnerabilityPriority {
	p := VulnerabilityPriority{
		CorrelationID:   c.CorrelationID,
		VulnerabilityID: c.VulnerabilityID,
		CandidateRef:    c.CandidateRef,
		Factors:         []Factor{{Name: "exploitability_context", Points: 35, Reason: "local version intelligence classifies this installed candidate as affected"}},
	}
	if c.Running == vulnerability.ContextPresent {
		p.Factors = append(p.Factors, Factor{Name: "runtime_presence", Points: 12, Reason: "the affected component is currently running"})
	}
	if c.ServiceBacked == vulnerability.ContextPresent {
		p.Factors = append(p.Factors, Factor{Name: "service_backing", Points: 7, Reason: "the affected component is associated with a live service"})
	}
	if external, sources := externalVulnerabilityListeners(c.Listeners); external {
		p.Factors = append(p.Factors, Factor{Name: "network_exposure", Points: 20, Reason: "the affected component owns or maps to a non-loopback listening endpoint", Sources: sources})
		state, fwSources := vulnerabilityFirewallState(c.Listeners, coverage)
		switch state {
		case firewall.CoverageAbsent:
			p.Factors = append(p.Factors, Factor{Name: "firewall_control_weakness", Points: 10, Reason: "a non-loopback listener for the affected component lacks a defensible local firewall restriction", Sources: fwSources})
		case firewall.CoverageAmbiguous, firewall.CoverageUnavailable:
			p.Factors = append(p.Factors, Factor{Name: "firewall_context_uncertainty", Points: 0, Reason: "local firewall coverage for a non-loopback affected listener is ambiguous or unavailable; no positive priority points are invented", Sources: fwSources})
		}
	} else if c.Listening == vulnerability.ContextPresent {
		p.Factors = append(p.Factors, Factor{Name: "local_listener_presence", Points: 0, Reason: "the affected component is listening only on loopback; listener presence is retained but is not scored as non-loopback network exposure", Sources: listenerSources(c.Listeners)})
	}
	if c.Privileged == vulnerability.ContextPresent {
		p.Factors = append(p.Factors, Factor{Name: "privilege_context", Points: 16, Reason: "the affected component executes with elevated authority"})
	}
	if strings.EqualFold(c.Tier, "UNKNOWN") {
		p.Factors = append(p.Factors, Factor{Name: "context_uncertainty", Points: 0, Reason: "runtime reachability could not be fully resolved; no positive points are invented"})
	}
	for _, f := range p.Factors {
		p.Score += f.Points
	}
	if p.Score > 100 {
		p.Score = 100
	}
	p.Band = bandForScore(p.Score)
	p.PriorityReason = priorityReason(p.Score, p.Band, p.Factors, false)
	return p
}

func vulnerabilityFirewallCoverage(findings []assessment.Finding) map[string]firewall.ListenerCoverage {
	out := make(map[string]firewall.ListenerCoverage)
	for _, f := range findings {
		for _, ref := range f.Evidence {
			c, ok := ref.Value.(firewall.ListenerCoverage)
			if !ok {
				continue
			}
			key := listenerKey(c.Protocol, c.LocalAddress, int(c.LocalPort))
			if key == "" {
				continue
			}
			if current, exists := out[key]; !exists || firewallCoverageRank(c.State) > firewallCoverageRank(current.State) {
				out[key] = c
			}
		}
	}
	return out
}

func vulnerabilityFirewallState(listeners []vulnerability.ListenerContext, coverage map[string]firewall.ListenerCoverage) (string, []string) {
	state := ""
	sources := make([]string, 0)
	for _, l := range listeners {
		if isLoopbackExposure(l.Exposure) {
			continue
		}
		c, ok := coverage[listenerKey(l.Protocol, l.LocalAddress, l.Port)]
		if !ok {
			if firewallCoverageRank(firewall.CoverageUnavailable) > firewallCoverageRank(state) {
				state = firewall.CoverageUnavailable
			}
			sources = appendUniqueString(sources, listenerSource(l)+" firewall=UNAVAILABLE")
			continue
		}
		if firewallCoverageRank(c.State) > firewallCoverageRank(state) {
			state = c.State
		}
		sources = appendUniqueString(sources, listenerSource(l)+" firewall="+c.State)
	}
	sort.Strings(sources)
	return state, sources
}

func firewallCoverageRank(state string) int {
	switch state {
	case firewall.CoverageAbsent:
		return 4
	case firewall.CoverageAmbiguous:
		return 3
	case firewall.CoverageUnavailable:
		return 2
	case firewall.CoveragePresent:
		return 1
	default:
		return 0
	}
}

func externalVulnerabilityListeners(listeners []vulnerability.ListenerContext) (bool, []string) {
	sources := make([]string, 0)
	for _, l := range listeners {
		if isLoopbackExposure(l.Exposure) {
			continue
		}
		exposure := strings.ToUpper(strings.TrimSpace(l.Exposure))
		if exposure != "ALL_INTERFACES" && exposure != "INTERFACE_BOUND" {
			continue
		}
		sources = appendUniqueString(sources, listenerSource(l))
	}
	sort.Strings(sources)
	return len(sources) > 0, sources
}

func listenerSources(listeners []vulnerability.ListenerContext) []string {
	out := make([]string, 0, len(listeners))
	for _, l := range listeners {
		out = appendUniqueString(out, listenerSource(l))
	}
	sort.Strings(out)
	return out
}

func listenerSource(l vulnerability.ListenerContext) string {
	return fmt.Sprintf("%s %s:%d (%s)", strings.ToUpper(strings.TrimSpace(l.Protocol)), strings.TrimSpace(l.LocalAddress), l.Port, strings.ToUpper(strings.TrimSpace(l.Exposure)))
}

func listenerKey(protocol, address string, port int) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	address = strings.Trim(strings.TrimSpace(strings.ToLower(address)), "[]")
	if protocol == "" || address == "" || port <= 0 || port > 65535 {
		return ""
	}
	return fmt.Sprintf("%s|%s|%d", protocol, address, port)
}

func isLoopbackExposure(exposure string) bool {
	return strings.EqualFold(strings.TrimSpace(exposure), "LOOPBACK")
}

func appendUniqueString(dst []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return dst
	}
	for _, existing := range dst {
		if existing == value {
			return dst
		}
	}
	return append(dst, value)
}

func severityPoints(s assessment.Severity) int {
	switch s {
	case assessment.SeverityCritical:
		return 60
	case assessment.SeverityHigh:
		return 45
	case assessment.SeverityMedium:
		return 30
	case assessment.SeverityLow:
		return 15
	case assessment.SeverityInfo:
		return 5
	default:
		return 0
	}
}

func statusPoints(s assessment.Status) int {
	switch s {
	case assessment.StatusFail:
		return 10
	case assessment.StatusWarn:
		return 5
	default:
		return 0
	}
}

func confidencePoints(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceExact:
		return 8
	case evidence.ConfidenceHigh:
		return 6
	case evidence.ConfidenceMedium:
		return 3
	default:
		return 0
	}
}

func bandForScore(score int) Band {
	switch {
	case score >= 80:
		return BandCritical
	case score >= 60:
		return BandHigh
	case score >= 40:
		return BandMedium
	case score > 0:
		return BandLow
	default:
		return BandNone
	}
}

func priorityReason(score int, band Band, factors []Factor, suppressed bool) string {
	names := make([]string, 0, len(factors))
	for _, f := range factors {
		if f.Points > 0 {
			names = append(names, f.Name)
		}
	}
	suffix := ""
	if suppressed {
		suffix = "; finding is suppressed and excluded from actionable rank"
	}
	return fmt.Sprintf("score %d (%s) from %s%s", score, band, strings.Join(names, ", "), suffix)
}

func evidenceKeys(refs []assessment.EvidenceRef) []string {
	keys := make([]string, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		key := strings.TrimSpace(ref.Key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func evidenceSources(refs []assessment.EvidenceRef) []string {
	sources := make([]string, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		s := strings.TrimSpace(ref.Source)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		sources = append(sources, s)
	}
	sort.Strings(sources)
	return sources
}

func matchingSources(keys []string, match func(string) bool) []string {
	out := make([]string, 0)
	for _, key := range keys {
		if match(strings.ToLower(key)) {
			out = append(out, key)
		}
	}
	return out
}

func runtimeKey(k string) bool {
	return strings.HasPrefix(k, "process.item.") || strings.HasPrefix(k, "service.item.") || strings.HasPrefix(k, "scheduled.item.") || strings.HasPrefix(k, "persistence.item.") || strings.HasPrefix(k, "container.item.")
}

func privilegeKey(k string) bool {
	return strings.Contains(k, "privilege") || strings.Contains(k, ".privileged") || strings.Contains(k, "account.item.")
}

func networkKey(k string) bool {
	return strings.HasPrefix(k, "network.endpoint.") || strings.HasPrefix(k, "remote_management.") || strings.Contains(k, "listener") || strings.Contains(k, "external_bind") || strings.Contains(k, "firewall.correlation")
}

func controlWeaknessKey(k string) bool {
	return strings.Contains(k, "permission") || strings.Contains(k, "path_integrity") || strings.Contains(k, "firewall") || strings.Contains(k, "hardening") || strings.Contains(k, "encryption") || strings.Contains(k, "isolation") || strings.Contains(k, "trust") || strings.Contains(k, "passwordless") || strings.Contains(k, "writable")
}

func privilegeContext(f assessment.Finding, keys []string) bool {
	for _, key := range keys {
		if privilegeKey(strings.ToLower(key)) {
			return true
		}
	}
	obj := strings.ToLower(f.AffectedObject)
	return containsAny(obj, "privileged", "elevated", "root", "admin", "system") || f.RuleID == "CHM-COR-001" || f.RuleID == "CHM-COR-002" || f.RuleID == "CHM-COR-003" || f.RuleID == "CHM-PER-003"
}

func networkContext(f assessment.Finding, keys []string) bool {
	for _, key := range keys {
		if networkKey(strings.ToLower(key)) {
			return true
		}
	}
	obj := strings.ToLower(f.AffectedObject)
	return containsAny(obj, "external", "listener", "exposure", "remote", "network") || strings.EqualFold(f.Category, "network") || strings.EqualFold(f.Category, "correlation")
}

func exploitabilityContext(f assessment.Finding, keys []string) (int, []string) {
	known := map[string]int{
		"CHM-KRN-021": 10,
		"CHM-COR-001": 10,
		"CHM-COR-002": 10,
		"CHM-NET-004": 8,
		"CHM-NET-005": 8,
		"CHM-NET-006": 8,
		"CHM-NET-007": 8,
		"CHM-NET-008": 8,
		"CHM-NET-009": 8,
		"CHM-NET-010": 8,
		"CHM-NET-011": 8,
		"CHM-NET-012": 8,
		"CHM-NET-013": 8,
		"CHM-NET-014": 8,
		"CHM-NET-015": 8,
	}
	pts := known[f.RuleID]
	if pts == 0 {
		return 0, nil
	}
	return pts, keys
}

func containsAny(v string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(v, term) {
			return true
		}
	}
	return false
}

func sortFindingPriorities(items []FindingPriority) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Actionable != items[j].Actionable {
			return items[i].Actionable
		}
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if items[i].Severity != items[j].Severity {
			return severityPoints(items[i].Severity) > severityPoints(items[j].Severity)
		}
		if items[i].RuleID != items[j].RuleID {
			return items[i].RuleID < items[j].RuleID
		}
		return items[i].FindingID < items[j].FindingID
	})
}

func assignFindingRanks(items []FindingPriority) {
	rank := 0
	for i := range items {
		if !items[i].Actionable || items[i].Score == 0 {
			items[i].Rank = 0
			continue
		}
		rank++
		items[i].Rank = rank
	}
}

func sortVulnerabilityPriorities(items []VulnerabilityPriority) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if items[i].VulnerabilityID != items[j].VulnerabilityID {
			return items[i].VulnerabilityID < items[j].VulnerabilityID
		}
		return items[i].CorrelationID < items[j].CorrelationID
	})
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion || r.EngineVersion != EngineVersion {
		return fmt.Errorf("unexpected prioritization contract %q / %q", r.Schema, r.EngineVersion)
	}
	if r.Findings == nil || r.Vulnerabilities == nil {
		return fmt.Errorf("prioritization collections must be non-nil")
	}
	if r.Summary.Findings != len(r.Findings) || r.Summary.Vulnerabilities != len(r.Vulnerabilities) {
		return fmt.Errorf("prioritization summary counts are inconsistent")
	}
	lastRank := 0
	for i, p := range r.Findings {
		if p.FindingID == "" || p.RuleID == "" || p.Score < 0 || p.Score > 100 || p.Band != bandForScore(p.Score) {
			return fmt.Errorf("invalid finding priority at index %d", i)
		}
		if p.Actionable && p.Score > 0 {
			if p.Rank <= lastRank {
				return fmt.Errorf("finding priority ranks are not strictly increasing")
			}
			lastRank = p.Rank
		} else if p.Rank != 0 {
			return fmt.Errorf("non-actionable finding priority %q has rank %d", p.FindingID, p.Rank)
		}
	}
	for i, p := range r.Vulnerabilities {
		if p.CorrelationID == "" || p.VulnerabilityID == "" || p.Score < 0 || p.Score > 100 || p.Band != bandForScore(p.Score) || p.Rank != i+1 {
			return fmt.Errorf("invalid vulnerability priority at index %d", i)
		}
	}
	return nil
}

// ValidateEngineContract exercises the fixed weights and ordering on
// synthetic normalized findings. It performs no host collection.
func ValidateEngineContract() error {
	base := assessment.Finding{
		ID: "CHM-F-PRIORITY-CHECK", RuleID: "CHM-COR-001", Title: "priority contract check",
		Status: assessment.StatusFail, Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh,
		Category: "correlation", Platform: "test", AffectedObject: "correlation.service.privileged_writable_external",
		ObservedState: "weak", ExpectedState: "hardened", Risk: "risk", Remediation: "fix",
		CollectionSource: "priority-contract", Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
	out := Compute([]assessment.Finding{base}, nil)
	if len(out.Findings) != 1 {
		return fmt.Errorf("priority contract produced %d finding records", len(out.Findings))
	}
	p := out.Findings[0]
	if p.Score <= severityPoints(base.Severity) || p.Severity != base.Severity || p.Rank != 1 || !p.Actionable {
		return fmt.Errorf("priority contract did not preserve severity and deterministic ranking: %#v", p)
	}
	return out.Validate()
}

package cisalign

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
)

const (
	SchemaVersion  = "chimera.cis-inspired-mapping/v1"
	CatalogVersion = "chimera.control-map/cis-inspired-v1-phase109"
)

const Disclaimer = "Chimera's CIS-inspired mapping is a benchmark-neutral alignment to selected security control concepts. It is not a CIS Benchmark assessment, CIS Controls Implementation Group assessment, CIS-CAT result, certification, endorsement, or assertion of compliance with any official CIS safeguard identifier."

type Framework struct {
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	OfficialBenchmark  bool   `json:"official_benchmark"`
	CertificationClaim bool   `json:"certification_claim"`
	Scope              string `json:"scope"`
}

type Concept struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Intent string `json:"intent"`
}

type Mapping struct {
	RuleID    string   `json:"rule_id"`
	ConceptID string   `json:"concept_id"`
	Rationale string   `json:"rationale"`
	Platforms []string `json:"platforms,omitempty"`
}

type State string

const (
	StatePass          State = "PASS"
	StateWarn          State = "WARN"
	StateFail          State = "FAIL"
	StateUnknown       State = "UNKNOWN"
	StateNotApplicable State = "NOT_APPLICABLE"
	StateNotEvaluated  State = "NOT_EVALUATED"
)

type Counts struct {
	Mapped        int `json:"mapped"`
	Evaluated     int `json:"evaluated"`
	Pass          int `json:"pass"`
	Warn          int `json:"warn"`
	Fail          int `json:"fail"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"not_applicable"`
	NotEvaluated  int `json:"not_evaluated"`
}

type RuleResult struct {
	RuleID    string `json:"rule_id"`
	ConceptID string `json:"concept_id"`
	Rationale string `json:"rationale"`
	Evaluated bool   `json:"evaluated"`
	State     State  `json:"state"`
	FindingID string `json:"finding_id,omitempty"`
}

type ConceptResult struct {
	Concept       Concept      `json:"concept"`
	State         State        `json:"state"`
	Coverage      string       `json:"coverage"`
	Counts        Counts       `json:"counts"`
	MappedRuleIDs []string     `json:"mapped_rule_ids"`
	Rules         []RuleResult `json:"rules"`
}

type Summary struct {
	ImplementedRules int `json:"implemented_rules"`
	MappedRules      int `json:"mapped_rules"`
	UnmappedRules    int `json:"unmapped_rules"`
	EvaluatedRules   int `json:"evaluated_rules"`
	MappedEvaluated  int `json:"mapped_evaluated_rules"`
	Concepts         int `json:"concepts"`
	FullConcepts     int `json:"full_concepts"`
	PartialConcepts  int `json:"partial_concepts"`
	Unevaluated      int `json:"unevaluated_concepts"`
}

type Result struct {
	Schema         string          `json:"schema"`
	CatalogVersion string          `json:"catalog_version"`
	Framework      Framework       `json:"framework"`
	Disclaimer     string          `json:"disclaimer"`
	Summary        Summary         `json:"summary"`
	Concepts       []ConceptResult `json:"concepts"`
}

type conceptSpec struct {
	Concept Concept
	Rules   []string
}

func FrameworkMetadata() Framework {
	return Framework{
		Name:               "CIS-inspired security control concept alignment",
		Kind:               "benchmark-neutral concept crosswalk",
		OfficialBenchmark:  false,
		CertificationClaim: false,
		Scope:              "selected Chimera checks mapped to high-level hardening concepts; official benchmark numbering and certification semantics are intentionally excluded",
	}
}

func Concepts() []Concept {
	specs := specs()
	out := make([]Concept, 0, len(specs))
	for _, spec := range specs {
		out = append(out, spec.Concept)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func Mappings() []Mapping {
	specs := specs()
	out := make([]Mapping, 0, 230)
	for _, spec := range specs {
		for _, ruleID := range spec.Rules {
			out = append(out, Mapping{
				RuleID: ruleID, ConceptID: spec.Concept.ID,
				Rationale: "This Chimera rule directly evaluates the local-host posture represented by the " + spec.Concept.Title + " concept.",
				Platforms: mappingPlatforms(ruleID),
			})
		}
	}
	sortMappings(out)
	return out
}

// MappingsForPlatform returns the canonical control crosswalk projected onto
// one supported runtime catalog. A nil Platforms field on a mapping means the
// rule is shared across all supported operating systems.
func MappingsForPlatform(platform string) []Mapping {
	out := make([]Mapping, 0, 230)
	for _, m := range Mappings() {
		if mappingAppliesToPlatform(m, platform) {
			out = append(out, m)
		}
	}
	sortMappings(out)
	return out
}

func sortMappings(mappings []Mapping) {
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].RuleID == mappings[j].RuleID {
			return mappings[i].ConceptID < mappings[j].ConceptID
		}
		return mappings[i].RuleID < mappings[j].RuleID
	})
}

func mappingPlatforms(ruleID string) []string {
	switch {
	case strings.HasPrefix(ruleID, "CHM-KRN-LNX-"):
		return []string{"linux"}
	case strings.HasPrefix(ruleID, "CHM-KRN-WIN-"):
		return []string{"windows"}
	case strings.HasPrefix(ruleID, "CHM-KRN-MAC-"):
		return []string{"darwin"}
	default:
		return nil
	}
}

func mappingAppliesToPlatform(m Mapping, platform string) bool {
	if len(m.Platforms) == 0 {
		return supportedPlatform(platform)
	}
	for _, candidate := range m.Platforms {
		if candidate == platform {
			return true
		}
	}
	return false
}

func supportedPlatform(platform string) bool {
	switch platform {
	case "linux", "windows", "darwin":
		return true
	default:
		return false
	}
}

var unmappedAllowed = map[string]bool{
	"CHM-CORE-001": true,
	"CHM-CORE-002": true,
	"CHM-CORE-003": true,
	"CHM-CORE-004": true,
	"CHM-CORE-005": true,
}

// ValidateCanonicalCatalog proves that every mapping references a real stable
// rule in the union of supported v1 platform catalogs, that platform-specific
// mapping metadata is coherent, and that only the observability-only core
// rules remain outside the CIS-inspired control layer.
func ValidateCanonicalCatalog() error {
	conceptByID, concepts, err := validateConcepts()
	if err != nil {
		return err
	}

	union := make(map[string]assessment.Rule)
	for _, platform := range []string{"linux", "windows", "darwin"} {
		for _, r := range assessment.ImplementedRulesForPlatform(platform) {
			if err := r.Validate(); err != nil {
				return fmt.Errorf("invalid %s implemented rule %s: %w", platform, r.ID, err)
			}
			if previous, exists := union[r.ID]; exists {
				if ruleMetadataSignature(previous) != ruleMetadataSignature(r) {
					return fmt.Errorf("stable rule %s has divergent metadata across platform catalogs", r.ID)
				}
				continue
			}
			union[r.ID] = r
		}
	}

	mapped := make(map[string]string, len(union))
	conceptCounts := make(map[string]int, len(concepts))
	for _, m := range Mappings() {
		if _, ok := conceptByID[m.ConceptID]; !ok {
			return fmt.Errorf("mapping for %s references unknown concept %s", m.RuleID, m.ConceptID)
		}
		if _, ok := union[m.RuleID]; !ok {
			return fmt.Errorf("mapping references non-existent canonical rule %s", m.RuleID)
		}
		if previous, exists := mapped[m.RuleID]; exists {
			return fmt.Errorf("rule %s is multiply mapped to %s and %s", m.RuleID, previous, m.ConceptID)
		}
		if strings.TrimSpace(m.Rationale) == "" {
			return fmt.Errorf("mapping for %s lacks rationale", m.RuleID)
		}
		wantPlatforms := mappingPlatforms(m.RuleID)
		if !equalStrings(m.Platforms, wantPlatforms) {
			return fmt.Errorf("mapping for %s platforms=%v want %v", m.RuleID, m.Platforms, wantPlatforms)
		}
		mapped[m.RuleID] = m.ConceptID
		conceptCounts[m.ConceptID]++
	}
	for _, c := range concepts {
		if conceptCounts[c.ID] == 0 {
			return fmt.Errorf("concept %s has no mapped Chimera rules", c.ID)
		}
	}
	for ruleID := range union {
		_, isMapped := mapped[ruleID]
		if isMapped {
			if unmappedAllowed[ruleID] {
				return fmt.Errorf("observability-only core rule %s must remain outside CIS-inspired control mapping", ruleID)
			}
			continue
		}
		if !unmappedAllowed[ruleID] {
			return fmt.Errorf("canonical security rule %s has no CIS-inspired control-concept mapping", ruleID)
		}
	}
	return nil
}

// ValidateCatalog validates the current runtime projection of the canonical
// v1 crosswalk.
func ValidateCatalog(rules []assessment.Rule) error {
	return ValidateCatalogForPlatform(runtime.GOOS, rules)
}

// ValidateCatalogForPlatform validates only mappings applicable to platform,
// so a Windows catalog is never required to contain Linux-only kernel IDs (and
// vice versa). Canonical validation still catches typos/orphans across all
// supported platform manifests.
func ValidateCatalogForPlatform(platform string, rules []assessment.Rule) error {
	if !supportedPlatform(platform) {
		return fmt.Errorf("unsupported CIS-inspired mapping platform %q", platform)
	}
	if err := ValidateCanonicalCatalog(); err != nil {
		return fmt.Errorf("canonical mapping: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("CIS-inspired mapping requires an implemented rule catalog")
	}
	conceptByID, concepts, err := validateConcepts()
	if err != nil {
		return err
	}

	implemented := make(map[string]assessment.Rule, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid implemented rule %s: %w", r.ID, err)
		}
		if _, exists := implemented[r.ID]; exists {
			return fmt.Errorf("duplicate implemented rule ID %q", r.ID)
		}
		implemented[r.ID] = r
	}

	mapped := make(map[string]string, len(rules))
	conceptCounts := make(map[string]int, len(concepts))
	for _, m := range MappingsForPlatform(platform) {
		if _, ok := conceptByID[m.ConceptID]; !ok {
			return fmt.Errorf("mapping for %s references unknown concept %s", m.RuleID, m.ConceptID)
		}
		if _, ok := implemented[m.RuleID]; !ok {
			return fmt.Errorf("%s mapping references non-existent runtime rule %s", platform, m.RuleID)
		}
		if previous, exists := mapped[m.RuleID]; exists {
			return fmt.Errorf("rule %s is multiply mapped to %s and %s", m.RuleID, previous, m.ConceptID)
		}
		mapped[m.RuleID] = m.ConceptID
		conceptCounts[m.ConceptID]++
	}
	for _, c := range concepts {
		if conceptCounts[c.ID] == 0 {
			return fmt.Errorf("%s concept %s has no mapped Chimera rules", platform, c.ID)
		}
	}
	for ruleID := range implemented {
		_, isMapped := mapped[ruleID]
		if isMapped {
			if unmappedAllowed[ruleID] {
				return fmt.Errorf("observability-only core rule %s must remain outside CIS-inspired control mapping", ruleID)
			}
			continue
		}
		if !unmappedAllowed[ruleID] {
			return fmt.Errorf("%s implemented security rule %s has no CIS-inspired control-concept mapping", platform, ruleID)
		}
	}
	return nil
}

func validateConcepts() (map[string]Concept, []Concept, error) {
	concepts := Concepts()
	if len(concepts) == 0 {
		return nil, nil, fmt.Errorf("CIS-inspired mapping requires at least one concept")
	}
	conceptByID := make(map[string]Concept, len(concepts))
	for _, c := range concepts {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Intent) == "" {
			return nil, nil, fmt.Errorf("invalid empty CIS-inspired concept metadata: %#v", c)
		}
		if _, exists := conceptByID[c.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate CIS-inspired concept ID %q", c.ID)
		}
		conceptByID[c.ID] = c
	}
	return conceptByID, concepts, nil
}

func ruleMetadataSignature(r assessment.Rule) string {
	refs := make([]string, 0, len(r.References))
	for _, ref := range r.References {
		refs = append(refs, ref.Title+"|"+ref.URL)
	}
	sort.Strings(refs)
	return strings.Join([]string{
		r.ID, r.Title, r.Category, string(r.Severity), r.AffectedObject,
		r.ExpectedState, r.Risk, r.Remediation, strings.Join(refs, ","),
	}, "\x1f")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Evaluate(findings []assessment.Finding, implemented []assessment.Rule) (Result, error) {
	return EvaluateForPlatform(runtime.GOOS, findings, implemented)
}

func EvaluateForPlatform(platform string, findings []assessment.Finding, implemented []assessment.Rule) (Result, error) {
	if err := ValidateCatalogForPlatform(platform, implemented); err != nil {
		return Result{}, err
	}

	findingByRule := make(map[string]assessment.Finding, len(findings))
	for _, f := range findings {
		if strings.TrimSpace(f.RuleID) == "" {
			return Result{}, fmt.Errorf("CIS-inspired mapping received finding with empty rule ID")
		}
		if _, exists := findingByRule[f.RuleID]; exists {
			return Result{}, fmt.Errorf("multiple findings received for rule %s", f.RuleID)
		}
		findingByRule[f.RuleID] = f
	}

	mappingByConcept := make(map[string][]Mapping)
	mappedRuleIDs := make(map[string]struct{})
	for _, m := range MappingsForPlatform(platform) {
		mappingByConcept[m.ConceptID] = append(mappingByConcept[m.ConceptID], m)
		mappedRuleIDs[m.RuleID] = struct{}{}
	}

	concepts := Concepts()
	results := make([]ConceptResult, 0, len(concepts))
	summary := Summary{
		ImplementedRules: len(implemented),
		MappedRules:      len(mappedRuleIDs),
		UnmappedRules:    len(implemented) - len(mappedRuleIDs),
		EvaluatedRules:   len(findings),
		Concepts:         len(concepts),
	}
	for _, concept := range concepts {
		mappings := append([]Mapping(nil), mappingByConcept[concept.ID]...)
		sort.Slice(mappings, func(i, j int) bool { return mappings[i].RuleID < mappings[j].RuleID })
		cr := ConceptResult{Concept: concept, MappedRuleIDs: make([]string, 0, len(mappings)), Rules: make([]RuleResult, 0, len(mappings))}
		for _, m := range mappings {
			cr.MappedRuleIDs = append(cr.MappedRuleIDs, m.RuleID)
			rr := RuleResult{RuleID: m.RuleID, ConceptID: m.ConceptID, Rationale: m.Rationale, State: StateNotEvaluated}
			cr.Counts.Mapped++
			if f, ok := findingByRule[m.RuleID]; ok {
				rr.Evaluated = true
				rr.FindingID = f.ID
				rr.State = stateForFinding(f)
				cr.Counts.Evaluated++
				summary.MappedEvaluated++
				addState(&cr.Counts, rr.State)
			} else {
				cr.Counts.NotEvaluated++
			}
			cr.Rules = append(cr.Rules, rr)
		}
		cr.State = stateForCounts(cr.Counts)
		switch {
		case cr.Counts.Evaluated == cr.Counts.Mapped:
			cr.Coverage = "FULL"
			summary.FullConcepts++
		case cr.Counts.Evaluated == 0:
			cr.Coverage = "NONE"
			summary.Unevaluated++
		default:
			cr.Coverage = "PARTIAL"
			summary.PartialConcepts++
		}
		results = append(results, cr)
	}

	return Result{
		Schema: SchemaVersion, CatalogVersion: CatalogVersion,
		Framework: FrameworkMetadata(), Disclaimer: Disclaimer,
		Summary: summary, Concepts: results,
	}, nil
}

func stateForFinding(f assessment.Finding) State {
	if f.Applicability == assessment.NotApplicable {
		return StateNotApplicable
	}
	switch f.Status {
	case assessment.StatusPass:
		return StatePass
	case assessment.StatusWarn:
		return StateWarn
	case assessment.StatusFail:
		return StateFail
	case assessment.StatusUnknown:
		return StateUnknown
	default:
		return StateUnknown
	}
}

func addState(c *Counts, state State) {
	switch state {
	case StatePass:
		c.Pass++
	case StateWarn:
		c.Warn++
	case StateFail:
		c.Fail++
	case StateUnknown:
		c.Unknown++
	case StateNotApplicable:
		c.NotApplicable++
	}
}

func stateForCounts(c Counts) State {
	if c.Fail > 0 {
		return StateFail
	}
	if c.Warn > 0 {
		return StateWarn
	}
	if c.Unknown > 0 {
		return StateUnknown
	}
	if c.Pass > 0 {
		return StatePass
	}
	if c.NotApplicable > 0 && c.Evaluated > 0 {
		return StateNotApplicable
	}
	return StateNotEvaluated
}

func specs() []conceptSpec {
	return []conceptSpec{
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-01", Title: "Secure platform configuration", Intent: "Harden boot, kernel, code-integrity, memory-mitigation, debug, privilege-bearing kernel features, driver trust, and mandatory-access-control posture."},
			Rules:   joinIDs([]string{"CHM-KRN-001", "CHM-KRN-020", "CHM-KRN-021"}, rangeIDs("CHM-KRN-LNX-", 1, 11), rangeIDs("CHM-KRN-WIN-", 1, 8), rangeIDs("CHM-KRN-MAC-", 1, 5)),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-02", Title: "Vulnerability intelligence and patch awareness", Intent: "Maintain defensible local vulnerability intelligence and freshness so version-based findings can be evaluated with explicit provenance."},
			Rules:   []string{"CHM-INTEL-001", "CHM-INTEL-002"},
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-03", Title: "Privileged account and local access governance", Intent: "Constrain privileged membership, risky local account state, UAC/local security policy, and delegated local authority."},
			Rules:   append(rangeIDs("CHM-ID-", 1, 4), rangeIDs("CHM-ID-", 7, 15)...),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-04", Title: "Authentication and credential protection", Intent: "Harden password requirements, credential-protection controls, sudo/PAM policy, and local authentication boundaries without retrieving credentials."},
			Rules:   joinIDs(rangeIDs("CHM-ID-", 5, 6), rangeIDs("CHM-ID-", 16, 31), rangeIDs("CHM-ID-", 33, 38)),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-05", Title: "Network exposure minimization", Intent: "Constrain externally bound, sensitive, administrative, debugging, development, and legacy cleartext-capable service exposure."},
			Rules:   rangeIDs("CHM-NET-", 1, 15),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-06", Title: "Host firewall boundary enforcement", Intent: "Keep host firewall protection enabled with restrictive defaults and scoped inbound exceptions aligned to observed listeners."},
			Rules:   rangeIDs("CHM-FW-", 1, 8),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-07", Title: "Remote administration hardening", Intent: "Constrain SSH, RDP, WinRM, screen-sharing, and related remote-management exposure and local SSH security policy."},
			Rules:   rangeIDs("CHM-NET-", 16, 24),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-08", Title: "File-sharing and network-share hardening", Intent: "Disable legacy SMB behavior and constrain signing, encryption, guest access, exported shares, NFS scope, and dangerous network-mount options."},
			Rules:   append(rangeIDs("CHM-NET-", 25, 29), rangeIDs("CHM-FS-", 17, 20)...),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-09", Title: "Filesystem permission and execution-boundary integrity", Intent: "Protect executables, privileged search paths, sensitive files, ACLs, temporary directories, and mount hardening boundaries from lower-privilege modification or unsafe execution."},
			Rules:   rangeIDs("CHM-FS-", 1, 16),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-10", Title: "Data-at-rest protection", Intent: "Protect system/data volumes, swap, hibernation state, and FileVault-backed system data with observable at-rest encryption controls."},
			Rules:   append([]string{"CHM-ID-032"}, rangeIDs("CHM-STG-", 1, 4)...),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-11", Title: "Process trust and runtime hardening", Intent: "Protect live executable trust, path permissions, runtime privilege, executable memory, loaded modules, isolation, and dangerous environment-hook boundaries."},
			Rules:   rangeIDs("CHM-PRC-", 1, 23),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-12", Title: "Service and scheduled-execution hardening", Intent: "Protect service and scheduled-execution identities, paths, ACLs, privilege boundaries, hardening controls, and legacy remote-capable service configuration."},
			Rules:   append(rangeIDs("CHM-SVC-", 1, 29), rangeIDs("CHM-SCH-", 1, 5)...),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-13", Title: "Container and orchestration isolation", Intent: "Constrain container privilege, namespace sharing, capabilities, host mounts, confinement, runtime sockets/APIs, and local orchestration credentials/exposure."},
			Rules:   rangeIDs("CHM-CTR-", 1, 22),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-14", Title: "Developer interface exposure control", Intent: "Keep local debug and developer interfaces consistent with host role and prevent accidental network reachability."},
			Rules:   rangeIDs("CHM-CTR-", 23, 25),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-15", Title: "Persistence integrity", Intent: "Protect startup, login, service, and scheduled persistence paths and definitions from lower-privilege modification, especially when execution is privileged."},
			Rules:   rangeIDs("CHM-PER-", 1, 5),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-16", Title: "Secret and key material protection", Intent: "Protect likely secret-bearing files, private keys, cloud/developer credential files, SSH trust paths, and privileged authorized-key integrity without exposing secret values."},
			Rules:   append(rangeIDs("CHM-SEC-", 1, 7), rangeIDs("CHM-ID-", 39, 43)...),
		},
		{
			Concept: Concept{ID: "CHM-CIS-CONCEPT-17", Title: "Cross-domain exposure correlation", Intent: "Prioritize materially higher-risk conditions where privilege, writable execution boundaries, service/process identity, and external reachability intersect."},
			Rules:   rangeIDs("CHM-COR-", 1, 3),
		},
	}
}

func rangeIDs(prefix string, first, last int) []string {
	out := make([]string, 0, last-first+1)
	for i := first; i <= last; i++ {
		out = append(out, fmt.Sprintf("%s%03d", prefix, i))
	}
	return out
}

func joinIDs(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

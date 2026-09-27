package productnorm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/intelligence"
	"github.com/Nikolov999/chimera/internal/software"
)

const (
	SchemaVersion = "chimera.product-normalization/v1"
	EngineVersion = "productnorm/v1"
)

type State string

const (
	StateMatched   State = "MATCHED"
	StateUnmatched State = "UNMATCHED"
	StateAmbiguous State = "AMBIGUOUS"
)

type Candidate struct {
	Ref           string              `json:"ref"`
	Kind          string              `json:"kind"`
	Product       string              `json:"product"`
	PackageID     string              `json:"package_id,omitempty"`
	Version       string              `json:"version"`
	Vendor        string              `json:"vendor,omitempty"`
	PackageSource string              `json:"package_source,omitempty"`
	Ecosystem     string              `json:"ecosystem"`
	Platform      string              `json:"platform"`
	CPEs          []string            `json:"cpes,omitempty"`
	PURLs         []string            `json:"purls,omitempty"`
	Confidence    evidence.Confidence `json:"confidence"`
}

type Match struct {
	ID                 string              `json:"id"`
	CandidateRef       string              `json:"candidate_ref"`
	CandidateKind      string              `json:"candidate_kind"`
	State              State               `json:"state"`
	ProductID          string              `json:"product_id,omitempty"`
	CanonicalVendor    string              `json:"canonical_vendor,omitempty"`
	CanonicalProduct   string              `json:"canonical_product,omitempty"`
	CanonicalCPEs      []string            `json:"canonical_cpes,omitempty"`
	CanonicalPURLs     []string            `json:"canonical_purls,omitempty"`
	MappingEcosystem   string              `json:"mapping_ecosystem,omitempty"`
	CandidateEcosystem string              `json:"candidate_ecosystem"`
	CandidatePlatform  string              `json:"candidate_platform"`
	Version            string              `json:"version"`
	VersionScheme      string              `json:"version_scheme"`
	VersionComparable  bool                `json:"version_comparable"`
	MatchMethod        string              `json:"match_method,omitempty"`
	MatchSignals       []string            `json:"match_signals,omitempty"`
	Confidence         evidence.Confidence `json:"confidence"`
	Alternatives       []string            `json:"alternatives,omitempty"`
	Reason             string              `json:"reason"`
}

type Summary struct {
	Candidates int `json:"candidates"`
	Matched    int `json:"matched"`
	Unmatched  int `json:"unmatched"`
	Ambiguous  int `json:"ambiguous"`
	Comparable int `json:"version_comparable"`
}

type Result struct {
	Schema              string    `json:"schema"`
	EngineVersion       string    `json:"engine_version"`
	State               string    `json:"state"`
	Reason              string    `json:"reason,omitempty"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	IntelligenceVersion string    `json:"intelligence_version"`
	IntelligenceDigest  string    `json:"intelligence_digest"`
	Summary             Summary   `json:"summary"`
	Matches             []Match   `json:"matches"`
}

// NormalizeInventory maps locally observed software identities to the pinned
// intelligence product catalog using exact normalized identities only. It does
// not infer a product from substring containment and does not evaluate CVEs.
func NormalizeInventory(inv software.Inventory, loaded intelligence.Loaded) Result {
	candidates := inventoryCandidates(inv)
	result := Result{
		Schema: SchemaVersion, EngineVersion: EngineVersion, State: "COMPLETE", EvaluatedAt: inv.CollectedAt.UTC(),
		IntelligenceVersion: loaded.Metadata.Version, IntelligenceDigest: loaded.Metadata.Digest,
		Matches: make([]Match, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		m := matchCandidate(candidate, loaded.Store.Products)
		result.Matches = append(result.Matches, m)
		result.Summary.Candidates++
		switch m.State {
		case StateMatched:
			result.Summary.Matched++
			if m.VersionComparable {
				result.Summary.Comparable++
			}
		case StateAmbiguous:
			result.Summary.Ambiguous++
		default:
			result.Summary.Unmatched++
		}
	}
	sort.Slice(result.Matches, func(i, j int) bool {
		if result.Matches[i].CandidateRef != result.Matches[j].CandidateRef {
			return result.Matches[i].CandidateRef < result.Matches[j].CandidateRef
		}
		return result.Matches[i].ID < result.Matches[j].ID
	})
	return result
}

// Unavailable records why normalization could not run without inventing product
// matches. It is used when the pinned intelligence store cannot be loaded.
func Unavailable(at time.Time, version, digest, reason string) Result {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if strings.TrimSpace(version) == "" {
		version = "unknown"
	}
	return Result{
		Schema: SchemaVersion, EngineVersion: EngineVersion, State: "UNAVAILABLE",
		Reason: strings.TrimSpace(reason), EvaluatedAt: at.UTC(),
		IntelligenceVersion: version, IntelligenceDigest: strings.TrimSpace(digest),
		Matches: []Match{},
	}
}

type scoredProduct struct {
	product intelligence.ProductMapping
	score   int
	method  string
	signals []string
}

func matchCandidate(c Candidate, products []intelligence.ProductMapping) Match {
	base := Match{
		CandidateRef: c.Ref, CandidateKind: c.Kind, CandidateEcosystem: c.Ecosystem, CandidatePlatform: normalizePlatform(c.Platform),
		Version: normalizedVersion(c.Version), VersionScheme: versionScheme(c.Ecosystem),
		Confidence: evidence.ConfidenceLow,
	}
	base.VersionComparable = IsComparable(c.Ecosystem, c.Version)
	scored := make([]scoredProduct, 0)
	for _, p := range products {
		score, method, signals := scoreProduct(c, p)
		if score <= 0 {
			continue
		}
		scored = append(scored, scoredProduct{product: p, score: score, method: method, signals: signals})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].product.ID < scored[j].product.ID
	})
	if len(scored) == 0 {
		base.State = StateUnmatched
		base.Reason = "no exact canonical, alias, CPE, PURL, or package identity matched the pinned product catalog"
		base.ID = stableMatchID(base)
		return base
	}
	top := scored[0].score
	alternatives := make([]string, 0)
	for _, s := range scored {
		if s.score != top {
			break
		}
		alternatives = append(alternatives, s.product.ID)
	}
	if len(alternatives) > 1 {
		base.State = StateAmbiguous
		base.Alternatives = alternatives
		base.Reason = "multiple catalog products matched with equal-strength exact identity evidence; no product was selected"
		base.ID = stableMatchID(base)
		return base
	}

	best := scored[0]
	base.State = StateMatched
	base.ProductID = best.product.ID
	base.CanonicalVendor = best.product.Vendor
	base.CanonicalProduct = best.product.Product
	base.CanonicalCPEs = canonicalIdentifiers(best.product.CPEs, normalizeCPE)
	base.CanonicalPURLs = canonicalIdentifiers(best.product.PURLs, normalizePURL)
	base.MappingEcosystem = best.product.Ecosystem
	base.MatchMethod = best.method
	base.MatchSignals = uniqueSorted(best.signals)
	base.Confidence = confidenceForScore(best.score, c.Confidence)
	if base.VersionComparable {
		base.Reason = "exact product identity resolved; observed version is supported by the ecosystem-aware comparison engine"
	} else {
		base.Reason = "exact product identity resolved; observed version is absent, unknown, or not safely comparable by the selected ecosystem comparator"
	}
	base.ID = stableMatchID(base)
	return base
}

func scoreProduct(c Candidate, p intelligence.ProductMapping) (int, string, []string) {
	if !ecosystemCompatible(c.Ecosystem, p.Ecosystem) {
		return 0, "", nil
	}
	candidateProduct := normalizeIdentity(c.Product)
	candidatePackage := normalizePackageIdentity(c.PackageID)
	candidateVendor := normalizeIdentity(c.Vendor)
	canonicalProduct := normalizeIdentity(p.Product)
	canonicalVendor := normalizeIdentity(p.Vendor)

	aliases := make(map[string]struct{}, len(p.Aliases)+1)
	aliases[canonicalProduct] = struct{}{}
	for _, alias := range p.Aliases {
		if n := normalizeIdentity(alias); n != "" {
			aliases[n] = struct{}{}
		}
	}

	score := 0
	method := ""
	signals := make([]string, 0, 4)
	set := func(v int, m, signal string) {
		if v > score {
			score, method = v, m
			signals = signals[:0]
		}
		if v == score && signal != "" {
			signals = append(signals, signal)
		}
	}

	for _, candidateCPE := range c.CPEs {
		cc := normalizeCPE(candidateCPE)
		if cc == "" {
			continue
		}
		for _, catalogCPE := range p.CPEs {
			if cc == normalizeCPE(catalogCPE) {
				set(110, "exact-cpe", "cpe="+cc)
			}
		}
	}
	for _, candidatePURL := range c.PURLs {
		cp := normalizePURL(candidatePURL)
		if cp == "" {
			continue
		}
		for _, catalogPURL := range p.PURLs {
			if cp == normalizePURL(catalogPURL) {
				set(110, "exact-purl", "purl="+cp)
			}
		}
	}

	if candidatePackage != "" {
		if _, ok := aliases[candidatePackage]; ok {
			set(100, "exact-package-alias", "package_id="+candidatePackage)
		}
		for _, purl := range p.PURLs {
			if packageFromPURL(purl) == candidatePackage {
				set(100, "exact-purl-package", "purl="+strings.TrimSpace(purl))
			}
		}
	}
	if candidateProduct != "" {
		if candidateProduct == canonicalProduct {
			set(95, "exact-canonical-product", "product="+candidateProduct)
		} else if _, ok := aliases[candidateProduct]; ok {
			set(90, "exact-product-alias", "product_alias="+candidateProduct)
		}
	}
	if candidateVendor != "" && canonicalVendor != "" && candidateVendor == canonicalVendor && candidateProduct == canonicalProduct {
		set(98, "exact-vendor-product", "vendor_product="+candidateVendor+"/"+candidateProduct)
	}
	return score, method, uniqueSorted(signals)
}

func inventoryCandidates(inv software.Inventory) []Candidate {
	out := make([]Candidate, 0, len(inv.Items)+len(inv.Runtimes)+len(inv.Infrastructure)+len(inv.Browsers)+len(inv.HighRiskClients)+len(inv.BinaryAttributions))
	for _, x := range inv.Items {
		c := Candidate{Ref: "software.item." + x.ID, Kind: "installed-software", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Vendor: x.Vendor, PackageSource: x.PackageSource, Ecosystem: inferEcosystem(x.PackageSource, x.PackageID, x.Kind), Platform: inv.Platform, Confidence: x.Confidence}
		c.CPEs, c.PURLs = identifiersFromPackageID(x.PackageID)
		out = append(out, c)
	}
	for _, x := range inv.Runtimes {
		out = append(out, Candidate{Ref: "software.runtime." + x.ID, Kind: "runtime", Product: x.Product, Version: x.Version, Ecosystem: runtimeEcosystem(x.Family), Platform: inv.Platform, Confidence: x.Confidence})
	}
	for _, x := range inv.Infrastructure {
		out = append(out, Candidate{Ref: "software.infrastructure." + x.ID, Kind: "infrastructure", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Ecosystem: inferEcosystemFromInventory(inv, x.PackageID), Platform: inv.Platform, Confidence: x.Confidence})
	}
	for _, x := range inv.Browsers {
		out = append(out, Candidate{Ref: "software.browser." + x.ID, Kind: "browser", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Ecosystem: inferEcosystemFromInventory(inv, x.PackageID), Platform: inv.Platform, Confidence: x.Confidence})
	}
	for _, x := range inv.HighRiskClients {
		out = append(out, Candidate{Ref: "software.client." + x.ID, Kind: "high-risk-client", Product: x.Product, PackageID: x.PackageID, Version: x.Version, Ecosystem: inferEcosystemFromInventory(inv, x.PackageID), Platform: inv.Platform, Confidence: x.Confidence})
	}
	for _, x := range inv.BinaryAttributions {
		if x.Ownership != software.OwnershipPackage && x.Ownership != software.OwnershipApplication {
			continue
		}
		c := Candidate{Ref: "software.attribution." + x.ID, Kind: "binary-attribution", Product: x.Product, PackageID: x.PackageID, Version: x.Version, PackageSource: x.PackageSource, Ecosystem: inferEcosystem(x.PackageSource, x.PackageID, "package"), Platform: inv.Platform, Confidence: x.Confidence}
		c.CPEs, c.PURLs = identifiersFromPackageID(x.PackageID)
		out = append(out, c)
	}
	// Deduplicate only exact candidate references. Cross-surface duplicates are
	// preserved because they carry different provenance and later reachability
	// context.
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func inferEcosystemFromInventory(inv software.Inventory, packageID string) string {
	key := normalizePackageIdentity(packageID)
	if key == "" {
		return "unknown"
	}
	for _, item := range inv.Items {
		if normalizePackageIdentity(item.PackageID) == key {
			return inferEcosystem(item.PackageSource, item.PackageID, item.Kind)
		}
	}
	return "unknown"
}

func inferEcosystem(source, packageID, kind string) string {
	s := strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.HasPrefix(s, "dpkg"):
		return "dpkg"
	case strings.HasPrefix(s, "rpm"):
		return "rpm"
	case strings.HasPrefix(s, "apk"):
		return "apk"
	case strings.HasPrefix(s, "pacman"):
		return "pacman"
	case strings.HasPrefix(s, "snap"):
		return "snap"
	case strings.HasPrefix(s, "flatpak"):
		return "flatpak"
	case strings.HasPrefix(s, "windows-appx"):
		return "appx"
	case strings.HasPrefix(s, "windows-uninstall"):
		return "windows"
	case strings.HasPrefix(s, "macos-application"):
		return "macos"
	}
	id := strings.ToLower(strings.TrimSpace(packageID))
	if strings.HasPrefix(id, "pkg:") {
		if i := strings.Index(strings.TrimPrefix(id, "pkg:"), "/"); i > 0 {
			return strings.TrimPrefix(id, "pkg:")[:i]
		}
	}
	if strings.EqualFold(strings.TrimSpace(kind), "package") {
		return "native-package"
	}
	return "unknown"
}

func runtimeEcosystem(family string) string {
	family = strings.ToLower(strings.TrimSpace(family))
	if family == "" {
		return "runtime"
	}
	return "runtime:" + family
}

func ecosystemCompatible(candidate, mapping string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	mapping = strings.ToLower(strings.TrimSpace(mapping))
	if candidate == "" || candidate == "unknown" || mapping == "" {
		return false
	}
	if candidate == mapping {
		return true
	}
	if mapping == "native-package" {
		switch candidate {
		case "native-package", "dpkg", "rpm", "apk", "pacman":
			return true
		}
	}
	// A generic runtime mapping may bind to a specific runtime family, but a
	// specific package ecosystem never crosses into another package manager.
	if mapping == "runtime" && strings.HasPrefix(candidate, "runtime:") {
		return true
	}
	return false
}

func normalizePlatform(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "macos", "osx":
		return "darwin"
	case "win", "win32", "win64":
		return "windows"
	case "windows", "linux", "darwin":
		return s
	default:
		return "unknown"
	}
}

func normalizeIdentity(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unknown" || s == "n/a" {
		return ""
	}
	var b strings.Builder
	lastSpace := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastSpace = false
		case r == ':' || r == '/' || r == '@' || r == '.' || r == '-' || r == '_' || unicode.IsSpace(r):
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
		default:
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
}

func normalizePackageIdentity(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unknown" || s == "n/a" {
		return ""
	}
	if strings.HasPrefix(s, "pkg:") {
		return normalizeIdentity(packageFromPURL(s))
	}
	// dpkg package IDs may carry an architecture suffix (name:amd64).
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], "/") {
		suffix := s[i+1:]
		switch suffix {
		case "amd64", "arm64", "i386", "386", "x86", "x86_64", "all", "armhf", "armel":
			s = s[:i]
		}
	}
	return normalizeIdentity(s)
}

func packageFromPURL(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(s), "pkg:") {
		return ""
	}
	s = strings.TrimPrefix(s, "pkg:")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return ""
	}
	// Preserve namespace + name for ecosystems where namespace is part of the
	// package identity (Maven, npm scopes, etc.).
	if len(parts) >= 3 {
		return strings.Join(parts[1:], ":")
	}
	return parts[len(parts)-1]
}

func identifiersFromPackageID(id string) ([]string, []string) {
	id = strings.TrimSpace(id)
	if normalizeCPE(id) != "" {
		return []string{id}, nil
	}
	if normalizePURL(id) != "" {
		return nil, []string{id}
	}
	return nil, nil
}

func normalizeCPE(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if !strings.HasPrefix(raw, "cpe:2.3:") || len(strings.Split(raw, ":")) != 13 {
		return ""
	}
	return raw
}

func normalizePURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "pkg:") {
		return ""
	}
	body := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	if i := strings.Index(body, "@"); i >= 0 {
		body = body[:i]
	}
	parts := strings.Split(body, "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[len(parts)-1]) == "" {
		return ""
	}
	return "pkg:" + strings.ToLower(strings.TrimSpace(body))
}

func canonicalIdentifiers(in []string, normalize func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if v := normalize(raw); v != "" {
			out = append(out, v)
		}
	}
	return uniqueSorted(out)
}

func normalizedVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func confidenceForScore(score int, observed evidence.Confidence) evidence.Confidence {
	switch {
	case score >= 100 && observed == evidence.ConfidenceExact:
		return evidence.ConfidenceExact
	case score >= 95:
		return evidence.ConfidenceHigh
	case score >= 90:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func stableMatchID(m Match) string {
	raw := strings.Join([]string{m.CandidateRef, string(m.State), m.ProductID, m.MatchMethod, strings.Join(m.Alternatives, ",")}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return "pn-" + hex.EncodeToString(sum[:8])
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion || r.EngineVersion != EngineVersion {
		return fmt.Errorf("unexpected product normalization contract %q / %q", r.Schema, r.EngineVersion)
	}
	if r.EvaluatedAt.IsZero() {
		return fmt.Errorf("normalization evaluation time is required")
	}
	switch r.State {
	case "COMPLETE":
		if strings.TrimSpace(r.IntelligenceVersion) == "" || len(strings.TrimSpace(r.IntelligenceDigest)) != 64 {
			return fmt.Errorf("normalization intelligence provenance is incomplete")
		}
	case "UNAVAILABLE":
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("unavailable normalization requires a reason")
		}
		if len(r.Matches) != 0 || r.Summary != (Summary{}) {
			return fmt.Errorf("unavailable normalization must not contain inferred matches")
		}
		return nil
	default:
		return fmt.Errorf("invalid normalization state %q", r.State)
	}
	if r.Summary.Candidates != len(r.Matches) || r.Summary.Matched+r.Summary.Unmatched+r.Summary.Ambiguous != r.Summary.Candidates {
		return fmt.Errorf("normalization summary counts are inconsistent")
	}
	comparable := 0
	seen := map[string]struct{}{}
	for i, m := range r.Matches {
		if m.ID == "" || m.CandidateRef == "" || m.CandidateKind == "" || m.State == "" || m.CandidateEcosystem == "" || m.CandidatePlatform == "" || m.VersionScheme == "" || m.Confidence == "" || m.Reason == "" {
			return fmt.Errorf("normalization match %d is incomplete", i)
		}
		if _, ok := seen[m.ID]; ok {
			return fmt.Errorf("duplicate normalization match id %q", m.ID)
		}
		seen[m.ID] = struct{}{}
		switch m.State {
		case StateMatched:
			if m.ProductID == "" || m.CanonicalProduct == "" || m.MappingEcosystem == "" || m.MatchMethod == "" || len(m.MatchSignals) == 0 {
				return fmt.Errorf("matched normalization record %q lacks identity evidence", m.ID)
			}
		case StateUnmatched:
			if m.ProductID != "" || len(m.Alternatives) != 0 {
				return fmt.Errorf("unmatched normalization record %q contains selected identities", m.ID)
			}
		case StateAmbiguous:
			if m.ProductID != "" || len(m.Alternatives) < 2 {
				return fmt.Errorf("ambiguous normalization record %q lacks alternatives", m.ID)
			}
		default:
			return fmt.Errorf("normalization record %q has invalid state %q", m.ID, m.State)
		}
		if m.State == StateMatched && m.VersionComparable {
			comparable++
		}
	}
	if comparable != r.Summary.Comparable {
		return fmt.Errorf("normalization comparable-version count is inconsistent")
	}
	return nil
}

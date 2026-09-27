package intelligence

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion  = "chimera.intelligence/v1"
	BuiltinVersion = "2026.08-post117-intel9"
	EnvDirectory   = "CHIMERA_INTELLIGENCE_DIR"
)

//go:embed seed.json
var seedFS embed.FS

type Source struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

type ProductMapping struct {
	ID        string   `json:"id"`
	Ecosystem string   `json:"ecosystem"`
	Vendor    string   `json:"vendor,omitempty"`
	Product   string   `json:"product"`
	Aliases   []string `json:"aliases,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	PURLs     []string `json:"purls,omitempty"`
}

type AffectedRange struct {
	Kind         string   `json:"kind"`
	Introduced   string   `json:"introduced,omitempty"`
	LastAffected string   `json:"last_affected,omitempty"`
	Fixed        string   `json:"fixed,omitempty"`
	Exact        []string `json:"exact,omitempty"`
	Constraint   string   `json:"constraint,omitempty"`
}

type AffectedProduct struct {
	ProductID     string          `json:"product_id"`
	VersionBasis  string          `json:"version_basis,omitempty"`
	Platforms     []string        `json:"platforms,omitempty"`
	Ranges        []AffectedRange `json:"ranges"`
	FixedVersions []string        `json:"fixed_versions,omitempty"`
}

type Reference struct {
	Type  string `json:"type"`
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

type Vulnerability struct {
	ID          string            `json:"id"`
	Aliases     []string          `json:"aliases,omitempty"`
	SourceID    string            `json:"source_id"`
	Summary     string            `json:"summary"`
	PublishedAt *time.Time        `json:"published_at,omitempty"`
	ModifiedAt  *time.Time        `json:"modified_at,omitempty"`
	Affected    []AffectedProduct `json:"affected"`
	References  []Reference       `json:"references"`
}

// LifecycleRecord is a pinned support-lifecycle fact for a specific, exact
// local identity and version series. It deliberately carries its own source
// and reference so an EOL/unsupported conclusion is independently auditable.
type LifecycleRecord struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	TargetKinds    []string  `json:"target_kinds"`
	Product        string    `json:"product"`
	Aliases        []string  `json:"aliases,omitempty"`
	NameContains   []string  `json:"name_contains,omitempty"`
	Family         string    `json:"family,omitempty"`
	VersionSeries  string    `json:"version_series"`
	EndOfSupport   time.Time `json:"end_of_support"`
	StatusAfterEnd string    `json:"status_after_end"`
	Reference      string    `json:"reference"`
}

type Store struct {
	Schema          string            `json:"schema"`
	Version         string            `json:"version"`
	RetrievedAt     time.Time         `json:"retrieved_at"`
	Sources         []Source          `json:"sources"`
	Products        []ProductMapping  `json:"products"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	Lifecycles      []LifecycleRecord `json:"lifecycles,omitempty"`
}

type Metadata struct {
	Schema             string    `json:"schema"`
	Version            string    `json:"version"`
	State              string    `json:"state"`
	Source             string    `json:"source"`
	Path               string    `json:"path,omitempty"`
	RetrievedAt        time.Time `json:"retrieved_at"`
	DigestAlgorithm    string    `json:"digest_algorithm"`
	Digest             string    `json:"digest"`
	SourceCount        int       `json:"source_count"`
	ProductCount       int       `json:"product_count"`
	VulnerabilityCount int       `json:"vulnerability_count"`
	LifecycleCount     int       `json:"lifecycle_count"`
}

type Loaded struct {
	Metadata Metadata `json:"metadata"`
	Store    Store    `json:"store"`
}

// Load opens the configured local store when CHIMERA_INTELLIGENCE_DIR is set;
// otherwise it loads the immutable intelligence seed embedded in this source
// build. It performs no network access and never modifies the store.
func Load() (Loaded, error) {
	dir := strings.TrimSpace(os.Getenv(EnvDirectory))
	if dir == "" {
		raw, err := seedFS.ReadFile("seed.json")
		if err != nil {
			return Loaded{}, fmt.Errorf("read embedded intelligence seed: %w", err)
		}
		return decode(raw, "embedded://internal/intelligence/seed.json", "PINNED_BUILTIN")
	}
	return loadConfiguredDirectory(dir)
}

func decode(raw []byte, source, state string) (Loaded, error) {
	var store Store
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store); err != nil {
		return Loaded{}, fmt.Errorf("decode intelligence store: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Loaded{}, errors.New("decode intelligence store: multiple JSON values are not allowed")
		}
		return Loaded{}, fmt.Errorf("decode intelligence store: trailing content: %w", err)
	}
	store.Normalize()
	if err := store.Validate(); err != nil {
		return Loaded{}, fmt.Errorf("validate intelligence store: %w", err)
	}
	canonical, err := json.Marshal(store)
	if err != nil {
		return Loaded{}, fmt.Errorf("canonicalize intelligence store: %w", err)
	}
	sum := sha256.Sum256(canonical)
	meta := Metadata{
		Schema: store.Schema, Version: store.Version, State: state, Source: source,
		RetrievedAt: store.RetrievedAt, DigestAlgorithm: "sha256", Digest: hex.EncodeToString(sum[:]),
		SourceCount: len(store.Sources), ProductCount: len(store.Products), VulnerabilityCount: len(store.Vulnerabilities), LifecycleCount: len(store.Lifecycles),
	}
	if state == "PINNED_LOCAL" {
		meta.Path = source
	}
	return Loaded{Metadata: meta, Store: store}, nil
}

func (s *Store) Normalize() {
	s.Schema = strings.TrimSpace(s.Schema)
	s.Version = strings.TrimSpace(s.Version)
	for i := range s.Sources {
		s.Sources[i].ID = strings.ToLower(strings.TrimSpace(s.Sources[i].ID))
		s.Sources[i].Name = strings.TrimSpace(s.Sources[i].Name)
		s.Sources[i].URL = strings.TrimSpace(s.Sources[i].URL)
	}
	sort.Slice(s.Sources, func(i, j int) bool { return s.Sources[i].ID < s.Sources[j].ID })

	for i := range s.Products {
		p := &s.Products[i]
		p.ID = strings.ToLower(strings.TrimSpace(p.ID))
		p.Ecosystem = strings.ToLower(strings.TrimSpace(p.Ecosystem))
		p.Vendor = strings.TrimSpace(p.Vendor)
		p.Product = strings.TrimSpace(p.Product)
		p.Aliases = normalizedStrings(p.Aliases)
		p.CPEs = normalizedStringsPreserveCase(p.CPEs)
		p.PURLs = normalizedStringsPreserveCase(p.PURLs)
	}
	sort.Slice(s.Products, func(i, j int) bool { return s.Products[i].ID < s.Products[j].ID })

	for i := range s.Vulnerabilities {
		v := &s.Vulnerabilities[i]
		v.ID = strings.ToUpper(strings.TrimSpace(v.ID))
		v.SourceID = strings.ToLower(strings.TrimSpace(v.SourceID))
		v.Summary = strings.TrimSpace(v.Summary)
		v.Aliases = normalizedStringsUpper(v.Aliases)
		for j := range v.Affected {
			a := &v.Affected[j]
			a.ProductID = strings.ToLower(strings.TrimSpace(a.ProductID))
			a.VersionBasis = strings.ToLower(strings.TrimSpace(a.VersionBasis))
			a.Platforms = normalizedPlatforms(a.Platforms)
			a.FixedVersions = normalizedStringsPreserveCase(a.FixedVersions)
			for k := range a.Ranges {
				r := &a.Ranges[k]
				r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
				r.Introduced = strings.TrimSpace(r.Introduced)
				r.LastAffected = strings.TrimSpace(r.LastAffected)
				r.Fixed = strings.TrimSpace(r.Fixed)
				r.Constraint = strings.TrimSpace(r.Constraint)
				r.Exact = normalizedStringsPreserveCase(r.Exact)
			}
		}
		sort.Slice(v.Affected, func(i, j int) bool { return v.Affected[i].ProductID < v.Affected[j].ProductID })
		for j := range v.References {
			v.References[j].Type = strings.ToLower(strings.TrimSpace(v.References[j].Type))
			v.References[j].Title = strings.TrimSpace(v.References[j].Title)
			v.References[j].URL = strings.TrimSpace(v.References[j].URL)
		}
		sort.Slice(v.References, func(i, j int) bool { return v.References[i].URL < v.References[j].URL })
	}
	sort.Slice(s.Vulnerabilities, func(i, j int) bool { return s.Vulnerabilities[i].ID < s.Vulnerabilities[j].ID })

	for i := range s.Lifecycles {
		r := &s.Lifecycles[i]
		r.ID = strings.ToLower(strings.TrimSpace(r.ID))
		r.SourceID = strings.ToLower(strings.TrimSpace(r.SourceID))
		r.TargetKinds = normalizedStrings(r.TargetKinds)
		r.Product = strings.TrimSpace(r.Product)
		r.Aliases = normalizedStringsPreserveCase(r.Aliases)
		r.NameContains = normalizedStringsPreserveCase(r.NameContains)
		r.Family = strings.ToLower(strings.TrimSpace(r.Family))
		r.VersionSeries = strings.TrimSpace(r.VersionSeries)
		r.StatusAfterEnd = strings.ToUpper(strings.TrimSpace(r.StatusAfterEnd))
		r.Reference = strings.TrimSpace(r.Reference)
	}
	sort.Slice(s.Lifecycles, func(i, j int) bool { return s.Lifecycles[i].ID < s.Lifecycles[j].ID })
}

func (s Store) Validate() error {
	if s.Schema != SchemaVersion {
		return fmt.Errorf("unexpected schema %q", s.Schema)
	}
	if strings.TrimSpace(s.Version) == "" {
		return errors.New("store version is required")
	}
	if s.RetrievedAt.IsZero() {
		return errors.New("store retrieval time is required")
	}
	if len(s.Sources) == 0 || len(s.Products) == 0 || len(s.Vulnerabilities) == 0 {
		return errors.New("sources, products, and vulnerabilities must be non-empty")
	}
	sources := make(map[string]struct{}, len(s.Sources))
	for i, src := range s.Sources {
		if src.ID == "" || src.Name == "" || src.URL == "" || src.RetrievedAt.IsZero() {
			return fmt.Errorf("source %d is incomplete", i)
		}
		if _, exists := sources[src.ID]; exists {
			return fmt.Errorf("duplicate source id %q", src.ID)
		}
		if err := validateHTTPURL(src.URL); err != nil {
			return fmt.Errorf("source %q: %w", src.ID, err)
		}
		sources[src.ID] = struct{}{}
	}
	products := make(map[string]struct{}, len(s.Products))
	for i, p := range s.Products {
		if p.ID == "" || p.Ecosystem == "" || p.Product == "" {
			return fmt.Errorf("product mapping %d is incomplete", i)
		}
		if _, exists := products[p.ID]; exists {
			return fmt.Errorf("duplicate product id %q", p.ID)
		}
		for j, cpe := range p.CPEs {
			if !validCPE23(cpe) {
				return fmt.Errorf("product %q cpe %d is not a canonical CPE 2.3 identifier", p.ID, j)
			}
		}
		for j, purl := range p.PURLs {
			if !validPURL(purl) {
				return fmt.Errorf("product %q purl %d is not a valid package URL identity", p.ID, j)
			}
		}
		products[p.ID] = struct{}{}
	}
	vulns := make(map[string]struct{}, len(s.Vulnerabilities))
	for i, v := range s.Vulnerabilities {
		if v.ID == "" || v.SourceID == "" || v.Summary == "" || len(v.Affected) == 0 || len(v.References) == 0 {
			return fmt.Errorf("vulnerability %d is incomplete", i)
		}
		if _, exists := vulns[v.ID]; exists {
			return fmt.Errorf("duplicate vulnerability id %q", v.ID)
		}
		vulns[v.ID] = struct{}{}
		if _, ok := sources[v.SourceID]; !ok {
			return fmt.Errorf("vulnerability %q references unknown source %q", v.ID, v.SourceID)
		}
		for j, a := range v.Affected {
			if _, ok := products[a.ProductID]; !ok {
				return fmt.Errorf("vulnerability %q affected product %d references unknown product %q", v.ID, j, a.ProductID)
			}
			switch a.VersionBasis {
			case "", "ecosystem", "upstream", "runtime":
			default:
				return fmt.Errorf("vulnerability %q product %q has unsupported version basis %q", v.ID, a.ProductID, a.VersionBasis)
			}
			for _, platform := range a.Platforms {
				switch platform {
				case "windows", "linux", "darwin":
				default:
					return fmt.Errorf("vulnerability %q product %q has unsupported affected platform %q", v.ID, a.ProductID, platform)
				}
			}
			if len(a.Ranges) == 0 {
				return fmt.Errorf("vulnerability %q product %q has no affected range", v.ID, a.ProductID)
			}
			for k, r := range a.Ranges {
				if r.Kind == "" {
					return fmt.Errorf("vulnerability %q product %q range %d has no kind", v.ID, a.ProductID, k)
				}
				if r.Introduced == "" && r.LastAffected == "" && r.Fixed == "" && r.Constraint == "" && len(r.Exact) == 0 {
					return fmt.Errorf("vulnerability %q product %q range %d has no bounds", v.ID, a.ProductID, k)
				}
			}
		}
		for _, ref := range v.References {
			if err := validateHTTPURL(ref.URL); err != nil {
				return fmt.Errorf("vulnerability %q reference: %w", v.ID, err)
			}
		}
	}
	lifecycles := make(map[string]struct{}, len(s.Lifecycles))
	for i, r := range s.Lifecycles {
		if r.ID == "" || r.SourceID == "" || len(r.TargetKinds) == 0 || r.Product == "" || r.VersionSeries == "" || r.EndOfSupport.IsZero() || r.Reference == "" {
			return fmt.Errorf("lifecycle record %d is incomplete", i)
		}
		if _, exists := lifecycles[r.ID]; exists {
			return fmt.Errorf("duplicate lifecycle id %q", r.ID)
		}
		lifecycles[r.ID] = struct{}{}
		if _, ok := sources[r.SourceID]; !ok {
			return fmt.Errorf("lifecycle %q references unknown source %q", r.ID, r.SourceID)
		}
		if r.StatusAfterEnd != "EOL" && r.StatusAfterEnd != "UNSUPPORTED" {
			return fmt.Errorf("lifecycle %q has invalid status_after_end %q", r.ID, r.StatusAfterEnd)
		}
		for _, kind := range r.TargetKinds {
			switch kind {
			case "os", "installed-software", "runtime", "browser":
			default:
				return fmt.Errorf("lifecycle %q has unsupported target kind %q", r.ID, kind)
			}
		}
		if err := validateHTTPURL(r.Reference); err != nil {
			return fmt.Errorf("lifecycle %q reference: %w", r.ID, err)
		}
	}
	return nil
}

func normalizedPlatforms(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.ToLower(strings.TrimSpace(value))
		switch v {
		case "macos", "osx":
			v = "darwin"
		case "win", "win32", "win64":
			v = "windows"
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return normalizedStrings(out)
}

func validCPE23(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "cpe:2.3:") {
		return false
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 13 {
		return false
	}
	switch strings.ToLower(parts[2]) {
	case "a", "o", "h", "*", "-":
		return strings.TrimSpace(parts[3]) != "" && strings.TrimSpace(parts[4]) != ""
	default:
		return false
	}
}

func validPURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "pkg:") {
		return false
	}
	body := raw[4:]
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	if i := strings.Index(body, "@"); i >= 0 {
		body = body[:i]
	}
	parts := strings.Split(body, "/")
	return len(parts) >= 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[len(parts)-1]) != ""
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid HTTP(S) URL %q", raw)
	}
	return nil
}

func normalizedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
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

func normalizedStringsUpper(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.ToUpper(strings.TrimSpace(v))
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

func normalizedStringsPreserveCase(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

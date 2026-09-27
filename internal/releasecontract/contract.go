package releasecontract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/baseline"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/exporter"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/report"
	"github.com/Nikolov999/chimera/internal/snapshot"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/version"
)

const (
	SchemaVersion   = "chimera.release-contract/v1"
	ContractVersion = "chimera.public-contract/v1"
	ReleaseVersion  = "1.0.0"
)

// PlatformManifest freezes the v1 rule projection for one supported operating
// system. Shared rules keep the same stable IDs and metadata; only explicitly
// platform-selected rule families differ between manifests.
type PlatformManifest struct {
	Platform      string `json:"platform"`
	RuleCount     int    `json:"rule_count"`
	CatalogDigest string `json:"catalog_digest"`
}

var v1PlatformManifests = map[string]PlatformManifest{
	"linux":   {Platform: "linux", RuleCount: 222, CatalogDigest: "5001db52b4f6cc21e4eba243d8fed64044e2858aa40f189a5432e368ae4d4560"},
	"windows": {Platform: "windows", RuleCount: 219, CatalogDigest: "14473dc690b0c621304fea52df6f4a5ba2b9e5039c518828608f73206606a936"},
	"darwin":  {Platform: "darwin", RuleCount: 216, CatalogDigest: "f3b778427964ae9feb9be199333f2fe282442a1523f3b35a2fafa9e845e35072"},
}

type CommandDescriptor struct {
	Name         string
	Lane         string
	Purpose      string
	Usage        string
	ExampleCount int
	Output       string
	Safety       string
	Requirements string
	NextSteps    string
}

type Contract struct {
	Schema           string            `json:"schema"`
	ContractVersion  string            `json:"contract_version"`
	ReleaseVersion   string            `json:"release_version"`
	Platform         string            `json:"platform"`
	RuleSetVersion   string            `json:"rule_set_version"`
	RuleCount        int               `json:"rule_count"`
	CatalogDigest    string            `json:"catalog_digest"`
	Profiles         []string          `json:"profiles"`
	RuleCategories   map[string]int    `json:"rule_categories"`
	Schemas          map[string]string `json:"schemas"`
	RequiredCommands []string          `json:"required_commands"`
}

var requiredCommands = []string{
	"accounts", "baseline", "config", "containers", "diff", "doctor", "evidence", "explain", "export", "exposure", "filesystem",
	"finding", "findings", "firewall", "hardening", "intelligence", "kernel", "misconfigurations", "network", "overview", "persistence",
	"processes", "profiles", "relationships", "remediation", "report", "rules", "scan", "scheduled", "secrets", "services", "software",
	"storage", "summary", "surface", "version", "vulnerabilities",
}

var requiredCategories = []string{
	"collection", "containers", "correlation", "filesystem", "firewall", "identity", "intelligence", "inventory", "kernel",
	"network", "persistence", "process", "scheduled", "secrets", "service", "storage",
}

var requiredProfiles = []string{"default", "developer", "high-security", "minimal", "server", "workstation"}

func RequiredCommands() []string {
	return append([]string(nil), requiredCommands...)
}

func Current() Contract {
	return CurrentForPlatform(runtime.GOOS)
}

func CurrentForPlatform(platform string) Contract {
	rules := assessment.ImplementedRulesForPlatform(platform)
	categories := make(map[string]int)
	for _, r := range rules {
		categories[r.Category]++
	}
	return Contract{
		Schema:           SchemaVersion,
		ContractVersion:  ContractVersion,
		ReleaseVersion:   ReleaseVersion,
		Platform:         platform,
		RuleSetVersion:   assessment.RuleSetVersion,
		RuleCount:        len(rules),
		CatalogDigest:    catalogDigest(rules),
		Profiles:         profile.Names(),
		RuleCategories:   categories,
		Schemas:          frozenSchemas(),
		RequiredCommands: RequiredCommands(),
	}
}

func PlatformManifestFor(platform string) (PlatformManifest, bool) {
	m, ok := v1PlatformManifests[platform]
	return m, ok
}

func SupportedPlatforms() []string {
	out := make([]string, 0, len(v1PlatformManifests))
	for platform := range v1PlatformManifests {
		out = append(out, platform)
	}
	sort.Strings(out)
	return out
}

func ValidateCore() error {
	return ValidateCoreForPlatform(runtime.GOOS)
}

func ValidateCoreForPlatform(platform string) error {
	expected, ok := PlatformManifestFor(platform)
	if !ok {
		return fmt.Errorf("no frozen v1 release manifest for platform %q", platform)
	}
	if version.Version != ReleaseVersion {
		return fmt.Errorf("release version=%q want %q", version.Version, ReleaseVersion)
	}
	if assessment.RuleSetVersion != "chimera.rules/v1" {
		return fmt.Errorf("rule-set version=%q want chimera.rules/v1", assessment.RuleSetVersion)
	}
	rules := assessment.ImplementedRulesForPlatform(platform)
	if len(rules) != expected.RuleCount {
		return fmt.Errorf("%s implemented rule count=%d want %d", platform, len(rules), expected.RuleCount)
	}
	seen := make(map[string]struct{}, len(rules))
	categories := make(map[string]int)
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %q invalid: %w", r.ID, err)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate stable rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		categories[r.Category]++
	}
	for _, category := range requiredCategories {
		if categories[category] == 0 {
			return fmt.Errorf("required v1 rule category %q has no implemented rules", category)
		}
	}
	if got := profile.Names(); !equalStrings(got, requiredProfiles) {
		return fmt.Errorf("built-in profile catalog=%v want %v", got, requiredProfiles)
	}
	if err := profile.ValidateEnterprisePolicyContract(rules); err != nil {
		return fmt.Errorf("enterprise profile semantics: %w", err)
	}
	for name, got := range frozenSchemas() {
		if strings.TrimSpace(got) == "" {
			return fmt.Errorf("frozen schema %q is empty", name)
		}
	}
	digest := catalogDigest(rules)
	if expected.CatalogDigest == "TO_BE_FILLED" {
		return fmt.Errorf("%s v1 catalog digest is not frozen", platform)
	}
	if digest != expected.CatalogDigest {
		return fmt.Errorf("%s v1 catalog digest=%s want %s", platform, digest, expected.CatalogDigest)
	}
	return nil
}

func ValidateCommandRegistry(commands []CommandDescriptor) error {
	if len(commands) != len(requiredCommands) {
		return fmt.Errorf("public command count=%d want %d", len(commands), len(requiredCommands))
	}
	seen := make(map[string]struct{}, len(commands))
	lanes := make(map[string]int)
	for _, c := range commands {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("public command has empty name")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate public command %q", name)
		}
		seen[name] = struct{}{}
		lanes[c.Lane]++
		if strings.TrimSpace(c.Purpose) == "" || strings.TrimSpace(c.Usage) == "" || c.ExampleCount == 0 || strings.TrimSpace(c.Output) == "" || strings.TrimSpace(c.Safety) == "" || strings.TrimSpace(c.Requirements) == "" || strings.TrimSpace(c.NextSteps) == "" {
			return fmt.Errorf("public command %q has an incomplete help contract", name)
		}
	}
	for _, name := range requiredCommands {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("required public command %q is missing", name)
		}
	}
	for _, lane := range []string{"Observe", "Assess", "Investigate", "Report", "Maintain"} {
		if lanes[lane] == 0 {
			return fmt.Errorf("workflow lane %q has no public commands", lane)
		}
	}
	return nil
}

func frozenSchemas() map[string]string {
	return map[string]string{
		"baseline":       baseline.SchemaVersion,
		"evidence":       evidence.SchemaVersion,
		"finding":        assessment.SchemaVersion,
		"profile":        profile.SchemaVersion,
		"prioritization": prioritization.SchemaVersion,
		"report":         report.SchemaVersion,
		"snapshot":       snapshot.SchemaVersion,
		"suppression":    suppression.SchemaVersion,
		"remediation":    remediation.SchemaVersion,
		"export_engine":  exporter.EngineVersion,
	}
}

func catalogDigest(rules []assessment.Rule) string {
	rows := make([]string, 0, len(rules)+32)
	for _, r := range rules {
		refs := make([]string, 0, len(r.References))
		for _, ref := range r.References {
			refs = append(refs, ref.Title+"|"+ref.URL)
		}
		sort.Strings(refs)
		rows = append(rows, strings.Join([]string{
			r.ID, r.Title, r.Category, string(r.Severity), r.AffectedObject,
			r.ExpectedState, r.Risk, r.Remediation, strings.Join(refs, ","),
		}, "\x1f"))
	}
	for _, p := range profile.Catalog() {
		rows = append(rows, strings.Join([]string{
			"profile", p.Name, p.BehaviorProfile, fmt.Sprint(p.DefaultApplicable), p.Description,
			strings.Join(p.EnabledCategories, ","), strings.Join(p.DisabledCategories, ","),
			severityMapString(p.SeverityFloors), severityMapString(p.SeverityOverrides),
		}, "\x1f"))
	}
	schemas := frozenSchemas()
	keys := make([]string, 0, len(schemas))
	for k := range schemas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rows = append(rows, "schema\x1f"+k+"\x1f"+schemas[k])
	}
	sort.Strings(rows)
	h := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(h[:])
}

func severityMapString(values map[string]assessment.Severity) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+string(values[key]))
	}
	return strings.Join(parts, ",")
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

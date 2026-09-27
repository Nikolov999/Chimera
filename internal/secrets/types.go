package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.secrets/v1"
	CollectorName    = "secret-storage"
	CollectorVersion = "secrets/phase103-v1"
	maxRecords       = 256
	maxCandidates    = 2048
)

type Record struct {
	ID                     string              `json:"id"`
	Kind                   string              `json:"kind"`
	Scope                  string              `json:"scope"`
	Path                   string              `json:"path"`
	State                  evidence.State      `json:"state"`
	Exists                 bool                `json:"exists"`
	Directory              bool                `json:"directory"`
	Symlink                bool                `json:"symlink"`
	SizeBytes              int64               `json:"size_bytes,omitempty"`
	ModifiedAt             time.Time           `json:"modified_at,omitempty"`
	PermissionState        string              `json:"permission_state"`
	PermissionModel        string              `json:"permission_model"`
	Mode                   string              `json:"mode,omitempty"`
	OwnerID                string              `json:"owner_id,omitempty"`
	GroupID                string              `json:"group_id,omitempty"`
	WorldReadable          string              `json:"world_readable"`
	WorldWritable          string              `json:"world_writable"`
	GroupReadable          string              `json:"group_readable"`
	GroupWritable          string              `json:"group_writable"`
	BroadlyAccessible      string              `json:"broadly_accessible"`
	BroadlyWritable        string              `json:"broadly_writable"`
	ContentInspected       bool                `json:"content_inspected"`
	ContentInspectionState string              `json:"content_inspection_state"`
	ContentBytesInspected  int64               `json:"content_bytes_inspected,omitempty"`
	ContentTruncated       bool                `json:"content_truncated,omitempty"`
	SecretIndicatorState   string              `json:"secret_indicator_state"`
	SecretIndicatorCount   int                 `json:"secret_indicator_count"`
	SecretIndicators       []SecretIndicator   `json:"secret_indicators,omitempty"`
	RedactionApplied       bool                `json:"redaction_applied"`
	ContentReason          string              `json:"content_reason,omitempty"`
	DiscoverySource        string              `json:"discovery_source"`
	CollectionSource       string              `json:"collection_source"`
	Confidence             evidence.Confidence `json:"confidence"`
	Reason                 string              `json:"reason,omitempty"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Records                     int `json:"records"`
	Files                       int `json:"files"`
	Directories                 int `json:"directories"`
	EnvironmentFiles            int `json:"environment_files"`
	CloudConfigs                int `json:"cloud_configs"`
	PrivateKeys                 int `json:"private_keys"`
	ServiceConfigs              int `json:"service_configs"`
	ShellHistories              int `json:"shell_histories"`
	CredentialStores            int `json:"credential_stores"`
	OrchestrationConfigs        int `json:"orchestration_configs"`
	DeveloperCredentials        int `json:"developer_credentials"`
	PermissionAssessed          int `json:"permission_assessed"`
	BroadlyAccessible           int `json:"broadly_accessible"`
	BroadlyWritable             int `json:"broadly_writable"`
	Denied                      int `json:"denied"`
	Unavailable                 int `json:"unavailable"`
	ContentInspected            int `json:"content_inspected"`
	FilesWithSecretIndicators   int `json:"files_with_secret_indicators"`
	SecretIndicators            int `json:"secret_indicators"`
	BroadlyAccessibleWithSecret int `json:"broadly_accessible_with_secret"`
}

type Inventory struct {
	Schema                string                       `json:"schema"`
	EvidenceSchema        string                       `json:"evidence_schema"`
	Collector             string                       `json:"collector"`
	CollectorVersion      string                       `json:"collector_version"`
	Platform              string                       `json:"platform"`
	Architecture          string                       `json:"architecture"`
	CollectedAt           time.Time                    `json:"collected_at"`
	Records               []Record                     `json:"records"`
	Sources               []SourceStatus               `json:"sources"`
	Summary               Summary                      `json:"summary"`
	PlaintextRisk         PlaintextRiskSummary         `json:"plaintext_risk"`
	PrivateKeyPermissions PrivateKeyPermissionSummary  `json:"private_key_permissions"`
	CredentialFilePosture CredentialFilePostureSummary `json:"credential_file_posture"`
	Evidence              []evidence.Observation       `json:"evidence"`
	Degraded              []string                     `json:"degraded,omitempty"`
}

type candidate struct {
	Kind   string
	Scope  string
	Path   string
	Source string
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
	}
	candidates, degraded := expandCandidates(platformCandidates())
	inv.Degraded = append(inv.Degraded, degraded...)
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			inv.Degraded = append(inv.Degraded, "secret-storage metadata collection interrupted: "+ctx.Err().Error())
			break
		}
		rec, keep := inspectMetadata(c)
		if keep {
			inv.Records = append(inv.Records, rec)
		}
		if len(inv.Records) >= maxRecords {
			inv.Degraded = append(inv.Degraded, "secret-storage inventory reached bounded record limit")
			break
		}
	}
	permissionCtx, permissionCancel, _ := secretEnrichmentStageContext(ctx, secretStagePermissions)
	inv.Degraded = append(inv.Degraded, enrichPlatformPermissions(permissionCtx, inv.Records)...)
	permissionCancel()

	contentCtx, contentCancel, _ := secretEnrichmentStageContext(ctx, secretStageContent)
	inv.Degraded = append(inv.Degraded, inspectContentPosture(contentCtx, inv.Records)...)
	contentCancel()
	inv.Records = normalizeRecords(inv.Records)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Records)
	inv.PlaintextRisk = buildPlaintextRiskSummary(inv.Records)
	inv.PrivateKeyPermissions = buildPrivateKeyPermissionSummary(inv.Records)
	inv.CredentialFilePosture = buildCredentialFilePostureSummary(inv.Records)
	state := evidence.StateObserved
	reason := ""
	if len(inv.Degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(inv.Degraded, "; ")
	}
	if ctx != nil && ctx.Err() != nil && len(inv.Records) == 0 {
		state = evidence.StateUnavailable
		reason = ctx.Err().Error()
	}
	inv.Sources = []SourceStatus{{ID: "local-secret-bearing-path-metadata", State: state, Source: "bounded local path/permission inspection plus redacted plaintext-secret indicators, private-key permission posture, and cloud/developer credential-file permission posture", ItemCount: len(inv.Records), Reason: reason}}
	inv.Evidence = buildEvidence(inv)
	return inv
}

func inspectMetadata(c candidate) (Record, bool) {
	path := filepath.Clean(strings.TrimSpace(c.Path))
	rec := Record{
		ID: stableID(c.Kind, path), Kind: normalizeWord(c.Kind), Scope: normalizeWord(c.Scope), Path: path,
		State: evidence.StateObserved, PermissionState: "UNKNOWN", PermissionModel: platformPermissionModel(),
		WorldReadable: "UNKNOWN", WorldWritable: "UNKNOWN", GroupReadable: "UNKNOWN", GroupWritable: "UNKNOWN",
		BroadlyAccessible: "UNKNOWN", BroadlyWritable: "UNKNOWN", ContentInspected: false,
		ContentInspectionState: "PENDING", SecretIndicatorState: "UNKNOWN", RedactionApplied: false,
		DiscoverySource: strings.TrimSpace(c.Source), CollectionSource: "filesystem metadata only; content not read", Confidence: evidence.ConfidenceHigh,
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, false
		}
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec, true
	}
	rec.Exists = true
	rec.Symlink = info.Mode()&os.ModeSymlink != 0
	if rec.Symlink {
		target, err := os.Stat(path)
		if err != nil {
			if os.IsPermission(err) {
				rec.State = evidence.StateDenied
			} else {
				rec.State = evidence.StateUnavailable
			}
			rec.Reason = "symbolic-link target metadata unavailable: " + err.Error()
			return rec, true
		}
		info = target
		rec.CollectionSource = "resolved target filesystem metadata only; content not read"
	}
	rec.Directory = info.IsDir()
	rec.SizeBytes = info.Size()
	rec.ModifiedAt = info.ModTime().UTC()
	applyBasicPermissionMetadata(&rec, info)
	return rec, true
}

func expandCandidates(in []candidate) ([]candidate, []string) {
	out := make([]candidate, 0, len(in))
	degraded := []string{}
	seen := map[string]struct{}{}
	add := func(c candidate) {
		c.Kind = normalizeWord(c.Kind)
		c.Scope = normalizeWord(c.Scope)
		c.Path = filepath.Clean(strings.TrimSpace(c.Path))
		c.Source = strings.TrimSpace(c.Source)
		if c.Kind == "" || c.Scope == "" || c.Path == "." || c.Path == "" {
			return
		}
		if c.Source == "" {
			c.Source = "common secret-bearing path inventory"
		}
		if c.Kind == "PRIVATE_KEY" && strings.HasSuffix(strings.ToLower(c.Path), ".pub") {
			return
		}
		key := c.Kind + "|" + platformPathKey(c.Path)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	for _, c := range in {
		if strings.ContainsAny(c.Path, "*?[") {
			matches, err := filepath.Glob(c.Path)
			if err != nil {
				degraded = append(degraded, "invalid secret-storage path pattern "+c.Path+": "+err.Error())
				continue
			}
			sort.Slice(matches, func(i, j int) bool { return platformPathKey(matches[i]) < platformPathKey(matches[j]) })
			for _, m := range matches {
				cc := c
				cc.Path = m
				add(cc)
				if len(out) >= maxCandidates {
					break
				}
			}
		} else {
			add(c)
		}
		if len(out) >= maxCandidates {
			degraded = append(degraded, "secret-storage candidate expansion reached bounded limit")
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return platformPathKey(out[i].Path) < platformPathKey(out[j].Path)
	})
	return out, uniqueSorted(degraded)
}

func normalizeRecords(in []Record) []Record {
	out := make([]Record, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r.Kind = normalizeWord(r.Kind)
		r.Scope = normalizeWord(r.Scope)
		r.Path = filepath.Clean(strings.TrimSpace(r.Path))
		if r.ID == "" {
			r.ID = stableID(r.Kind, r.Path)
		}
		r.PermissionState = normalizeWord(r.PermissionState)
		if r.PermissionState == "" {
			r.PermissionState = "UNKNOWN"
		}
		r.PermissionModel = strings.TrimSpace(r.PermissionModel)
		r.WorldReadable = tri(r.WorldReadable)
		r.WorldWritable = tri(r.WorldWritable)
		r.GroupReadable = tri(r.GroupReadable)
		r.GroupWritable = tri(r.GroupWritable)
		r.BroadlyAccessible = tri(r.BroadlyAccessible)
		r.BroadlyWritable = tri(r.BroadlyWritable)
		r.ContentInspectionState = normalizeWord(r.ContentInspectionState)
		if r.ContentInspectionState == "" || r.ContentInspectionState == "PENDING" {
			r.ContentInspectionState = "SKIPPED"
		}
		r.SecretIndicatorState = normalizeWord(r.SecretIndicatorState)
		if r.SecretIndicatorState == "" {
			r.SecretIndicatorState = "UNKNOWN"
		}
		if r.SecretIndicatorCount != len(r.SecretIndicators) {
			r.SecretIndicatorCount = len(r.SecretIndicators)
		}
		if r.SecretIndicatorCount > 0 {
			r.RedactionApplied = true
		}
		r.DiscoverySource = strings.TrimSpace(r.DiscoverySource)
		r.CollectionSource = strings.TrimSpace(r.CollectionSource)
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceMedium
		}
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return platformPathKey(out[i].Path) < platformPathKey(out[j].Path)
	})
	return out
}

func summarize(records []Record) Summary {
	var s Summary
	for _, r := range records {
		s.Records++
		if r.Directory {
			s.Directories++
		} else {
			s.Files++
		}
		switch r.Kind {
		case "ENVIRONMENT_FILE":
			s.EnvironmentFiles++
		case "CLOUD_CONFIG":
			s.CloudConfigs++
		case "PRIVATE_KEY":
			s.PrivateKeys++
		case "SERVICE_CONFIG":
			s.ServiceConfigs++
		case "SHELL_HISTORY":
			s.ShellHistories++
		case "CREDENTIAL_STORE":
			s.CredentialStores++
		case "ORCHESTRATION_CONFIG":
			s.OrchestrationConfigs++
		case "DEVELOPER_CREDENTIAL":
			s.DeveloperCredentials++
		}
		if r.PermissionState == "OBSERVED" {
			s.PermissionAssessed++
		}
		if r.BroadlyAccessible == "TRUE" {
			s.BroadlyAccessible++
		}
		if r.BroadlyWritable == "TRUE" {
			s.BroadlyWritable++
		}
		if r.State == evidence.StateDenied {
			s.Denied++
		}
		if r.State == evidence.StateUnavailable {
			s.Unavailable++
		}
		if r.ContentInspected {
			s.ContentInspected++
		}
		if r.SecretIndicatorCount > 0 {
			s.FilesWithSecretIndicators++
			s.SecretIndicators += r.SecretIndicatorCount
			if r.BroadlyAccessible == "TRUE" {
				s.BroadlyAccessibleWithSecret++
			}
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("secret_storage.summary", inv.Summary, "secret-storage posture with redacted plaintext-secret indicators, private-key permissions, and cloud/developer credential-file permission inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("secret_storage.plaintext_risk", inv.PlaintextRisk, "bounded local plaintext-secret indicator inspection with matched values redacted", at, evidence.ConfidenceHigh),
		evidence.NewObserved("secret_storage.private_key_permissions", inv.PrivateKeyPermissions, "private-key ownership and access-mode/ACL posture derived from normalized local permission metadata", at, evidence.ConfidenceHigh),
		evidence.NewObserved("secret_storage.credential_file_posture", inv.CredentialFilePosture, "cloud/developer credential and configuration file read/write exposure posture derived from normalized local permission metadata; credential values are not retained", at, evidence.ConfidenceHigh),
	}
	for _, s := range inv.Sources {
		key := "secret_storage.source." + stableToken(s.ID)
		if s.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, s, s.Source, at, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState(key, s.State, s.Source, at, evidence.ConfidenceMedium, fallback(s.Reason, "secret-storage provider did not complete normally")))
		}
	}
	for _, r := range inv.Records {
		key := "secret_storage.item." + r.ID
		if r.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, r, r.CollectionSource, at, r.Confidence))
		} else {
			out = append(out, evidence.NewState(key, r.State, r.CollectionSource, at, r.Confidence, fallback(r.Reason, "secret-storage metadata unavailable")))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("invalid secret-storage inventory contract")
	}
	if inv.Platform == "" || inv.Architecture == "" || inv.CollectedAt.IsZero() {
		return fmt.Errorf("secret-storage inventory metadata incomplete")
	}
	if inv.Summary.Records != len(inv.Records) {
		return fmt.Errorf("secret-storage summary record count mismatch")
	}
	if err := inv.PrivateKeyPermissions.Validate(); err != nil {
		return fmt.Errorf("private-key permission summary: %w", err)
	}
	if inv.Summary.PrivateKeys != inv.PrivateKeyPermissions.Keys {
		return fmt.Errorf("private-key permission summary count mismatch")
	}
	if err := inv.CredentialFilePosture.Validate(); err != nil {
		return fmt.Errorf("credential-file posture summary: %w", err)
	}
	if inv.Summary.ContentInspected != inv.PlaintextRisk.InspectedFiles {
		return fmt.Errorf("plaintext-secret inspection summary mismatch")
	}
	if inv.Summary.FilesWithSecretIndicators != inv.PlaintextRisk.FilesWithIndicators || inv.Summary.SecretIndicators != inv.PlaintextRisk.IndicatorCount || inv.Summary.BroadlyAccessibleWithSecret != inv.PlaintextRisk.BroadlyAccessibleWithIndicators {
		return fmt.Errorf("plaintext-secret risk summary mismatch")
	}
	seen := map[string]struct{}{}
	for _, r := range inv.Records {
		if r.ID == "" || r.Kind == "" || r.Scope == "" || strings.TrimSpace(r.Path) == "" || r.State == "" || r.PermissionState == "" || r.PermissionModel == "" || r.WorldReadable == "" || r.WorldWritable == "" || r.GroupReadable == "" || r.GroupWritable == "" || r.BroadlyAccessible == "" || r.BroadlyWritable == "" || r.ContentInspectionState == "" || r.SecretIndicatorState == "" || r.CollectionSource == "" || r.Confidence == "" {
			return fmt.Errorf("secret-storage record %q incomplete", r.ID)
		}
		if r.SecretIndicatorCount != len(r.SecretIndicators) {
			return fmt.Errorf("secret-storage record %q indicator count mismatch", r.ID)
		}
		if r.SecretIndicatorCount > 0 && !r.RedactionApplied {
			return fmt.Errorf("secret-storage record %q indicator evidence is not marked redacted", r.ID)
		}
		for _, ind := range r.SecretIndicators {
			if strings.TrimSpace(ind.Type) == "" || ind.Line < 1 {
				return fmt.Errorf("secret-storage record %q has invalid redacted indicator metadata", r.ID)
			}
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate secret-storage record id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return evidence.ValidateAll(inv.Evidence)
}

func stableID(kind, path string) string {
	sum := sha256.Sum256([]byte(normalizeWord(kind) + "|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}
func stableToken(v string) string { return stableID("source", strings.ToLower(strings.TrimSpace(v))) }
func platformPathKey(v string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(filepath.Clean(v))
	}
	return filepath.Clean(v)
}
func normalizeWord(v string) string { return strings.ToUpper(strings.TrimSpace(v)) }
func tri(v string) string {
	switch normalizeWord(v) {
	case "TRUE":
		return "TRUE"
	case "FALSE":
		return "FALSE"
	default:
		return "UNKNOWN"
	}
}
func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
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

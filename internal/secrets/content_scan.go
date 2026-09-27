package secrets

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxContentBytes       = 1024 * 1024
	maxContentFiles       = 128
	maxIndicatorsPerFile  = 32
	maxIndicatorLineBytes = maxContentBytes + 1
)

type SecretIndicator struct {
	Type string `json:"type"`
	Line int    `json:"line,omitempty"`
}

type PlaintextRiskRecord struct {
	RecordID          string   `json:"record_id"`
	Kind              string   `json:"kind"`
	Scope             string   `json:"scope"`
	Path              string   `json:"path"`
	IndicatorCount    int      `json:"indicator_count"`
	IndicatorTypes    []string `json:"indicator_types"`
	BroadlyAccessible string   `json:"broadly_accessible"`
	PermissionState   string   `json:"permission_state"`
	InspectionState   string   `json:"inspection_state"`
}

type PlaintextRiskSummary struct {
	InspectionState                 string                `json:"inspection_state"`
	EligibleFiles                   int                   `json:"eligible_files"`
	InspectedFiles                  int                   `json:"inspected_files"`
	PartiallyInspectedFiles         int                   `json:"partially_inspected_files"`
	SkippedFiles                    int                   `json:"skipped_files"`
	DeniedFiles                     int                   `json:"denied_files"`
	UnavailableFiles                int                   `json:"unavailable_files"`
	FilesWithIndicators             int                   `json:"files_with_indicators"`
	IndicatorCount                  int                   `json:"indicator_count"`
	BroadlyAccessibleWithIndicators int                   `json:"broadly_accessible_with_indicators"`
	UnknownAccessWithIndicators     int                   `json:"unknown_access_with_indicators"`
	Records                         []PlaintextRiskRecord `json:"records,omitempty"`
}

var (
	assignmentPattern         = regexp.MustCompile(`(?i)^\s*(?:(?:export|set|setx)\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]{1,96})["']?\s*[:=]\s*(.+?)\s*[,;]?\s*$`)
	embeddedAssignmentPattern = regexp.MustCompile(`(?i)(?:^|[\s"'])((?:[A-Za-z_][A-Za-z0-9_.-]{1,96}))\s*=\s*([^\s"']{4,})`)
	pemPrivateKey             = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	githubToken               = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	gitlabToken               = regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)
	slackToken                = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`)
	openAIToken               = regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)
	bearerToken               = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/=-]{12,}`)
	credentialURI             = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)
)

func inspectContentPosture(ctx context.Context, records []Record) []string {
	degraded := []string{}
	inspected := 0
	for i := range records {
		if ctx != nil && ctx.Err() != nil {
			remaining := 0
			for j := i; j < len(records); j++ {
				r := &records[j]
				if !contentEligible(*r) || (r.ContentInspectionState != "" && r.ContentInspectionState != "PENDING") {
					continue
				}
				remaining++
				r.ContentInspectionState = "SKIPPED"
				r.SecretIndicatorState = "UNKNOWN"
				r.ContentReason = "bounded plaintext-secret content enrichment stage ended before this candidate was inspected"
			}
			degraded = append(degraded, fmt.Sprintf("plaintext-secret content enrichment preserved %d inspected file(s); %d eligible file(s) remained when the bounded stage ended: %v", inspected, remaining, ctx.Err()))
			break
		}
		r := &records[i]
		if !contentEligible(*r) {
			if r.ContentInspectionState == "" || r.ContentInspectionState == "PENDING" {
				switch r.State {
				case "DENIED":
					r.ContentInspectionState = "DENIED"
					r.SecretIndicatorState = "UNKNOWN"
				case "UNAVAILABLE":
					r.ContentInspectionState = "UNAVAILABLE"
					r.SecretIndicatorState = "UNKNOWN"
				default:
					r.ContentInspectionState = "SKIPPED"
					r.SecretIndicatorState = "SKIPPED"
				}
				r.ContentReason = contentSkipReason(*r)
			}
			continue
		}
		if inspected >= maxContentFiles {
			r.ContentInspectionState = "SKIPPED"
			r.SecretIndicatorState = "UNKNOWN"
			r.ContentReason = "bounded plaintext-secret inspection file limit reached"
			degraded = append(degraded, "plaintext-secret indicator inspection reached bounded file limit")
			continue
		}
		inspected++
		if err := inspectRecordContent(ctx, r); err != nil {
			degraded = append(degraded, fmt.Sprintf("plaintext-secret indicator inspection for %s: %v", r.Path, err))
		}
	}
	return uniqueSorted(degraded)
}

func contentEligible(r Record) bool {
	if !r.Exists || r.Directory || r.State != "OBSERVED" || !contentKindEligible(r.Kind) {
		return false
	}
	return true
}

func contentKindEligible(kind string) bool {
	switch normalizeWord(kind) {
	case "ENVIRONMENT_FILE", "CLOUD_CONFIG", "PRIVATE_KEY", "SERVICE_CONFIG", "SHELL_HISTORY", "ORCHESTRATION_CONFIG", "DEVELOPER_CREDENTIAL":
		return true
	default:
		return false
	}
}

func contentSkipReason(r Record) string {
	if !r.Exists {
		return "path not present"
	}
	if r.Directory {
		return "directory content is not inspected"
	}
	if r.State != "OBSERVED" {
		return "file metadata is not fully observable"
	}
	if normalizeWord(r.Kind) == "CREDENTIAL_STORE" {
		return "credential-store contents are outside plaintext-indicator scope"
	}
	return "record kind is outside plaintext-indicator scope"
}

func inspectRecordContent(ctx context.Context, r *Record) error {
	if r == nil {
		return fmt.Errorf("nil record")
	}
	f, err := os.Open(r.Path)
	if err != nil {
		if os.IsPermission(err) {
			r.ContentInspectionState = "DENIED"
		} else {
			r.ContentInspectionState = "UNAVAILABLE"
		}
		r.SecretIndicatorState = "UNKNOWN"
		r.ContentReason = err.Error()
		return err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxContentBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		r.ContentInspectionState = "UNAVAILABLE"
		r.SecretIndicatorState = "UNKNOWN"
		r.ContentReason = err.Error()
		return err
	}
	if ctx != nil && ctx.Err() != nil {
		r.ContentInspectionState = "UNAVAILABLE"
		r.SecretIndicatorState = "UNKNOWN"
		r.ContentReason = ctx.Err().Error()
		return ctx.Err()
	}

	truncated := len(data) > maxContentBytes
	if truncated {
		data = data[:maxContentBytes]
	}
	if looksBinary(data) {
		r.ContentInspectionState = "SKIPPED"
		r.SecretIndicatorState = "UNKNOWN"
		r.ContentReason = "binary or non-text content is not scanned for plaintext indicators"
		return nil
	}

	r.ContentInspected = true
	r.CollectionSource = "filesystem metadata plus bounded plaintext-secret indicator inspection; matched values and source lines not retained"
	r.ContentBytesInspected = int64(len(data))
	r.ContentTruncated = truncated
	if truncated {
		r.ContentInspectionState = "PARTIAL"
		r.ContentReason = "content inspection bounded to first 1 MiB"
	} else {
		r.ContentInspectionState = "OBSERVED"
	}
	indicators := detectSecretIndicators(data)
	if len(indicators) > maxIndicatorsPerFile {
		indicators = indicators[:maxIndicatorsPerFile]
		if r.ContentReason == "" {
			r.ContentReason = "indicator detail bounded to first 32 matches"
		} else {
			r.ContentReason += "; indicator detail bounded to first 32 matches"
		}
	}
	r.SecretIndicators = indicators
	r.SecretIndicatorCount = len(indicators)
	if len(indicators) > 0 {
		r.SecretIndicatorState = "DETECTED"
		r.RedactionApplied = true
	} else if truncated {
		r.SecretIndicatorState = "UNKNOWN"
	} else {
		r.SecretIndicatorState = "NONE"
	}
	return nil
}

func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return true
	}
	control := 0
	for _, b := range data {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			control++
		}
	}
	return control*100/len(data) > 5
}

func detectSecretIndicators(data []byte) []SecretIndicator {
	out := []SecretIndicator{}
	seen := map[string]struct{}{}
	add := func(kind string, line int) {
		kind = normalizeWord(kind)
		if kind == "" || line < 1 {
			return
		}
		key := fmt.Sprintf("%s|%d", kind, line)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, SecretIndicator{Type: kind, Line: line})
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxIndicatorLineBytes)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if m := assignmentPattern.FindStringSubmatch(trimmed); len(m) == 3 {
			if sensitiveKey(m[1]) && materialValue(m[2]) {
				add("SENSITIVE_ASSIGNMENT", line)
			}
		}
		for _, m := range embeddedAssignmentPattern.FindAllStringSubmatch(trimmed, -1) {
			if len(m) == 3 && sensitiveKey(m[1]) && materialValue(m[2]) {
				add("SENSITIVE_ASSIGNMENT", line)
			}
		}
		if pemPrivateKey.MatchString(text) {
			add("PRIVATE_KEY_MATERIAL", line)
		}
		if githubToken.MatchString(text) {
			add("GITHUB_TOKEN", line)
		}
		if gitlabToken.MatchString(text) {
			add("GITLAB_TOKEN", line)
		}
		if slackToken.MatchString(text) {
			add("SLACK_TOKEN", line)
		}
		if openAIToken.MatchString(text) {
			add("API_TOKEN", line)
		}
		if bearerToken.MatchString(text) {
			add("BEARER_TOKEN", line)
		}
		if credentialURI.MatchString(text) {
			add("URI_EMBEDDED_CREDENTIAL", line)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func sensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	compact := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k)
	needles := []string{
		"password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey",
		"clientsecret", "privatekey", "credential", "authkey", "signingkey", "encryptionkey",
	}
	for _, n := range needles {
		if strings.Contains(compact, n) {
			return true
		}
	}
	return false
}

func materialValue(raw string) bool {
	v := strings.TrimSpace(raw)
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSuffix(v, ";")
	v = strings.TrimSpace(v)
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	placeholders := []string{"<redacted>", "redacted", "***", "xxxxx", "changeme", "change-me", "example", "example-value", "null", "none", "nil", "false", "true"}
	for _, p := range placeholders {
		if lower == p {
			return false
		}
	}
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return false
	}
	if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") {
		return false
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return false
	}
	return len(v) >= 4
}

func buildPlaintextRiskSummary(records []Record) PlaintextRiskSummary {
	s := PlaintextRiskSummary{InspectionState: "COMPLETE"}
	for _, r := range records {
		if contentKindEligible(r.Kind) && !r.Directory && (r.Exists || r.State == "DENIED" || r.State == "UNAVAILABLE") {
			s.EligibleFiles++
		}
		switch normalizeWord(r.ContentInspectionState) {
		case "OBSERVED":
			s.InspectedFiles++
		case "PARTIAL":
			s.InspectedFiles++
			s.PartiallyInspectedFiles++
		case "SKIPPED":
			s.SkippedFiles++
		case "DENIED":
			s.DeniedFiles++
		case "UNAVAILABLE":
			s.UnavailableFiles++
		}
		if r.SecretIndicatorCount <= 0 {
			continue
		}
		s.FilesWithIndicators++
		s.IndicatorCount += r.SecretIndicatorCount
		if r.BroadlyAccessible == "TRUE" {
			s.BroadlyAccessibleWithIndicators++
		} else if r.BroadlyAccessible == "UNKNOWN" {
			s.UnknownAccessWithIndicators++
		}
		types := make([]string, 0, len(r.SecretIndicators))
		seen := map[string]struct{}{}
		for _, ind := range r.SecretIndicators {
			if _, ok := seen[ind.Type]; ok {
				continue
			}
			seen[ind.Type] = struct{}{}
			types = append(types, ind.Type)
		}
		sort.Strings(types)
		s.Records = append(s.Records, PlaintextRiskRecord{
			RecordID: r.ID, Kind: r.Kind, Scope: r.Scope, Path: r.Path,
			IndicatorCount: r.SecretIndicatorCount, IndicatorTypes: types,
			BroadlyAccessible: r.BroadlyAccessible, PermissionState: r.PermissionState,
			InspectionState: r.ContentInspectionState,
		})
	}
	if s.PartiallyInspectedFiles > 0 || s.DeniedFiles > 0 || s.UnavailableFiles > 0 || s.EligibleFiles > s.InspectedFiles {
		s.InspectionState = "DEGRADED"
	}
	if s.EligibleFiles == 0 {
		s.InspectionState = "COMPLETE"
	}
	sort.Slice(s.Records, func(i, j int) bool { return s.Records[i].RecordID < s.Records[j].RecordID })
	return s
}

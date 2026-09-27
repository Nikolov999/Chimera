package secrets

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	CredentialSensitivityCredential    = "CREDENTIAL"
	CredentialSensitivityMixed         = "MIXED"
	CredentialSensitivityConfiguration = "CONFIGURATION"

	CredentialPostureRestricted    = "RESTRICTED"
	CredentialPostureExposed       = "EXPOSED"
	CredentialPostureUnknown       = "UNKNOWN"
	CredentialPostureNotApplicable = "NOT_APPLICABLE"

	CredentialAssessmentComplete      = "COMPLETE"
	CredentialAssessmentDegraded      = "DEGRADED"
	CredentialAssessmentNotApplicable = "NOT_APPLICABLE"
)

// CredentialFilePostureRecord contains only path classification and permission
// posture. It never contains credential values, tokens, passwords, key material,
// decoded configuration values, or authentication results.
type CredentialFilePostureRecord struct {
	RecordID        string `json:"record_id"`
	Provider        string `json:"provider"`
	Role            string `json:"role"`
	Sensitivity     string `json:"sensitivity"`
	Scope           string `json:"scope"`
	Path            string `json:"path"`
	Symlink         bool   `json:"symlink"`
	PermissionState string `json:"permission_state"`
	PermissionModel string `json:"permission_model"`
	OwnerID         string `json:"owner_id,omitempty"`
	Mode            string `json:"mode,omitempty"`
	ReadPosture     string `json:"read_posture"`
	WritePosture    string `json:"write_posture"`
	Reason          string `json:"reason,omitempty"`
}

type CredentialProviderSummary struct {
	Provider          string `json:"provider"`
	Files             int    `json:"files"`
	CredentialBearing int    `json:"credential_bearing"`
	ConfigurationOnly int    `json:"configuration_only"`
	ReadExposed       int    `json:"read_exposed"`
	WriteExposed      int    `json:"write_exposed"`
	UnknownPosture    int    `json:"unknown_posture"`
}

type CredentialFilePostureSummary struct {
	AssessmentState    string                        `json:"assessment_state"`
	Files              int                           `json:"files"`
	CredentialBearing  int                           `json:"credential_bearing"`
	ConfigurationOnly  int                           `json:"configuration_only"`
	PermissionAssessed int                           `json:"permission_assessed"`
	ReadRestricted     int                           `json:"read_restricted"`
	ReadExposed        int                           `json:"read_exposed"`
	ReadUnknown        int                           `json:"read_unknown"`
	ReadNotApplicable  int                           `json:"read_not_applicable"`
	WriteRestricted    int                           `json:"write_restricted"`
	WriteExposed       int                           `json:"write_exposed"`
	WriteUnknown       int                           `json:"write_unknown"`
	UnknownPosture     int                           `json:"unknown_posture"`
	Providers          []CredentialProviderSummary   `json:"providers,omitempty"`
	Records            []CredentialFilePostureRecord `json:"records,omitempty"`
}

type credentialDescriptor struct {
	Provider    string
	Role        string
	Sensitivity string
}

func buildCredentialFilePostureSummary(records []Record) CredentialFilePostureSummary {
	out := CredentialFilePostureSummary{AssessmentState: CredentialAssessmentNotApplicable}
	providerIndex := map[string]*CredentialProviderSummary{}

	for _, r := range records {
		if r.Directory {
			continue
		}
		d, ok := credentialDescriptorForRecord(r)
		if !ok {
			continue
		}
		p := classifyCredentialFilePermission(r, d)
		out.Files++
		if d.Sensitivity == CredentialSensitivityConfiguration {
			out.ConfigurationOnly++
		} else {
			out.CredentialBearing++
		}
		if normalizeWord(r.PermissionState) == "OBSERVED" {
			out.PermissionAssessed++
		}
		switch p.ReadPosture {
		case CredentialPostureRestricted:
			out.ReadRestricted++
		case CredentialPostureExposed:
			out.ReadExposed++
		case CredentialPostureUnknown:
			out.ReadUnknown++
		case CredentialPostureNotApplicable:
			out.ReadNotApplicable++
		}
		switch p.WritePosture {
		case CredentialPostureRestricted:
			out.WriteRestricted++
		case CredentialPostureExposed:
			out.WriteExposed++
		case CredentialPostureUnknown:
			out.WriteUnknown++
		}
		if p.ReadPosture == CredentialPostureUnknown || p.WritePosture == CredentialPostureUnknown {
			out.UnknownPosture++
		}
		out.Records = append(out.Records, p)

		ps := providerIndex[d.Provider]
		if ps == nil {
			ps = &CredentialProviderSummary{Provider: d.Provider}
			providerIndex[d.Provider] = ps
		}
		ps.Files++
		if d.Sensitivity == CredentialSensitivityConfiguration {
			ps.ConfigurationOnly++
		} else {
			ps.CredentialBearing++
		}
		if p.ReadPosture == CredentialPostureExposed {
			ps.ReadExposed++
		}
		if p.WritePosture == CredentialPostureExposed {
			ps.WriteExposed++
		}
		if p.ReadPosture == CredentialPostureUnknown || p.WritePosture == CredentialPostureUnknown {
			ps.UnknownPosture++
		}
	}

	sort.Slice(out.Records, func(i, j int) bool {
		if out.Records[i].Provider != out.Records[j].Provider {
			return out.Records[i].Provider < out.Records[j].Provider
		}
		return platformPathKey(out.Records[i].Path) < platformPathKey(out.Records[j].Path)
	})
	providers := make([]string, 0, len(providerIndex))
	for provider := range providerIndex {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	for _, provider := range providers {
		out.Providers = append(out.Providers, *providerIndex[provider])
	}

	if out.Files == 0 {
		return out
	}
	out.AssessmentState = CredentialAssessmentComplete
	if out.UnknownPosture > 0 || out.PermissionAssessed < out.Files {
		out.AssessmentState = CredentialAssessmentDegraded
	}
	return out
}

func classifyCredentialFilePermission(r Record, d credentialDescriptor) CredentialFilePostureRecord {
	p := CredentialFilePostureRecord{
		RecordID: r.ID, Provider: d.Provider, Role: d.Role, Sensitivity: d.Sensitivity,
		Scope: normalizeWord(r.Scope), Path: r.Path, Symlink: r.Symlink,
		PermissionState: normalizeWord(r.PermissionState), PermissionModel: strings.TrimSpace(r.PermissionModel),
		OwnerID: strings.TrimSpace(r.OwnerID), Mode: strings.TrimSpace(r.Mode),
		ReadPosture: CredentialPostureUnknown, WritePosture: CredentialPostureUnknown,
	}
	if d.Sensitivity == CredentialSensitivityConfiguration {
		p.ReadPosture = CredentialPostureNotApplicable
	}
	if r.State != "OBSERVED" || p.PermissionState != "OBSERVED" {
		p.Reason = fallback(r.Reason, "credential/config permission metadata is not fully observable")
		return p
	}
	if d.Sensitivity != CredentialSensitivityConfiguration {
		p.ReadPosture = credentialExposurePosture(r.BroadlyAccessible)
	}
	p.WritePosture = credentialExposurePosture(r.BroadlyWritable)
	return p
}

func credentialExposurePosture(v string) string {
	switch tri(v) {
	case "TRUE":
		return CredentialPostureExposed
	case "FALSE":
		return CredentialPostureRestricted
	default:
		return CredentialPostureUnknown
	}
}

func credentialDescriptorForRecord(r Record) (credentialDescriptor, bool) {
	path := strings.ToLower(filepath.ToSlash(filepath.Clean(strings.TrimSpace(r.Path))))
	base := strings.ToLower(filepath.Base(path))
	has := func(fragment string) bool { return strings.Contains(path, strings.ToLower(fragment)) }

	switch {
	case has("/.aws/credentials"):
		return credentialDescriptor{"AWS", "CREDENTIAL_FILE", CredentialSensitivityCredential}, true
	case has("/.aws/config"):
		return credentialDescriptor{"AWS", "CLIENT_CONFIG", CredentialSensitivityConfiguration}, true
	case has("/.azure/"):
		return credentialDescriptor{"AZURE", "LOCAL_PROFILE", CredentialSensitivityMixed}, true
	case strings.Contains(path, "/gcloud/application_default_credentials.json"):
		return credentialDescriptor{"GCP", "APPLICATION_DEFAULT_CREDENTIALS", CredentialSensitivityCredential}, true
	case strings.Contains(path, "/gcloud/credentials.db"):
		return credentialDescriptor{"GCP", "CREDENTIAL_DATABASE", CredentialSensitivityCredential}, true
	case has("/.kube/config"):
		return credentialDescriptor{"KUBERNETES", "KUBECONFIG", CredentialSensitivityMixed}, true
	case has("/.docker/config.json"):
		return credentialDescriptor{"DOCKER", "CLIENT_CONFIG", CredentialSensitivityMixed}, true
	case base == ".git-credentials":
		return credentialDescriptor{"GIT", "CREDENTIAL_FILE", CredentialSensitivityCredential}, true
	case base == ".gitconfig" || strings.HasSuffix(path, "/.config/git/config"):
		return credentialDescriptor{"GIT", "GLOBAL_CONFIG", CredentialSensitivityConfiguration}, true
	case base == ".npmrc":
		return credentialDescriptor{"NPM", "USER_CONFIG", CredentialSensitivityMixed}, true
	case base == ".pypirc":
		return credentialDescriptor{"PYPI", "REPOSITORY_CONFIG", CredentialSensitivityMixed}, true
	case strings.HasSuffix(path, "/pip/pip.conf") || strings.HasSuffix(path, "/pip/pip.ini"):
		return credentialDescriptor{"PIP", "CLIENT_CONFIG", CredentialSensitivityMixed}, true
	case base == ".netrc" || base == "_netrc":
		return credentialDescriptor{"NETRC", "CREDENTIAL_FILE", CredentialSensitivityCredential}, true
	case strings.HasSuffix(path, "/.config/gh/hosts.yml") || strings.HasSuffix(path, "/github cli/hosts.yml"):
		return credentialDescriptor{"GITHUB_CLI", "HOST_CONFIG", CredentialSensitivityMixed}, true
	default:
		return credentialDescriptor{}, false
	}
}

func (s CredentialFilePostureSummary) Validate() error {
	switch s.AssessmentState {
	case CredentialAssessmentComplete, CredentialAssessmentDegraded, CredentialAssessmentNotApplicable:
	default:
		return fmt.Errorf("invalid credential-file assessment state %q", s.AssessmentState)
	}
	if s.Files != len(s.Records) || s.CredentialBearing+s.ConfigurationOnly != s.Files || s.PermissionAssessed > s.Files {
		return fmt.Errorf("credential-file posture counters are inconsistent")
	}
	if s.Files == 0 && s.AssessmentState != CredentialAssessmentNotApplicable {
		return fmt.Errorf("empty credential-file inventory must be NOT_APPLICABLE")
	}
	if s.ReadRestricted+s.ReadExposed+s.ReadUnknown+s.ReadNotApplicable != s.Files {
		return fmt.Errorf("credential-file read posture counters are inconsistent")
	}
	if s.WriteRestricted+s.WriteExposed+s.WriteUnknown != s.Files {
		return fmt.Errorf("credential-file write posture counters are inconsistent")
	}
	providerFiles := 0
	seenProviders := map[string]struct{}{}
	for _, p := range s.Providers {
		if strings.TrimSpace(p.Provider) == "" || p.Files < 1 || p.CredentialBearing+p.ConfigurationOnly != p.Files {
			return fmt.Errorf("credential provider summary is inconsistent")
		}
		if _, ok := seenProviders[p.Provider]; ok {
			return fmt.Errorf("duplicate credential provider summary %q", p.Provider)
		}
		seenProviders[p.Provider] = struct{}{}
		providerFiles += p.Files
	}
	if providerFiles != s.Files {
		return fmt.Errorf("credential provider file count mismatch")
	}
	seen := map[string]struct{}{}
	for _, r := range s.Records {
		if strings.TrimSpace(r.RecordID) == "" || strings.TrimSpace(r.Provider) == "" || strings.TrimSpace(r.Role) == "" || strings.TrimSpace(r.Scope) == "" || strings.TrimSpace(r.Path) == "" || strings.TrimSpace(r.PermissionState) == "" || strings.TrimSpace(r.PermissionModel) == "" {
			return fmt.Errorf("credential-file posture record is incomplete")
		}
		switch r.Sensitivity {
		case CredentialSensitivityCredential, CredentialSensitivityMixed, CredentialSensitivityConfiguration:
		default:
			return fmt.Errorf("credential-file posture record %q has invalid sensitivity", r.RecordID)
		}
		if !validCredentialReadPosture(r.ReadPosture) || !validCredentialWritePosture(r.WritePosture) {
			return fmt.Errorf("credential-file posture record %q has invalid access posture", r.RecordID)
		}
		if r.Sensitivity == CredentialSensitivityConfiguration && r.ReadPosture != CredentialPostureNotApplicable {
			return fmt.Errorf("configuration-only credential record %q must not claim read-secret posture", r.RecordID)
		}
		if _, ok := seen[r.RecordID]; ok {
			return fmt.Errorf("duplicate credential-file posture record %q", r.RecordID)
		}
		seen[r.RecordID] = struct{}{}
	}
	return nil
}

func validCredentialReadPosture(v string) bool {
	switch v {
	case CredentialPostureRestricted, CredentialPostureExposed, CredentialPostureUnknown, CredentialPostureNotApplicable:
		return true
	default:
		return false
	}
}

func validCredentialWritePosture(v string) bool {
	switch v {
	case CredentialPostureRestricted, CredentialPostureExposed, CredentialPostureUnknown:
		return true
	default:
		return false
	}
}

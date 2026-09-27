package secrets

import (
	"fmt"
	"sort"
	"strings"
)

const (
	PrivateKeyPostureRestricted    = "RESTRICTED"
	PrivateKeyPostureExposed       = "EXPOSED"
	PrivateKeyPostureReview        = "REVIEW"
	PrivateKeyPostureExpected      = "EXPECTED"
	PrivateKeyPostureUnexpected    = "UNEXPECTED"
	PrivateKeyPostureUnknown       = "UNKNOWN"
	PrivateKeyPostureNotApplicable = "NOT_APPLICABLE"

	PrivateKeyAssessmentComplete      = "COMPLETE"
	PrivateKeyAssessmentDegraded      = "DEGRADED"
	PrivateKeyAssessmentNotApplicable = "NOT_APPLICABLE"
)

// PrivateKeyPermissionRecord contains permission posture only. It never contains
// private-key content, a key fingerprint, or any derived secret material.
type PrivateKeyPermissionRecord struct {
	RecordID        string `json:"record_id"`
	Scope           string `json:"scope"`
	Path            string `json:"path"`
	PermissionState string `json:"permission_state"`
	PermissionModel string `json:"permission_model"`
	OwnerID         string `json:"owner_id,omitempty"`
	Mode            string `json:"mode,omitempty"`
	ReadPosture     string `json:"read_posture"`
	WritePosture    string `json:"write_posture"`
	OwnerPosture    string `json:"owner_posture"`
	Reason          string `json:"reason,omitempty"`
}

type PrivateKeyPermissionSummary struct {
	AssessmentState       string                       `json:"assessment_state"`
	Keys                  int                          `json:"keys"`
	UserKeys              int                          `json:"user_keys"`
	SystemKeys            int                          `json:"system_keys"`
	PermissionAssessed    int                          `json:"permission_assessed"`
	ReadRestricted        int                          `json:"read_restricted"`
	ReadExposed           int                          `json:"read_exposed"`
	ReadReview            int                          `json:"read_review"`
	WriteRestricted       int                          `json:"write_restricted"`
	WriteExposed          int                          `json:"write_exposed"`
	SystemOwnerExpected   int                          `json:"system_owner_expected"`
	SystemOwnerUnexpected int                          `json:"system_owner_unexpected"`
	UnknownPosture        int                          `json:"unknown_posture"`
	Records               []PrivateKeyPermissionRecord `json:"records,omitempty"`
}

func buildPrivateKeyPermissionSummary(records []Record) PrivateKeyPermissionSummary {
	out := PrivateKeyPermissionSummary{AssessmentState: PrivateKeyAssessmentNotApplicable}
	for _, r := range records {
		if normalizeWord(r.Kind) != "PRIVATE_KEY" || r.Directory {
			continue
		}
		p := classifyPrivateKeyPermission(r)
		out.Keys++
		switch normalizeWord(r.Scope) {
		case "USER":
			out.UserKeys++
		case "SYSTEM":
			out.SystemKeys++
		}
		if r.PermissionState == "OBSERVED" {
			out.PermissionAssessed++
		}
		switch p.ReadPosture {
		case PrivateKeyPostureRestricted:
			out.ReadRestricted++
		case PrivateKeyPostureExposed:
			out.ReadExposed++
		case PrivateKeyPostureReview:
			out.ReadReview++
		}
		switch p.WritePosture {
		case PrivateKeyPostureRestricted:
			out.WriteRestricted++
		case PrivateKeyPostureExposed:
			out.WriteExposed++
		}
		switch p.OwnerPosture {
		case PrivateKeyPostureExpected:
			out.SystemOwnerExpected++
		case PrivateKeyPostureUnexpected:
			out.SystemOwnerUnexpected++
		}
		if p.ReadPosture == PrivateKeyPostureUnknown || p.WritePosture == PrivateKeyPostureUnknown || p.OwnerPosture == PrivateKeyPostureUnknown {
			out.UnknownPosture++
		}
		out.Records = append(out.Records, p)
	}
	sort.Slice(out.Records, func(i, j int) bool {
		if out.Records[i].Scope != out.Records[j].Scope {
			return out.Records[i].Scope < out.Records[j].Scope
		}
		return platformPathKey(out.Records[i].Path) < platformPathKey(out.Records[j].Path)
	})
	if out.Keys == 0 {
		return out
	}
	out.AssessmentState = PrivateKeyAssessmentComplete
	if out.UnknownPosture > 0 || out.PermissionAssessed < out.Keys {
		out.AssessmentState = PrivateKeyAssessmentDegraded
	}
	return out
}

func classifyPrivateKeyPermission(r Record) PrivateKeyPermissionRecord {
	p := PrivateKeyPermissionRecord{
		RecordID: r.ID, Scope: normalizeWord(r.Scope), Path: r.Path,
		PermissionState: normalizeWord(r.PermissionState), PermissionModel: strings.TrimSpace(r.PermissionModel),
		OwnerID: strings.TrimSpace(r.OwnerID), Mode: strings.TrimSpace(r.Mode),
		ReadPosture: PrivateKeyPostureUnknown, WritePosture: PrivateKeyPostureUnknown,
		OwnerPosture: PrivateKeyPostureNotApplicable,
	}
	if r.State != "OBSERVED" || p.PermissionState != "OBSERVED" {
		p.Reason = fallback(r.Reason, "private-key permission metadata is not fully observable")
		if p.Scope == "SYSTEM" {
			p.OwnerPosture = PrivateKeyPostureUnknown
		}
		return p
	}

	model := normalizeWord(p.PermissionModel)
	switch model {
	case "POSIX_MODE":
		p.ReadPosture = classifyPOSIXPrivateKeyRead(r)
		p.WritePosture = classifyPOSIXPrivateKeyWrite(r)
	case "WINDOWS_DACL":
		p.ReadPosture = classifyTriExposure(r.BroadlyAccessible)
		p.WritePosture = classifyTriExposure(r.BroadlyWritable)
	default:
		p.ReadPosture = classifyTriExposure(r.BroadlyAccessible)
		p.WritePosture = classifyTriExposure(r.BroadlyWritable)
	}

	if p.Scope == "SYSTEM" {
		p.OwnerPosture = classifySystemPrivateKeyOwner(r)
	}
	if p.ReadPosture == PrivateKeyPostureReview {
		p.Reason = "system private key is group-readable; verify the group is explicitly trusted and operationally required"
	}
	return p
}

func classifyPOSIXPrivateKeyRead(r Record) string {
	if tri(r.WorldReadable) == "TRUE" {
		return PrivateKeyPostureExposed
	}
	if normalizeWord(r.Scope) == "USER" && tri(r.GroupReadable) == "TRUE" {
		return PrivateKeyPostureExposed
	}
	if tri(r.WorldReadable) == "UNKNOWN" || tri(r.GroupReadable) == "UNKNOWN" {
		return PrivateKeyPostureUnknown
	}
	if normalizeWord(r.Scope) == "SYSTEM" && tri(r.GroupReadable) == "TRUE" {
		return PrivateKeyPostureReview
	}
	return PrivateKeyPostureRestricted
}

func classifyPOSIXPrivateKeyWrite(r Record) string {
	if tri(r.WorldWritable) == "TRUE" || tri(r.GroupWritable) == "TRUE" {
		return PrivateKeyPostureExposed
	}
	if tri(r.WorldWritable) == "UNKNOWN" || tri(r.GroupWritable) == "UNKNOWN" {
		return PrivateKeyPostureUnknown
	}
	return PrivateKeyPostureRestricted
}

func classifyTriExposure(v string) string {
	switch tri(v) {
	case "TRUE":
		return PrivateKeyPostureExposed
	case "FALSE":
		return PrivateKeyPostureRestricted
	default:
		return PrivateKeyPostureUnknown
	}
}

func classifySystemPrivateKeyOwner(r Record) string {
	owner := strings.TrimSpace(r.OwnerID)
	if owner == "" {
		return PrivateKeyPostureUnknown
	}
	switch normalizeWord(r.PermissionModel) {
	case "POSIX_MODE":
		if owner == "0" {
			return PrivateKeyPostureExpected
		}
		return PrivateKeyPostureUnexpected
	case "WINDOWS_DACL":
		u := strings.ToUpper(owner)
		if strings.Contains(u, "SYSTEM") || strings.Contains(u, "ADMINISTRATORS") {
			return PrivateKeyPostureExpected
		}
		return PrivateKeyPostureUnexpected
	default:
		// The current supported platforms use POSIX_MODE or WINDOWS_DACL. Keep
		// unknown providers explicit rather than inventing an ownership policy.
		return PrivateKeyPostureUnknown
	}
}

func (s PrivateKeyPermissionSummary) Validate() error {
	switch s.AssessmentState {
	case PrivateKeyAssessmentComplete, PrivateKeyAssessmentDegraded, PrivateKeyAssessmentNotApplicable:
	default:
		return fmt.Errorf("invalid assessment state %q", s.AssessmentState)
	}
	if s.Keys != len(s.Records) || s.UserKeys+s.SystemKeys > s.Keys || s.PermissionAssessed > s.Keys {
		return fmt.Errorf("private-key permission counters are inconsistent")
	}
	if s.Keys == 0 && s.AssessmentState != PrivateKeyAssessmentNotApplicable {
		return fmt.Errorf("empty private-key inventory must be NOT_APPLICABLE")
	}
	if s.ReadRestricted+s.ReadExposed+s.ReadReview > s.Keys || s.WriteRestricted+s.WriteExposed > s.Keys {
		return fmt.Errorf("private-key access posture counters are inconsistent")
	}
	if s.SystemOwnerExpected+s.SystemOwnerUnexpected > s.SystemKeys {
		return fmt.Errorf("private-key ownership counters are inconsistent")
	}
	seen := map[string]struct{}{}
	for _, r := range s.Records {
		if strings.TrimSpace(r.RecordID) == "" || strings.TrimSpace(r.Scope) == "" || strings.TrimSpace(r.Path) == "" || strings.TrimSpace(r.PermissionState) == "" || strings.TrimSpace(r.PermissionModel) == "" {
			return fmt.Errorf("private-key permission record is incomplete")
		}
		if !validPrivateKeyAccessPosture(r.ReadPosture) || !validPrivateKeyAccessPosture(r.WritePosture) {
			return fmt.Errorf("private-key permission record %q has invalid access posture", r.RecordID)
		}
		if !validPrivateKeyOwnerPosture(r.OwnerPosture) {
			return fmt.Errorf("private-key permission record %q has invalid owner posture", r.RecordID)
		}
		if _, ok := seen[r.RecordID]; ok {
			return fmt.Errorf("duplicate private-key permission record %q", r.RecordID)
		}
		seen[r.RecordID] = struct{}{}
	}
	return nil
}

func validPrivateKeyAccessPosture(v string) bool {
	switch v {
	case PrivateKeyPostureRestricted, PrivateKeyPostureExposed, PrivateKeyPostureReview, PrivateKeyPostureUnknown:
		return true
	default:
		return false
	}
}

func validPrivateKeyOwnerPosture(v string) bool {
	switch v {
	case PrivateKeyPostureExpected, PrivateKeyPostureUnexpected, PrivateKeyPostureUnknown, PrivateKeyPostureNotApplicable:
		return true
	default:
		return false
	}
}

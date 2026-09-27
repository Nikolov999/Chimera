package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
)

func phase101RiskObservation(s secretinv.PlaintextRiskSummary) evidence.Observation {
	return evidence.NewObserved("secret_storage.plaintext_risk", s, "redacted plaintext-secret indicator test evidence", time.Now().UTC(), evidence.ConfidenceHigh)
}

func phase102PrivateKeyObservation(s secretinv.PrivateKeyPermissionSummary) evidence.Observation {
	return evidence.NewObserved("secret_storage.private_key_permissions", s, "private-key permission test evidence", time.Now().UTC(), evidence.ConfidenceHigh)
}

func findingByRule(t *testing.T, findings []Finding, ruleID string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("rule %s missing from findings: %#v", ruleID, findings)
	return Finding{}
}

func TestPhase101SecretRulesFailOnRedactedIndicators(t *testing.T) {
	s := secretinv.PlaintextRiskSummary{
		InspectionState: "COMPLETE", EligibleFiles: 2, InspectedFiles: 2,
		FilesWithIndicators: 1, IndicatorCount: 2,
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase101RiskObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, findings, "CHM-SEC-001"); got.Status != StatusFail {
		t.Fatalf("unexpected plaintext-secret finding: %#v", got)
	}
	if got := findingByRule(t, findings, "CHM-SEC-002"); got.Status != StatusPass {
		t.Fatalf("unexpected broad-access finding: %#v", got)
	}
}

func TestPhase101SecretAccessRuleFailsWhenBroadlyAccessible(t *testing.T) {
	s := secretinv.PlaintextRiskSummary{
		InspectionState: "COMPLETE", EligibleFiles: 1, InspectedFiles: 1,
		FilesWithIndicators: 1, IndicatorCount: 1, BroadlyAccessibleWithIndicators: 1,
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase101RiskObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, findings, "CHM-SEC-002"); got.Status != StatusFail {
		t.Fatalf("expected broad-access failure: %#v", got)
	}
}

func TestPhase101SecretRulesStayUnknownWhenCleanResultHasIncompleteCoverage(t *testing.T) {
	s := secretinv.PlaintextRiskSummary{
		InspectionState: "DEGRADED", EligibleFiles: 2, InspectedFiles: 1, DeniedFiles: 1,
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase101RiskObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CHM-SEC-001", "CHM-SEC-002"} {
		if got := findingByRule(t, findings, id); got.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN for incomplete clean coverage: %#v", got)
		}
	}
}

func TestPhase102PrivateKeyReadAndWriteExposureRulesFail(t *testing.T) {
	s := secretinv.PrivateKeyPermissionSummary{
		AssessmentState: secretinv.PrivateKeyAssessmentComplete,
		Keys:            2, UserKeys: 1, SystemKeys: 1, PermissionAssessed: 2,
		ReadExposed: 1, ReadRestricted: 1, WriteExposed: 1, WriteRestricted: 1,
		SystemOwnerExpected: 1,
		Records: []secretinv.PrivateKeyPermissionRecord{
			{RecordID: "u", Scope: "USER", Path: "/home/u/.ssh/id_ed25519", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.PrivateKeyPostureExposed, WritePosture: secretinv.PrivateKeyPostureExposed, OwnerPosture: secretinv.PrivateKeyPostureNotApplicable},
			{RecordID: "s", Scope: "SYSTEM", Path: "/etc/ssh/ssh_host_ed25519_key", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.PrivateKeyPostureRestricted, WritePosture: secretinv.PrivateKeyPostureRestricted, OwnerPosture: secretinv.PrivateKeyPostureExpected},
		},
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase102PrivateKeyObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, findings, "CHM-SEC-003"); got.Status != StatusFail {
		t.Fatalf("expected read-exposure failure: %#v", got)
	}
	if got := findingByRule(t, findings, "CHM-SEC-004"); got.Status != StatusFail {
		t.Fatalf("expected write-exposure failure: %#v", got)
	}
	if got := findingByRule(t, findings, "CHM-SEC-005"); got.Status != StatusPass {
		t.Fatalf("expected system ownership pass: %#v", got)
	}
}

func TestPhase102SystemPrivateKeyOwnershipRuleFails(t *testing.T) {
	s := secretinv.PrivateKeyPermissionSummary{
		AssessmentState: secretinv.PrivateKeyAssessmentComplete,
		Keys:            1, SystemKeys: 1, PermissionAssessed: 1,
		ReadRestricted: 1, WriteRestricted: 1, SystemOwnerUnexpected: 1,
		Records: []secretinv.PrivateKeyPermissionRecord{
			{RecordID: "s", Scope: "SYSTEM", Path: "/etc/ssh/ssh_host_rsa_key", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.PrivateKeyPostureRestricted, WritePosture: secretinv.PrivateKeyPostureRestricted, OwnerPosture: secretinv.PrivateKeyPostureUnexpected},
		},
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase102PrivateKeyObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, findings, "CHM-SEC-005"); got.Status != StatusFail {
		t.Fatalf("expected ownership failure: %#v", got)
	}
}

func TestPhase102PrivateKeyRulesStayUnknownWhenPermissionEvidenceIncomplete(t *testing.T) {
	s := secretinv.PrivateKeyPermissionSummary{
		AssessmentState: secretinv.PrivateKeyAssessmentDegraded,
		Keys:            1, UserKeys: 1, PermissionAssessed: 0, UnknownPosture: 1,
		Records: []secretinv.PrivateKeyPermissionRecord{
			{RecordID: "u", Scope: "USER", Path: "/home/u/.ssh/id_ed25519", PermissionState: "DENIED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.PrivateKeyPostureUnknown, WritePosture: secretinv.PrivateKeyPostureUnknown, OwnerPosture: secretinv.PrivateKeyPostureNotApplicable},
		},
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase102PrivateKeyObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CHM-SEC-003", "CHM-SEC-004"} {
		if got := findingByRule(t, findings, id); got.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN for incomplete private-key evidence: %#v", got)
		}
	}
	if got := findingByRule(t, findings, "CHM-SEC-005"); got.Applicability != NotApplicable {
		t.Fatalf("user-only key inventory should make system ownership rule not applicable: %#v", got)
	}
}

func TestImplementedRulesIncludesPhase103SecretRulesExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		counts[r.ID]++
	}
	for _, id := range []string{"CHM-SEC-001", "CHM-SEC-002", "CHM-SEC-003", "CHM-SEC-004", "CHM-SEC-005", "CHM-SEC-006", "CHM-SEC-007"} {
		if counts[id] != 1 {
			t.Fatalf("%s count=%d", id, counts[id])
		}
	}
}

func phase103CredentialObservation(s secretinv.CredentialFilePostureSummary) evidence.Observation {
	return evidence.NewObserved("secret_storage.credential_file_posture", s, "credential-file permission test evidence", time.Now().UTC(), evidence.ConfidenceHigh)
}

func TestPhase103CredentialReadAndWriteExposureRulesFail(t *testing.T) {
	s := secretinv.CredentialFilePostureSummary{
		AssessmentState: secretinv.CredentialAssessmentComplete,
		Files:           2, CredentialBearing: 1, ConfigurationOnly: 1, PermissionAssessed: 2,
		ReadExposed: 1, ReadNotApplicable: 1, WriteRestricted: 1, WriteExposed: 1,
		Providers: []secretinv.CredentialProviderSummary{
			{Provider: "AWS", Files: 1, CredentialBearing: 1, ReadExposed: 1},
			{Provider: "GIT", Files: 1, ConfigurationOnly: 1, WriteExposed: 1},
		},
		Records: []secretinv.CredentialFilePostureRecord{
			{RecordID: "aws", Provider: "AWS", Role: "CREDENTIAL_FILE", Sensitivity: secretinv.CredentialSensitivityCredential, Scope: "USER", Path: "/home/u/.aws/credentials", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.CredentialPostureExposed, WritePosture: secretinv.CredentialPostureRestricted},
			{RecordID: "git", Provider: "GIT", Role: "GLOBAL_CONFIG", Sensitivity: secretinv.CredentialSensitivityConfiguration, Scope: "USER", Path: "/home/u/.gitconfig", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.CredentialPostureNotApplicable, WritePosture: secretinv.CredentialPostureExposed},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase103CredentialObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, findings, "CHM-SEC-006"); got.Status != StatusFail {
		t.Fatalf("expected credential read-exposure failure: %#v", got)
	}
	if got := findingByRule(t, findings, "CHM-SEC-007"); got.Status != StatusFail {
		t.Fatalf("expected credential/config write-exposure failure: %#v", got)
	}
}

func TestPhase103CredentialRulesStayUnknownWhenPermissionEvidenceIncomplete(t *testing.T) {
	s := secretinv.CredentialFilePostureSummary{
		AssessmentState: secretinv.CredentialAssessmentDegraded,
		Files:           1, CredentialBearing: 1, PermissionAssessed: 0,
		ReadUnknown: 1, WriteUnknown: 1, UnknownPosture: 1,
		Providers: []secretinv.CredentialProviderSummary{{Provider: "KUBERNETES", Files: 1, CredentialBearing: 1, UnknownPosture: 1}},
		Records:   []secretinv.CredentialFilePostureRecord{{RecordID: "k", Provider: "KUBERNETES", Role: "KUBECONFIG", Sensitivity: secretinv.CredentialSensitivityMixed, Scope: "USER", Path: "/home/u/.kube/config", PermissionState: "DENIED", PermissionModel: "POSIX_MODE", ReadPosture: secretinv.CredentialPostureUnknown, WritePosture: secretinv.CredentialPostureUnknown}},
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	findings, err := EvaluateRules(SecretStorageRules(), []evidence.Observation{phase103CredentialObservation(s)}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CHM-SEC-006", "CHM-SEC-007"} {
		if got := findingByRule(t, findings, id); got.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN for incomplete credential-file evidence: %#v", got)
		}
	}
}

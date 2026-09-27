package assessment

import (
	"fmt"

	"github.com/Nikolov999/chimera/internal/evidence"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
)

// SecretStorageRules implement redacted plaintext-secret risk indicators,
// private-key ownership/access permission rules, and cloud/
// developer credential-file permission posture. Rules consume normalized evidence;
// credential values and private-key content never enter findings.
func SecretStorageRules() []Rule {
	return []Rule{
		{
			ID: "CHM-SEC-001", Title: "Likely plaintext secret material is not stored in inspected local files", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.plaintext_indicators", ExpectedState: "no likely plaintext-secret indicators detected in eligible inspected files",
			Risk:        "Plaintext passwords, tokens, private-key material, embedded credentials, or similar secret values can be exposed through file access, backups, support bundles, or accidental disclosure.",
			Remediation: "Move secrets into an appropriate protected credential store or secret-management mechanism, remove unnecessary plaintext copies, rotate exposed credentials where warranted, and rerun Chimera. Do not paste secret values into remediation records.",
			Evaluate:    evaluatePlaintextSecretIndicators,
		},
		{
			ID: "CHM-SEC-002", Title: "Files with likely plaintext secrets are not broadly accessible", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.plaintext_indicators.access", ExpectedState: "no file containing likely plaintext-secret indicators is broadly accessible",
			Risk:        "A plaintext secret stored in a file readable by broad or unrelated principals increases the chance of credential disclosure and lateral access.",
			Remediation: "Restrict the affected file to the minimum required principals and migrate the secret to a protected store. Rotate credentials if unauthorized read access may have occurred.",
			Evaluate:    evaluatePlaintextSecretAccess,
		},
		{
			ID: "CHM-SEC-003", Title: "Private keys are not readable by broad or unrelated principals", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.private_keys.read_access", ExpectedState: "private-key read access is restricted to the owning or explicitly trusted principal set",
			Risk:        "A private key readable by broad or unrelated principals can enable account impersonation, service compromise, unauthorized decryption, or lateral access.",
			Remediation: "Restrict the private-key file to the minimum required owner/principal set. For user keys, remove group/world read access; for Windows keys, remove broad Users/Authenticated Users/Everyone read grants. Verify any intentionally group-readable system key against local policy.",
			Evaluate:    evaluatePrivateKeyReadPermissions,
		},
		{
			ID: "CHM-SEC-004", Title: "Private keys are not writable by broad principals", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.private_keys.write_access", ExpectedState: "private-key files are not group/world/broad-principal writable",
			Risk:        "Broad write access to a private-key file can let another principal replace or corrupt key material, redirect trust, or disrupt authentication.",
			Remediation: "Remove broad write/modify grants from private-key files and retain write access only for the owning or explicitly required administrative principal.",
			Evaluate:    evaluatePrivateKeyWritePermissions,
		},
		{
			ID: "CHM-SEC-005", Title: "System private keys are owned by a privileged system principal", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.private_keys.system_owner", ExpectedState: "system-scoped private keys are owned by root/SYSTEM/Administrators-equivalent control",
			Risk:        "A system private key owned by a non-privileged or unexpected principal weakens the trust boundary around host and service identity material.",
			Remediation: "Restore system private-key ownership to the platform-appropriate privileged principal and verify the service still has only the access it requires.",
			Evaluate:    evaluatePrivateKeySystemOwnership,
		},
		{
			ID: "CHM-SEC-006", Title: "Cloud and developer credential files are not broadly readable", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.credential_files.read_access", ExpectedState: "credential-bearing AWS/Azure/GCP/Kubernetes/Git/npm/pip and similar local files are not readable by broad or unrelated principals",
			Risk:        "Broad read access to local cloud or developer credential files can expose reusable tokens, client credentials, registry credentials, kubeconfig authentication material, or other account access material.",
			Remediation: "Restrict credential-bearing files to the owning or explicitly required principal set. Rotate credentials when unauthorized read access may have occurred. Do not copy credential values into tickets or reports.",
			Evaluate:    evaluateCredentialFileReadPermissions,
		},
		{
			ID: "CHM-SEC-007", Title: "Cloud and developer credential/config files are not broadly writable", Category: "secrets", Severity: SeverityHigh,
			AffectedObject: "secret_storage.credential_files.write_access", ExpectedState: "credential and security-relevant client configuration files are not writable by broad or unrelated principals",
			Risk:        "Broad write access can let another principal replace credentials, alter registry or endpoint configuration, redirect credential helpers, or weaken authentication behavior even when the file itself does not contain a secret value.",
			Remediation: "Remove broad write/modify grants and retain write access only for the owning or explicitly required administrative principal. Review affected client configuration for unauthorized changes before restoring trust.",
			Evaluate:    evaluateCredentialFileWritePermissions,
		},
	}
}

func plaintextRisk(idx Index) (secretinv.PlaintextRiskSummary, evidence.Observation, bool) {
	o, ok := idx["secret_storage.plaintext_risk"]
	if !ok {
		return secretinv.PlaintextRiskSummary{}, evidence.Observation{}, false
	}
	s, ok := o.Value.(secretinv.PlaintextRiskSummary)
	return s, o, ok
}

func evaluatePlaintextSecretIndicators(idx Index) Evaluation {
	const key = "secret_storage.plaintext_risk"
	s, o, ok := plaintextRisk(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "plaintext-secret risk evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.FilesWithIndicators > 0 {
		return Evaluation{
			Status: StatusFail, Confidence: evidence.ConfidenceHigh,
			ObservedState: fmt.Sprintf("%d likely plaintext-secret indicator(s) across %d file(s); matched values are redacted", s.IndicatorCount, s.FilesWithIndicators),
			Applicability: Applicable, EvidenceKeys: []string{key},
		}
	}
	if s.EligibleFiles > 0 && (s.InspectedFiles == 0 || s.InspectionState == "DEGRADED") {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceMedium,
			ObservedState: fmt.Sprintf("no indicator observed, but inspection coverage is incomplete: eligible=%d inspected=%d denied=%d unavailable=%d partial=%d", s.EligibleFiles, s.InspectedFiles, s.DeniedFiles, s.UnavailableFiles, s.PartiallyInspectedFiles),
			Applicability: Applicable, EvidenceKeys: []string{key},
		}
	}
	return Evaluation{
		Status: StatusPass, Confidence: evidence.ConfidenceHigh,
		ObservedState: fmt.Sprintf("no likely plaintext-secret indicators detected across %d inspected eligible file(s)", s.InspectedFiles),
		Applicability: Applicable, EvidenceKeys: []string{key},
	}
}

func evaluatePlaintextSecretAccess(idx Index) Evaluation {
	const key = "secret_storage.plaintext_risk"
	s, o, ok := plaintextRisk(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "plaintext-secret risk evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.BroadlyAccessibleWithIndicators > 0 {
		return Evaluation{
			Status: StatusFail, Confidence: evidence.ConfidenceHigh,
			ObservedState: fmt.Sprintf("%d file(s) with redacted plaintext-secret indicators are broadly accessible", s.BroadlyAccessibleWithIndicators),
			Applicability: Applicable, EvidenceKeys: []string{key},
		}
	}
	if s.FilesWithIndicators > 0 && s.UnknownAccessWithIndicators > 0 {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceMedium,
			ObservedState: fmt.Sprintf("%d file(s) contain redacted plaintext-secret indicators but broad-access posture is unresolved", s.UnknownAccessWithIndicators),
			Applicability: Applicable, EvidenceKeys: []string{key},
		}
	}
	if s.FilesWithIndicators == 0 && s.EligibleFiles > 0 && (s.InspectedFiles == 0 || s.InspectionState == "DEGRADED") {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceMedium,
			ObservedState: "plaintext-secret inspection coverage is incomplete, so broad-access correlation cannot be fully established",
			Applicability: Applicable, EvidenceKeys: []string{key},
		}
	}
	return Evaluation{
		Status: StatusPass, Confidence: evidence.ConfidenceHigh,
		ObservedState: "no broadly accessible file with a likely plaintext-secret indicator was observed",
		Applicability: Applicable, EvidenceKeys: []string{key},
	}
}

func privateKeyPermissions(idx Index) (secretinv.PrivateKeyPermissionSummary, evidence.Observation, bool) {
	o, ok := idx["secret_storage.private_key_permissions"]
	if !ok {
		return secretinv.PrivateKeyPermissionSummary{}, evidence.Observation{}, false
	}
	s, ok := o.Value.(secretinv.PrivateKeyPermissionSummary)
	return s, o, ok
}

func evaluatePrivateKeyReadPermissions(idx Index) Evaluation {
	const key = "secret_storage.private_key_permissions"
	s, o, ok := privateKeyPermissions(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "private-key permission evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.Keys == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "no private-key files were present in the bounded secret-storage inventory", Applicability: NotApplicable, EvidenceKeys: []string{key}}
	}
	if s.ReadExposed > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d private-key file(s) have broad/unrelated-principal read exposure", s.ReadExposed, s.Keys), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.UnknownPosture > 0 || s.PermissionAssessed < s.Keys {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad private-key read exposure was proven, but permission coverage is incomplete: keys=%d assessed=%d unknown=%d", s.Keys, s.PermissionAssessed, s.UnknownPosture), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.ReadReview > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d system private-key file(s) are group-readable and require explicit trusted-group policy review; no world/broad-principal read exposure observed", s.ReadReview), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("read access is restricted for %d observed private-key file(s)", s.Keys), Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluatePrivateKeyWritePermissions(idx Index) Evaluation {
	const key = "secret_storage.private_key_permissions"
	s, o, ok := privateKeyPermissions(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "private-key permission evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.Keys == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "no private-key files were present in the bounded secret-storage inventory", Applicability: NotApplicable, EvidenceKeys: []string{key}}
	}
	if s.WriteExposed > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d private-key file(s) are writable by broad principals", s.WriteExposed, s.Keys), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.UnknownPosture > 0 || s.PermissionAssessed < s.Keys {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad private-key write exposure was proven, but permission coverage is incomplete: keys=%d assessed=%d unknown=%d", s.Keys, s.PermissionAssessed, s.UnknownPosture), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("no broad write access observed across %d private-key file(s)", s.Keys), Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluatePrivateKeySystemOwnership(idx Index) Evaluation {
	const key = "secret_storage.private_key_permissions"
	s, o, ok := privateKeyPermissions(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "private-key permission evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.SystemKeys == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "no system-scoped private-key files were present in the bounded inventory", Applicability: NotApplicable, EvidenceKeys: []string{key}}
	}
	if s.SystemOwnerUnexpected > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d system private-key file(s) have unexpected ownership", s.SystemOwnerUnexpected, s.SystemKeys), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.SystemOwnerExpected < s.SystemKeys {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("system private-key ownership is incomplete: system_keys=%d expected_owner=%d", s.SystemKeys, s.SystemOwnerExpected), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("all %d observed system private-key file(s) are owned by the expected privileged principal", s.SystemKeys), Applicability: Applicable, EvidenceKeys: []string{key}}
}

func credentialFilePosture(idx Index) (secretinv.CredentialFilePostureSummary, evidence.Observation, bool) {
	o, ok := idx["secret_storage.credential_file_posture"]
	if !ok {
		return secretinv.CredentialFilePostureSummary{}, evidence.Observation{}, false
	}
	s, ok := o.Value.(secretinv.CredentialFilePostureSummary)
	return s, o, ok
}

func evaluateCredentialFileReadPermissions(idx Index) Evaluation {
	const key = "secret_storage.credential_file_posture"
	s, o, ok := credentialFilePosture(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "credential-file posture evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.CredentialBearing == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "no credential-bearing cloud/developer files were present in the bounded inventory", Applicability: NotApplicable, EvidenceKeys: []string{key}}
	}
	if s.ReadExposed > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d credential-bearing cloud/developer file(s) are readable by broad or unrelated principals", s.ReadExposed, s.CredentialBearing), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.ReadUnknown > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad credential-file read access was proven, but read-permission posture is unresolved for %d of %d credential-bearing file(s)", s.ReadUnknown, s.CredentialBearing), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("read access is restricted for all %d observed credential-bearing cloud/developer file(s)", s.CredentialBearing), Applicability: Applicable, EvidenceKeys: []string{key}}
}

func evaluateCredentialFileWritePermissions(idx Index) Evaluation {
	const key = "secret_storage.credential_file_posture"
	s, o, ok := credentialFilePosture(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "credential-file posture evidence unavailable", Applicability: Undetermined, EvidenceKeys: []string{key}}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.Files == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "no cloud/developer credential or security-relevant client configuration files were present in the bounded inventory", Applicability: NotApplicable, EvidenceKeys: []string{key}}
	}
	if s.WriteExposed > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d cloud/developer credential or configuration file(s) are writable by broad or unrelated principals", s.WriteExposed, s.Files), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	if s.WriteUnknown > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no broad credential/config write access was proven, but write-permission posture is unresolved for %d of %d file(s)", s.WriteUnknown, s.Files), Applicability: Applicable, EvidenceKeys: []string{key}}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("no broad write access observed across %d cloud/developer credential or configuration file(s)", s.Files), Applicability: Applicable, EvidenceKeys: []string{key}}
}

package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

// SSHKeyPostureRules implements using metadata-only local filesystem
// and ACL evidence. Private-key contents and authorized_keys contents are never
// required by these rules.
func SSHKeyPostureRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-039", Title: "SSH key directories and trust-path ancestors resist untrusted writes", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "ssh.key_path.directory_integrity", ExpectedState: "home/.ssh path boundaries used for local SSH key trust are not writable by untrusted principals and retain expected ownership",
			Risk:        "A writable SSH home or .ssh directory can let another local principal replace key files or authorized-key policy and convert a weaker file-write boundary into account access.",
			Remediation: "Restore the affected home/.ssh ownership to the intended account or trusted system owner and remove group, world, or broadly delegated write access before relying on SSH key authentication.",
			Evaluate:    evaluateSSHDirectoryIntegrity,
		},
		{
			ID: "CHM-ID-040", Title: "authorized_keys files resist unauthorized modification", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "ssh.authorized_keys.integrity", ExpectedState: "authorized_keys files are owned by the intended account or trusted system owner and are not writable through broad local permissions or ACLs",
			Risk:        "A locally writable authorized_keys file can allow another principal to add an SSH public key and create an unintended authentication path into the affected account.",
			Remediation: "Restore secure ownership and write permissions on the affected authorized_keys file and its containing directories, then review the authorized key set through approved administrative tooling.",
			Evaluate:    evaluateAuthorizedKeysIntegrity,
		},
		{
			ID: "CHM-ID-041", Title: "Local SSH private-key candidates are not broadly accessible", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "ssh.private_key.permissions", ExpectedState: "recognized SSH private-key candidate files are not group/world/broad-ACL readable or writable and retain expected ownership",
			Risk:        "Overly broad read access can expose private authentication material to other local principals, while broad write access can replace or corrupt trusted key material.",
			Remediation: "Restrict each reported private-key candidate to the owning account or approved system administrator boundary and remove broad read/write ACLs or group/world permissions. Rotate keys if unauthorized read access may have occurred.",
			Evaluate:    evaluateSSHPrivateKeyPermissions,
		},
		{
			ID: "CHM-ID-042", Title: "Direct SSH key access to privileged local accounts is explicitly reviewed", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "ssh.privileged.authorized_keys", ExpectedState: "direct authorized_keys access for root/administrator-equivalent local accounts is absent or explicitly approved",
			Risk:        "Direct key-based access to a privileged local identity creates a high-impact authentication path whose compromise bypasses a separate privilege-elevation step.",
			Remediation: "Prefer key-based access to a non-privileged named account followed by controlled elevation where operationally possible. Where direct privileged SSH access is required, document ownership, restrict source/network policy, and tightly manage authorized keys.",
			Evaluate:    evaluatePrivilegedAuthorizedKeysPresence,
		},
		{
			ID: "CHM-ID-043", Title: "Privileged authorized_keys paths retain strict local integrity", Category: "identity", Severity: SeverityCritical,
			AffectedObject: "ssh.privileged.authorized_keys_integrity", ExpectedState: "authorized_keys files for root/administrator-equivalent accounts and their SSH directories are not writable through weaker local boundaries",
			Risk:        "Weak write access on a privileged account's SSH trust path can turn ordinary local file modification into direct privileged authentication capability.",
			Remediation: "Immediately restore trusted ownership and restrictive write permissions on the privileged account's home, .ssh directory, and authorized_keys file; then review the authorized key set and investigate unauthorized modification.",
			Evaluate:    evaluatePrivilegedAuthorizedKeysIntegrity,
		},
	}
}

type sshPathEvidence struct {
	Key    string
	Record accounts.SSHKeyPathRecord
}

func evaluateSSHDirectoryIntegrity(idx Index) Evaluation {
	if e, ok := sshPostureNotApplicable(idx); ok {
		return e
	}
	bad := []sshPathEvidence{}
	for _, item := range sshPathEvidenceItems(idx) {
		if item.Record.State == evidence.StateObserved && (item.Record.Kind == "HOME_DIRECTORY" || item.Record.Kind == "SSH_DIRECTORY") && item.Record.Insecure {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return sshPathFailure(bad, "weak SSH directory/ancestor boundaries")
	}
	return sshCleanOrUnknown(idx, "no weak local write or ownership boundary was observed on SSH home/.ssh paths")
}

func evaluateAuthorizedKeysIntegrity(idx Index) Evaluation {
	if e, ok := sshPostureNotApplicable(idx); ok {
		return e
	}
	bad := []sshPathEvidence{}
	for _, item := range sshPathEvidenceItems(idx) {
		if item.Record.State == evidence.StateObserved && item.Record.Kind == "AUTHORIZED_KEYS" && item.Record.Insecure {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return sshPathFailure(bad, "weak authorized_keys integrity")
	}
	return sshCleanOrUnknown(idx, "all observed authorized_keys files retain expected ownership and write boundaries")
}

func evaluateSSHPrivateKeyPermissions(idx Index) Evaluation {
	if e, ok := sshPostureNotApplicable(idx); ok {
		return e
	}
	bad := []sshPathEvidence{}
	for _, item := range sshPathEvidenceItems(idx) {
		if item.Record.State == evidence.StateObserved && item.Record.Kind == "PRIVATE_KEY_CANDIDATE" && item.Record.Insecure {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return sshPathFailure(bad, "overexposed SSH private-key candidate metadata")
	}
	return sshCleanOrUnknown(idx, "no broadly readable/writable recognized SSH private-key candidate was observed")
}

func evaluatePrivilegedAuthorizedKeysPresence(idx Index) Evaluation {
	if e, ok := sshPostureNotApplicable(idx); ok {
		return e
	}
	found := []sshPathEvidence{}
	for _, item := range sshPathEvidenceItems(idx) {
		if item.Record.State == evidence.StateObserved && item.Record.Kind == "AUTHORIZED_KEYS" && item.Record.Privileged {
			found = append(found, item)
		}
	}
	if len(found) > 0 {
		parts, keys := sshPathDescriptions(found)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "direct authorized_keys paths exist for privileged local accounts: " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sshCleanOrUnknown(idx, "no direct authorized_keys path was observed for a privileged local account")
}

func evaluatePrivilegedAuthorizedKeysIntegrity(idx Index) Evaluation {
	if e, ok := sshPostureNotApplicable(idx); ok {
		return e
	}
	privilegedPrincipals := map[string]struct{}{}
	bad := []sshPathEvidence{}
	for _, item := range sshPathEvidenceItems(idx) {
		r := item.Record
		if r.State != evidence.StateObserved || !r.Privileged {
			continue
		}
		if r.Kind == "AUTHORIZED_KEYS" {
			privilegedPrincipals[strings.ToLower(r.Principal)] = struct{}{}
			if r.Insecure {
				bad = append(bad, item)
			}
		}
	}
	if len(privilegedPrincipals) == 0 {
		return sshCleanOrUnknown(idx, "no privileged authorized_keys path requires integrity correlation")
	}
	for _, item := range sshPathEvidenceItems(idx) {
		r := item.Record
		if r.State != evidence.StateObserved || !r.Privileged || (r.Kind != "HOME_DIRECTORY" && r.Kind != "SSH_DIRECTORY") || !r.Insecure {
			continue
		}
		if _, ok := privilegedPrincipals[strings.ToLower(r.Principal)]; ok {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		return sshPathFailure(bad, "weak privileged SSH trust-path integrity")
	}
	return sshCleanOrUnknown(idx, fmt.Sprintf("%d privileged account(s) with authorized_keys retain observed trusted local write boundaries", len(privilegedPrincipals)))
}

func sshPathFailure(items []sshPathEvidence, prefix string) Evaluation {
	parts, keys := sshPathDescriptions(items)
	return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: prefix + ": " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
}

func sshPathDescriptions(items []sshPathEvidence) ([]string, []string) {
	parts := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		reason := strings.Join(item.Record.InsecureBasis, ", ")
		if reason == "" {
			reason = "review required"
		}
		parts = append(parts, fmt.Sprintf("%s %s [%s]", item.Record.Principal, item.Record.Path, reason))
		keys = append(keys, item.Key)
	}
	sort.Strings(parts)
	sort.Strings(keys)
	return parts, keys
}

func sshPostureNotApplicable(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "linux" && platform != "darwin" && platform != "windows" {
		keys := sshProviderEvidenceKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "SSH key/authorized_keys posture is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	if o, ok := idx["account.ssh_key.provider"]; ok && o.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: NotApplicable, EvidenceKeys: []string{o.Key}}, true
	}
	return Evaluation{}, false
}

func sshCleanOrUnknown(idx Index, clean string) Evaluation {
	o, ok := idx["account.ssh_key.provider"]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SSH key/authorized_keys provider evidence is missing", Applicability: Undetermined, EvidenceKeys: sshProviderEvidenceKeys(idx)}
	}
	if o.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: sshProviderEvidenceKeys(idx)}
	}
	if m, ok := o.Value.(map[string]any); ok && strings.EqualFold(fmt.Sprint(m["state"]), string(evidence.StateDegraded)) {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: "SSH metadata collection was degraded; a clean conclusion is not defensible", Applicability: Applicable, EvidenceKeys: sshProviderEvidenceKeys(idx)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: clean, Applicability: Applicable, EvidenceKeys: sshProviderEvidenceKeys(idx)}
}

func sshProviderEvidenceKeys(idx Index) []string {
	keys := []string{}
	for _, key := range []string{"account.platform", "account.ssh_key.provider", "account.ssh_key.summary"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sshPathEvidenceItems(idx Index) []sshPathEvidence {
	out := []sshPathEvidence{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.ssh_key.path.") || obs.State != evidence.StateObserved {
			continue
		}
		if r, ok := obs.Value.(accounts.SSHKeyPathRecord); ok {
			out = append(out, sshPathEvidence{Key: key, Record: r})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

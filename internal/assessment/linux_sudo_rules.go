package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

const sudoersManualURL = "https://www.sudo.ws/docs/man/sudoers.man/"

// LinuxSudoRules implements . The rules consume only normalized,
// read-only sudoers authorization and filesystem metadata collected locally by
// the accounts collector. They never authenticate through sudo or execute a
// configured sudo command.
func LinuxSudoRules() []Rule {
	return []Rule{
		{
			ID: "CHM-ID-021", Title: "NOPASSWD sudo grants are narrowly scoped", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "linux.sudo.nopasswd_scope", ExpectedState: "NOPASSWD is not combined with ALL or wildcard command specifications",
			Risk:        "Broad passwordless sudo delegation can turn compromise of a delegated local account into immediate privileged command execution without an additional authentication boundary.",
			Remediation: "Replace broad NOPASSWD grants with the smallest explicit command set required for the workload, keep paths immutable to delegated users, and require authentication where unattended execution is not necessary.",
			References:  []Reference{{Title: "sudoers manual", URL: sudoersManualURL}},
			Evaluate:    evaluateSudoNOPASSWDOverbreadth,
		},
		{
			ID: "CHM-ID-022", Title: "Sudo command grants are least-privilege scoped", Category: "identity", Severity: SeverityMedium,
			AffectedObject: "linux.sudo.unrestricted_commands", ExpectedState: "delegated sudo rules avoid unrestricted ALL command grants unless explicitly accepted as administrator policy",
			Risk:        "An unrestricted sudo command grant provides root-equivalent command authority to the matching principal and therefore materially expands the consequence of account compromise or policy error.",
			Remediation: "Use explicit command allow-lists for delegated operational roles. Where full administrator authority is intentional, document the exception and tightly control membership in the matching principal or group.",
			References:  []Reference{{Title: "sudoers manual", URL: sudoersManualURL}},
			Evaluate:    evaluateSudoUnrestrictedGrants,
		},
		{
			ID: "CHM-ID-023", Title: "Sudo environment preservation is constrained", Category: "identity", Severity: SeverityHigh,
			AffectedObject: "linux.sudo.environment", ExpectedState: "env_reset remains enabled and dangerous loader/interpreter variables or SETENV delegation are not broadly preserved",
			Risk:        "Weak sudo environment controls can allow a delegated principal to influence privileged program loading or interpreter behavior through attacker-controlled environment state.",
			Remediation: "Keep env_reset enabled, remove dangerous variables from env_keep, and avoid SETENV delegation unless a narrowly scoped operational requirement has been reviewed.",
			References:  []Reference{{Title: "sudoers manual", URL: sudoersManualURL}},
			Evaluate:    evaluateSudoEnvironment,
		},
		{
			ID: "CHM-ID-024", Title: "Sudo-referenced executables and scripts are protected from weak writes", Category: "identity", Severity: SeverityCritical,
			AffectedObject: "linux.sudo.referenced_paths", ExpectedState: "sudo-authorized executable and interpreter-script paths are not writable through non-root, group, world, or weak parent-directory boundaries",
			Risk:        "If a sudo-authorized executable or script can be modified or replaced through a weaker local write boundary, the authorized principal may be able to convert that file write into privileged code execution.",
			Remediation: "Move sudo-authorized code to root-controlled paths, remove unnecessary write grants from the file and parent directories, and separate editable data from privileged executable content.",
			References:  []Reference{{Title: "sudoers manual", URL: sudoersManualURL}},
			Evaluate:    evaluateSudoWritableReferences,
		},
		{
			ID: "CHM-ID-025", Title: "Sudoers configuration paths are securely owned and writable", Category: "identity", Severity: SeverityCritical,
			AffectedObject: "linux.sudo.configuration_integrity", ExpectedState: "sudoers files and include directories are root-owned and are not group- or world-writable",
			Risk:        "A writable sudoers file or include directory allows local policy tampering at the privilege-delegation boundary and can grant unintended root-equivalent authority.",
			Remediation: "Restore root ownership and restrictive write permissions on /etc/sudoers and every active include file/directory, then validate the resulting configuration with approved sudo tooling.",
			References:  []Reference{{Title: "sudoers manual", URL: sudoersManualURL}},
			Evaluate:    evaluateSudoConfigIntegrity,
		},
	}
}

type sudoGrantEvidence struct {
	Key   string
	Grant accounts.SudoGrant
}

type sudoEnvEvidence struct {
	Key   string
	Issue accounts.SudoEnvironmentIssue
}

type sudoPathEvidence struct {
	Key   string
	Issue accounts.SudoPathIssue
}

type sudoConfigEvidence struct {
	Key  string
	Path accounts.SudoConfigPath
}

func evaluateSudoNOPASSWDOverbreadth(idx Index) Evaluation {
	if e, ok := linuxSudoNotApplicable(idx); ok {
		return e
	}
	var bad []string
	var keys []string
	for _, item := range sudoGrantEvidenceItems(idx) {
		for _, cmd := range item.Grant.Commands {
			if cmd.Negated || !cmd.NOPASSWD || (!cmd.Unrestricted && !cmd.Wildcard) {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s %s:%d -> %s", item.Grant.Subjects, item.Grant.Source, item.Grant.Line, cmd.Spec))
			keys = appendUnique(keys, item.Key)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "broad NOPASSWD command specifications: " + strings.Join(bad, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sudoCleanOrUnknown(idx, "no NOPASSWD grant is combined with ALL or wildcard command scope")
}

func evaluateSudoUnrestrictedGrants(idx Index) Evaluation {
	if e, ok := linuxSudoNotApplicable(idx); ok {
		return e
	}
	var bad []string
	var keys []string
	for _, item := range sudoGrantEvidenceItems(idx) {
		for _, cmd := range item.Grant.Commands {
			if cmd.Negated || !cmd.Unrestricted {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s %s:%d -> ALL", item.Grant.Subjects, item.Grant.Source, item.Grant.Line))
			keys = appendUnique(keys, item.Key)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		sort.Strings(keys)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "unrestricted sudo command authority is configured: " + strings.Join(bad, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sudoCleanOrUnknown(idx, "no unrestricted positive ALL command grant was observed")
}

func evaluateSudoEnvironment(idx Index) Evaluation {
	if e, ok := linuxSudoNotApplicable(idx); ok {
		return e
	}
	var critical []string
	var warning []string
	var keys []string
	for _, item := range sudoEnvironmentEvidenceItems(idx) {
		detail := fmt.Sprintf("%s %s:%d", item.Issue.Kind, item.Issue.Source, item.Issue.Line)
		switch item.Issue.Kind {
		case "ENV_RESET_DISABLED", "DANGEROUS_ENV_KEEP":
			critical = append(critical, detail)
		default:
			warning = append(warning, detail)
		}
		keys = appendUnique(keys, item.Key)
	}
	for _, item := range sudoGrantEvidenceItems(idx) {
		for _, cmd := range item.Grant.Commands {
			if cmd.Negated || !cmd.SetEnv {
				continue
			}
			warning = append(warning, fmt.Sprintf("SETENV %s %s:%d -> %s", item.Grant.Subjects, item.Grant.Source, item.Grant.Line, cmd.Spec))
			keys = appendUnique(keys, item.Key)
		}
	}
	if len(critical) > 0 {
		sort.Strings(critical)
		sort.Strings(warning)
		sort.Strings(keys)
		parts := append([]string(nil), critical...)
		parts = append(parts, warning...)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "unsafe sudo environment controls: " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(warning) > 0 {
		sort.Strings(warning)
		sort.Strings(keys)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "explicit sudo environment delegation requires review: " + strings.Join(warning, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sudoCleanOrUnknown(idx, "no unsafe sudo environment-preservation construct was observed")
}

func evaluateSudoWritableReferences(idx Index) Evaluation {
	if e, ok := linuxSudoNotApplicable(idx); ok {
		return e
	}
	items := sudoPathEvidenceItems(idx)
	if len(items) > 0 {
		parts := make([]string, 0, len(items))
		keys := make([]string, 0, len(items))
		for _, item := range items {
			parts = append(parts, item.Issue.Path+" ["+item.Issue.Reason+"]")
			keys = append(keys, item.Key)
		}
		sort.Strings(parts)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: "sudo-authorized writable path boundaries: " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sudoCleanOrUnknown(idx, "no writable sudo-authorized executable/script boundary was observed")
}

func evaluateSudoConfigIntegrity(idx Index) Evaluation {
	if e, ok := linuxSudoNotApplicable(idx); ok {
		return e
	}
	var bad []sudoConfigEvidence
	for _, item := range sudoConfigEvidenceItems(idx) {
		if item.Path.State == evidence.StateObserved && item.Path.Insecure {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		parts := make([]string, 0, len(bad))
		keys := make([]string, 0, len(bad))
		for _, item := range bad {
			parts = append(parts, item.Path.Path+" ["+strings.Join(item.Path.InsecureBasis, ", ")+"]")
			keys = append(keys, item.Key)
		}
		sort.Strings(parts)
		sort.Strings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: "insecure sudoers configuration path metadata: " + strings.Join(parts, "; "), Applicability: Applicable, EvidenceKeys: keys}
	}
	return sudoCleanOrUnknown(idx, "all observed sudoers configuration paths are root-owned and not group/world-writable")
}

func linuxSudoNotApplicable(idx Index) (Evaluation, bool) {
	platform := accountPlatform(idx)
	if platform != "linux" {
		keys := sudoProviderEvidenceKeys(idx)
		if o, ok := idx["account.platform"]; ok {
			keys = appendUnique(keys, o.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "Linux sudo/sudoers assessment is not applicable to " + fallbackAccountPlatform(platform), Applicability: NotApplicable, EvidenceKeys: keys}, true
	}
	if provider, ok := idx["account.sudo.provider"]; ok && provider.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: provider.Confidence, ObservedState: observedText(provider), Applicability: NotApplicable, EvidenceKeys: []string{provider.Key}}, true
	}
	return Evaluation{}, false
}

func sudoCleanOrUnknown(idx Index, passText string) Evaluation {
	provider, ok := idx["account.sudo.provider"]
	keys := sudoProviderEvidenceKeys(idx)
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Linux sudoers provider evidence is missing", Applicability: Undetermined, EvidenceKeys: keys}
	}
	if provider.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: provider.Confidence, ObservedState: observedText(provider), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: passText, Applicability: Applicable, EvidenceKeys: keys}
}

func sudoProviderEvidenceKeys(idx Index) []string {
	var keys []string
	for _, key := range []string{"account.platform", "account.sudo.provider", "account.sudo.summary"} {
		if _, ok := idx[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sudoGrantEvidenceItems(idx Index) []sudoGrantEvidence {
	var out []sudoGrantEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.sudo.grant.") || obs.State != evidence.StateObserved {
			continue
		}
		if grant, ok := obs.Value.(accounts.SudoGrant); ok {
			out = append(out, sudoGrantEvidence{Key: key, Grant: grant})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sudoEnvironmentEvidenceItems(idx Index) []sudoEnvEvidence {
	var out []sudoEnvEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.sudo.environment.") || obs.State != evidence.StateObserved {
			continue
		}
		if issue, ok := obs.Value.(accounts.SudoEnvironmentIssue); ok {
			out = append(out, sudoEnvEvidence{Key: key, Issue: issue})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sudoPathEvidenceItems(idx Index) []sudoPathEvidence {
	var out []sudoPathEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.sudo.path.") || obs.State != evidence.StateObserved {
			continue
		}
		if issue, ok := obs.Value.(accounts.SudoPathIssue); ok {
			out = append(out, sudoPathEvidence{Key: key, Issue: issue})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sudoConfigEvidenceItems(idx Index) []sudoConfigEvidence {
	var out []sudoConfigEvidence
	for key, obs := range idx {
		if !strings.HasPrefix(key, "account.sudo.config.") || obs.State != evidence.StateObserved {
			continue
		}
		if path, ok := obs.Value.(accounts.SudoConfigPath); ok {
			out = append(out, sudoConfigEvidence{Key: key, Path: path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

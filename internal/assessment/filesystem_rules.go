package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
	"github.com/Nikolov999/chimera/internal/services"
)

// FilesystemRules returns the concrete filesystem assessment catalog implemented
// through . The rules consume bounded metadata-only executable,
// privileged search-path, Linux set-ID/file-capability, sensitive-file permission, native ACL boundary, temporary-directory, mount-hardening, and network-share evidence and never connect to remote shares, authenticate, execute, modify, hash, read sensitive file contents, or change mount state.
func FilesystemRules() []Rule {
	return []Rule{
		{
			ID: "CHM-FS-001", Title: "Executable files are not writable by broad untrusted principals", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.executable.untrusted_write", ExpectedState: "executable files discovered in bounded executable search locations do not grant write-equivalent access to untrusted broad principals",
			Risk:        "A world-writable executable on POSIX systems or an executable with broad low-privilege write-equivalent DACL grants on Windows can allow another local principal to replace code that users, services, administrators, or automation may later execute.",
			Remediation: "Remove broad write, modify, delete, ownership, or permission-changing access from the affected executable. Limit modification to the intended owner and narrowly scoped trusted administrative or deployment principals.",
			Evaluate:    evaluateUntrustedWritableExecutables,
		},
		{
			ID: "CHM-FS-002", Title: "Executable files avoid non-system group write exposure", Category: "filesystem", Severity: SeverityMedium,
			AffectedObject: "filesystem.executable.group_write", ExpectedState: "POSIX executable files are not group-writable by non-system groups unless the grant is explicitly required and trusted",
			Risk:        "Group-writable executable code broadens the set of principals that may be able to modify a launch target. POSIX mode metadata alone cannot prove that every member of a non-system group is trusted, so this condition requires review rather than being treated as equivalent to world-write access.",
			Remediation: "Remove unnecessary group-write permission from executable files or restrict the owning group to a documented trusted deployment boundary. Keep ordinary execution permission separate from modification permission.",
			Evaluate:    evaluateGroupWritableExecutables,
		},
		{
			ID: "CHM-FS-003", Title: "Privileged command and system search directories resist lower-privilege modification", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.privileged_search_path.integrity", ExpectedState: "directories participating in privileged user, service, scheduled-job, or system-component command resolution are controlled only by trusted privileged principals",
			Risk:        "A lower-privilege-writable directory in a privileged command search boundary can allow a different executable or script to be selected when privileged code resolves a command by name.",
			Remediation: "Remove lower-privilege ownership or write access from the affected search directory, use explicit protected executable paths for privileged services and jobs, and keep privileged PATH entries restricted to administrator-controlled locations.",
			Evaluate:    evaluatePrivilegedCommandSearchPaths,
		},
		{
			ID: "CHM-FS-004", Title: "System loader search directories resist lower-privilege modification", Category: "filesystem", Severity: SeverityCritical,
			AffectedObject: "filesystem.loader_search_path.integrity", ExpectedState: "system loader and library search roots are controlled only by trusted privileged principals",
			Risk:        "A lower-privilege-writable system loader or library search root can weaken the code-loading trust boundary for privileged or system components that resolve libraries from that location.",
			Remediation: "Restore privileged ownership and restrictive write permissions on the affected loader/library directory. Remove broad DACL grants or non-system POSIX ownership and review any local loader-path customization separately.",
			Evaluate:    evaluateLoaderSearchPaths,
		},
		{
			ID: "CHM-FS-005", Title: "Custom or unexpected Linux set-ID executables are reviewed", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.linux_setid.review", ExpectedState: "Linux setuid/setgid executables are distribution-managed or otherwise explicitly trusted, and are not located in weak custom/user/temporary boundaries",
			Risk:        "Setuid and setgid executables can cross local identity boundaries at execution time. Unmanaged, custom-path, non-root-owned, or broadly writable set-ID executables deserve explicit review because a compromised or unintended launch target can grant authority beyond the caller's ordinary identity.",
			Remediation: "Verify that each flagged set-ID executable is required and intentionally installed. Prefer distribution-managed implementations, remove unnecessary setuid/setgid bits, keep the file under privileged ownership, and eliminate group/other write access.",
			Evaluate:    evaluateUnexpectedLinuxSetID,
		},
		{
			ID: "CHM-FS-006", Title: "Custom or unexpected Linux file-capability executables are reviewed", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.linux_file_capability.review", ExpectedState: "Linux capability-bearing executables are distribution-managed or otherwise explicitly trusted, and are not located in weak custom/user/temporary boundaries",
			Risk:        "Linux file capabilities can grant selected kernel privileges without full setuid-root semantics. An unmanaged or weakly controlled capability-bearing executable can therefore create a focused but material privilege boundary bypass.",
			Remediation: "Confirm that each capability assignment is required, minimize the granted capability set, remove capabilities from unnecessary custom executables, and keep the executable under privileged ownership with restrictive write permissions.",
			Evaluate:    evaluateUnexpectedLinuxCapabilities,
		},
		{
			ID: "CHM-FS-007", Title: "Security-sensitive files resist broad modification", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.sensitive_file.write_boundary", ExpectedState: "security-sensitive authentication, SSH, service, scheduled-execution, environment, cloud, orchestration, and private-key paths are not writable by broad lower-privilege principals",
			Risk:        "Broad modification rights on security-sensitive files or directories can let a lower-privilege principal alter authentication behavior, service configuration, scheduled execution, key material, or credential-bearing configuration consumed by a more trusted process or user.",
			Remediation: "Remove world/Everyone/Users-style write grants and unnecessary group write access from the affected path. Preserve only the narrowly intended owner and trusted administrative or service principals, including the parent directory where it defines the modification boundary.",
			Evaluate:    evaluateSensitiveWriteBoundary,
		},
		{
			ID: "CHM-FS-008", Title: "Secret-bearing files restrict broad read or traversal access", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.sensitive_file.read_boundary", ExpectedState: "private keys and credential-bearing local configuration follow owner-only or no-world-read policy appropriate to the path",
			Risk:        "Overly broad read or directory-traversal access can expose private keys, cloud/orchestration credentials, authentication-secret metadata, or environment-held secrets to principals outside the intended trust boundary.",
			Remediation: "Restrict the affected secret-bearing file or directory to its intended owner and explicitly trusted service or administrative group. Remove world/Everyone/Authenticated Users access and unnecessary group read/traverse grants where owner-only policy applies.",
			Evaluate:    evaluateSensitiveReadBoundary,
		},
		{
			ID: "CHM-FS-009", Title: "Security-sensitive files retain expected ownership", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.sensitive_file.ownership", ExpectedState: "system security configuration is privileged-owned and user-scoped sensitive paths remain owned by the corresponding user where the platform exposes a reliable ownership boundary",
			Risk:        "Unexpected ownership can grant a different principal durable control over authentication policy, service or scheduler configuration, private keys, or credential-bearing files even when the visible mode or DACL appears otherwise restrictive.",
			Remediation: "Restore ownership to the intended privileged system identity or corresponding user, then review inherited ACLs, group membership, symlink targets, and parent-directory permissions before trusting the path again.",
			Evaluate:    evaluateSensitiveOwnership,
		},
		{
			ID: "CHM-FS-010", Title: "High-impact filesystem ACLs avoid broad write or control grants", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.acl_boundary.broad_control", ExpectedState: "selected high-impact files and directories do not grant broad lower-privilege principals effective write, ownership, permission-changing, or equivalent control through native ACLs",
			Risk:        "An effective broad ACL grant on an authentication, service, privileged search, system, or other high-impact path can let low-privilege principals alter code or configuration consumed across a stronger trust boundary, even when basic mode bits appear restrictive.",
			Remediation: "Remove broad Everyone/Authenticated Users/Users/other-style write or control ACL entries from the affected path. Preserve only narrowly scoped trusted administrative, service, or owning principals and verify inherited entries at the parent boundary.",
			Evaluate:    evaluateDangerousACLBoundaries,
		},
		{
			ID: "CHM-FS-011", Title: "High-impact filesystem ACLs avoid unexpected non-owner write grants", Category: "filesystem", Severity: SeverityMedium,
			AffectedObject: "filesystem.acl_boundary.named_write_review", ExpectedState: "named user or group ACL write grants on selected high-impact paths are limited to the intended owner and explicitly trusted privileged principals",
			Risk:        "A named user or group write grant can weaken a high-impact filesystem boundary without being visible in ordinary owner/group/other mode bits. Chimera cannot prove every named principal is inappropriate, so these grants require explicit trust-boundary review.",
			Remediation: "Confirm that each named writer is required and trusted for the affected path. Remove stale or unnecessary ACL entries, prefer least-privilege access, and review inherited ACLs when the grant originates from a parent directory.",
			Evaluate:    evaluateACLNamedWriteReview,
		},
		{
			ID: "CHM-FS-012", Title: "Temporary directories preserve protective ownership and write semantics", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.temp_directory.security_boundary", ExpectedState: "shared system temporary areas retain trusted ownership and anti-replacement semantics, while process/user temporary areas do not expose broad uncontrolled write access or weak parent boundaries",
			Risk:        "A weak temporary-directory or parent boundary can let a lower-privilege principal create, replace, rename, or delete artifacts that a more trusted process later consumes. Shared POSIX temporary areas require sticky-bit protection rather than being treated as unsafe merely because they are intentionally writable.",
			Remediation: "Restore trusted ownership on shared system temporary directories, preserve sticky-bit protection on world-writable POSIX shared temp areas, remove broad control rights from Windows temp DACLs, and secure the parent directory so lower-privilege principals cannot replace the temp boundary itself.",
			Evaluate:    evaluateTemporaryDirectorySecurity,
		},
		{
			ID: "CHM-FS-013", Title: "Privileged service launch artifacts avoid temporary directories", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.temp_directory.privileged_service_usage", ExpectedState: "privileged service executables, definitions, and configuration paths are stored outside temporary-directory boundaries",
			Risk:        "A privileged service that loads executable or configuration artifacts from a temporary directory crosses a weak lifecycle boundary where temporary content is commonly user-controlled, automatically cleaned, or shared. This can turn an otherwise ordinary temp-path weakness into privileged code or configuration replacement risk.",
			Remediation: "Move privileged service executables and configuration to administrator-controlled persistent directories, update the service definition to use explicit protected paths, and retain service-specific temporary data only for non-executable runtime artifacts with appropriate isolation.",
			Evaluate:    evaluatePrivilegedServiceTemporaryPaths,
		},
		{
			ID: "CHM-FS-014", Title: "High-risk POSIX data mounts suppress set-ID privilege", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.mount.nosuid", ExpectedState: "profile-relevant removable, network, temporary, and other untrusted-data mount boundaries use effective nosuid semantics where POSIX mount options apply",
			Risk:        "Allowing setuid or setgid semantics on data mounted from removable, remote, or shared temporary boundaries can let privilege-bearing files from a weaker trust domain participate in local identity transitions.",
			Remediation: "Add the platform-appropriate nosuid mount policy to the affected data boundary when compatible with the workload. If set-ID execution is intentionally required, document the exception and constrain the source, ownership, and write boundary instead of applying a blanket exception to unrelated mounts.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateMountHardening("default", idx, mountHardeningNoSuid)
			},
			EvaluateProfile: func(profile string, idx Index) Evaluation {
				return evaluateMountHardening(profile, idx, mountHardeningNoSuid)
			},
		},
		{
			ID: "CHM-FS-015", Title: "High-risk POSIX data mounts block device-node interpretation", Category: "filesystem", Severity: SeverityMedium,
			AffectedObject: "filesystem.mount.nodev", ExpectedState: "profile-relevant removable, network, temporary, and other untrusted-data mount boundaries use effective nodev semantics where POSIX mount options apply",
			Risk:        "Permitting device-node interpretation on a data mount can expose kernel device interfaces through filesystem objects originating outside the intended device-management boundary.",
			Remediation: "Add the platform-appropriate nodev mount policy to data-only removable, remote, or temporary filesystems when device nodes are not an explicit requirement. Keep genuine device files confined to dedicated system-managed device filesystems.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateMountHardening("default", idx, mountHardeningNoDev)
			},
			EvaluateProfile: func(profile string, idx Index) Evaluation {
				return evaluateMountHardening(profile, idx, mountHardeningNoDev)
			},
		},
		{
			ID: "CHM-FS-016", Title: "Profile-selected data mounts restrict direct executable launch", Category: "filesystem", Severity: SeverityMedium,
			AffectedObject: "filesystem.mount.noexec", ExpectedState: "mounts classified by the active profile as data-only or higher-risk use effective noexec semantics where POSIX mount options apply",
			Risk:        "Direct execution from removable, temporary, or selected remote data boundaries increases the chance that untrusted or transient content can become an executable launch source. Some development and server workloads legitimately execute from such mounts, so applicability is profile-scoped rather than universal.",
			Remediation: "Use noexec on data-only mounts selected by the active profile. Where executable content is a documented requirement, keep the mount outside the profile's data-only role, restrict ownership and write access, and record a narrow policy exception instead of disabling the expectation globally.",
			Evaluate: func(idx Index) Evaluation {
				return evaluateMountHardening("default", idx, mountHardeningNoExec)
			},
			EvaluateProfile: func(profile string, idx Index) Evaluation {
				return evaluateMountHardening(profile, idx, mountHardeningNoExec)
			},
		},
		{
			ID: "CHM-FS-017", Title: "Mounted network shares avoid guest or anonymous client access", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.network_share.mounted_anonymous", ExpectedState: "mounted SMB/NFS network filesystems use authenticated client access rather than guest, anonymous, or sec=none configuration",
			Risk:        "A locally mounted network share that uses guest or anonymous access weakens identity accountability and can make remote content available without the normal authenticated user boundary expected for enterprise storage.",
			Remediation: "Remount the affected network share using an authenticated SMB or NFS security mechanism and remove guest/anonymous client options. Preserve credentials in the platform's protected credential mechanism rather than embedding secret values in mount options.",
			Evaluate:    evaluateMountedNetworkShareAnonymousAccess,
		},
		{
			ID: "CHM-FS-018", Title: "NFS export client scope is constrained", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.network_share.nfs_scope", ExpectedState: "local NFS exports are limited to intended clients or networks and do not grant broad wildcard write access",
			Risk:        "A broadly scoped NFS export can expose host data to unintended systems. Broad write access materially increases the risk because remote clients can modify shared content across the host's trust boundary.",
			Remediation: "Replace wildcard or all-machines NFS export scope with explicit hosts, narrowly bounded subnets, or managed client groups. Keep broadly consumed data read-only where feasible and require explicit write grants only for the systems that need them.",
			Evaluate:    evaluateNFSExportScope,
		},
		{
			ID: "CHM-FS-019", Title: "NFS exports preserve root and identity-mapping boundaries", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.network_share.nfs_identity_boundary", ExpectedState: "NFS exports do not disable root squashing, map anonymous identities to UID/GID 0, permit unauthenticated security modes, or broadly grant root access",
			Risk:        "NFS options that preserve remote root authority or map anonymous identities to privileged local identities can collapse the expected client/server privilege boundary and turn a file share into a host-level authorization weakness.",
			Remediation: "Restore root squashing or equivalent root isolation, remove anonymous UID/GID 0 mappings, disable sec=none/unmapped anonymous access, require authenticated NFS security where supported, and scope any exceptional root access to narrowly trusted clients.",
			Evaluate:    evaluateNFSExportIdentityBoundary,
		},
		{
			ID: "CHM-FS-020", Title: "Mounted network shares avoid permission-bypass and legacy client options", Category: "filesystem", Severity: SeverityHigh,
			AffectedObject: "filesystem.network_share.client_hardening", ExpectedState: "mounted network filesystems do not disable local permission enforcement or force legacy SMB1/NFSv2 client semantics",
			Risk:        "Client options such as SMB noperm or legacy protocol selection can weaken local authorization enforcement or retain obsolete protocol behavior on a live host even when the remote server is otherwise hardened.",
			Remediation: "Remove permission-bypass client options, use supported current SMB/NFS protocol versions, and retain local permission checks unless a documented architecture supplies an equivalent trusted authorization boundary.",
			Evaluate:    evaluateMountedNetworkShareClientHardening,
		},
	}
}

type filesystemExecutableEvidence struct {
	Key    string
	Record fsinv.ExecutableRecord
}

func evaluateUntrustedWritableExecutables(idx Index) Evaluation {
	items := filesystemExecutableItems(idx)
	bad := make([]filesystemExecutableEvidence, 0)
	unresolved := make([]filesystemExecutableEvidence, 0)
	for _, item := range items {
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.UntrustedWrite {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemExecutableDescriptions(bad)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d executable(s) are writable through a broad untrusted-principal boundary: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.executable-permissions"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemExecutableDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no untrusted write grant observed, but permission metadata is unresolved for %d executable(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.executable-permissions"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 untrusted-principal writable executables across %d assessed executable(s)", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateGroupWritableExecutables(idx Index) Evaluation {
	items := filesystemExecutableItems(idx)
	bad := make([]filesystemExecutableEvidence, 0)
	unresolved := make([]filesystemExecutableEvidence, 0)
	for _, item := range items {
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.GroupWritable && strings.TrimSpace(item.Record.GroupID) != "" && strings.TrimSpace(item.Record.GroupID) != "0" {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemExecutableDescriptions(bad)
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d executable(s) are group-writable by non-system groups: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.executable-permissions"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemExecutableDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no non-system group-write exposure observed, but permission metadata is unresolved for %d executable(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.executable-permissions"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 non-system group-writable executables across %d assessed executable(s)", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemExecutableItems(idx Index) []filesystemExecutableEvidence {
	out := make([]filesystemExecutableEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.executable.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.ExecutableRecord)
		if !ok {
			continue
		}
		out = append(out, filesystemExecutableEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemExecutableDescriptions(items []filesystemExecutableEvidence) ([]string, []string) {
	descriptions := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		detail := item.Record.Path
		if len(item.Record.WritePrincipals) > 0 {
			detail += " [writers=" + strings.Join(item.Record.WritePrincipals, ",") + "]"
		} else if item.Record.GroupWritable && item.Record.GroupID != "" {
			detail += " [group=" + item.Record.GroupID + "]"
		}
		descriptions = append(descriptions, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(descriptions)
	sort.Strings(keys)
	return descriptions, keys
}

type filesystemSearchPathEvidence struct {
	Key    string
	Record fsinv.SearchPathRecord
}

func evaluatePrivilegedCommandSearchPaths(idx Index) Evaluation {
	return evaluateSearchPathContexts(idx, []string{"PRIVILEGED_USER", "SERVICE", "SCHEDULED_JOB", "SYSTEM_COMPONENT"}, false)
}

func evaluateLoaderSearchPaths(idx Index) Evaluation {
	return evaluateSearchPathContexts(idx, []string{"LOADER"}, true)
}

func evaluateSearchPathContexts(idx Index, contexts []string, loader bool) Evaluation {
	items := filesystemSearchPathItems(idx, contexts)
	bad := make([]filesystemSearchPathEvidence, 0)
	unresolved := make([]filesystemSearchPathEvidence, 0)
	for _, item := range items {
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if !item.Record.Exists {
			continue
		}
		if !item.Record.Directory {
			bad = append(bad, item)
			continue
		}
		if item.Record.UntrustedWrite {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemSearchPathDescriptions(bad)
		subject := "privileged command/system"
		if loader {
			subject = "system loader"
		}
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d %s search path(s) have a lower-privilege-controlled boundary: %s", len(bad), subject, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemSearchPathDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak search-path boundary was confirmed, but permission metadata is unresolved for %d relevant path(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(items) == 0 {
		keys := []string{}
		if src, ok := idx["filesystem.source.privileged-search-paths"]; ok {
			keys = append(keys, "filesystem.source.privileged-search-paths")
			if src.State != evidence.StateObserved {
				return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Undetermined, EvidenceKeys: keys}
			}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "no applicable privileged search-path records were available", Applicability: Undetermined, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.privileged-search-paths"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d relevant privileged search-path boundary/boundaries have no observed lower-privilege write control", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemSearchPathItems(idx Index, contexts []string) []filesystemSearchPathEvidence {
	wanted := map[string]struct{}{}
	for _, c := range contexts {
		wanted[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	out := make([]filesystemSearchPathEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.search_path.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.SearchPathRecord)
		if !ok {
			continue
		}
		match := false
		for _, c := range rec.Contexts {
			if _, ok := wanted[strings.ToUpper(strings.TrimSpace(c))]; ok {
				match = true
				break
			}
		}
		if match {
			out = append(out, filesystemSearchPathEvidence{Key: key, Record: rec})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemSearchPathDescriptions(items []filesystemSearchPathEvidence) ([]string, []string) {
	descriptions := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		detail := item.Record.Path + " [contexts=" + strings.Join(item.Record.Contexts, ",") + "]"
		if len(item.Record.WritePrincipals) > 0 {
			detail += " [writers=" + strings.Join(item.Record.WritePrincipals, ",") + "]"
		}
		if item.Record.Exists && !item.Record.Directory {
			detail += " [not-a-directory]"
		}
		descriptions = append(descriptions, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(descriptions)
	sort.Strings(keys)
	return descriptions, keys
}

type filesystemPrivilegedFileEvidence struct {
	Key    string
	Record fsinv.PrivilegedFileRecord
}

func evaluateUnexpectedLinuxSetID(idx Index) Evaluation {
	return evaluateLinuxPrivilegedFiles(idx, func(rec fsinv.PrivilegedFileRecord) bool { return rec.SetUID || rec.SetGID }, "set-ID")
}

func evaluateUnexpectedLinuxCapabilities(idx Index) Evaluation {
	return evaluateLinuxPrivilegedFiles(idx, func(rec fsinv.PrivilegedFileRecord) bool {
		return len(rec.Capabilities) > 0 || len(rec.InheritableCaps) > 0
	}, "file-capability")
}

func evaluateLinuxPrivilegedFiles(idx Index, relevant func(fsinv.PrivilegedFileRecord) bool, kind string) Evaluation {
	items := filesystemPrivilegedFileItems(idx, relevant)
	bad := make([]filesystemPrivilegedFileEvidence, 0)
	unresolved := make([]filesystemPrivilegedFileEvidence, 0)
	for _, item := range items {
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.ReviewRequired {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemPrivilegedFileDescriptions(bad)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d custom/unexpected Linux %s executable(s) require review: %s", len(bad), kind, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	src, hasSource := idx["filesystem.source.linux-privileged-files"]
	if hasSource && src.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: NotApplicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemPrivilegedFileDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no custom/unexpected Linux %s executable was confirmed, but metadata is unresolved for %d relevant record(s)", kind, len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if hasSource && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if !hasSource {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "Linux privileged-file source evidence is missing", Applicability: Undetermined}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 custom/unexpected Linux %s executables across %d relevant privileged executable(s)", kind, len(items)), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
}

func filesystemPrivilegedFileItems(idx Index, relevant func(fsinv.PrivilegedFileRecord) bool) []filesystemPrivilegedFileEvidence {
	out := make([]filesystemPrivilegedFileEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.privileged_executable.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.PrivilegedFileRecord)
		if !ok || !relevant(rec) {
			continue
		}
		out = append(out, filesystemPrivilegedFileEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemPrivilegedFileDescriptions(items []filesystemPrivilegedFileEvidence) ([]string, []string) {
	descriptions := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{}
		if item.Record.SetUID {
			parts = append(parts, "setuid")
		}
		if item.Record.SetGID {
			parts = append(parts, "setgid")
		}
		if len(item.Record.Capabilities) > 0 {
			parts = append(parts, "caps="+strings.Join(item.Record.Capabilities, ","))
		}
		detail := item.Record.Path + " [" + strings.Join(parts, ",") + "]"
		if len(item.Record.ReviewReasons) > 0 {
			detail += " [" + strings.Join(item.Record.ReviewReasons, "; ") + "]"
		}
		descriptions = append(descriptions, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(descriptions)
	sort.Strings(keys)
	return descriptions, keys
}

type filesystemSensitiveFileEvidence struct {
	Key    string
	Record fsinv.SensitiveFileRecord
}

func evaluateSensitiveWriteBoundary(idx Index) Evaluation {
	items := filesystemSensitiveFileItems(idx)
	untrusted := make([]filesystemSensitiveFileEvidence, 0)
	broad := make([]filesystemSensitiveFileEvidence, 0)
	unresolved := make([]filesystemSensitiveFileEvidence, 0)
	for _, item := range items {
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if !item.Record.Exists {
			continue
		}
		if item.Record.UntrustedWrite {
			untrusted = append(untrusted, item)
		} else if item.Record.BroadlyWritable {
			broad = append(broad, item)
		}
	}
	if len(untrusted) > 0 {
		desc, keys := filesystemSensitiveFileDescriptions(untrusted, "write")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d security-sensitive path(s) are writable by broad untrusted principals: %s", len(untrusted), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(broad) > 0 {
		desc, keys := filesystemSensitiveFileDescriptions(broad, "write")
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d security-sensitive path(s) retain group/broad write access requiring trust-boundary review: %s", len(broad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.sensitive-file-permissions"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemSensitiveFileDescriptions(unresolved, "write")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak sensitive-file write boundary was confirmed, but permission metadata is unresolved for %d path(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.sensitive-file-permissions"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 broad lower-privilege write boundaries across %d sensitive-path record(s)", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSensitiveReadBoundary(idx Index) Evaluation {
	items := filesystemSensitiveFileItems(idx)
	untrusted := make([]filesystemSensitiveFileEvidence, 0)
	broadOwnerOnly := make([]filesystemSensitiveFileEvidence, 0)
	unresolved := make([]filesystemSensitiveFileEvidence, 0)
	applicable := 0
	for _, item := range items {
		policy := strings.ToUpper(strings.TrimSpace(item.Record.AccessPolicy))
		if policy != fsinv.SensitivePolicyOwnerOnly && policy != fsinv.SensitivePolicyNoWorldRead {
			continue
		}
		if item.Record.State == evidence.StateObserved && !item.Record.Exists {
			continue
		}
		applicable++
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.UntrustedAccess {
			untrusted = append(untrusted, item)
			continue
		}
		if policy == fsinv.SensitivePolicyOwnerOnly && item.Record.BroadlyAccessible {
			broadOwnerOnly = append(broadOwnerOnly, item)
		}
	}
	if len(untrusted) > 0 {
		desc, keys := filesystemSensitiveFileDescriptions(untrusted, "read")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d secret-bearing path(s) permit untrusted broad read/traversal access: %s", len(untrusted), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(broadOwnerOnly) > 0 {
		desc, keys := filesystemSensitiveFileDescriptions(broadOwnerOnly, "read")
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d owner-only sensitive path(s) retain group read/traversal access requiring review: %s", len(broadOwnerOnly), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.sensitive-file-permissions"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemSensitiveFileDescriptions(unresolved, "read")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no weak sensitive read boundary was confirmed, but permission metadata is unresolved for %d applicable path(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.sensitive-file-permissions"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d applicable secret-bearing path(s) have no observed violation of their normalized read policy", applicable), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSensitiveOwnership(idx Index) Evaluation {
	items := filesystemSensitiveFileItems(idx)
	bad := make([]filesystemSensitiveFileEvidence, 0)
	unknown := make([]filesystemSensitiveFileEvidence, 0)
	checked := 0
	for _, item := range items {
		if item.Record.State == evidence.StateObserved && !item.Record.Exists {
			continue
		}
		if item.Record.State != evidence.StateObserved {
			if item.Record.OwnerState != fsinv.SensitiveOwnerNotApplicable {
				unknown = append(unknown, item)
			}
			continue
		}
		switch item.Record.OwnerState {
		case fsinv.SensitiveOwnerExpected:
			checked++
		case fsinv.SensitiveOwnerUnexpected:
			checked++
			bad = append(bad, item)
		case fsinv.SensitiveOwnerUnknown:
			unknown = append(unknown, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemSensitiveFileDescriptions(bad, "owner")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d security-sensitive path(s) have unexpected ownership: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.sensitive-file-permissions"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unknown) > 0 && checked == 0 {
		_, keys := filesystemSensitiveFileDescriptions(unknown, "owner")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("expected-owner comparison is unavailable for %d sensitive path(s)", len(unknown)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.sensitive-file-permissions"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	if len(unknown) > 0 {
		_, unknownKeys := filesystemSensitiveFileDescriptions(unknown, "owner")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("%d sensitive path(s) match the expected owner boundary; ownership comparison remains unavailable for %d additional path(s)", checked, len(unknown)), Applicability: Applicable, EvidenceKeys: unknownKeys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d security-sensitive path(s) match their expected owner boundary", checked), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemSensitiveFileItems(idx Index) []filesystemSensitiveFileEvidence {
	out := make([]filesystemSensitiveFileEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.sensitive_file.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.SensitiveFileRecord)
		if !ok {
			continue
		}
		out = append(out, filesystemSensitiveFileEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemSensitiveFileDescriptions(items []filesystemSensitiveFileEvidence, mode string) ([]string, []string) {
	descriptions := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		detail := item.Record.Path + " [" + item.Record.Kind + "/" + item.Record.AccessPolicy + "]"
		switch mode {
		case "write":
			if len(item.Record.WritePrincipals) > 0 {
				detail += " [writers=" + strings.Join(item.Record.WritePrincipals, ",") + "]"
			}
		case "read":
			if len(item.Record.ReadPrincipals) > 0 {
				detail += " [readers=" + strings.Join(item.Record.ReadPrincipals, ",") + "]"
			}
		case "owner":
			detail += " [owner=" + item.Record.OwnerID + " expected=" + item.Record.ExpectedOwnerID + "]"
		}
		descriptions = append(descriptions, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(descriptions)
	sort.Strings(keys)
	return descriptions, keys
}

type filesystemACLBoundaryEvidence struct {
	Key    string
	Record fsinv.ACLBoundaryRecord
}

func evaluateDangerousACLBoundaries(idx Index) Evaluation {
	items := filesystemACLBoundaryItems(idx)
	bad := make([]filesystemACLBoundaryEvidence, 0)
	unresolved := make([]filesystemACLBoundaryEvidence, 0)
	for _, item := range items {
		if item.Record.State == evidence.StateObserved && !item.Record.Exists {
			continue
		}
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.DangerousBroadWrite || item.Record.DangerousBroadControl {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemACLBoundaryDescriptions(bad, "dangerous")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d selected high-impact path(s) expose effective broad ACL write/control grants: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.acl-boundaries"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemACLBoundaryDescriptions(unresolved, "dangerous")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no dangerous broad ACL grant was confirmed, but native ACL metadata is unresolved for %d selected path(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.acl-boundaries"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 effective broad write/control grants across %d selected ACL boundary record(s)", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateACLNamedWriteReview(idx Index) Evaluation {
	items := filesystemACLBoundaryItems(idx)
	review := make([]filesystemACLBoundaryEvidence, 0)
	unresolved := make([]filesystemACLBoundaryEvidence, 0)
	for _, item := range items {
		if item.Record.State == evidence.StateObserved && !item.Record.Exists {
			continue
		}
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.ReviewWriteGrant {
			review = append(review, item)
		}
	}
	if len(review) > 0 {
		desc, keys := filesystemACLBoundaryDescriptions(review, "review")
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d selected high-impact path(s) contain non-owner named/group ACL write grants requiring trust review: %s", len(review), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.acl-boundaries"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemACLBoundaryDescriptions(unresolved, "review")
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no unexpected named ACL writer was confirmed, but native ACL metadata is unresolved for %d selected path(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := []string{"filesystem.source.acl-boundaries"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("0 non-owner named/group write grants requiring review across %d selected ACL boundary record(s)", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemACLBoundaryItems(idx Index) []filesystemACLBoundaryEvidence {
	out := make([]filesystemACLBoundaryEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.acl_boundary.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.ACLBoundaryRecord)
		if !ok {
			continue
		}
		out = append(out, filesystemACLBoundaryEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemACLBoundaryDescriptions(items []filesystemACLBoundaryEvidence, mode string) ([]string, []string) {
	descriptions := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		detail := item.Record.Path + " [" + strings.Join(item.Record.Contexts, ",") + "]"
		if mode == "dangerous" && len(item.Record.DangerousPrincipals) > 0 {
			detail += " [broad=" + strings.Join(item.Record.DangerousPrincipals, ",") + "]"
		}
		if mode == "review" && len(item.Record.ReviewPrincipals) > 0 {
			detail += " [writers=" + strings.Join(item.Record.ReviewPrincipals, ",") + "]"
		}
		descriptions = append(descriptions, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(descriptions)
	sort.Strings(keys)
	return descriptions, keys
}

type filesystemTempDirectoryEvidence struct {
	Key    string
	Record fsinv.TempDirectoryRecord
}

func evaluateTemporaryDirectorySecurity(idx Index) Evaluation {
	items := filesystemTempDirectoryItems(idx)
	bad := make([]filesystemTempDirectoryEvidence, 0)
	unresolved := make([]filesystemTempDirectoryEvidence, 0)
	for _, item := range items {
		if item.Record.State == evidence.StateObserved && !item.Record.Exists {
			continue
		}
		if item.Record.State != evidence.StateObserved || (item.Record.ParentState != "" && item.Record.ParentState != evidence.StateObserved) || (item.Record.Shared && !item.Record.TrustedOwnerKnown) || (item.Record.Shared && item.Record.ParentPath != "" && !item.Record.ParentTrustKnown) {
			unresolved = append(unresolved, item)
			continue
		}
		if item.Record.UnsafeOwnership || item.Record.UnsafePermissions || item.Record.ParentUnsafe || !item.Record.Directory {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemTempDirectoryDescriptions(bad)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d temporary-directory boundary/boundaries have unsafe ownership, write semantics, or parent integrity: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.temporary-directory-security"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemTempDirectoryDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("no unsafe temporary-directory boundary was confirmed, but security metadata is unresolved for %d temporary area(s)", len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(items) == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "no temporary-directory security records were available", Applicability: Undetermined}
	}
	keys := []string{"filesystem.source.temporary-directory-security"}
	if _, ok := idx[keys[0]]; !ok {
		keys = nil
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d temporary-directory boundary/boundaries retain expected ownership and write-protection semantics", len(items)), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemTempDirectoryItems(idx Index) []filesystemTempDirectoryEvidence {
	out := make([]filesystemTempDirectoryEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.temp_directory.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.TempDirectoryRecord)
		if !ok {
			continue
		}
		out = append(out, filesystemTempDirectoryEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func filesystemTempDirectoryDescriptions(items []filesystemTempDirectoryEvidence) ([]string, []string) {
	desc := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{item.Record.Scope}
		if item.Record.UnsafeOwnership {
			parts = append(parts, "unsafe-owner")
		}
		if item.Record.UnsafePermissions {
			parts = append(parts, "unsafe-permissions")
		}
		if item.Record.ParentUnsafe {
			parts = append(parts, "unsafe-parent")
		}
		if item.Record.Shared && item.Record.OtherWritable && !item.Record.StickyBit {
			parts = append(parts, "shared-write-without-sticky")
		}
		desc = append(desc, item.Record.Path+" ["+strings.Join(parts, ",")+"]")
		keys = append(keys, item.Key)
	}
	sort.Strings(desc)
	sort.Strings(keys)
	return desc, keys
}

type serviceTempPathEvidence struct {
	Key     string
	Service services.Service
	Paths   []string
}

func evaluatePrivilegedServiceTemporaryPaths(idx Index) Evaluation {
	temps := filesystemTempDirectoryItems(idx)
	roots := make([]string, 0, len(temps))
	for _, td := range temps {
		if td.Record.State == evidence.StateObserved && td.Record.Exists && td.Record.Directory {
			root := td.Record.Path
			if td.Record.ResolvedPath != "" {
				root = td.Record.ResolvedPath
			}
			roots = append(roots, root)
		}
	}
	bad := []serviceTempPathEvidence{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.item.") {
			continue
		}
		s, ok := obs.Value.(services.Service)
		if !ok {
			continue
		}
		priv := strings.EqualFold(s.PrivilegeContext, "ROOT") || strings.EqualFold(s.PrivilegeContext, "SYSTEM") || strings.EqualFold(s.PrivilegeContext, "PRIVILEGED") || strings.EqualFold(s.PrivilegeContext, "ROOT_EQUIVALENT")
		if s.PathIntegrity != nil && s.PathIntegrity.Privileged {
			priv = true
		}
		if !priv {
			continue
		}
		paths := serviceLaunchArtifactPaths(s)
		matched := []string{}
		for _, p := range paths {
			for _, root := range roots {
				if pathWithinTemporaryRoot(p, root) {
					matched = append(matched, p)
					break
				}
			}
		}
		matched = uniqueAssessmentStrings(matched)
		if len(matched) > 0 {
			bad = append(bad, serviceTempPathEvidence{Key: key, Service: s, Paths: matched})
		}
	}
	if len(bad) > 0 {
		sort.Slice(bad, func(i, j int) bool { return bad[i].Service.Name < bad[j].Service.Name })
		desc := make([]string, 0, len(bad))
		keys := make([]string, 0, len(bad)+len(temps))
		for _, item := range bad {
			desc = append(desc, item.Service.Name+" ["+strings.Join(item.Paths, ",")+"]")
			keys = append(keys, item.Key)
		}
		for _, td := range temps {
			keys = append(keys, td.Key)
		}
		keys = uniqueAssessmentStrings(keys)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d privileged service(s) load executable/definition/configuration artifacts from temporary-directory boundaries: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if src, ok := idx["filesystem.source.temporary-directory-security"]; ok && src.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: "temporary-directory inventory is incomplete, so privileged service temp-path correlation is incomplete", Applicability: Applicable, EvidenceKeys: []string{src.Key}}
	}
	serviceCount := 0
	for key, obs := range idx {
		if strings.HasPrefix(key, "service.item.") {
			if _, ok := obs.Value.(services.Service); ok {
				serviceCount++
			}
		}
	}
	if serviceCount == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "service inventory unavailable for temporary-path correlation", Applicability: Undetermined}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no privileged service executable, definition, or configuration path was observed beneath a normalized temporary-directory root", Applicability: Applicable, EvidenceKeys: []string{"filesystem.source.temporary-directory-security"}}
}

const (
	mountHardeningNoSuid = "nosuid"
	mountHardeningNoDev  = "nodev"
	mountHardeningNoExec = "noexec"
)

type filesystemMountEvidence struct {
	Key    string
	Record fsinv.MountBoundary
}

func evaluateMountHardening(profileName string, idx Index, control string) Evaluation {
	posix, capabilityKey, capabilityConfidence, capabilityText := filesystemPOSIXMountSemantics(idx)
	if !posix {
		if capabilityText == "NON_POSIX" {
			keys := []string{}
			if capabilityKey != "" {
				keys = append(keys, capabilityKey)
			}
			return Evaluation{Status: StatusPass, Confidence: capabilityConfidence, ObservedState: "POSIX mount-option semantics are not applicable on this filesystem provider", Applicability: NotApplicable, EvidenceKeys: keys}
		}
		keys := []string{}
		if capabilityKey != "" {
			keys = append(keys, capabilityKey)
		}
		return Evaluation{Status: StatusUnknown, Confidence: capabilityConfidence, ObservedState: "filesystem provider semantics are unavailable; mount hardening applicability cannot be determined", Applicability: Undetermined, EvidenceKeys: keys}
	}

	items := filesystemMountItems(idx)
	relevant := make([]filesystemMountEvidence, 0)
	bad := make([]filesystemMountEvidence, 0)
	unresolved := make([]filesystemMountEvidence, 0)
	for _, item := range items {
		if !mountRequiresControl(profileName, item.Record, control) {
			continue
		}
		relevant = append(relevant, item)
		if item.Record.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		if !mountHasOption(item.Record, control) {
			bad = append(bad, item)
		}
	}

	if len(bad) > 0 {
		desc, keys := filesystemMountDescriptions(bad, control)
		return Evaluation{
			Status: StatusFail, Confidence: evidence.ConfidenceHigh, Applicability: Applicable, EvidenceKeys: keys,
			ObservedState: fmt.Sprintf("profile %s requires %s on %d mount boundary/boundaries where it is absent: %s", normalizeProfileName(profileName), control, len(bad), strings.Join(desc, "; ")),
		}
	}
	if src, ok := idx["filesystem.source.mount-boundaries"]; ok && src.State != evidence.StateObserved {
		keys := []string{src.Key}
		for _, item := range relevant {
			keys = append(keys, item.Key)
		}
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: fmt.Sprintf("mount inventory is incomplete, so profile %s %s coverage cannot be proven complete", normalizeProfileName(profileName), control), Applicability: Applicable, EvidenceKeys: uniqueAssessmentStrings(keys)}
	}
	if len(unresolved) > 0 {
		_, keys := filesystemMountDescriptions(unresolved, control)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("profile %s has no confirmed %s violation, but %d relevant mount boundary/boundaries remain unresolved", normalizeProfileName(profileName), control, len(unresolved)), Applicability: Applicable, EvidenceKeys: keys}
	}
	keys := make([]string, 0, len(relevant)+1)
	if capabilityKey != "" {
		keys = append(keys, capabilityKey)
	}
	for _, item := range relevant {
		keys = append(keys, item.Key)
	}
	if src, ok := idx["filesystem.source.mount-boundaries"]; ok {
		keys = append(keys, src.Key)
	}
	keys = uniqueAssessmentStrings(keys)
	if len(relevant) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("profile %s has no observed mount boundary requiring %s", normalizeProfileName(profileName), control), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("all %d profile-relevant mount boundary/boundaries use %s", len(relevant), control), Applicability: Applicable, EvidenceKeys: keys}
}

func filesystemPOSIXMountSemantics(idx Index) (applicable bool, key string, confidence evidence.Confidence, state string) {
	o, ok := idx["filesystem.permission_capability"]
	if !ok {
		return false, "", evidence.ConfidenceLow, "UNKNOWN"
	}
	key = o.Key
	confidence = o.Confidence
	if o.State != evidence.StateObserved {
		return false, key, confidence, "UNKNOWN"
	}
	cap, ok := o.Value.(fsinv.PermissionCapability)
	if !ok {
		return false, key, evidence.ConfidenceLow, "UNKNOWN"
	}
	model := strings.ToUpper(strings.TrimSpace(cap.Model))
	if strings.Contains(model, "POSIX") {
		return true, key, confidence, "POSIX"
	}
	if strings.Contains(model, "NTFS") || strings.Contains(model, "DACL") {
		return false, key, confidence, "NON_POSIX"
	}
	return false, key, confidence, "UNKNOWN"
}

func filesystemMountItems(idx Index) []filesystemMountEvidence {
	out := make([]filesystemMountEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.mount.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.MountBoundary)
		if !ok {
			continue
		}
		out = append(out, filesystemMountEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.Path != out[j].Record.Path {
			return out[i].Record.Path < out[j].Record.Path
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func mountRequiresControl(profileName string, m fsinv.MountBoundary, control string) bool {
	if m.State == evidence.StateNotApplicable || m.Classification == fsinv.MountClassOptical {
		return false
	}
	profileName = normalizeProfileName(profileName)
	class := strings.ToUpper(strings.TrimSpace(m.Classification))
	temporary := mountIsTemporaryDataBoundary(m)
	userData := mountIsDedicatedUserDataBoundary(m)
	removable := class == fsinv.MountClassRemovable || m.Removable
	network := class == fsinv.MountClassNetwork || m.Network

	switch control {
	case mountHardeningNoSuid, mountHardeningNoDev:
		if removable || network || temporary {
			return true
		}
		return profileName == "high-security" && userData
	case mountHardeningNoExec:
		switch profileName {
		case "high-security":
			return removable || network || temporary
		case "workstation", "server":
			return removable || temporary
		case "developer", "default":
			return removable
		default:
			return removable
		}
	default:
		return false
	}
}

func mountIsTemporaryDataBoundary(m fsinv.MountBoundary) bool {
	p := normalizeAssessmentPath(m.Path)
	switch p {
	case "/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp":
		return true
	}
	return false
}

func mountIsDedicatedUserDataBoundary(m fsinv.MountBoundary) bool {
	p := strings.ToLower(normalizeAssessmentPath(m.Path))
	return p == "/home" || p == "/users" || strings.HasPrefix(p, "/home/") || strings.HasPrefix(p, "/users/")
}

func mountHasOption(m fsinv.MountBoundary, want string) bool {
	for _, opt := range m.Options {
		name := strings.ToLower(strings.TrimSpace(opt))
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if name == strings.ToLower(want) {
			return true
		}
	}
	return false
}

func filesystemMountDescriptions(items []filesystemMountEvidence, missing string) ([]string, []string) {
	desc := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		r := item.Record
		detail := r.Path + " [" + r.Classification
		if r.Filesystem != "" {
			detail += "/" + r.Filesystem
		}
		detail += "; missing=" + missing + "]"
		desc = append(desc, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(desc)
	sort.Strings(keys)
	return desc, keys
}

func serviceLaunchArtifactPaths(s services.Service) []string {
	out := []string{s.ExecutablePath, s.DefinitionPath}
	if s.PathIntegrity != nil {
		out = append(out, s.PathIntegrity.Executable.Path, s.PathIntegrity.Configuration.Path)
	}
	return uniqueAssessmentStrings(out)
}

func pathWithinTemporaryRoot(path, root string) bool {
	p := normalizeAssessmentPath(path)
	r := normalizeAssessmentPath(root)
	if p == "" || r == "" {
		return false
	}
	if p == r {
		return true
	}
	return strings.HasPrefix(p, strings.TrimRight(r, "/")+"/")
}

func normalizeAssessmentPath(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "\\\"'"))
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, `\\`, "/")
	for strings.Contains(v, "//") {
		v = strings.ReplaceAll(v, "//", "/")
	}
	if len(v) >= 2 && v[1] == ':' {
		v = strings.ToLower(v)
	}
	return strings.TrimRight(v, "/")
}

func uniqueAssessmentStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
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

//go:build linux || darwin

package persistence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func assessPlatformPathIntegrity(ctx context.Context, inv *Inventory) {
	unresolved := 0
	assessed := 0
	for i := range inv.Entries {
		if err := ctx.Err(); err != nil {
			inv.Degraded = append(inv.Degraded, "persistence path-integrity collection deadline reached: "+err.Error())
			break
		}
		// Service and scheduled records already carry stronger provider-native
		// path metadata from Phases 047 and 050. Only fill missing/unavailable
		// roles; do not overwrite proven upstream ACL/mode evidence.
		fillUnixPathIntegrity(&inv.Entries[i])
		if inv.Entries[i].PathIntegrity.State != evidence.StateNotApplicable {
			assessed++
		}
		if inv.Entries[i].PathIntegrity.State == evidence.StateDegraded {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if assessed == 0 {
		state = evidence.StateNotApplicable
		reason = "no persistence records exposed filesystem paths for integrity assessment"
	} else if unresolved > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("path permission metadata unresolved for %d of %d persistence record(s)", unresolved, assessed)
	}
	addSource(inv, "persistence-path-integrity", state, "provider-native metadata plus local POSIX ownership/mode path assessment", assessed, reason)
}

func fillUnixPathIntegrity(e *Entry) {
	p := e.PathIntegrity
	privileged, basis := privilegedContext(e.PrivilegeContext)
	if strings.TrimSpace(p.PrivilegeBasis) == "" || p.PrivilegeBasis == "UNKNOWN" {
		p.Privileged, p.PrivilegeBasis = privileged, basis
	}
	p.Executable = fillUnixExecutablePosture(*e, p.Executable)
	p.ExecutableDirectory = fillUnixDirectoryPosture(p.ExecutableDirectory, p.Executable.Path)
	p.ReferencedScript = fillUnixPosture(p.ReferencedScript, e.ReferencedScriptPath, false)
	p.ReferencedScriptDirectory = fillUnixDirectoryPosture(p.ReferencedScriptDirectory, p.ReferencedScript.Path)
	p.Definition = fillUnixPosture(p.Definition, e.DefinitionPath, false)
	p.DefinitionDirectory = fillUnixDirectoryPosture(p.DefinitionDirectory, p.Definition.Path)
	e.PathIntegrity = normalizePathIntegrity(p)
}

func fillUnixExecutablePosture(e Entry, existing PathPosture) PathPosture {
	path := strings.TrimSpace(e.ExecutablePath)
	if path == "" {
		return pathNotApplicable("local POSIX ownership/mode metadata")
	}
	// Preserve an explicit upstream service/scheduler applicability decision.
	// In particular, Fix64 can prove that a systemd basename is absent from the
	// fully assessed manager search path, or that an absolute configured
	// executable is currently absent while the parent creation boundary is
	// independently observed. Re-opening that same path here would turn a
	// stronger provider-native NOT_APPLICABLE result back into UNAVAILABLE.
	if existing.State == evidence.StateNotApplicable && strings.TrimSpace(existing.CollectionSource) != "" {
		return existing
	}
	if filepath.IsAbs(path) {
		if isLinuxXDGAutostartEntry(e) {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				// An absolute XDG autostart target that is provably absent cannot be
				// modified as an existing executable. Preserve the configured path
				// and let the independently assessed parent directory represent the
				// creation/replacement boundary, mirroring the Fix64 systemd service
				// contract instead of turning observed absence into provider failure.
				return PathPosture{
					Path: path, State: evidence.StateNotApplicable, CollectionSource: "local POSIX ownership/mode metadata",
					Confidence: evidence.ConfidenceHigh, Reason: "configured XDG autostart executable is not currently present; parent creation/replacement boundary assessed separately",
				}
			}
		}
		return fillUnixPosture(existing, path, true)
	}
	if resolved, ok := resolveLinuxXDGExecutable(e, path); ok {
		p := inspectUnixPersistencePath(resolved)
		if p.State == evidence.StateObserved {
			p.Reason = strings.TrimSpace(strings.Join([]string{p.Reason, "XDG Exec command resolved through bounded system desktop search path"}, "; "))
		}
		return p
	}
	return fillUnixPosture(existing, path, true)
}

func isLinuxXDGAutostartEntry(e Entry) bool {
	return strings.EqualFold(strings.TrimSpace(e.Manager), "xdg-autostart") && normalizeWord(e.Mechanism) == "XDG_AUTOSTART"
}

// resolveLinuxXDGExecutable resolves only the narrow freedesktop XDG autostart
// contract. Desktop Exec= commonly contains a command basename rather than an
// absolute path. Treating every such packaged desktop entry as unresolved was
// producing dozens of false persistence-path degradations on Kali. We do not
// use Chimera's current PATH (sudo/root PATH can differ from the login desktop)
// and we do not resolve commands containing path separators. Instead, search a
// small deterministic set of standard system executable directories in normal
// desktop precedence order. Anything outside that contract remains unresolved.
func resolveLinuxXDGExecutable(e Entry, command string) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(e.Manager), "xdg-autostart") || normalizeWord(e.Mechanism) != "XDG_AUTOSTART" {
		return "", false
	}
	command = strings.TrimSpace(command)
	if command == "" || filepath.IsAbs(command) || strings.ContainsRune(command, filepath.Separator) {
		return "", false
	}
	for _, dir := range []string{"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		candidate := filepath.Join(dir, command)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil && filepath.IsAbs(resolved) {
			candidate = resolved
		}
		return filepath.Clean(candidate), true
	}
	return "", false
}

func fillUnixPosture(existing PathPosture, path string, executable bool) PathPosture {
	path = strings.TrimSpace(path)
	if path == "" {
		return pathNotApplicable("local POSIX ownership/mode metadata")
	}
	if existing.State == evidence.StateNotApplicable && strings.TrimSpace(existing.CollectionSource) != "" {
		return existing
	}
	if !filepath.IsAbs(path) {
		// Do not resolve manager/startup commands through Chimera's own PATH: the
		// launch environment may differ. Preserve stronger upstream evidence when
		// available; otherwise keep the boundary unresolved.
		if existing.State == evidence.StateObserved {
			return existing
		}
		label := "relative persistence path cannot be safely resolved without the launch mechanism's effective search path"
		if executable {
			label = "relative persistence executable cannot be safely resolved without the launch mechanism's effective search path"
		}
		return PathPosture{Path: path, State: evidence.StateUnavailable, CollectionSource: "local POSIX ownership/mode metadata", Confidence: evidence.ConfidenceMedium, Reason: label}
	}
	// Reinspect absolute paths even when upstream metadata exists. This handles
	// symlinked unit definitions correctly (for example masked systemd units
	// pointing at /dev/null) and gives one consistent path contract.
	return inspectUnixPersistencePath(path)
}

func fillUnixDirectoryPosture(existing PathPosture, path string) PathPosture {
	if existing.State == evidence.StateObserved {
		return existing
	}
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return pathNotApplicable("local POSIX ownership/mode metadata")
	}
	return inspectUnixPersistencePath(filepath.Dir(path))
}

func inspectUnixPersistencePath(path string) PathPosture {
	source := "local POSIX ownership/mode metadata"
	original := filepath.Clean(path)
	linfo, err := os.Lstat(original)
	if err != nil {
		st := evidence.StateUnavailable
		if os.IsPermission(err) {
			st = evidence.StateDenied
		}
		return PathPosture{Path: original, State: st, CollectionSource: source, Confidence: evidence.ConfidenceMedium, Reason: err.Error()}
	}

	resolved := original
	info := linfo
	isLink := linfo.Mode()&os.ModeSymlink != 0
	if isLink {
		r, err := filepath.EvalSymlinks(original)
		if err != nil {
			return PathPosture{Path: original, State: evidence.StateUnavailable, PermissionModel: "POSIX symlink metadata", CollectionSource: source, Confidence: evidence.ConfidenceMedium, Reason: "symlink target could not be resolved: " + err.Error()}
		}
		resolved = r
		info, err = os.Stat(resolved)
		if err != nil {
			st := evidence.StateUnavailable
			if os.IsPermission(err) {
				st = evidence.StateDenied
			}
			return PathPosture{Path: original, ResolvedPath: resolved, State: st, PermissionModel: "POSIX symlink target metadata", CollectionSource: source, Confidence: evidence.ConfidenceMedium, Reason: err.Error()}
		}
	}

	p := PathPosture{Path: original, ResolvedPath: resolved, State: evidence.StateObserved, Exists: true, Directory: info.IsDir(), Mode: fmt.Sprintf("%#o", info.Mode().Perm()), PermissionModel: "POSIX mode/uid/gid", DACLState: "NOT_APPLICABLE", CollectionSource: source, Confidence: evidence.ConfidenceHigh}
	if isLink {
		p.PermissionModel = "POSIX symlink boundary + resolved target mode/uid/gid"
	}

	// Write permission on a character/block device, socket, FIFO, or other
	// special target describes I/O to that object, not permission to replace the
	// persistence definition. Replacement is covered by the containing-directory
	// posture instead. This prevents masked systemd units -> /dev/null from being
	// misclassified as writable configuration files.
	if !info.Mode().IsRegular() && !info.IsDir() {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
			p.OwnerID = fmt.Sprint(st.Uid)
			p.GroupID = fmt.Sprint(st.Gid)
			if st.Uid == 0 {
				p.OwnerTrust = "TRUSTED"
			} else {
				p.OwnerTrust = "UNTRUSTED"
			}
		}
		p.BroadlyWritable = false
		p.UntrustedWrite = false
		p.Reason = "resolved target is a special filesystem object; target I/O permissions do not imply persistence-definition replacement"
		return normalizePathPosture(p)
	}

	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		p.OwnerID = fmt.Sprint(st.Uid)
		p.GroupID = fmt.Sprint(st.Gid)
		if st.Uid == 0 {
			p.OwnerTrust = "TRUSTED"
		} else {
			p.OwnerTrust = "UNTRUSTED"
		}
		groupWrite := info.Mode().Perm()&0020 != 0
		otherWrite := info.Mode().Perm()&0002 != 0
		p.BroadlyWritable = otherWrite
		p.UntrustedWrite = otherWrite || (groupWrite && st.Gid != 0) || st.Uid != 0
		if otherWrite {
			p.WritePrincipals = append(p.WritePrincipals, "other")
		}
		if groupWrite {
			p.WritePrincipals = append(p.WritePrincipals, "gid:"+fmt.Sprint(st.Gid))
		}
		if st.Uid != 0 {
			p.WritePrincipals = append(p.WritePrincipals, "owner-uid:"+fmt.Sprint(st.Uid))
		}
	} else {
		p.PermissionModel = "POSIX mode; uid/gid unavailable"
		p.BroadlyWritable = info.Mode().Perm()&0002 != 0
		p.UntrustedWrite = p.BroadlyWritable
	}
	return normalizePathPosture(p)
}

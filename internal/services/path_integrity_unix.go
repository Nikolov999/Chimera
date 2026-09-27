//go:build linux || darwin

package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPathIntegrity(ctx context.Context, inv *Inventory) {
	assessed := 0
	degraded := 0
	for i := range inv.Services {
		if err := ctx.Err(); err != nil {
			inv.Degraded = append(inv.Degraded, "service path-integrity collection deadline reached: "+err.Error())
			break
		}
		pi := unixServicePathIntegrity(inv.Services[i])
		inv.Services[i].PathIntegrity = pi
		assessed++
		if pi.State != "COMPLETE" {
			degraded++
		}
	}
	if assessed == 0 {
		addSource(inv, inv.Platform+"-service-path-integrity", evidence.StateUnavailable, "local filesystem ownership/permission metadata", 0, "no service records were available for path-integrity correlation")
		return
	}
	state := evidence.StateObserved
	reason := ""
	if degraded > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("path-integrity metadata incomplete for %d of %d service records", degraded, assessed)
	}
	addSource(inv, inv.Platform+"-service-path-integrity", state, "local filesystem ownership/permission metadata", assessed, reason)
}

func unixServicePathIntegrity(s Service) *ServicePathIntegrity {
	privileged, basis := serviceIsPrivileged(s)
	pi := &ServicePathIntegrity{State: "COMPLETE", Privileged: privileged, PrivilegeBasis: basis}
	executablePath := strings.TrimSpace(s.ExecutablePath)
	pi.Executable = unixServiceExecutablePosture(executablePath)
	pi.ExecutableDirectory = unixPathPosture(parentPath(executablePath))
	pi.Configuration = unixPathPosture(s.DefinitionPath)
	pi.ConfigurationDirectory = unixPathPosture(parentPath(s.DefinitionPath))

	if executablePath == "" {
		if reason := systemdExecutableNotApplicableReason(s); reason != "" {
			pi.Executable = PathPosture{State: "NOT_APPLICABLE", Reason: reason}
			pi.ExecutableDirectory = PathPosture{State: "NOT_APPLICABLE", Reason: reason + "; no executable directory boundary exists"}
			pi.SearchResolution = "NOT_APPLICABLE"
			pi.SearchPathState = "NOT_APPLICABLE"
		} else {
			pi.Executable = PathPosture{State: "UNAVAILABLE", Reason: "service executable path unavailable"}
			pi.ExecutableDirectory = PathPosture{State: "UNAVAILABLE", Reason: "service executable directory unavailable because executable path is unknown"}
			pi.SearchResolution = "UNKNOWN"
			pi.SearchPathState = "UNKNOWN"
			pi.Degraded = append(pi.Degraded, "service executable path unavailable")
		}
	} else if filepath.IsAbs(executablePath) {
		pi.SearchResolution = "ABSOLUTE"
		if pi.ExecutableDirectory.State == "OBSERVED" {
			pi.SearchPathState = "OBSERVED"
			pi.SearchPathWritable = pi.ExecutableDirectory.LowerPrivilegeWritable
			if pi.SearchPathWritable {
				pi.SearchEvidence = append(pi.SearchEvidence, "executable-parent-directory")
			}
		} else {
			pi.SearchPathState = pi.ExecutableDirectory.State
		}
	} else if strings.EqualFold(strings.TrimSpace(s.Manager), "systemd") {
		search, eligible := resolveSystemdManagerExecutable(executablePath)
		if eligible {
			// Preserve that the configured command is relative; SearchPathState and
			// SearchEvidence prove that the systemd manager-specific lookup itself
			// was observed. This keeps the shared cross-platform resolution enum and
			// Windows rule behavior completely unchanged.
			pi.SearchResolution = "RELATIVE"
			pi.SearchPathState = search.State
			pi.SearchPathWritable = search.Writable
			pi.SearchEvidence = append(pi.SearchEvidence, search.Evidence...)
			if search.ResolvedPath != "" {
				pi.Executable = unixServiceExecutablePosture(search.ResolvedPath)
				pi.ExecutableDirectory = unixPathPosture(parentPath(search.ResolvedPath))
			} else if search.State == "OBSERVED" {
				// A simple systemd executable name that is absent from every observed
				// manager search directory has no current executable-file boundary.
				// The creation/hijack risk is still represented by SearchPathWritable
				// across the searched directories, so absence is applicability rather
				// than an acquisition failure.
				pi.Executable = PathPosture{State: "NOT_APPLICABLE", Path: executablePath, Reason: "systemd executable basename is absent from the observed manager search path; no current executable file boundary exists"}
				pi.ExecutableDirectory = PathPosture{State: "NOT_APPLICABLE", Reason: "systemd executable basename did not resolve to a current executable directory; manager search directories were assessed separately"}
			}
			if search.State != "OBSERVED" && strings.TrimSpace(search.Reason) != "" {
				pi.Degraded = append(pi.Degraded, "systemd executable search path: "+strings.TrimSpace(search.Reason))
			}
		} else {
			pi.SearchResolution = "RELATIVE"
			pi.SearchPathState = "UNKNOWN"
			pi.Degraded = append(pi.Degraded, "relative systemd executable contains a path separator and cannot use the manager basename search contract")
		}
	} else {
		// Do not resolve relative service commands through Chimera's own PATH;
		// that could differ from the service manager's effective search path.
		pi.SearchResolution = "RELATIVE"
		pi.SearchPathState = "UNKNOWN"
		pi.Degraded = append(pi.Degraded, "relative service executable requires manager-specific search-path resolution")
	}

	if strings.TrimSpace(s.DefinitionPath) == "" {
		if reason := systemdDefinitionNotFileBackedReason(s); reason != "" {
			pi.Configuration = PathPosture{State: "NOT_APPLICABLE", Reason: reason}
			pi.ConfigurationDirectory = PathPosture{State: "NOT_APPLICABLE", Reason: reason + "; no fragment directory boundary exists"}
		} else {
			pi.Configuration = PathPosture{State: "UNAVAILABLE", Reason: "service definition/configuration path unavailable"}
			pi.ConfigurationDirectory = PathPosture{State: "UNAVAILABLE", Reason: "configuration directory unavailable because definition path is unknown"}
			pi.Degraded = append(pi.Degraded, "service definition/configuration path unavailable")
		}
	}

	appendWeakRole(pi, "executable", pi.Executable)
	appendWeakRole(pi, "executable-directory", pi.ExecutableDirectory)
	appendWeakRole(pi, "configuration", pi.Configuration)
	appendWeakRole(pi, "configuration-directory", pi.ConfigurationDirectory)
	if pi.SearchPathWritable {
		pi.WeakRoles = append(pi.WeakRoles, "search-path")
	}
	pi.normalize()
	return pi
}

// unixServiceExecutablePosture distinguishes an observable absent executable
// from a permission/provider failure. If an absolute configured executable no
// longer exists but its containing directory remains observable, the file
// itself has no current write boundary; creation/replacement risk is assessed
// independently on the containing directory. Broken symlinks are intentionally
// left UNAVAILABLE because the configured link boundary still exists while its
// target cannot be validated.
func unixServiceExecutablePosture(path string) PathPosture {
	path = strings.TrimSpace(path)
	p := unixPathPosture(path)
	if path == "" || !filepath.IsAbs(path) || p.State != "UNAVAILABLE" {
		return p
	}
	if _, err := os.Lstat(filepath.Clean(path)); os.IsNotExist(err) {
		return PathPosture{
			State: "NOT_APPLICABLE", Path: filepath.Clean(path),
			Reason: "configured service executable is not currently present; executable-file write posture is not applicable while the containing-directory creation/replacement boundary is assessed separately",
		}
	}
	return p
}

type systemdExecutableSearchResult struct {
	ResolvedPath string
	State        string
	Writable     bool
	Evidence     []string
	Reason       string
}

var systemdManagerSearchDirs = []string{"/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin", "/bin", "/sbin"}

// resolveSystemdManagerExecutable implements the bounded system-manager
// basename search contract used by systemd Exec*= directives. It never consults
// Chimera's current PATH (which may be a sudo/root shell PATH). Each search
// directory that can influence resolution is assessed for lower-privilege write
// control before a matching executable is accepted. The list deliberately
// includes split-/usr compatibility paths; symlink resolution inside
// unixPathPosture collapses merged-/usr aliases to their real permission
// boundary.
func resolveSystemdManagerExecutable(command string) (systemdExecutableSearchResult, bool) {
	command = strings.TrimSpace(command)
	if command == "" || filepath.IsAbs(command) || strings.ContainsRune(command, filepath.Separator) {
		return systemdExecutableSearchResult{}, false
	}

	result := systemdExecutableSearchResult{State: "OBSERVED"}
	for _, dir := range systemdManagerSearchDirs {
		posture := unixPathPosture(dir)
		if posture.State == "UNAVAILABLE" {
			if _, err := os.Lstat(dir); os.IsNotExist(err) {
				// A currently absent search directory cannot presently supply the
				// command. Assess its parent because a lower-privilege writer there
				// could create the missing search directory before a later launch.
				parent := unixPathPosture(filepath.Dir(dir))
				if parent.State == "OBSERVED" {
					result.Evidence = append(result.Evidence, "systemd-search-parent:"+filepath.Clean(parent.Path))
					result.Writable = result.Writable || parent.LowerPrivilegeWritable
					continue
				}
			}
		}
		if posture.State != "OBSERVED" {
			result.State = "DEGRADED"
			reason := fallback(strings.TrimSpace(posture.Reason), strings.ToLower(posture.State))
			result.Reason = strings.Trim(strings.Join([]string{result.Reason, dir + ": " + reason}, "; "), "; ")
		} else {
			result.Evidence = append(result.Evidence, "systemd-search-dir:"+filepath.Clean(dir))
			result.Writable = result.Writable || posture.LowerPrivilegeWritable
		}

		candidate := filepath.Join(dir, command)
		info, err := os.Stat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.State = "DEGRADED"
			result.Reason = strings.Trim(strings.Join([]string{result.Reason, candidate + ": " + err.Error()}, "; "), "; ")
			continue
		}
		if info.IsDir() || info.Mode()&0111 == 0 {
			continue
		}
		resolved := filepath.Clean(candidate)
		if target, err := filepath.EvalSymlinks(candidate); err == nil && filepath.IsAbs(target) {
			resolved = filepath.Clean(target)
		}
		result.ResolvedPath = resolved
		break
	}
	result.Evidence = uniqueSorted(result.Evidence)
	return result, true
}

func unixPathPosture(path string) PathPosture {
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return PathPosture{State: "NOT_APPLICABLE"}
	}
	original := filepath.Clean(path)
	linfo, err := os.Lstat(original)
	if err != nil {
		if os.IsPermission(err) {
			return PathPosture{State: "DENIED", Path: original, Reason: "permission denied"}
		}
		return PathPosture{State: "UNAVAILABLE", Path: original, Reason: err.Error()}
	}

	info := linfo
	resolved := original
	if linfo.Mode()&os.ModeSymlink != 0 {
		resolved, err = filepath.EvalSymlinks(original)
		if err != nil {
			return PathPosture{State: "UNAVAILABLE", Path: original, Reason: "symbolic-link target resolution failed: " + err.Error()}
		}
		info, err = os.Stat(resolved)
		if err != nil {
			if os.IsPermission(err) {
				return PathPosture{State: "DENIED", Path: original, Reason: "symbolic-link target permission denied"}
			}
			return PathPosture{State: "UNAVAILABLE", Path: original, Reason: "symbolic-link target metadata unavailable: " + err.Error()}
		}
	}

	p := PathPosture{State: "OBSERVED", Path: original, Mode: fmt.Sprintf("%04o", info.Mode().Perm())}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		p.Owner = strconv.FormatUint(uint64(st.Uid), 10)
		p.Group = strconv.FormatUint(uint64(st.Gid), 10)
		// Device/socket/FIFO permissions govern I/O to the target, not replacement
		// of the service definition symlink. The containing-directory posture covers
		// replacement of that link. This matters for masked systemd units -> /dev/null.
		if !info.Mode().IsRegular() && !info.IsDir() {
			p.LowerPrivilegeWritable = false
			p.Reason = "resolved target is a special filesystem object; target I/O permissions do not imply service-path replacement"
			return p
		}
		// For a root/SYSTEM-equivalent boundary, a non-root owner can change
		// its own mode and content. Group write is weak when the controlling
		// group is not root/wheel-equivalent gid 0; other-write is always weak.
		p.LowerPrivilegeWritable = st.Uid != 0 || (info.Mode().Perm()&0020 != 0 && st.Gid != 0) || info.Mode().Perm()&0002 != 0
	} else {
		p.Reason = "ownership metadata unavailable"
	}
	if resolved != original && p.Reason == "" {
		p.Reason = "permissions assessed on resolved symbolic-link target " + resolved
	}
	return p
}

func systemdExecutableNotApplicableReason(s Service) string {
	if !strings.EqualFold(strings.TrimSpace(s.Manager), "systemd") {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(s.StartMode), "masked") {
		return "masked systemd unit has no executable launch boundary"
	}
	// `systemctl show` is the effective manager view (including drop-ins). When
	// it successfully reports a loaded unit but every requested lifecycle
	// executable property is empty, the unit genuinely has no executable launch
	// boundary represented by systemd. Treat that as non-applicable rather than
	// calling the provider incomplete. File-only fallback records do not get this
	// shortcut because drop-ins may not have been observed there.
	if strings.EqualFold(strings.TrimSpace(s.CollectionSource), "systemctl show") &&
		strings.EqualFold(strings.TrimSpace(s.DefinitionState), "loaded") {
		return "effective systemd metadata exposes no executable lifecycle command"
	}
	return ""
}

func systemdDefinitionNotFileBackedReason(s Service) string {
	if !strings.EqualFold(strings.TrimSpace(s.Manager), "systemd") {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(s.StartMode)) {
	case "masked", "transient", "generated":
		return "masked/transient/generated systemd unit has no file-backed fragment"
	}
	// A successful effective systemd record with LoadState=loaded and no
	// FragmentPath/SourcePath is manager-backed but not file-backed (for example
	// a transient or synthetic unit). The missing fragment is therefore not an
	// acquisition failure.
	if strings.EqualFold(strings.TrimSpace(s.CollectionSource), "systemctl show") &&
		strings.EqualFold(strings.TrimSpace(s.DefinitionState), "loaded") {
		return "effective systemd metadata exposes no file-backed unit fragment"
	}
	return ""
}

func parentPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return ""
	}
	return filepath.Dir(clean)
}

//go:build windows

package services

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

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
		pi := windowsServicePathIntegrity(inv.Services[i])
		inv.Services[i].PathIntegrity = pi
		assessed++
		if pi.State != "COMPLETE" {
			degraded++
		}
	}
	if assessed == 0 {
		addSource(inv, "windows-service-path-integrity", evidence.StateUnavailable, "SCM registry and NTFS ACL metadata", 0, "no Windows service records were available for path-integrity correlation")
		return
	}
	state := evidence.StateObserved
	reason := ""
	if degraded > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("path-integrity metadata incomplete for %d of %d service records", degraded, assessed)
	}
	addSource(inv, "windows-service-path-integrity", state, "SCM registry and NTFS ACL metadata", assessed, reason)
}

func windowsServicePathIntegrity(s Service) *ServicePathIntegrity {
	privileged, basis := serviceIsPrivileged(s)
	pi := &ServicePathIntegrity{State: "DEGRADED", Privileged: privileged, PrivilegeBasis: basis, SearchResolution: "UNKNOWN", SearchPathState: "UNKNOWN"}
	sec := s.WindowsSecurity
	if sec == nil {
		pi.Executable = PathPosture{State: "UNAVAILABLE", Path: s.ExecutablePath, Reason: "Windows service security metadata unavailable"}
		pi.ExecutableDirectory = PathPosture{State: "UNAVAILABLE", Reason: "Windows service security metadata unavailable"}
		pi.Configuration = PathPosture{State: "UNAVAILABLE", Path: s.DefinitionPath, Reason: "Windows service registry ACL metadata unavailable"}
		pi.ConfigurationDirectory = PathPosture{State: "NOT_APPLICABLE"}
		pi.Degraded = []string{"Windows service security metadata unavailable"}
		pi.normalize()
		return pi
	}
	pi.State = "COMPLETE"
	pi.Executable = windowsACLPathPosture(s.ExecutablePath, sec.ExecutableACL)
	executableDir := ""
	if strings.TrimSpace(s.ExecutablePath) != "" {
		executableDir = filepath.Dir(s.ExecutablePath)
	}
	pi.ExecutableDirectory = windowsACLPathPosture(executableDir, sec.ExecutableDirectoryACL)
	pi.Configuration = windowsACLPathPosture(s.DefinitionPath, sec.RegistryACL)
	pi.ConfigurationDirectory = PathPosture{State: "NOT_APPLICABLE", Reason: "registry configuration is represented by the service registry key ACL"}
	switch sec.ServiceDLLState {
	case "NOT_APPLICABLE":
		pi.ServiceDLL = &PathPosture{State: "NOT_APPLICABLE", Reason: "service does not configure ServiceDll"}
		pi.ServiceDLLDirectory = &PathPosture{State: "NOT_APPLICABLE", Reason: "service does not configure ServiceDll"}
	case "OBSERVED":
		dll := windowsACLPathPosture(sec.ServiceDLLPath, sec.ServiceDLLACL)
		dllDirPath := ""
		if strings.TrimSpace(sec.ServiceDLLPath) != "" {
			dllDirPath = filepath.Dir(sec.ServiceDLLPath)
		}
		dllDir := windowsACLPathPosture(dllDirPath, sec.ServiceDLLDirectoryACL)
		pi.ServiceDLL = &dll
		pi.ServiceDLLDirectory = &dllDir
	default:
		state := componentState(sec.ServiceDLLState)
		pi.ServiceDLL = &PathPosture{State: state, Path: sec.ServiceDLLPath, Reason: fallback(sec.ServiceDLLReason, "ServiceDll configuration unavailable")}
		pi.ServiceDLLDirectory = &PathPosture{State: state, Reason: fallback(sec.ServiceDLLReason, "ServiceDll configuration unavailable")}
	}
	switch sec.FailureCommandState {
	case "NOT_APPLICABLE":
		pi.RecoveryExecutable = &PathPosture{State: "NOT_APPLICABLE", Reason: "service does not configure a recovery command"}
		pi.RecoveryExecutableDirectory = &PathPosture{State: "NOT_APPLICABLE", Reason: "service does not configure a recovery command"}
	case "OBSERVED":
		recovery := windowsACLPathPosture(sec.FailureExecutablePath, sec.FailureExecutableACL)
		recoveryDirPath := ""
		if strings.TrimSpace(sec.FailureExecutablePath) != "" {
			recoveryDirPath = filepath.Dir(sec.FailureExecutablePath)
		}
		recoveryDir := windowsACLPathPosture(recoveryDirPath, sec.FailureExecutableDirectoryACL)
		pi.RecoveryExecutable = &recovery
		pi.RecoveryExecutableDirectory = &recoveryDir
	default:
		state := componentState(sec.FailureCommandState)
		pi.RecoveryExecutable = &PathPosture{State: state, Path: sec.FailureExecutablePath, Reason: fallback(sec.FailureCommandReason, "service recovery configuration unavailable")}
		pi.RecoveryExecutableDirectory = &PathPosture{State: state, Reason: fallback(sec.FailureCommandReason, "service recovery configuration unavailable")}
	}
	appendWindowsPathComponentDegradation(pi, "service executable ACL", pi.Executable)
	appendWindowsPathComponentDegradation(pi, "service executable directory ACL", pi.ExecutableDirectory)
	appendWindowsPathComponentDegradation(pi, "service registry ACL", pi.Configuration)
	if pi.ServiceDLL != nil && pi.ServiceDLL.State != "NOT_APPLICABLE" {
		appendWindowsPathComponentDegradation(pi, "service DLL ACL", *pi.ServiceDLL)
	}
	if pi.ServiceDLLDirectory != nil && pi.ServiceDLLDirectory.State != "NOT_APPLICABLE" {
		appendWindowsPathComponentDegradation(pi, "service DLL directory ACL", *pi.ServiceDLLDirectory)
	}
	if pi.RecoveryExecutable != nil && pi.RecoveryExecutable.State != "NOT_APPLICABLE" {
		appendWindowsPathComponentDegradation(pi, "service recovery executable ACL", *pi.RecoveryExecutable)
	}
	if pi.RecoveryExecutableDirectory != nil && pi.RecoveryExecutableDirectory.State != "NOT_APPLICABLE" {
		appendWindowsPathComponentDegradation(pi, "service recovery executable directory ACL", *pi.RecoveryExecutableDirectory)
	}

	if strings.TrimSpace(s.ExecutablePath) == "" {
		pi.Executable = PathPosture{State: "UNAVAILABLE", Reason: "service executable path unavailable"}
		pi.ExecutableDirectory = PathPosture{State: "UNAVAILABLE", Reason: "service executable directory unavailable because executable path is unknown"}
		pi.SearchResolution = "UNKNOWN"
		pi.SearchPathState = "UNKNOWN"
		pi.Degraded = append(pi.Degraded, "service executable path unavailable")
	} else if sec.ExecutableResolution == "UNQUOTED" || sec.UnquotedExecutablePath {
		pi.SearchResolution = "UNQUOTED"
		if sec.ExecutableDirectoryACL.State == "OBSERVED" && sec.ExecutableDirectoryACL.BroadWriteGranted {
			// A writable executable directory is sufficient to prove a weak
			// resolution boundary. A non-writable final directory is not enough
			// to prove every earlier unquoted candidate prefix is safe.
			pi.SearchPathState = "OBSERVED"
			pi.SearchPathWritable = true
			pi.SearchEvidence = append(pi.SearchEvidence, "unquoted-executable-parent-directory")
		} else {
			pi.SearchPathState = "UNKNOWN"
			pi.Degraded = append(pi.Degraded, "unquoted service path candidate-prefix ACLs are not fully resolved")
		}
	} else if sec.ExecutableResolution == "QUOTED_OR_ABSOLUTE" {
		pi.SearchResolution = "QUOTED_OR_ABSOLUTE"
		pi.SearchPathState = "OBSERVED"
	} else {
		pi.SearchResolution = "UNKNOWN"
		pi.SearchPathState = "UNKNOWN"
		pi.Degraded = append(pi.Degraded, "service executable quoting/resolution semantics unavailable")
	}

	appendWeakRole(pi, "executable", pi.Executable)
	appendWeakRole(pi, "executable-directory", pi.ExecutableDirectory)
	appendWeakRole(pi, "configuration", pi.Configuration)
	if pi.ServiceDLL != nil {
		appendWeakRole(pi, "service-dll", *pi.ServiceDLL)
	}
	if pi.ServiceDLLDirectory != nil {
		appendWeakRole(pi, "service-dll-directory", *pi.ServiceDLLDirectory)
	}
	if pi.RecoveryExecutable != nil {
		appendWeakRole(pi, "recovery-executable", *pi.RecoveryExecutable)
	}
	if pi.RecoveryExecutableDirectory != nil {
		appendWeakRole(pi, "recovery-executable-directory", *pi.RecoveryExecutableDirectory)
	}
	if pi.SearchPathWritable {
		pi.WeakRoles = append(pi.WeakRoles, "search-path")
	}
	pi.normalize()
	return pi
}

func windowsACLPathPosture(path string, acl WindowsACLPosture) PathPosture {
	return PathPosture{
		State: acl.State, Path: strings.TrimSpace(path), Owner: strings.TrimSpace(acl.OwnerSID), LowerPrivilegeWritable: acl.BroadWriteGranted,
		Principals: append([]string(nil), acl.Principals...), Rights: append([]string(nil), acl.Rights...), Reason: acl.Reason,
	}
}

func appendWindowsPathComponentDegradation(pi *ServicePathIntegrity, label string, posture PathPosture) {
	if pi == nil || posture.State == "OBSERVED" || posture.State == "NOT_APPLICABLE" {
		return
	}
	reason := strings.TrimSpace(posture.Reason)
	if reason == "" {
		reason = strings.ToLower(strings.TrimSpace(posture.State))
	}
	pi.Degraded = append(pi.Degraded, label+": "+reason)
}

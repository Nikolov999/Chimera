//go:build darwin

package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type launchdPathPosture struct {
	state           string
	owner           string
	mode            string
	broadlyWritable bool
}

func collectLaunchdHardening(m map[string]any, definitionPath, kind, account, program string) *LaunchdHardening {
	sec := &LaunchdHardening{State: "COMPLETE", EnvironmentValuesRedacted: true}
	def := launchdPathMetadata(definitionPath)
	sec.DefinitionOwner, sec.DefinitionMode, sec.DefinitionBroadlyWritable = def.owner, def.mode, def.broadlyWritable
	if def.state != "OBSERVED" {
		sec.Degraded = append(sec.Degraded, "definition metadata "+strings.ToLower(def.state))
	}

	program = strings.TrimSpace(program)
	sec.ProgramAbsolute = program != "" && filepath.IsAbs(program)
	if program == "" {
		sec.ExecutableState = "UNAVAILABLE"
		sec.ExecutableParentState = "UNAVAILABLE"
		sec.Degraded = append(sec.Degraded, "launchd program path unavailable")
	} else {
		exe := launchdPathMetadata(program)
		sec.ExecutableState, sec.ExecutableOwner, sec.ExecutableMode, sec.ExecutableBroadlyWritable = exe.state, exe.owner, exe.mode, exe.broadlyWritable
		parent := launchdPathMetadata(filepath.Dir(program))
		sec.ExecutableParentState, sec.ExecutableParentOwner, sec.ExecutableParentMode, sec.ExecutableParentBroadlyWritable = parent.state, parent.owner, parent.mode, parent.broadlyWritable
		if exe.state != "OBSERVED" {
			sec.Degraded = append(sec.Degraded, "executable metadata "+strings.ToLower(exe.state))
		}
		if parent.state != "OBSERVED" {
			sec.Degraded = append(sec.Degraded, "executable parent metadata "+strings.ToLower(parent.state))
		}
	}

	if env, ok := m["EnvironmentVariables"].(map[string]any); ok {
		for key := range env {
			sec.EnvironmentVariableNames = append(sec.EnvironmentVariableNames, key)
		}
	}
	dangerousEnv := map[string]struct{}{
		"DYLD_INSERT_LIBRARIES": {}, "DYLD_LIBRARY_PATH": {}, "DYLD_FRAMEWORK_PATH": {},
		"DYLD_FALLBACK_LIBRARY_PATH": {}, "DYLD_FALLBACK_FRAMEWORK_PATH": {}, "DYLD_IMAGE_SUFFIX": {},
	}
	for _, key := range sec.EnvironmentVariableNames {
		if _, ok := dangerousEnv[strings.ToUpper(key)]; ok {
			sec.DangerousEnvironmentKeys = append(sec.DangerousEnvironmentKeys, key)
		}
	}

	sec.WorkingDirectory = anyString(m["WorkingDirectory"])
	if sec.WorkingDirectory != "" {
		sec.WorkingDirectoryBroadlyWritable = launchdPathMetadata(sec.WorkingDirectory).broadlyWritable
	}
	sec.RootDirectory = anyString(m["RootDirectory"])
	if sec.RootDirectory != "" {
		sec.RootDirectoryBroadlyWritable = launchdPathMetadata(sec.RootDirectory).broadlyWritable
	}

	privileged := strings.EqualFold(account, "root") || strings.TrimSpace(account) == "0"
	if privileged && launchdWeakExecutablePath(program) {
		sec.PrivilegedWeakPath = true
	}
	if !sec.ProgramAbsolute && program != "" {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "relative-program-path")
	}
	if privileged && sec.PrivilegedWeakPath {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "privileged-weak-executable-location")
	}
	if privileged && sec.WorkingDirectoryBroadlyWritable {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "privileged-broadly-writable-working-directory")
	}
	if privileged && sec.RootDirectoryBroadlyWritable {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "privileged-broadly-writable-root-directory")
	}
	if strings.EqualFold(kind, "LaunchAgent") && privileged {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "root-launch-agent")
	}
	if privileged && len(sec.DangerousEnvironmentKeys) > 0 {
		sec.DangerousConfiguration = append(sec.DangerousConfiguration, "privileged-dyld-environment")
	}

	sec.normalize()
	return sec
}

func launchdPathMetadata(path string) launchdPathPosture {
	path = strings.TrimSpace(path)
	if path == "" {
		return launchdPathPosture{state: "NOT_APPLICABLE"}
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsPermission(err) {
			return launchdPathPosture{state: "DENIED"}
		}
		return launchdPathPosture{state: "UNAVAILABLE"}
	}
	owner := "UNKNOWN"
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = strconv.FormatUint(uint64(st.Uid), 10)
	}
	mode := fmt.Sprintf("%04o", info.Mode().Perm())
	return launchdPathPosture{state: "OBSERVED", owner: owner, mode: mode, broadlyWritable: info.Mode().Perm()&0022 != 0}
}

func launchdWeakExecutablePath(path string) bool {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == "" {
		return false
	}
	lower := strings.ToLower(clean)
	weakRoots := []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/users/", "/volumes/"}
	for _, root := range weakRoots {
		if strings.HasPrefix(lower+"/", root) {
			return true
		}
	}
	return false
}

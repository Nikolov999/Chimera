//go:build windows

package filesystem

import (
	"os"
	"path/filepath"
)

func platformCandidates() []candidate {
	systemDrive := fallback(os.Getenv("SystemDrive"), `C:`)
	systemRoot := fallback(os.Getenv("SystemRoot"), filepath.Join(systemDrive+`\\`, "Windows"))
	programFiles := fallback(os.Getenv("ProgramFiles"), filepath.Join(systemDrive+`\\`, "Program Files"))
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	programData := fallback(os.Getenv("ProgramData"), filepath.Join(systemDrive+`\\`, "ProgramData"))
	users := filepath.Join(systemDrive+`\\`, "Users")
	out := []candidate{
		{"ROOT", systemDrive + `\\`, "Windows system volume root"},
		{"ROOT", systemRoot, "Windows operating-system root"},
		{"ROOT", programFiles, "Windows application root"},
		{"ROOT", programData, "Windows shared application-data root"},
		{"ROOT", users, "Windows user-profile root"},
		{"TEMP", filepath.Join(systemRoot, "Temp"), "Windows system temporary area"},
		{"SENSITIVE_CONFIG", filepath.Join(systemRoot, "System32", "config"), "Windows registry hive location"},
		{"SENSITIVE_CONFIG", filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts"), "Windows host-resolution configuration location"},
		{"SENSITIVE_CONFIG", filepath.Join(systemRoot, "System32", "Tasks"), "Windows scheduled-task definition location"},
		{"SENSITIVE_CONFIG", filepath.Join(programData, "ssh", "sshd_config"), "Windows OpenSSH service configuration location"},
	}
	if programFilesX86 != "" {
		out = append(out, candidate{"ROOT", programFilesX86, "Windows 32-bit application root"})
	}
	return out
}

func platformExecutableDirectories() []string {
	systemDrive := fallback(os.Getenv("SystemDrive"), `C:`)
	systemRoot := fallback(os.Getenv("SystemRoot"), filepath.Join(systemDrive+`\`, "Windows"))
	return []string{
		systemRoot,
		filepath.Join(systemRoot, "System32"),
		filepath.Join(systemRoot, "SysWOW64"),
		filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0"),
	}
}

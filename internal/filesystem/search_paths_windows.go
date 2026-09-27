//go:build windows

package filesystem

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func currentProcessPrivileged() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	closeHandle := kernel32.NewProc("CloseHandle")
	openProcessToken := advapi32.NewProc("OpenProcessToken")
	getTokenInformation := advapi32.NewProc("GetTokenInformation")

	process, _, _ := getCurrentProcess.Call()
	var token syscall.Handle
	const tokenQuery = 0x0008
	r, _, _ := openProcessToken.Call(process, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer closeHandle.Call(uintptr(token))

	var elevation uint32
	var returned uint32
	const tokenElevationClass = 20
	r, _, _ = getTokenInformation.Call(
		uintptr(token),
		tokenElevationClass,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returned)),
	)
	return r != 0 && elevation != 0
}

func platformPrivilegedSearchPathCandidates() []searchPathCandidate {
	systemDrive := fallback(os.Getenv("SystemDrive"), `C:`)
	systemRoot := fallback(os.Getenv("SystemRoot"), filepath.Join(systemDrive+`\`, "Windows"))
	system32 := filepath.Join(systemRoot, "System32")
	command := []string{"PRIVILEGED_USER", "SERVICE", "SCHEDULED_JOB", "SYSTEM_COMPONENT"}
	loader := []string{"LOADER", "SYSTEM_COMPONENT"}
	return []searchPathCandidate{
		{Path: system32, Contexts: append(command, loader...), Source: "Windows protected system command and DLL search directory"},
		{Path: systemRoot, Contexts: append(command, loader...), Source: "Windows protected operating-system search directory"},
		{Path: filepath.Join(system32, "WindowsPowerShell", "v1.0"), Contexts: command, Source: "Windows system PowerShell command search directory"},
	}
}

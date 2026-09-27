//go:build windows

package remotemgmt

import (
	"os"
	"path/filepath"
)

func sshCandidateConfigPaths() []string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return []string{filepath.Join(pd, "ssh", "sshd_config")}
}

func sshCandidateDaemonPaths() []string {
	pf := os.Getenv("WINDIR")
	if pf == "" {
		pf = `C:\Windows`
	}
	pfiles := os.Getenv("ProgramFiles")
	if pfiles == "" {
		pfiles = `C:\Program Files`
	}
	return []string{
		filepath.Join(pf, "System32", "OpenSSH", "sshd.exe"),
		filepath.Join(pfiles, "OpenSSH", "sshd.exe"),
	}
}

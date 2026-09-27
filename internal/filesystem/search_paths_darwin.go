//go:build darwin

package filesystem

import "os"

func currentProcessPrivileged() bool { return os.Geteuid() == 0 }

func platformPrivilegedSearchPathCandidates() []searchPathCandidate {
	command := []string{"PRIVILEGED_USER", "SERVICE", "SCHEDULED_JOB", "SYSTEM_COMPONENT"}
	loader := []string{"LOADER"}
	out := []searchPathCandidate{}
	for _, p := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"} {
		out = append(out, searchPathCandidate{Path: p, Contexts: command, Source: "macOS standard privileged command search directory"})
	}
	for _, p := range []string{"/usr/lib", "/System/Library/Frameworks", "/System/Library/PrivateFrameworks"} {
		out = append(out, searchPathCandidate{Path: p, Contexts: loader, Source: "macOS protected system loader/framework search root"})
	}
	return out
}

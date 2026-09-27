//go:build !linux && !darwin && !windows

package remotemgmt

func sshCandidateConfigPaths() []string { return nil }
func sshCandidateDaemonPaths() []string { return nil }

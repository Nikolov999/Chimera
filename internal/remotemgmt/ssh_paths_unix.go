//go:build linux || darwin

package remotemgmt

func sshCandidateConfigPaths() []string {
	return []string{"/etc/ssh/sshd_config", "/usr/local/etc/ssh/sshd_config"}
}

func sshCandidateDaemonPaths() []string {
	return []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/opt/homebrew/sbin/sshd"}
}

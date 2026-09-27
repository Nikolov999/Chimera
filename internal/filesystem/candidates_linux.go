//go:build linux

package filesystem

func platformCandidates() []candidate {
	return []candidate{
		{"ROOT", "/", "Linux filesystem root"},
		{"ROOT", "/etc", "Linux system configuration root"},
		{"ROOT", "/usr", "Linux system software root"},
		{"ROOT", "/usr/local", "Linux local software root"},
		{"ROOT", "/opt", "Linux optional software root"},
		{"ROOT", "/var", "Linux variable-data root"},
		{"ROOT", "/home", "Linux user-home root"},
		{"TEMP", "/tmp", "Linux temporary area"},
		{"TEMP", "/var/tmp", "Linux persistent temporary area"},
		{"TEMP", "/dev/shm", "Linux shared-memory temporary area"},
		{"SENSITIVE_CONFIG", "/etc/passwd", "Linux identity configuration location"},
		{"SENSITIVE_CONFIG", "/etc/shadow", "Linux authentication configuration location"},
		{"SENSITIVE_CONFIG", "/etc/group", "Linux group configuration location"},
		{"SENSITIVE_CONFIG", "/etc/sudoers", "Linux sudo policy location"},
		{"SENSITIVE_CONFIG", "/etc/sudoers.d", "Linux sudo include location"},
		{"SENSITIVE_CONFIG", "/etc/ssh/sshd_config", "Linux SSH service configuration location"},
		{"SENSITIVE_CONFIG", "/etc/fstab", "Linux mount configuration location"},
		{"SENSITIVE_CONFIG", "/etc/crypttab", "Linux encrypted-volume configuration location"},
		{"SENSITIVE_CONFIG", "/etc/systemd", "Linux systemd configuration location"},
		{"SENSITIVE_CONFIG", "/etc/cron.d", "Linux scheduled-execution configuration location"},
	}
}

func platformExecutableDirectories() []string {
	return []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/bin"}
}

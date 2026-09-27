//go:build darwin

package filesystem

func platformCandidates() []candidate {
	return []candidate{
		{"ROOT", "/", "macOS filesystem root"},
		{"ROOT", "/System", "macOS system root"},
		{"ROOT", "/Library", "macOS system library root"},
		{"ROOT", "/Applications", "macOS applications root"},
		{"ROOT", "/Users", "macOS user-home root"},
		{"ROOT", "/usr/local", "macOS local software root"},
		{"TEMP", "/private/tmp", "macOS shared temporary area"},
		{"TEMP", "/private/var/tmp", "macOS persistent temporary area"},
		{"SENSITIVE_CONFIG", "/etc/hosts", "macOS host-resolution configuration location"},
		{"SENSITIVE_CONFIG", "/etc/ssh/sshd_config", "macOS SSH service configuration location"},
		{"SENSITIVE_CONFIG", "/etc/sudoers", "macOS sudo policy location"},
		{"SENSITIVE_CONFIG", "/etc/sudoers.d", "macOS sudo include location"},
		{"SENSITIVE_CONFIG", "/Library/LaunchDaemons", "macOS privileged launchd configuration location"},
		{"SENSITIVE_CONFIG", "/Library/LaunchAgents", "macOS launch-agent configuration location"},
		{"SENSITIVE_CONFIG", "/Library/Preferences", "macOS system preference configuration location"},
	}
}

func platformExecutableDirectories() []string {
	return []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin", "/opt/homebrew/sbin", "/opt/local/bin", "/opt/local/sbin"}
}

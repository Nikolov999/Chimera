//go:build darwin

package filesystem

func platformSensitiveCandidates() []sensitiveCandidate {
	c := []sensitiveCandidate{
		{"AUTH_SECRET", "SYSTEM", "/private/etc/master.passwd", SensitivePolicyNoWorldRead, "0", "macOS local authentication metadata"},
		{"SUDO_CONFIG", "SYSTEM", "/private/etc/sudoers", SensitivePolicyWriteRestricted, "0", "macOS sudo policy"},
		{"SUDO_CONFIG", "SYSTEM", "/private/etc/sudoers.d", SensitivePolicyWriteRestricted, "0", "macOS sudo include directory"},
		{"SSH_CONFIG", "SYSTEM", "/private/etc/ssh/sshd_config", SensitivePolicyWriteRestricted, "0", "macOS SSH daemon configuration"},
		{"PRIVATE_KEY", "SYSTEM", "/private/etc/ssh/ssh_host_*_key", SensitivePolicyOwnerOnly, "0", "macOS SSH host private key"},
		{"AUTH_CONFIG", "SYSTEM", "/private/etc/pam.d", SensitivePolicyWriteRestricted, "0", "macOS PAM policy directory"},
		{"SERVICE_CONFIG", "SYSTEM", "/Library/LaunchDaemons", SensitivePolicyWriteRestricted, "0", "macOS privileged launchd configuration directory"},
		{"SERVICE_CONFIG", "SYSTEM", "/Library/LaunchAgents", SensitivePolicyWriteRestricted, "0", "macOS launch-agent configuration directory"},
		{"SECURITY_CONFIG", "SYSTEM", "/Library/Preferences", SensitivePolicyWriteRestricted, "0", "macOS system preference configuration directory"},
	}
	for _, home := range []string{"/Users/*", "/var/root"} {
		c = append(c, darwinUserSensitiveCandidates(home)...)
	}
	for _, p := range []string{"/opt/*/.env", "/usr/local/*/.env"} {
		c = append(c, sensitiveCandidate{"ENVIRONMENT_SECRET", "APPLICATION", p, SensitivePolicyNoWorldRead, "", "bounded application environment-file metadata"})
	}
	return c
}

func darwinUserSensitiveCandidates(home string) []sensitiveCandidate {
	return []sensitiveCandidate{
		{"SSH_DIRECTORY", "USER", home + "/.ssh", SensitivePolicyOwnerOnly, "", "user SSH directory metadata"},
		{"SSH_AUTHORIZED_KEYS", "USER", home + "/.ssh/authorized_keys", SensitivePolicyWriteRestricted, "", "user SSH authorized_keys metadata"},
		{"PRIVATE_KEY", "USER", home + "/.ssh/id_*", SensitivePolicyOwnerOnly, "", "user SSH private-key filename metadata"},
		{"PRIVATE_KEY", "USER", home + "/.ssh/*.pem", SensitivePolicyOwnerOnly, "", "user SSH PEM private-key filename metadata"},
		{"PRIVATE_KEY", "USER", home + "/.ssh/*.key", SensitivePolicyOwnerOnly, "", "user SSH private-key filename metadata"},
		{"CLOUD_CREDENTIAL_DIR", "USER", home + "/.aws", SensitivePolicyOwnerOnly, "", "AWS credential directory metadata"},
		{"CLOUD_CREDENTIAL", "USER", home + "/.aws/credentials", SensitivePolicyOwnerOnly, "", "AWS credential file metadata"},
		{"CLOUD_CREDENTIAL_DIR", "USER", home + "/.config/gcloud", SensitivePolicyOwnerOnly, "", "Google Cloud credential directory metadata"},
		{"CLOUD_CREDENTIAL", "USER", home + "/.config/gcloud/application_default_credentials.json", SensitivePolicyOwnerOnly, "", "Google Cloud application-default credential metadata"},
		{"ORCHESTRATION_CREDENTIAL_DIR", "USER", home + "/.kube", SensitivePolicyOwnerOnly, "", "Kubernetes credential/config directory metadata"},
		{"ORCHESTRATION_CREDENTIAL", "USER", home + "/.kube/config", SensitivePolicyOwnerOnly, "", "Kubernetes credential/config file metadata"},
		{"ENVIRONMENT_SECRET", "USER", home + "/.env", SensitivePolicyOwnerOnly, "", "user environment-file metadata"},
	}
}

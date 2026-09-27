//go:build linux

package filesystem

func platformSensitiveCandidates() []sensitiveCandidate {
	c := []sensitiveCandidate{
		{"AUTH_SECRET", "SYSTEM", "/etc/shadow", SensitivePolicyNoWorldRead, "0", "Linux authentication secret metadata"},
		{"AUTH_SECRET", "SYSTEM", "/etc/gshadow", SensitivePolicyNoWorldRead, "0", "Linux group authentication secret metadata"},
		{"AUTH_CONFIG", "SYSTEM", "/etc/passwd", SensitivePolicyWriteRestricted, "0", "Linux account configuration"},
		{"AUTH_CONFIG", "SYSTEM", "/etc/group", SensitivePolicyWriteRestricted, "0", "Linux group configuration"},
		{"SUDO_CONFIG", "SYSTEM", "/etc/sudoers", SensitivePolicyWriteRestricted, "0", "Linux sudo policy"},
		{"SUDO_CONFIG", "SYSTEM", "/etc/sudoers.d", SensitivePolicyWriteRestricted, "0", "Linux sudo policy include directory"},
		{"SSH_CONFIG", "SYSTEM", "/etc/ssh/sshd_config", SensitivePolicyWriteRestricted, "0", "Linux SSH daemon configuration"},
		{"PRIVATE_KEY", "SYSTEM", "/etc/ssh/ssh_host_*_key", SensitivePolicyOwnerOnly, "0", "Linux SSH host private key"},
		{"AUTH_CONFIG", "SYSTEM", "/etc/pam.d", SensitivePolicyWriteRestricted, "0", "Linux PAM policy directory"},
		{"AUTH_CONFIG", "SYSTEM", "/etc/security", SensitivePolicyWriteRestricted, "0", "Linux authentication/security policy directory"},
		{"SERVICE_CONFIG", "SYSTEM", "/etc/systemd/system", SensitivePolicyWriteRestricted, "0", "Linux systemd service configuration directory"},
		{"SCHEDULE_CONFIG", "SYSTEM", "/etc/cron.d", SensitivePolicyWriteRestricted, "0", "Linux cron configuration directory"},
		{"SCHEDULE_CONFIG", "SYSTEM", "/etc/crontab", SensitivePolicyWriteRestricted, "0", "Linux system crontab"},
		{"ENVIRONMENT_CONFIG", "SYSTEM", "/etc/environment", SensitivePolicyWriteRestricted, "0", "Linux system environment configuration"},
		{"STORAGE_CONFIG", "SYSTEM", "/etc/crypttab", SensitivePolicyWriteRestricted, "0", "Linux encrypted-volume configuration"},
	}
	c = append(c, linuxUserSensitiveCandidates("/root")...)
	for _, base := range []string{"/home/*", "/srv/*", "/var/lib/*"} {
		c = append(c, linuxUserSensitiveCandidates(base)...)
	}
	for _, p := range []string{"/opt/*/.env", "/srv/*/.env", "/var/www/*/.env"} {
		c = append(c, sensitiveCandidate{"ENVIRONMENT_SECRET", "APPLICATION", p, SensitivePolicyNoWorldRead, "", "bounded application environment-file metadata"})
	}
	return c
}

func linuxUserSensitiveCandidates(home string) []sensitiveCandidate {
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

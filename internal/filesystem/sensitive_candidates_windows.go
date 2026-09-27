//go:build windows

package filesystem

import (
	"os"
	"path/filepath"
)

func platformSensitiveCandidates() []sensitiveCandidate {
	systemDrive := fallback(os.Getenv("SystemDrive"), `C:`)
	systemRoot := fallback(os.Getenv("SystemRoot"), filepath.Join(systemDrive+`\`, "Windows"))
	programData := fallback(os.Getenv("ProgramData"), filepath.Join(systemDrive+`\`, "ProgramData"))
	users := filepath.Join(systemDrive+`\`, "Users")
	sshRoot := filepath.Join(programData, "ssh")
	c := []sensitiveCandidate{
		{"SECURITY_CONFIG", "SYSTEM", filepath.Join(systemRoot, "System32", "config"), SensitivePolicyWriteRestricted, "", "Windows registry hive directory ACL metadata"},
		{"SCHEDULE_CONFIG", "SYSTEM", filepath.Join(systemRoot, "System32", "Tasks"), SensitivePolicyWriteRestricted, "", "Windows scheduled-task definition directory ACL metadata"},
		{"SSH_CONFIG", "SYSTEM", filepath.Join(sshRoot, "sshd_config"), SensitivePolicyWriteRestricted, "", "Windows OpenSSH daemon configuration ACL metadata"},
		{"PRIVATE_KEY", "SYSTEM", filepath.Join(sshRoot, "ssh_host_*_key"), SensitivePolicyOwnerOnly, "", "Windows OpenSSH host private-key ACL metadata"},
		{"SSH_AUTHORIZED_KEYS", "SYSTEM", filepath.Join(sshRoot, "administrators_authorized_keys"), SensitivePolicyWriteRestricted, "", "Windows administrators authorized_keys ACL metadata"},
		{"SERVICE_CONFIG", "SYSTEM", filepath.Join(programData, "Docker", "config", "daemon.json"), SensitivePolicyWriteRestricted, "", "Windows Docker daemon configuration ACL metadata"},
	}
	home := filepath.Join(users, "*")
	c = append(c,
		sensitiveCandidate{"SSH_DIRECTORY", "USER", filepath.Join(home, ".ssh"), SensitivePolicyOwnerOnly, "", "user SSH directory ACL metadata"},
		sensitiveCandidate{"SSH_AUTHORIZED_KEYS", "USER", filepath.Join(home, ".ssh", "authorized_keys"), SensitivePolicyWriteRestricted, "", "user SSH authorized_keys ACL metadata"},
		sensitiveCandidate{"PRIVATE_KEY", "USER", filepath.Join(home, ".ssh", "id_*"), SensitivePolicyOwnerOnly, "", "user SSH private-key filename ACL metadata"},
		sensitiveCandidate{"PRIVATE_KEY", "USER", filepath.Join(home, ".ssh", "*.pem"), SensitivePolicyOwnerOnly, "", "user SSH PEM private-key ACL metadata"},
		sensitiveCandidate{"PRIVATE_KEY", "USER", filepath.Join(home, ".ssh", "*.key"), SensitivePolicyOwnerOnly, "", "user SSH private-key ACL metadata"},
		sensitiveCandidate{"CLOUD_CREDENTIAL_DIR", "USER", filepath.Join(home, ".aws"), SensitivePolicyOwnerOnly, "", "AWS credential directory ACL metadata"},
		sensitiveCandidate{"CLOUD_CREDENTIAL", "USER", filepath.Join(home, ".aws", "credentials"), SensitivePolicyOwnerOnly, "", "AWS credential file ACL metadata"},
		sensitiveCandidate{"ORCHESTRATION_CREDENTIAL_DIR", "USER", filepath.Join(home, ".kube"), SensitivePolicyOwnerOnly, "", "Kubernetes credential/config directory ACL metadata"},
		sensitiveCandidate{"ORCHESTRATION_CREDENTIAL", "USER", filepath.Join(home, ".kube", "config"), SensitivePolicyOwnerOnly, "", "Kubernetes credential/config file ACL metadata"},
		sensitiveCandidate{"ENVIRONMENT_SECRET", "USER", filepath.Join(home, ".env"), SensitivePolicyOwnerOnly, "", "user environment-file ACL metadata"},
	)
	return c
}

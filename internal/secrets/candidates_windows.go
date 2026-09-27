//go:build windows

package secrets

import (
	"os"
	"path/filepath"
)

func platformCandidates() []candidate {
	home, _ := os.UserHomeDir()
	app := os.Getenv("APPDATA")
	local := os.Getenv("LOCALAPPDATA")
	programData := os.Getenv("ProgramData")
	out := userCandidates(home)
	add := func(kind, scope, path, source string) {
		if path != "" {
			out = append(out, candidate{kind, scope, path, source})
		}
	}
	add("CREDENTIAL_STORE", "USER", filepath.Join(app, "Microsoft", "Credentials", "*"), "Windows Credential Manager roaming store metadata")
	add("CREDENTIAL_STORE", "USER", filepath.Join(local, "Microsoft", "Credentials", "*"), "Windows Credential Manager local store metadata")
	add("CREDENTIAL_STORE", "USER", filepath.Join(app, "Microsoft", "Protect", "*"), "Windows DPAPI protect metadata")
	add("CREDENTIAL_STORE", "USER", filepath.Join(local, "Microsoft", "Vault", "*"), "Windows Vault metadata")
	add("SERVICE_CONFIG", "SYSTEM", filepath.Join(programData, "ssh", "sshd_config"), "OpenSSH service configuration metadata")
	add("PRIVATE_KEY", "SYSTEM", filepath.Join(programData, "ssh", "ssh_host_*_key"), "OpenSSH host private-key metadata")
	add("CLOUD_CONFIG", "USER", filepath.Join(app, "gcloud", "application_default_credentials.json"), "Google Cloud application-default credential metadata")
	add("CLOUD_CONFIG", "USER", filepath.Join(app, "gcloud", "credentials.db"), "Google Cloud credential database metadata")
	add("DEVELOPER_CREDENTIAL", "USER", filepath.Join(app, "pip", "pip.ini"), "pip client configuration metadata")
	add("DEVELOPER_CREDENTIAL", "USER", filepath.Join(app, "GitHub CLI", "hosts.yml"), "GitHub CLI credential metadata")
	return out
}

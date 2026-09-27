package secrets

import "path/filepath"

func userCandidates(home string) []candidate {
	if home == "" {
		return nil
	}
	c := func(kind, path, source string) candidate {
		return candidate{kind, "USER", filepath.Join(home, path), source}
	}
	return []candidate{
		c("ENVIRONMENT_FILE", ".env", "user .env metadata"),
		c("CLOUD_CONFIG", filepath.Join(".aws", "credentials"), "AWS credential-file metadata"),
		c("CLOUD_CONFIG", filepath.Join(".aws", "config"), "AWS config metadata"),
		c("CLOUD_CONFIG", filepath.Join(".azure", "*"), "Azure local configuration metadata"),
		c("CLOUD_CONFIG", filepath.Join(".config", "gcloud", "application_default_credentials.json"), "Google Cloud application-default credential metadata"),
		c("CLOUD_CONFIG", filepath.Join(".config", "gcloud", "credentials.db"), "Google Cloud credential database metadata"),
		c("ORCHESTRATION_CONFIG", filepath.Join(".kube", "config"), "Kubernetes kubeconfig metadata"),
		c("ORCHESTRATION_CONFIG", filepath.Join(".docker", "config.json"), "Docker client configuration metadata"),
		c("PRIVATE_KEY", filepath.Join(".ssh", "id_*"), "SSH private-key filename metadata"),
		c("PRIVATE_KEY", filepath.Join(".ssh", "*.pem"), "SSH PEM private-key metadata"),
		c("PRIVATE_KEY", filepath.Join(".ssh", "*.key"), "SSH private-key metadata"),
		c("SHELL_HISTORY", ".bash_history", "Bash history metadata"),
		c("SHELL_HISTORY", ".zsh_history", "Zsh history metadata"),
		c("SHELL_HISTORY", ".python_history", "Python history metadata"),
		c("SHELL_HISTORY", ".psql_history", "PostgreSQL client history metadata"),
		c("SHELL_HISTORY", ".mysql_history", "MySQL client history metadata"),
		c("DEVELOPER_CREDENTIAL", ".netrc", "netrc credential-file metadata"),
		c("DEVELOPER_CREDENTIAL", "_netrc", "netrc credential-file metadata"),
		c("DEVELOPER_CREDENTIAL", ".npmrc", "npm configuration/credential metadata"),
		c("DEVELOPER_CREDENTIAL", ".pypirc", "Python package repository credential metadata"),
		c("DEVELOPER_CREDENTIAL", ".git-credentials", "Git credential-file metadata"),
		c("DEVELOPER_CREDENTIAL", ".gitconfig", "Git global configuration metadata"),
		c("DEVELOPER_CREDENTIAL", filepath.Join(".config", "git", "config"), "Git XDG global configuration metadata"),
		c("DEVELOPER_CREDENTIAL", filepath.Join(".config", "pip", "pip.conf"), "pip client configuration metadata"),
		c("DEVELOPER_CREDENTIAL", filepath.Join(".pip", "pip.conf"), "pip legacy client configuration metadata"),
		c("DEVELOPER_CREDENTIAL", filepath.Join(".config", "gh", "hosts.yml"), "GitHub CLI credential metadata"),
		c("CREDENTIAL_STORE", filepath.Join(".local", "share", "keyrings", "*"), "desktop keyring metadata"),
		c("CREDENTIAL_STORE", filepath.Join(".config", "kwalletd", "*"), "KWallet metadata"),
	}
}

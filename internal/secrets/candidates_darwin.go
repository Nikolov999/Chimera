//go:build darwin

package secrets

import (
	"os"
	"path/filepath"
)

func platformCandidates() []candidate {
	out := []candidate{
		{"CREDENTIAL_STORE", "SYSTEM", "/Library/Keychains/System.keychain", "macOS system keychain metadata"},
		{"SERVICE_CONFIG", "SYSTEM", "/Library/LaunchDaemons/*.plist", "launch daemon configuration metadata"},
		{"SERVICE_CONFIG", "SYSTEM", "/Library/LaunchAgents/*.plist", "launch agent configuration metadata"},
		{"PRIVATE_KEY", "SYSTEM", "/etc/ssh/ssh_host_*_key", "SSH host private-key metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/opt/*/.env", "bounded application .env metadata"},
	}
	for _, home := range darwinHomes() {
		out = append(out, userCandidates(home)...)
		out = append(out, candidate{"CREDENTIAL_STORE", "USER", filepath.Join(home, "Library", "Keychains", "login.keychain-db"), "macOS login keychain metadata"})
	}
	return out
}
func darwinHomes() []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(h string) {
		if h == "" {
			return
		}
		h = filepath.Clean(h)
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	if h, err := os.UserHomeDir(); err == nil {
		add(h)
	}
	if es, err := os.ReadDir("/Users"); err == nil {
		for _, e := range es {
			if e.IsDir() && e.Name() != "Shared" {
				add(filepath.Join("/Users", e.Name()))
				if len(out) >= 33 {
					break
				}
			}
		}
	}
	return out
}

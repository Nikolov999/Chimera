//go:build linux

package secrets

import (
	"os"
	"path/filepath"
)

func platformCandidates() []candidate {
	out := []candidate{
		{"ENVIRONMENT_FILE", "SYSTEM", "/etc/environment", "system environment metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/etc/default/*", "service environment/default metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/etc/sysconfig/*", "service environment/sysconfig metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/opt/*/.env", "bounded application .env metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/srv/*/.env", "bounded application .env metadata"},
		{"ENVIRONMENT_FILE", "APPLICATION", "/var/www/*/.env", "bounded web application .env metadata"},
		{"SERVICE_CONFIG", "SYSTEM", "/etc/systemd/system/*.service", "systemd service definition metadata"},
		{"SERVICE_CONFIG", "SYSTEM", "/etc/systemd/system/*.service.d/*.conf", "systemd service override metadata"},
		{"SERVICE_CONFIG", "SYSTEM", "/etc/NetworkManager/system-connections/*", "NetworkManager connection profile metadata"},
		{"PRIVATE_KEY", "SYSTEM", "/etc/ssl/private/*", "system private-key directory metadata"},
		{"PRIVATE_KEY", "SYSTEM", "/etc/ssh/ssh_host_*_key", "SSH host private-key metadata"},
	}
	for _, home := range linuxHomes() {
		out = append(out, userCandidates(home)...)
	}
	return out
}

func linuxHomes() []string {
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
	add("/root")
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join("/home", e.Name()))
				if len(out) >= 34 {
					break
				}
			}
		}
	}
	return out
}

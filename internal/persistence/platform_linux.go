//go:build linux

package persistence

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectLinuxXDGAutostart(ctx, inv)
	collectLinuxSystemdAutostart(ctx, inv)
	collectLinuxRCLocal(inv)
}

func collectLinuxXDGAutostart(ctx context.Context, inv *Inventory) {
	type root struct {
		path  string
		scope string
		user  string
	}
	roots := []root{{path: "/etc/xdg/autostart", scope: "SYSTEM", user: "LOGIN_USER"}}
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.HomeDir) != "" {
		roots = append(roots, root{path: filepath.Join(u.HomeDir, ".config", "autostart"), scope: "USER", user: fallback(u.Username, "CURRENT_USER")})
	}
	count, denied := 0, 0
	reasons := []string{}
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		entries, err := os.ReadDir(root.path)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			} else if !os.IsNotExist(err) {
				reasons = append(reasons, root.path+": "+err.Error())
			}
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, de := range entries {
			if de.IsDir() || !strings.HasSuffix(strings.ToLower(de.Name()), ".desktop") || len(inv.Entries) >= maxEntries {
				continue
			}
			path := filepath.Join(root.path, de.Name())
			rec, err := parseDesktopAutostart(path, root.scope, root.user)
			if err != nil {
				if os.IsPermission(err) {
					denied++
				} else {
					reasons = append(reasons, filepath.Base(path)+": "+err.Error())
				}
				continue
			}
			inv.Entries = append(inv.Entries, rec)
			count++
		}
	}
	state := evidence.StateObserved
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if denied > 0 || reason != "" {
		state = evidence.StateDegraded
		if denied > 0 {
			reason = strings.Trim(strings.Join([]string{reason, fmt.Sprintf("%d autostart path(s) were permission-restricted", denied)}, "; "), "; ")
		}
	}
	addSource(inv, "linux-xdg-autostart", state, "XDG autostart .desktop metadata", count, reason)
}

func parseDesktopAutostart(path, scope, account string) (Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	if info.Size() > 1024*1024 {
		return Entry{}, fmt.Errorf("desktop entry exceeds 1 MiB metadata limit")
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	execValue := ""
	hidden := false
	disabled := false
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 16*1024), 1024*1024)
	inDesktop := false
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDesktop = strings.EqualFold(line, "[Desktop Entry]")
			continue
		}
		if !inDesktop || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			if strings.TrimSpace(value) != "" {
				name = strings.TrimSpace(value)
			}
		case "exec":
			execValue = strings.TrimSpace(value)
		case "hidden":
			hidden = strings.EqualFold(strings.TrimSpace(value), "true")
		case "x-gnome-autostart-enabled":
			disabled = strings.EqualFold(strings.TrimSpace(value), "false")
		}
	}
	if err := s.Err(); err != nil {
		return Entry{}, err
	}
	executable, args := firstCommandToken(execValue)
	enabled := "ENABLED"
	if hidden || disabled {
		enabled = "DISABLED"
	}
	return Entry{
		Name: name, Mechanism: "XDG_AUTOSTART", Manager: "xdg-autostart", Scope: scope,
		EnabledState: enabled, RuntimeState: "NOT_ASSESSED", Account: account, PrivilegeContext: "USER",
		ExecutablePath: executable, ArgumentsPresent: args, DefinitionPath: path, ConfigurationSource: path,
		CollectionSource: "XDG autostart .desktop metadata", Confidence: evidence.ConfidenceHigh,
	}, nil
}

func collectLinuxSystemdAutostart(ctx context.Context, inv *Inventory) {
	type root struct {
		pattern string
		scope   string
		account string
	}
	roots := []root{
		{"/etc/systemd/system/*.wants/*.service", "SYSTEM", "root"},
		{"/etc/systemd/system/*.requires/*.service", "SYSTEM", "root"},
	}
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.HomeDir) != "" {
		roots = append(roots,
			root{filepath.Join(u.HomeDir, ".config", "systemd", "user", "*.wants", "*.service"), "USER", fallback(u.Username, "CURRENT_USER")},
			root{filepath.Join(u.HomeDir, ".config", "systemd", "user", "*.requires", "*.service"), "USER", fallback(u.Username, "CURRENT_USER")},
		)
	}
	count := 0
	reasons := []string{}
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		matches, err := filepath.Glob(root.pattern)
		if err != nil {
			reasons = append(reasons, root.pattern+": "+err.Error())
			continue
		}
		sort.Strings(matches)
		for _, path := range matches {
			if len(inv.Entries) >= maxEntries {
				reasons = append(reasons, fmt.Sprintf("persistence inventory truncated at %d records", maxEntries))
				break
			}
			target := ""
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				target = resolved
			}
			inv.Entries = append(inv.Entries, Entry{
				Name: filepath.Base(path), Mechanism: "SYSTEMD_AUTOSTART", Manager: "systemd", Scope: root.scope,
				EnabledState: "ENABLED", RuntimeState: "NOT_ASSESSED", Account: root.account,
				PrivilegeContext: map[bool]string{true: "ROOT", false: "USER"}[root.scope == "SYSTEM"],
				DefinitionPath:   path, ConfigurationSource: fallback(target, path), CollectionSource: "systemd wants/requires symlink metadata", Confidence: evidence.ConfidenceExact,
			})
			count++
		}
	}
	state := evidence.StateObserved
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if reason != "" {
		state = evidence.StateDegraded
	}
	addSource(inv, "linux-systemd-autostart", state, "systemd wants/requires symlink metadata", count, reason)
}

func collectLinuxRCLocal(inv *Inventory) {
	const path = "/etc/rc.local"
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addSource(inv, "linux-rc-local", evidence.StateNotApplicable, path+" metadata", 0, "rc.local was not present")
			return
		}
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		addSource(inv, "linux-rc-local", state, path+" metadata", 0, err.Error())
		return
	}
	enabled := "UNKNOWN"
	if info.Mode()&0111 != 0 {
		enabled = "ENABLED"
	}
	inv.Entries = append(inv.Entries, Entry{
		Name: "rc.local", Mechanism: "RC_LOCAL", Manager: "init-compat", Scope: "SYSTEM", EnabledState: enabled,
		RuntimeState: "NOT_ASSESSED", Account: "root", PrivilegeContext: "ROOT", ExecutablePath: path,
		DefinitionPath: path, ConfigurationSource: path, CollectionSource: "rc.local file metadata", Confidence: evidence.ConfidenceHigh,
	})
	addSource(inv, "linux-rc-local", evidence.StateObserved, path+" metadata", 1, "")
}

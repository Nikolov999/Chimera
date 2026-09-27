//go:build windows

package persistence

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectWindowsRunKeys(ctx, inv)
	collectWindowsStartupFolders(inv)
}

func collectWindowsRunKeys(ctx context.Context, inv *Inventory) {
	reg, err := exec.LookPath("reg.exe")
	if err != nil {
		addSource(inv, "windows-run-keys", evidence.StateUnavailable, "reg.exe local Run/RunOnce metadata", 0, "reg.exe was not found")
		return
	}
	type keySpec struct {
		key, scope, mechanism, account string
	}
	keys := []keySpec{
		{`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "MACHINE", "RUN_KEY", "LOGIN_USER"},
		{`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`, "MACHINE", "RUN_ONCE_KEY", "LOGIN_USER"},
		{`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "MACHINE", "RUN_KEY", "LOGIN_USER"},
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "USER", "RUN_KEY", "CURRENT_USER"},
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, "USER", "RUN_ONCE_KEY", "CURRENT_USER"},
	}
	count := 0
	reasons := []string{}
	denied := 0
	for _, spec := range keys {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		cmd := exec.CommandContext(ctx, reg, "query", spec.key)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			text := strings.ToLower(string(raw))
			if strings.Contains(text, "unable to find") || strings.Contains(text, "cannot find") || strings.Contains(text, "not found") {
				continue
			}
			if strings.Contains(text, "access is denied") {
				denied++
			} else {
				reasons = append(reasons, spec.key+": "+err.Error())
			}
			continue
		}
		values := parseRegQueryValues(raw)
		for _, v := range values {
			exe, args := firstCommandToken(v.Data)
			inv.Entries = append(inv.Entries, Entry{
				Name: v.Name, Mechanism: spec.mechanism, Manager: "windows-registry", Scope: spec.scope,
				EnabledState: "ENABLED", RuntimeState: "NOT_ASSESSED", Account: spec.account, PrivilegeContext: "USER",
				ExecutablePath: exe, ArgumentsPresent: args, DefinitionPath: spec.key + `\` + v.Name,
				ConfigurationSource: spec.key, CollectionSource: "reg.exe Run/RunOnce metadata (command value redacted)", Confidence: evidence.ConfidenceHigh,
			})
			count++
		}
	}
	state := evidence.StateObserved
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if denied > 0 || reason != "" {
		state = evidence.StateDegraded
		if denied > 0 {
			reason = strings.Trim(strings.Join([]string{reason, fmt.Sprintf("%d registry key(s) were permission-restricted", denied)}, "; "), "; ")
		}
	}
	addSource(inv, "windows-run-keys", state, "reg.exe local Run/RunOnce metadata", count, reason)
}

type regValue struct{ Name, Type, Data string }

func parseRegQueryValues(raw []byte) []regValue {
	out := []regValue{}
	s := bufio.NewScanner(bytes.NewReader(raw))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(strings.ToUpper(line), "HKEY_") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		typeIndex := -1
		for i, f := range fields {
			if strings.HasPrefix(strings.ToUpper(f), "REG_") {
				typeIndex = i
				break
			}
		}
		if typeIndex <= 0 || typeIndex >= len(fields)-1 {
			continue
		}
		name := strings.Join(fields[:typeIndex], " ")
		typ := fields[typeIndex]
		data := strings.Join(fields[typeIndex+1:], " ")
		out = append(out, regValue{Name: name, Type: typ, Data: data})
	}
	return out
}

func collectWindowsStartupFolders(inv *Inventory) {
	type root struct{ path, scope, account string }
	roots := []root{}
	if p := strings.TrimSpace(os.Getenv("ProgramData")); p != "" {
		roots = append(roots, root{filepath.Join(p, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"), "MACHINE", "LOGIN_USER"})
	}
	if p := strings.TrimSpace(os.Getenv("APPDATA")); p != "" {
		roots = append(roots, root{filepath.Join(p, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "USER", "CURRENT_USER"})
	}
	count, denied := 0, 0
	reasons := []string{}
	for _, root := range roots {
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
			if de.IsDir() {
				continue
			}
			path := filepath.Join(root.path, de.Name())
			exe := ""
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".exe" || ext == ".com" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" {
				exe = path
			}
			inv.Entries = append(inv.Entries, Entry{
				Name: de.Name(), Mechanism: "STARTUP_FOLDER", Manager: "windows-startup-folder", Scope: root.scope,
				EnabledState: "ENABLED", RuntimeState: "NOT_ASSESSED", Account: root.account, PrivilegeContext: "USER",
				ExecutablePath: exe, DefinitionPath: path, ConfigurationSource: root.path,
				CollectionSource: "Windows Startup folder metadata; shortcut targets are not resolved", Confidence: evidence.ConfidenceExact,
			})
			count++
		}
	}
	if len(roots) == 0 {
		addSource(inv, "windows-startup-folders", evidence.StateUnavailable, "Windows Startup folder metadata", 0, "ProgramData and APPDATA paths were unavailable")
		return
	}
	state := evidence.StateObserved
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if denied > 0 || reason != "" {
		state = evidence.StateDegraded
		if denied > 0 {
			reason = strings.Trim(strings.Join([]string{reason, fmt.Sprintf("%d startup folder(s) were permission-restricted", denied)}, "; "), "; ")
		}
	}
	addSource(inv, "windows-startup-folders", state, "Windows Startup folder metadata", count, reason)
}

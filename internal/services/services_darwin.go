//go:build darwin

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type launchRuntime struct {
	PID   int
	State string
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	runtimeByLabel, runtimeReason := collectLaunchctlRuntime(ctx)
	if runtimeReason != "" {
		addSource(inv, "darwin-launchctl-runtime", evidence.StateDegraded, "launchctl list", len(runtimeByLabel), runtimeReason)
	} else {
		addSource(inv, "darwin-launchctl-runtime", evidence.StateObserved, "launchctl list", len(runtimeByLabel), "")
	}

	records, denied, reason := collectLaunchdDefinitions(ctx, runtimeByLabel)
	inv.Services = append(inv.Services, records...)
	if len(records) > 0 {
		state := evidence.StateObserved
		detail := reason
		if denied > 0 || reason != "" {
			state = evidence.StateDegraded
			if denied > 0 {
				detail = strings.TrimSpace(strings.Join([]string{detail, fmt.Sprintf("%d launchd definitions were permission-restricted or unreadable", denied)}, "; "))
			}
		}
		addSource(inv, "darwin-launchd-definitions", state, "launchd plist metadata", len(records), detail)
		hardeningCount, hardeningDegraded := launchdHardeningSourceState(records)
		hardeningState := evidence.StateObserved
		if hardeningDegraded != "" {
			hardeningState = evidence.StateDegraded
		}
		addSource(inv, "darwin-launchd-hardening", hardeningState, "launchd plist + local filesystem metadata", hardeningCount, hardeningDegraded)
		return
	}
	if reason == "" {
		reason = "no launchd service definitions were observable"
	}
	addSource(inv, "darwin-launchd-definitions", evidence.StateUnavailable, "launchd plist metadata", 0, reason)
}

func collectLaunchctlRuntime(ctx context.Context) (map[string]launchRuntime, string) {
	path, err := exec.LookPath("launchctl")
	if err != nil {
		return map[string]launchRuntime{}, "launchctl was not found"
	}
	raw, err := exec.CommandContext(ctx, path, "list").Output()
	if err != nil {
		if ctx.Err() != nil {
			return map[string]launchRuntime{}, ctx.Err().Error()
		}
		return map[string]launchRuntime{}, err.Error()
	}
	out := map[string]launchRuntime{}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || strings.EqualFold(fields[0], "PID") {
			continue
		}
		label := fields[len(fields)-1]
		pid := 0
		state := "STOPPED"
		if fields[0] != "-" {
			if n, err := strconv.Atoi(fields[0]); err == nil && n > 0 {
				pid = n
				state = "RUNNING"
			} else {
				state = "UNKNOWN"
			}
		}
		out[label] = launchRuntime{PID: pid, State: state}
	}
	return out, ""
}

func collectLaunchdDefinitions(ctx context.Context, runtimeByLabel map[string]launchRuntime) ([]Service, int, string) {
	type root struct {
		path       string
		kind       string
		defaultAcc string
	}
	roots := []root{
		{"/Library/LaunchDaemons", "LaunchDaemon", "root"},
		{"/System/Library/LaunchDaemons", "LaunchDaemon", "root"},
		{"/Library/LaunchAgents", "LaunchAgent", "SESSION_USER"},
		{"/System/Library/LaunchAgents", "LaunchAgent", "SESSION_USER"},
	}
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.HomeDir) != "" {
		roots = append(roots, root{filepath.Join(u.HomeDir, "Library", "LaunchAgents"), "LaunchAgent", fallback(u.Username, "SESSION_USER")})
	}

	plutil, plutilErr := exec.LookPath("plutil")
	if plutilErr != nil {
		return nil, 0, "plutil was not found for launchd plist decoding"
	}
	records := []Service{}
	denied := 0
	reasons := []string{}
	for _, r := range roots {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		entries, err := os.ReadDir(r.path)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				reasons = append(reasons, "collection deadline reached: "+err.Error())
				break
			}
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".plist") {
				continue
			}
			path := filepath.Join(r.path, entry.Name())
			raw, err := exec.CommandContext(ctx, plutil, "-convert", "json", "-o", "-", "--", path).Output()
			if err != nil {
				denied++
				continue
			}
			rec, err := parseLaunchdPlist(raw, path, r.kind, r.defaultAcc, runtimeByLabel)
			if err != nil {
				reasons = append(reasons, filepath.Base(path)+": "+err.Error())
				continue
			}
			records = append(records, rec)
			if len(records) >= maxServices {
				reasons = append(reasons, fmt.Sprintf("launchd inventory truncated at %d records", maxServices))
				return records, denied, strings.Join(uniqueSorted(reasons), "; ")
			}
		}
	}
	return records, denied, strings.Join(uniqueSorted(reasons), "; ")
}

func parseLaunchdPlist(raw []byte, path, kind, defaultAccount string, runtimeByLabel map[string]launchRuntime) (Service, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Service{}, err
	}
	label := anyString(m["Label"])
	if label == "" {
		label = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	program := anyString(m["Program"])
	if program == "" {
		if args, ok := m["ProgramArguments"].([]any); ok && len(args) > 0 {
			program = anyString(args[0])
		}
	}
	account := anyString(m["UserName"])
	if account == "" {
		account = defaultAccount
	}
	group := anyString(m["GroupName"])
	mode := launchdStartMode(m)
	rt, ok := runtimeByLabel[label]
	runtimeState := "UNKNOWN"
	pid := 0
	if ok {
		runtimeState, pid = rt.State, rt.PID
	}
	return Service{
		Name: label, DisplayName: label, Manager: "launchd", ServiceType: kind,
		ExecutablePath: program, Account: fallback(account, "UNKNOWN"), AccountGroup: group,
		StartMode: mode, RuntimePID: pid, RuntimeState: runtimeState,
		PrivilegeContext: darwinServicePrivilege(account), DefinitionState: "PRESENT", DefinitionPath: path,
		ConfigurationSource: path, CollectionSource: "launchd plist metadata + launchctl runtime state", Confidence: evidence.ConfidenceHigh,
		LaunchdHardening: collectLaunchdHardening(m, path, kind, fallback(account, "UNKNOWN"), program),
	}, nil
}

func launchdStartMode(m map[string]any) string {
	if disabled, ok := m["Disabled"].(bool); ok && disabled {
		return "DISABLED"
	}
	if keep, ok := m["KeepAlive"]; ok {
		switch v := keep.(type) {
		case bool:
			if v {
				return "KEEP_ALIVE"
			}
		case map[string]any:
			if len(v) > 0 {
				return "KEEP_ALIVE"
			}
		}
	}
	if run, ok := m["RunAtLoad"].(bool); ok && run {
		return "RUN_AT_LOAD"
	}
	return "ON_DEMAND"
}

func darwinServicePrivilege(account string) string {
	switch strings.ToLower(strings.TrimSpace(account)) {
	case "root", "0":
		return "ROOT"
	case "", "unknown":
		return "UNKNOWN"
	case "session_user":
		return "SESSION_USER"
	default:
		return "SERVICE_ACCOUNT"
	}
}

func anyString(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func launchdHardeningSourceState(records []Service) (int, string) {
	count := 0
	degraded := 0
	for _, svc := range records {
		if svc.LaunchdHardening == nil {
			continue
		}
		count++
		if svc.LaunchdHardening.State != "COMPLETE" {
			degraded++
		}
	}
	if count == 0 {
		return 0, "no launchd hardening records were observable"
	}
	if degraded > 0 {
		return count, fmt.Sprintf("%d of %d launchd hardening records are degraded", degraded, count)
	}
	return count, ""
}

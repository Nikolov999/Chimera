//go:build darwin

package scheduled

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		addSource(inv, "darwin-launchd-schedules", evidence.StateUnavailable, "launchd plist schedule metadata", 0, "plutil not found")
		return
	}
	type root struct{ path, kind, acct string }
	roots := []root{{"/Library/LaunchDaemons", "LaunchDaemon", "root"}, {"/System/Library/LaunchDaemons", "LaunchDaemon", "root"}, {"/Library/LaunchAgents", "LaunchAgent", "SESSION_USER"}, {"/System/Library/LaunchAgents", "LaunchAgent", "SESSION_USER"}}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		roots = append(roots, root{filepath.Join(u.HomeDir, "Library", "LaunchAgents"), "LaunchAgent", fallback(u.Username, "SESSION_USER")})
	}
	count := 0
	denied := 0
	reasons := []string{}
	for _, r := range roots {
		ents, err := os.ReadDir(r.path)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for _, e := range ents {
			if ctx.Err() != nil {
				break
			}
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".plist") {
				continue
			}
			p := filepath.Join(r.path, e.Name())
			raw, err := exec.CommandContext(ctx, plutil, "-convert", "json", "-o", "-", "--", p).Output()
			if err != nil {
				denied++
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				reasons = append(reasons, e.Name()+": "+err.Error())
				continue
			}
			sched := launchSchedule(m)
			if sched == "" {
				continue
			}
			label := asString(m["Label"])
			if label == "" {
				label = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			}
			program := asString(m["Program"])
			argsPresent := false
			scriptPath := ""
			if arr, ok := m["ProgramArguments"].([]any); ok && len(arr) > 0 {
				if program == "" {
					program = asString(arr[0])
				}
				argsPresent = len(arr) > 1
				scriptPath = launchdScriptPath(program, arr)
			}
			acct := asString(m["UserName"])
			if acct == "" {
				acct = r.acct
			}
			priv := "SERVICE_ACCOUNT"
			if acct == "root" {
				priv = "ROOT"
			} else if acct == "SESSION_USER" {
				priv = "SESSION_USER"
			}
			enabled := "ENABLED"
			if b, ok := m["Disabled"].(bool); ok && b {
				enabled = "DISABLED"
			}
			inv.Entries = append(inv.Entries, Entry{Name: label, Manager: "launchd", Kind: r.kind, EnabledState: enabled, RuntimeState: "ON_DEMAND", Account: acct, PrivilegeContext: priv, Schedule: sched, ActionExecutable: program, ArgumentsPresent: argsPresent, ReferencedScriptPath: scriptPath, WorkingDirectory: asString(m["WorkingDirectory"]), DefinitionPath: p, RunLevel: "NOT_APPLICABLE", LogonType: "LAUNCHD", HiddenState: "NOT_APPLICABLE", ConfigurationSource: p, CollectionSource: "launchd plist schedule metadata", Confidence: evidence.ConfidenceHigh})
			count++
		}
	}
	st := evidence.StateObserved
	detail := ""
	if denied > 0 || len(reasons) > 0 {
		st = evidence.StateDegraded
		parts := reasons
		if denied > 0 {
			parts = append(parts, fmt.Sprintf("%d launchd plist reads were restricted", denied))
		}
		detail = strings.Join(uniqueSorted(parts), "; ")
	}
	if count == 0 && st == evidence.StateObserved {
		st = evidence.StateUnavailable
		detail = "no launchd definitions with scheduled triggers were observable"
	}
	addSource(inv, "darwin-launchd-schedules", st, "launchd plist schedule metadata", count, detail)
}
func asString(v any) string { s, _ := v.(string); return strings.TrimSpace(s) }
func launchSchedule(m map[string]any) string {
	parts := []string{}
	if v, ok := m["StartInterval"].(float64); ok && v > 0 {
		parts = append(parts, fmt.Sprintf("interval=%ds", int64(v)))
	}
	if v, ok := m["StartCalendarInterval"]; ok {
		switch x := v.(type) {
		case map[string]any:
			parts = append(parts, "calendar="+calendarSummary(x))
		case []any:
			parts = append(parts, fmt.Sprintf("calendar_entries=%d", len(x)))
		}
	}
	if b, ok := m["RunAtLoad"].(bool); ok && b {
		parts = append(parts, "run-at-load")
	}
	return strings.Join(parts, "; ")
}
func calendarSummary(m map[string]any) string {
	keys := []string{"Month", "Day", "Weekday", "Hour", "Minute"}
	out := []string{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out = append(out, fmt.Sprintf("%s=%v", strings.ToLower(k), v))
		}
	}
	return strings.Join(out, ",")
}

func launchdScriptPath(program string, args []any) string {
	leaf := strings.ToLower(filepath.Base(strings.TrimSpace(program)))
	if !isDarwinScriptInterpreter(leaf) || len(args) < 2 {
		return ""
	}
	candidate := strings.TrimSpace(asString(args[1]))
	if candidate == "" || strings.HasPrefix(candidate, "-") {
		return ""
	}
	return candidate
}

func isDarwinScriptInterpreter(leaf string) bool {
	switch leaf {
	case "sh", "bash", "zsh", "python", "python3", "perl", "ruby", "node", "osascript":
		return true
	default:
		return false
	}
}

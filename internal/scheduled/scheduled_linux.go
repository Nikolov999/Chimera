//go:build linux

package scheduled

import (
	"bufio"
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
	collectSystemdTimers(ctx, inv)
	collectCron(ctx, inv)
}

func collectSystemdTimers(ctx context.Context, inv *Inventory) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		addSource(inv, "linux-systemd-timers", evidence.StateUnavailable, "systemctl timer metadata", 0, "systemctl not found")
		return
	}
	raw, err := exec.CommandContext(ctx, systemctl, "list-unit-files", "--type=timer", "--no-legend", "--no-pager").Output()
	if err != nil {
		addSource(inv, "linux-systemd-timers", evidence.StateUnavailable, "systemctl timer metadata", 0, reason(ctx, err))
		return
	}
	names := parseSystemdTimerUnitFileNames(string(raw))
	if len(names) > 4096 {
		names = names[:4096]
	}
	records := []Entry{}
	degraded := []string{}
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		out, err := exec.CommandContext(ctx, systemctl, "show", name, "--no-pager", "--property=Id", "--property=Description", "--property=LoadState", "--property=ActiveState", "--property=UnitFileState", "--property=FragmentPath", "--property=Triggers", "--property=NextElapseUSecRealtime", "--property=LastTriggerUSec").Output()
		if err != nil {
			degraded = append(degraded, name+": "+reason(ctx, err))
			continue
		}
		m := parseKV(string(out))
		target := firstTarget(m["Triggers"])
		action, script, workdir, acct, priv, def := systemdTargetMetadata(ctx, systemctl, target)
		rec := Entry{Name: fallback(m["Id"], name), Manager: "systemd-timer", Kind: "timer", EnabledState: fallback(m["UnitFileState"], "UNKNOWN"), RuntimeState: fallback(m["ActiveState"], "UNKNOWN"), Account: fallback(acct, "UNKNOWN"), PrivilegeContext: fallback(priv, "UNKNOWN"), Schedule: timerSchedule(m), TriggerTarget: target, ActionExecutable: action, ReferencedScriptPath: script, WorkingDirectory: workdir, DefinitionPath: m["FragmentPath"], RunLevel: "NOT_APPLICABLE", LogonType: "SYSTEMD", HiddenState: "NOT_APPLICABLE", ConfigurationSource: fallback(m["FragmentPath"], "systemctl show"), CollectionSource: "systemctl local timer/service metadata", Confidence: evidence.ConfidenceHigh}
		if def != "" && rec.DefinitionPath == "" {
			rec.DefinitionPath = def
		}
		records = append(records, rec)
	}
	inv.Entries = append(inv.Entries, records...)
	st := evidence.StateObserved
	rs := ""
	if len(degraded) > 0 {
		st = evidence.StateDegraded
		rs = strings.Join(uniqueSorted(degraded), "; ")
	}
	addSource(inv, "linux-systemd-timers", st, "systemctl timer/service metadata", len(records), rs)
}

func parseSystemdTimerUnitFileNames(raw string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		name := strings.TrimSpace(f[0])
		// An uninstantiated template (foo@.timer) is a definition, not a
		// concrete scheduled execution instance. systemctl show on these can
		// fail even though the host is healthy; instantiated foo@x.timer units
		// remain fully observable.
		if !strings.HasSuffix(name, ".timer") || strings.Contains(name, "@.") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func parseKV(raw string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if ok {
			m[k] = v
		}
	}
	return m
}
func firstTarget(v string) string {
	for _, f := range strings.Fields(v) {
		if strings.HasSuffix(f, ".service") || strings.HasSuffix(f, ".target") {
			return strings.TrimSpace(f)
		}
	}
	return strings.TrimSpace(v)
}
func timerSchedule(m map[string]string) string {
	if v := strings.TrimSpace(m["NextElapseUSecRealtime"]); v != "" && v != "n/a" {
		return "next=" + v
	}
	if v := strings.TrimSpace(m["LastTriggerUSec"]); v != "" && v != "n/a" {
		return "timer; last=" + v
	}
	return "systemd timer"
}
func systemdTargetMetadata(ctx context.Context, systemctl, target string) (string, string, string, string, string, string) {
	if target == "" {
		return "", "", "", "", "", ""
	}
	raw, err := exec.CommandContext(ctx, systemctl, "show", target, "--no-pager", "--property=User", "--property=ExecStart", "--property=WorkingDirectory", "--property=FragmentPath").Output()
	if err != nil {
		return "", "", "", "", "", ""
	}
	m := parseKV(string(raw))
	acct := m["User"]
	if acct == "" {
		acct = "root"
	}
	priv := "SERVICE_ACCOUNT"
	if acct == "root" || acct == "0" {
		priv = "ROOT"
	}
	action, script := systemdExecMetadata(m["ExecStart"])
	workdir := strings.TrimSpace(m["WorkingDirectory"])
	if workdir == "~" || workdir == "-" {
		workdir = ""
	}
	return action, script, workdir, acct, priv, m["FragmentPath"]
}
func systemdExec(v string) string {
	exe, _ := systemdExecMetadata(v)
	return exe
}

func systemdExecMetadata(v string) (string, string) {
	v = strings.TrimSpace(v)
	exe := ""
	if i := strings.Index(v, "path="); i >= 0 {
		r := v[i+5:]
		if j := strings.Index(r, " ;"); j >= 0 {
			r = r[:j]
		}
		if j := strings.Index(r, ";"); j >= 0 {
			r = r[:j]
		}
		exe = strings.Trim(strings.TrimSpace(r), "\"'{}")
	}
	if exe == "" {
		f := strings.Fields(strings.Trim(v, "{}"))
		if len(f) > 0 {
			exe = strings.Trim(f[0], "\"'")
		}
	}
	argv := ""
	if i := strings.Index(v, "argv[]="); i >= 0 {
		argv = v[i+7:]
		if j := strings.Index(argv, " ;"); j >= 0 {
			argv = argv[:j]
		}
	}
	_, _, script := commandExecutableAndScript(argv)
	return exe, script
}

func collectCron(ctx context.Context, inv *Inventory) {
	records := []Entry{}
	denied := 0
	reasons := []string{}
	files := []struct {
		path    string
		system  bool
		account string
	}{{"/etc/crontab", true, ""}}
	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for _, e := range ents {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				files = append(files, struct {
					path    string
					system  bool
					account string
				}{filepath.Join("/etc/cron.d", e.Name()), true, ""})
			}
		}
	}
	for _, root := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if ents, err := os.ReadDir(root); err == nil {
			sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
			for _, e := range ents {
				if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					files = append(files, struct {
						path    string
						system  bool
						account string
					}{filepath.Join(root, e.Name()), false, e.Name()})
				}
			}
		} else if os.IsPermission(err) {
			denied++
		}
	}
	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		rs, err := parseCronFile(f.path, f.system, f.account)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			} else {
				reasons = append(reasons, f.path+": "+err.Error())
			}
			continue
		}
		records = append(records, rs...)
	}
	dirs := []struct{ path, schedule string }{{"/etc/cron.hourly", "@hourly"}, {"/etc/cron.daily", "@daily"}, {"/etc/cron.weekly", "@weekly"}, {"/etc/cron.monthly", "@monthly"}}
	for _, d := range dirs {
		ents, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			records = append(records, Entry{Name: e.Name(), Manager: "cron", Kind: "periodic-script", EnabledState: "ENABLED", RuntimeState: "ON_DEMAND", Account: "root", PrivilegeContext: "ROOT", Schedule: d.schedule, ActionExecutable: p, ReferencedScriptPath: p, DefinitionPath: p, RunLevel: "NOT_APPLICABLE", LogonType: "CRON", HiddenState: "NOT_APPLICABLE", ConfigurationSource: p, CollectionSource: "cron periodic directory", Confidence: evidence.ConfidenceHigh})
		}
	}
	inv.Entries = append(inv.Entries, records...)
	st := evidence.StateObserved
	detail := ""
	if denied > 0 || len(reasons) > 0 {
		st = evidence.StateDegraded
		parts := reasons
		if denied > 0 {
			parts = append(parts, fmt.Sprintf("%d cron locations were permission-restricted", denied))
		}
		detail = strings.Join(uniqueSorted(parts), "; ")
	}
	if len(records) == 0 && st == evidence.StateObserved {
		st = evidence.StateUnavailable
		detail = "no readable cron definitions were found"
	}
	addSource(inv, "linux-cron", st, "cron files and periodic directories", len(records), detail)
}
func parseCronFile(path string, system bool, account string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []Entry{}
	sc := bufio.NewScanner(f)
	line := 0
	cronPath := defaultCronSearchPath()
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "@") && strings.Contains(fields[0], "=") {
			if key, value, ok := strings.Cut(t, "="); ok && strings.EqualFold(strings.TrimSpace(key), "PATH") {
				value = strings.Trim(strings.TrimSpace(value), "\"'")
				if strings.TrimSpace(value) != "" {
					cronPath = value
				}
			}
			continue
		}
		if len(fields) < 2 {
			continue
		}
		idx := 0
		sched := ""
		if strings.HasPrefix(fields[0], "@") {
			sched = fields[0]
			idx = 1
		} else {
			if len(fields) < 6 {
				continue
			}
			sched = strings.Join(fields[:5], " ")
			idx = 5
		}
		acct := account
		if system {
			if len(fields) <= idx {
				continue
			}
			acct = fields[idx]
			idx++
		}
		if len(fields) <= idx {
			continue
		}
		cmd := strings.Join(fields[idx:], " ")
		exe, args, script, workdir := cronCommandMetadata(cmd, cronPath)
		priv := "USER"
		if acct == "root" || acct == "0" {
			priv = "ROOT"
		}
		out = append(out, Entry{Name: fmt.Sprintf("%s:%d", filepath.Base(path), line), Manager: "cron", Kind: "cron-entry", EnabledState: "ENABLED", RuntimeState: "ON_DEMAND", Account: fallback(acct, "UNKNOWN"), PrivilegeContext: priv, Schedule: sched, ActionExecutable: exe, ArgumentsPresent: args, ReferencedScriptPath: script, WorkingDirectory: workdir, DefinitionPath: path, RunLevel: "NOT_APPLICABLE", LogonType: "CRON", HiddenState: "NOT_APPLICABLE", ConfigurationSource: path, CollectionSource: "cron definition file", Confidence: evidence.ConfidenceHigh})
	}
	return out, sc.Err()
}

// cronCommandMetadata extracts the executable boundary from the small shell
// scaffolding patterns commonly used by Debian-family system crontabs. Cron
// entries run through a shell, so the first token can legitimately be a shell
// builtin such as "cd" or "command -v" rather than the program that eventually
// executes. Treating those builtins as the action executable produced false
// UNKNOWN path-integrity states on otherwise fully observable Kali hosts.
//
// The parser is intentionally conservative: it understands only leading
// assignment tokens, a leading absolute `cd DIR && ...`, and condition/preflight
// segments (`command -v`, `test`, `[ ... ]`) followed by &&/||/;. It never
// executes the command and never retains argument values.
func cronCommandMetadata(cmd, searchPath string) (string, bool, string, string) {
	fields := splitCronShellFields(cmd)
	if len(fields) == 0 {
		return "", false, "", ""
	}
	workdir := ""
	for len(fields) > 0 {
		for len(fields) > 0 && cronAssignmentToken(fields[0]) {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			return "", false, "", workdir
		}
		leaf := strings.ToLower(strings.Trim(fields[0], "\"'"))
		switch leaf {
		case "(":
			// Some Debian-family cron definitions use a subshell fallback:
			//   test -x /usr/sbin/anacron || ( cd / && run-parts ... )
			// The grouping token is shell structure, not an executable. Strip only
			// a standalone leading parenthesis; compact/ambiguous shell syntax is
			// deliberately left unresolved rather than guessed.
			fields = fields[1:]
			continue
		case "{":
			// Current Debian/Kali /etc/crontab uses a brace-grouped fallback:
			//   test -x /usr/sbin/anacron || { cd / && run-parts ...; }
			// A standalone opening brace is shell structure, not the scheduled
			// executable. Preserve the same conservative standalone-token rule.
			fields = fields[1:]
			continue
		case "cd":
			if len(fields) > 1 {
				candidate := strings.Trim(fields[1], "\"'")
				if filepath.IsAbs(candidate) {
					workdir = filepath.Clean(candidate)
				}
			}
			fields = cronAfterControlOperator(fields)
			continue
		case "command":
			if len(fields) > 1 && (fields[1] == "-v" || fields[1] == "-V") {
				fields = cronAfterControlOperator(fields)
				continue
			}
		case "test", "[", "[[":
			fields = cronAfterControlOperator(fields)
			continue
		case "if":
			if next := cronAfterKeyword(fields, "then"); len(next) > 0 {
				fields = next
				continue
			}
		}
		segment := cronCommandSegment(fields)
		if len(segment) == 0 {
			return "", false, "", workdir
		}
		exe, args, script := commandExecutableAndScript(strings.Join(segment, " "))
		exe = resolveCronExecutable(exe, searchPath)
		if script != "" && !filepath.IsAbs(script) && workdir != "" {
			script = filepath.Clean(filepath.Join(workdir, script))
		}
		return exe, args, script, workdir
	}
	return "", false, "", workdir
}

func splitCronShellFields(cmd string) []string {
	replacer := strings.NewReplacer("&&", " && ", "||", " || ", ";", " ; ")
	return strings.Fields(replacer.Replace(strings.TrimSpace(cmd)))
}

func cronAssignmentToken(token string) bool {
	if strings.HasPrefix(token, "=") || !strings.Contains(token, "=") {
		return false
	}
	key, _, ok := strings.Cut(token, "=")
	if !ok || key == "" {
		return false
	}
	for i, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func cronControlOperator(token string) bool {
	switch token {
	case "&&", "||", ";":
		return true
	default:
		return false
	}
}

func cronAfterControlOperator(fields []string) []string {
	for i, token := range fields {
		if cronControlOperator(token) {
			if i+1 < len(fields) {
				return fields[i+1:]
			}
			return nil
		}
	}
	return nil
}

func cronAfterKeyword(fields []string, keyword string) []string {
	for i, token := range fields {
		if strings.EqualFold(strings.Trim(token, "\"'"), keyword) {
			if i+1 < len(fields) {
				return fields[i+1:]
			}
			return nil
		}
	}
	return nil
}

func cronCommandSegment(fields []string) []string {
	for i, token := range fields {
		if cronControlOperator(token) || strings.EqualFold(token, "fi") || token == ")" || token == "}" {
			return fields[:i]
		}
	}
	return fields
}

func defaultCronSearchPath() string {
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

func resolveCronExecutable(executable, searchPath string) string {
	executable = strings.Trim(strings.TrimSpace(executable), "\"'")
	if executable == "" || filepath.IsAbs(executable) || strings.ContainsRune(executable, filepath.Separator) {
		return cleanPath(executable)
	}
	if strings.TrimSpace(searchPath) == "" {
		searchPath = defaultCronSearchPath()
	}
	for _, dir := range strings.Split(searchPath, ":") {
		dir = strings.Trim(strings.TrimSpace(dir), "\"'")
		if !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, executable)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil && filepath.IsAbs(resolved) {
			candidate = resolved
		}
		return filepath.Clean(candidate)
	}
	return executable
}

func shellExecutable(cmd string) (string, bool) {
	exe, args, _ := commandExecutableAndScript(cmd)
	return exe, args
}

func commandExecutableAndScript(cmd string) (string, bool, string) {
	f := strings.Fields(strings.TrimSpace(cmd))
	if len(f) == 0 {
		return "", false, ""
	}
	i := 0
	for i < len(f)-1 && strings.Contains(f[i], "=") && !strings.Contains(f[i], "/") {
		i++
	}
	exe := strings.Trim(f[i], "\"'")
	args := len(f) > i+1
	script := ""
	leaf := strings.ToLower(filepath.Base(exe))
	if isScriptInterpreter(leaf) && len(f) > i+1 {
		candidate := strings.Trim(f[i+1], "\"'")
		if candidate != "" && !strings.HasPrefix(candidate, "-") {
			script = candidate
		}
	}
	return exe, args, script
}

func isScriptInterpreter(leaf string) bool {
	switch leaf {
	case "sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "node", "php":
		return true
	default:
		return false
	}
}
func reason(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return ctx.Err().Error()
	}
	return err.Error()
}

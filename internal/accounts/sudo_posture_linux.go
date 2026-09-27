//go:build linux

package accounts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxSudoFileBytes    = 2 << 20
	maxSudoLogicalLine  = 128 << 10
	maxSudoIncludeDepth = 16
)

type sudoSourceLine struct {
	Source string
	Line   int
	Text   string
}

type sudoWalk struct {
	ctx       context.Context
	seen      map[string]struct{}
	paths     map[string]int
	config    []SudoConfigPath
	lines     []sudoSourceLine
	problems  []string
	parsed    int
	fileCount int
}

func collectSudoPosture(ctx context.Context, inv *Inventory) {
	inv.SudoPosture = collectLinuxSudoPosture(ctx, "/etc/sudoers")
}

func collectLinuxSudoPosture(ctx context.Context, mainPath string) SudoPosture {
	provider := "Linux sudoers parser"
	_, sudoErr := exec.LookPath("sudo")
	_, statErr := os.Lstat(mainPath)
	if errors.Is(statErr, fs.ErrNotExist) && sudoErr != nil {
		return SudoPosture{
			State:  evidence.StateNotApplicable,
			Source: provider,
			Reason: "sudo is not installed and the primary sudoers configuration is absent",
		}
	}

	w := &sudoWalk{ctx: ctx, seen: map[string]struct{}{}, paths: map[string]int{}}
	mainErr := w.walkFile(mainPath, 0)

	posture := SudoPosture{Source: provider, ConfigPaths: w.config}
	if len(w.lines) > 0 {
		aliases := parseSudoCommandAliases(w.lines)
		posture.EnvironmentIssues = parseSudoEnvironmentIssues(w.lines)
		posture.Grants = parseSudoGrants(w.lines, aliases)
		posture.PathIssues = inspectSudoGrantPaths(posture.Grants)
	}

	switch {
	case ctx.Err() != nil:
		posture.State = evidence.StateUnavailable
		posture.Reason = "sudoers collection cancelled or timed out: " + ctx.Err().Error()
	case mainErr != nil && w.parsed == 0:
		if errors.Is(mainErr, fs.ErrPermission) {
			posture.State = evidence.StateDenied
			posture.Reason = "primary sudoers content is not readable in the current privilege context; rerun with elevation for deeper evidence"
		} else if errors.Is(mainErr, fs.ErrNotExist) {
			posture.State = evidence.StateUnavailable
			posture.Reason = "primary sudoers configuration is absent"
		} else {
			posture.State = evidence.StateUnavailable
			posture.Reason = "primary sudoers configuration could not be parsed: " + mainErr.Error()
		}
	case len(w.problems) > 0:
		posture.State = evidence.StateDegraded
		posture.Reason = strings.Join(uniqueSorted(w.problems), "; ")
	default:
		posture.State = evidence.StateObserved
	}
	return normalizeSudoPosture("linux", posture)
}

func (w *sudoWalk) walkFile(path string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > maxSudoIncludeDepth {
		err := fmt.Errorf("sudoers include depth exceeds %d at %s", maxSudoIncludeDepth, path)
		w.problems = append(w.problems, err.Error())
		return err
	}
	clean, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		clean = filepath.Clean(path)
	}
	if _, ok := w.seen[clean]; ok {
		return nil
	}
	if w.fileCount >= maxSudoFiles {
		err := fmt.Errorf("sudoers file count exceeds %d", maxSudoFiles)
		w.problems = append(w.problems, err.Error())
		return err
	}
	w.seen[clean] = struct{}{}
	w.fileCount++

	idx := w.recordConfigPath(clean, "FILE")
	lines, err := readSudoLogicalLines(w.ctx, clean)
	if err != nil {
		w.markConfigReadFailure(idx, err)
		w.problems = append(w.problems, clean+": "+err.Error())
		return err
	}
	w.config[idx].Parsed = true
	w.parsed++

	for _, line := range lines {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if kind, includePath, ok := sudoIncludeDirective(line.Text); ok {
			resolved := resolveSudoIncludePath(clean, includePath)
			if resolved == "" {
				w.problems = append(w.problems, fmt.Sprintf("%s:%d invalid sudoers include path", clean, line.Line))
				continue
			}
			if kind == "DIR" {
				if err := w.walkDir(resolved, depth+1); err != nil {
					w.problems = append(w.problems, fmt.Sprintf("%s:%d include directory %s: %v", clean, line.Line, resolved, err))
				}
			} else if err := w.walkFile(resolved, depth+1); err != nil {
				w.problems = append(w.problems, fmt.Sprintf("%s:%d include file %s: %v", clean, line.Line, resolved, err))
			}
			continue
		}
		text := strings.TrimSpace(stripSudoComment(line.Text))
		if text == "" {
			continue
		}
		line.Text = text
		w.lines = append(w.lines, line)
	}
	return nil
}

func (w *sudoWalk) walkDir(path string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	idx := w.recordConfigPath(path, "DIRECTORY")
	entries, err := os.ReadDir(path)
	if err != nil {
		w.markConfigReadFailure(idx, err)
		return err
	}
	w.config[idx].Parsed = true
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		// sudoers @includedir/#includedir ignores names containing a dot and
		// editor backup names ending in '~'. Mirror that behavior so Chimera does
		// not assess files sudo itself will ignore.
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		if err := w.walkFile(filepath.Join(path, name), depth); err != nil {
			w.problems = append(w.problems, filepath.Join(path, name)+": "+err.Error())
		}
	}
	return nil
}

func (w *sudoWalk) recordConfigPath(path, kind string) int {
	key := kind + "\x00" + path
	if idx, ok := w.paths[key]; ok {
		return idx
	}
	item := SudoConfigPath{
		Path:       path,
		Kind:       kind,
		State:      evidence.StateUnavailable,
		Source:     path,
		Confidence: evidence.ConfidenceLow,
		Reason:     "path metadata is unavailable",
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			item.State = evidence.StateDenied
			item.Reason = "permission denied reading path metadata"
		} else if errors.Is(err, fs.ErrNotExist) {
			item.State = evidence.StateUnavailable
			item.Reason = "path does not exist"
		} else {
			item.Reason = err.Error()
		}
	} else {
		item.Symlink = info.Mode()&os.ModeSymlink != 0
		metaInfo := info
		if item.Symlink {
			if target, statErr := os.Stat(path); statErr == nil {
				metaInfo = target
			}
		}
		item.State = evidence.StateObserved
		item.Confidence = evidence.ConfidenceExact
		item.Reason = ""
		item.Mode = formatFileMode(metaInfo.Mode())
		if st, ok := metaInfo.Sys().(*syscall.Stat_t); ok {
			item.UID = st.Uid
			item.GID = st.Gid
		}
		item.InsecureBasis = sudoConfigPermissionRisks(metaInfo.Mode(), item.UID, item.GID)
		item.Insecure = len(item.InsecureBasis) > 0
	}
	item.ID = stableSudoID("sudo-config", item.Path, item.Kind)
	idx := len(w.config)
	w.config = append(w.config, item)
	w.paths[key] = idx
	return idx
}

func (w *sudoWalk) markConfigReadFailure(idx int, err error) {
	if idx < 0 || idx >= len(w.config) || err == nil {
		return
	}
	// Keep successfully observed metadata, but record that the file/directory
	// content could not be consumed by the parser.
	if w.config[idx].State == evidence.StateObserved {
		w.config[idx].Parsed = false
		return
	}
	if errors.Is(err, fs.ErrPermission) {
		w.config[idx].State = evidence.StateDenied
		w.config[idx].Reason = "permission denied reading sudoers content"
	} else {
		w.config[idx].State = evidence.StateUnavailable
		w.config[idx].Reason = err.Error()
	}
}

func readSudoLogicalLines(ctx context.Context, path string) ([]sudoSourceLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lr := io.LimitReader(f, maxSudoFileBytes+1)
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 64*1024), maxSudoLogicalLine)
	var out []sudoSourceLine
	var current strings.Builder
	startLine := 0
	lineNo := 0
	bytesRead := 0
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineNo++
		text := s.Text()
		bytesRead += len(text) + 1
		if bytesRead > maxSudoFileBytes {
			return nil, fmt.Errorf("sudoers file exceeds %d bytes", maxSudoFileBytes)
		}
		if startLine == 0 {
			startLine = lineNo
		}
		if sudoLineContinues(text) {
			trimmed := strings.TrimRightFunc(text, unicode.IsSpace)
			trimmed = strings.TrimSuffix(trimmed, "\\")
			current.WriteString(trimmed)
			current.WriteByte(' ')
			continue
		}
		current.WriteString(text)
		out = append(out, sudoSourceLine{Source: path, Line: startLine, Text: current.String()})
		current.Reset()
		startLine = 0
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if current.Len() > 0 {
		out = append(out, sudoSourceLine{Source: path, Line: startLine, Text: current.String()})
	}
	return out, nil
}

func sudoLineContinues(line string) bool {
	trimmed := strings.TrimRightFunc(line, unicode.IsSpace)
	if trimmed == "" {
		return false
	}
	count := 0
	for i := len(trimmed) - 1; i >= 0 && trimmed[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func sudoIncludeDirective(line string) (kind, path string, ok bool) {
	t := strings.TrimSpace(line)
	for _, prefix := range []struct {
		Token string
		Kind  string
	}{
		{"#includedir", "DIR"}, {"@includedir", "DIR"}, {"#include", "FILE"}, {"@include", "FILE"},
	} {
		if len(t) < len(prefix.Token) || !strings.EqualFold(t[:len(prefix.Token)], prefix.Token) {
			continue
		}
		if len(t) > len(prefix.Token) && !unicode.IsSpace(rune(t[len(prefix.Token)])) {
			continue
		}
		rest := strings.TrimSpace(t[len(prefix.Token):])
		if rest == "" {
			return prefix.Kind, "", true
		}
		return prefix.Kind, unquoteSudoPath(rest), true
	}
	return "", "", false
}

func unquoteSudoPath(s string) string {
	s = strings.TrimSpace(stripSudoComment(s))
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = s[1 : len(s)-1]
	}
	s = strings.ReplaceAll(s, "\\ ", " ")
	s = strings.ReplaceAll(s, "\\#", "#")
	return strings.TrimSpace(s)
}

func resolveSudoIncludePath(parentFile, includePath string) string {
	includePath = strings.TrimSpace(includePath)
	if includePath == "" {
		return ""
	}
	if strings.Contains(includePath, "%h") {
		if host, err := os.Hostname(); err == nil && host != "" {
			includePath = strings.ReplaceAll(includePath, "%h", host)
		}
	}
	if filepath.IsAbs(includePath) {
		return filepath.Clean(includePath)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(parentFile), includePath))
}

func stripSudoComment(line string) string {
	quote := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '#' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func parseSudoCommandAliases(lines []sudoSourceLine) map[string][]string {
	aliases := map[string][]string{}
	for _, line := range lines {
		t := strings.TrimSpace(line.Text)
		const prefix = "Cmnd_Alias"
		if len(t) <= len(prefix) || !strings.EqualFold(t[:len(prefix)], prefix) || !unicode.IsSpace(rune(t[len(prefix)])) {
			continue
		}
		rest := strings.TrimSpace(t[len(prefix):])
		eq := findSudoTopLevelEqual(rest)
		if eq <= 0 {
			continue
		}
		name := strings.TrimSpace(rest[:eq])
		if !looksSudoAlias(name) {
			continue
		}
		values := splitSudoTopLevel(rest[eq+1:], ',')
		clean := make([]string, 0, len(values))
		for _, value := range values {
			if v := strings.TrimSpace(value); v != "" {
				clean = append(clean, v)
			}
		}
		if len(clean) > 0 {
			aliases[name] = clean
		}
	}
	return aliases
}

var dangerousSudoEnvVars = map[string]struct{}{
	"LD_PRELOAD": {}, "LD_LIBRARY_PATH": {}, "LD_AUDIT": {}, "GCONV_PATH": {},
	"PYTHONPATH": {}, "PYTHONHOME": {}, "PERL5LIB": {}, "PERLLIB": {},
	"RUBYLIB": {}, "RUBYOPT": {}, "BASH_ENV": {}, "ENV": {},
	"NODE_OPTIONS": {}, "JAVA_TOOL_OPTIONS": {}, "_JAVA_OPTIONS": {},
}

func parseSudoEnvironmentIssues(lines []sudoSourceLine) []SudoEnvironmentIssue {
	var out []SudoEnvironmentIssue
	for _, line := range lines {
		t := strings.TrimSpace(line.Text)
		const prefix = "Defaults"
		if len(t) < len(prefix) || !strings.EqualFold(t[:len(prefix)], prefix) {
			continue
		}
		if len(t) > len(prefix) && !unicode.IsSpace(rune(t[len(prefix)])) && !strings.ContainsRune(":@>!", rune(t[len(prefix)])) {
			continue
		}
		rest := strings.TrimSpace(t[len(prefix):])
		scope := "GLOBAL"
		if rest != "" && strings.ContainsRune(":@>!", rune(rest[0])) {
			if i := strings.IndexFunc(rest, unicode.IsSpace); i >= 0 {
				scope = strings.TrimSpace(rest[:i])
				rest = strings.TrimSpace(rest[i:])
			} else {
				continue
			}
		}
		for _, raw := range splitSudoTopLevel(rest, ',') {
			setting := strings.TrimSpace(raw)
			lower := strings.ToLower(setting)
			switch {
			case lower == "!env_reset":
				out = append(out, SudoEnvironmentIssue{Kind: "ENV_RESET_DISABLED", Scope: scope, Source: line.Source, Line: line.Line, Detail: "sudo environment reset is explicitly disabled for this Defaults scope"})
			case lower == "setenv":
				out = append(out, SudoEnvironmentIssue{Kind: "SETENV_DEFAULT", Scope: scope, Source: line.Source, Line: line.Line, Detail: "sudo SETENV permission is enabled by Defaults for this scope"})
			case strings.HasPrefix(lower, "env_keep"):
				vars := sudoEnvKeepVariables(setting)
				var risky []string
				for _, name := range vars {
					upper := strings.ToUpper(name)
					if _, ok := dangerousSudoEnvVars[upper]; ok {
						risky = append(risky, upper)
					}
				}
				if len(risky) > 0 {
					out = append(out, SudoEnvironmentIssue{Kind: "DANGEROUS_ENV_KEEP", Scope: scope, Values: uniqueSorted(risky), Source: line.Source, Line: line.Line, Detail: "sudoers preserves security-sensitive loader/interpreter environment variable names"})
				}
			}
		}
	}
	return out
}

func sudoEnvKeepVariables(setting string) []string {
	idx := strings.Index(setting, "=")
	if idx < 0 || idx+1 >= len(setting) {
		return nil
	}
	rhs := strings.TrimSpace(setting[idx+1:])
	rhs = strings.Trim(rhs, "\"'")
	rhs = strings.NewReplacer("\"", " ", "'", " ").Replace(rhs)
	fields := strings.FieldsFunc(rhs, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })
	return uniqueSorted(fields)
}

func parseSudoGrants(lines []sudoSourceLine, aliases map[string][]string) []SudoGrant {
	var out []SudoGrant
	for _, line := range lines {
		t := strings.TrimSpace(line.Text)
		if sudoReservedLine(t) {
			continue
		}
		eq := findSudoTopLevelEqual(t)
		if eq <= 0 || eq+1 >= len(t) {
			continue
		}
		left := strings.TrimSpace(t[:eq])
		right := strings.TrimSpace(t[eq+1:])
		fields := strings.Fields(left)
		if len(fields) < 2 || right == "" {
			continue
		}
		subjects := fields[0]
		hosts := strings.Join(fields[1:], " ")
		commands, runAs := parseSudoCommandList(right, aliases)
		if len(commands) == 0 {
			continue
		}
		grant := SudoGrant{Subjects: subjects, Hosts: hosts, RunAs: runAs, Commands: commands, Source: line.Source, Line: line.Line}
		grant.ID = stableSudoID("sudo-grant", line.Source, fmt.Sprint(line.Line), subjects, hosts, runAs, right)
		out = append(out, grant)
		if len(out) >= maxSudoGrants {
			break
		}
	}
	return out
}

func sudoReservedLine(t string) bool {
	for _, prefix := range []string{"Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"} {
		if len(t) >= len(prefix) && strings.EqualFold(t[:len(prefix)], prefix) && (len(t) == len(prefix) || unicode.IsSpace(rune(t[len(prefix)]))) {
			return true
		}
	}
	if _, _, ok := sudoIncludeDirective(t); ok {
		return true
	}
	return false
}

func parseSudoCommandList(right string, aliases map[string][]string) ([]SudoCommand, string) {
	segments := splitSudoTopLevel(right, ',')
	var out []SudoCommand
	currentRunAs := ""
	nopasswd := false
	setenv := false
	for _, raw := range segments {
		seg := strings.TrimSpace(raw)
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "(") {
			if end := matchingParen(seg); end > 0 {
				currentRunAs = strings.TrimSpace(seg[1:end])
				seg = strings.TrimSpace(seg[end+1:])
			}
		}
		for {
			tag, rest, ok := sudoLeadingTag(seg)
			if !ok {
				break
			}
			switch tag {
			case "NOPASSWD":
				nopasswd = true
			case "PASSWD":
				nopasswd = false
			case "SETENV":
				setenv = true
			case "NOSETENV":
				setenv = false
			}
			seg = rest
		}
		if seg == "" {
			continue
		}
		expanded := expandSudoCommandSpec(seg, aliases, 0, map[string]struct{}{})
		if len(expanded) == 0 {
			expanded = []string{seg}
		}
		for _, spec := range expanded {
			cmd := normalizeSudoCommand(spec, aliases)
			cmd.NOPASSWD = nopasswd
			cmd.SetEnv = setenv
			out = append(out, cmd)
		}
	}
	return out, currentRunAs
}

func sudoLeadingTag(s string) (tag, rest string, ok bool) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return "", s, false
	}
	candidate := strings.ToUpper(strings.TrimSpace(s[:idx]))
	switch candidate {
	case "EXEC", "NOEXEC", "FOLLOW", "NOFOLLOW", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "PASSWD", "NOPASSWD", "SETENV", "NOSETENV":
		return candidate, strings.TrimSpace(s[idx+1:]), true
	default:
		return "", s, false
	}
}

func normalizeSudoCommand(spec string, aliases map[string][]string) SudoCommand {
	raw := strings.TrimSpace(spec)
	cmd := SudoCommand{}
	for strings.HasPrefix(raw, "!") {
		cmd.Negated = !cmd.Negated
		raw = strings.TrimSpace(raw[1:])
	}
	if strings.EqualFold(raw, "ALL") {
		cmd.Unrestricted = true
		cmd.Spec = "ALL"
		return cmd
	}
	if looksSudoAlias(raw) {
		cmd.Spec = raw
		if _, ok := aliases[raw]; !ok {
			cmd.Alias = raw
		}
		return cmd
	}
	cmd.Path = sudoCommandPath(raw)
	cmd.Wildcard = strings.ContainsAny(raw, "*?[")
	if refs := sudoScriptReferences(raw, cmd.Path); len(refs) > 0 {
		cmd.ScriptPath = refs[0]
	}
	cmd.Spec = sudoSafeCommandDescriptor(raw, cmd.Path, cmd.Wildcard)
	return cmd
}

func sudoSafeCommandDescriptor(raw, path string, wildcard bool) string {
	if path == "" {
		if wildcard {
			return "UNRESOLVED_COMMAND [wildcard]"
		}
		return "UNRESOLVED_COMMAND"
	}
	tokens := sudoTokenize(raw)
	argCount := len(tokens) - 1
	if len(tokens) > 0 && isSudoDigestToken(tokens[0]) {
		argCount--
	}
	if argCount < 0 {
		argCount = 0
	}
	desc := path
	if argCount > 0 {
		desc += " [arguments redacted]"
	}
	if wildcard {
		desc += " [wildcard scope]"
	}
	return boundedSudoText(desc, 640)
}

func expandSudoCommandSpec(spec string, aliases map[string][]string, depth int, seen map[string]struct{}) []string {
	if depth > 8 {
		return nil
	}
	trimmed := strings.TrimSpace(spec)
	neg := ""
	for strings.HasPrefix(trimmed, "!") {
		neg += "!"
		trimmed = strings.TrimSpace(trimmed[1:])
	}
	items, ok := aliases[trimmed]
	if !ok {
		return []string{spec}
	}
	if _, loop := seen[trimmed]; loop {
		return nil
	}
	seen2 := make(map[string]struct{}, len(seen)+1)
	for k := range seen {
		seen2[k] = struct{}{}
	}
	seen2[trimmed] = struct{}{}
	var out []string
	for _, item := range items {
		for _, expanded := range expandSudoCommandSpec(item, aliases, depth+1, seen2) {
			out = append(out, neg+expanded)
		}
	}
	return out
}

func findSudoTopLevelEqual(s string) int {
	quote := byte(0)
	escaped := false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitSudoTopLevel(s string, sep byte) []string {
	var out []string
	start := 0
	quote := byte(0)
	escaped := false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if c == sep && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func matchingParen(s string) int {
	depth := 0
	quote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func looksSudoAlias(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || unicode.IsDigit(r) || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func sudoCommandPath(spec string) string {
	tokens := sudoTokenize(spec)
	if len(tokens) == 0 {
		return ""
	}
	idx := 0
	if isSudoDigestToken(tokens[0]) {
		idx++
	}
	if idx >= len(tokens) {
		return ""
	}
	path := sudoUnescapeToken(tokens[idx])
	if !filepath.IsAbs(path) {
		return ""
	}
	return filepath.Clean(path)
}

func isSudoDigestToken(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, prefix := range []string{"sha224:", "sha256:", "sha384:", "sha512:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func sudoTokenize(s string) []string {
	var out []string
	var current strings.Builder
	quote := byte(0)
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			out = append(out, current.String())
			current.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				current.WriteByte(c)
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		current.WriteByte(c)
	}
	if escaped {
		current.WriteByte('\\')
	}
	flush()
	return out
}

func sudoUnescapeToken(s string) string {
	return strings.TrimSpace(s)
}

func inspectSudoGrantPaths(grants []SudoGrant) []SudoPathIssue {
	seen := map[string]struct{}{}
	var out []SudoPathIssue
	for _, grant := range grants {
		for _, cmd := range grant.Commands {
			if cmd.Negated || cmd.Unrestricted || cmd.Path == "" || strings.ContainsAny(cmd.Path, "*?[") {
				continue
			}
			refs := []struct {
				Kind string
				Path string
			}{{Kind: "COMMAND", Path: cmd.Path}}
			if cmd.ScriptPath != "" {
				refs = append(refs, struct {
					Kind string
					Path string
				}{Kind: "SCRIPT", Path: cmd.ScriptPath})
			}
			for _, ref := range refs {
				key := grant.Source + "\x00" + fmt.Sprint(grant.Line) + "\x00" + ref.Kind + "\x00" + ref.Path
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				issue, ok := inspectSudoWritablePath(ref.Kind, ref.Path, grant.Source, grant.Line)
				if ok {
					out = append(out, issue)
					if len(out) >= maxSudoPathIssues {
						return out
					}
				}
			}
		}
	}
	return out
}

func sudoScriptReferences(spec, commandPath string) []string {
	tokens := sudoTokenize(strings.TrimLeft(strings.TrimSpace(spec), "!"))
	if len(tokens) < 2 {
		return nil
	}
	if isSudoDigestToken(tokens[0]) {
		tokens = tokens[1:]
	}
	if len(tokens) < 2 {
		return nil
	}
	base := strings.ToLower(filepath.Base(commandPath))
	interpreter := false
	for _, name := range []string{"sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3", "perl", "ruby", "node", "php", "lua", "pwsh"} {
		if base == name || strings.HasPrefix(base, name+".") {
			interpreter = true
			break
		}
	}
	if !interpreter {
		return nil
	}
	for _, token := range tokens[1:] {
		if strings.HasPrefix(token, "-") {
			continue
		}
		if filepath.IsAbs(token) && !strings.ContainsAny(token, "*?[") {
			return []string{filepath.Clean(token)}
		}
		break
	}
	return nil
}

func inspectSudoWritablePath(kind, path, source string, line int) (SudoPathIssue, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return SudoPathIssue{}, false
	}
	meta := info
	if info.Mode()&os.ModeSymlink != 0 {
		if target, statErr := os.Stat(path); statErr == nil {
			meta = target
		}
	}
	uid, gid := uint32(0), uint32(0)
	if st, ok := meta.Sys().(*syscall.Stat_t); ok {
		uid, gid = st.Uid, st.Gid
	}
	reasons := sudoWritableBoundaryRisks(path, meta.Mode(), uid, gid)
	if len(reasons) == 0 {
		return SudoPathIssue{}, false
	}
	issue := SudoPathIssue{Kind: kind, Path: path, Mode: formatFileMode(meta.Mode()), UID: uid, GID: gid, Source: source, Line: line, Reason: strings.Join(uniqueSorted(reasons), "; ")}
	issue.ID = stableSudoID("sudo-path", source, fmt.Sprint(line), kind, path, issue.Reason)
	return issue, true
}

func sudoWritableBoundaryRisks(path string, mode os.FileMode, uid, gid uint32) []string {
	var risks []string
	perm := mode.Perm()
	if uid != 0 && perm&0o200 != 0 {
		risks = append(risks, fmt.Sprintf("target is writable by non-root owner UID %d", uid))
	}
	if perm&0o020 != 0 {
		risks = append(risks, fmt.Sprintf("target is group-writable (GID %d)", gid))
	}
	if perm&0o002 != 0 {
		risks = append(risks, "target is world-writable")
	}

	parent := filepath.Dir(path)
	for parent != "." && parent != "" {
		info, err := os.Stat(parent)
		if err != nil {
			break
		}
		puid, pgid := uint32(0), uint32(0)
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			puid, pgid = st.Uid, st.Gid
		}
		pperm := info.Mode().Perm()
		canTraverse := pperm&0o111 != 0
		if canTraverse {
			if puid != 0 && pperm&0o200 != 0 {
				risks = append(risks, fmt.Sprintf("parent directory %s is writable by non-root owner UID %d", parent, puid))
			}
			if pperm&0o020 != 0 {
				risks = append(risks, fmt.Sprintf("parent directory %s is group-writable (GID %d)", parent, pgid))
			}
			if pperm&0o002 != 0 && info.Mode()&os.ModeSticky == 0 {
				risks = append(risks, fmt.Sprintf("parent directory %s is world-writable without sticky-bit protection", parent))
			}
		}
		if parent == string(filepath.Separator) {
			break
		}
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	return risks
}

func sudoConfigPermissionRisks(mode os.FileMode, uid, gid uint32) []string {
	var risks []string
	if uid != 0 {
		risks = append(risks, fmt.Sprintf("owned by non-root UID %d", uid))
	}
	perm := mode.Perm()
	if perm&0o020 != 0 {
		risks = append(risks, fmt.Sprintf("group-writable (GID %d)", gid))
	}
	if perm&0o002 != 0 {
		risks = append(risks, "world-writable")
	}
	return risks
}

func formatFileMode(mode os.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

func boundedSudoText(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

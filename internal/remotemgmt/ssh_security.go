package remotemgmt

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const sshSecuritySchemaVersion = "chimera.ssh-security/v1"

const (
	sshStateComplete      = "COMPLETE"
	sshStateDegraded      = "DEGRADED"
	sshStateNotApplicable = "NOT_APPLICABLE"
)

type SSHSetting struct {
	Name       string              `json:"name"`
	State      evidence.State      `json:"state"`
	Value      string              `json:"value,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Explicit   bool                `json:"explicit"`
	Reason     string              `json:"reason,omitempty"`
}

type SSHFilePosture struct {
	ID              string              `json:"id"`
	Path            string              `json:"path"`
	State           evidence.State      `json:"state"`
	Exists          bool                `json:"exists"`
	Mode            string              `json:"mode,omitempty"`
	Owner           string              `json:"owner,omitempty"`
	Group           string              `json:"group,omitempty"`
	BroadlyWritable bool                `json:"broadly_writable"`
	TrustedOwner    bool                `json:"trusted_owner"`
	PermissionBasis string              `json:"permission_basis"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

type SSHAlgorithmPosture struct {
	Family     string              `json:"family"`
	State      evidence.State      `json:"state"`
	Values     []string            `json:"values,omitempty"`
	Weak       []string            `json:"weak,omitempty"`
	Source     string              `json:"source"`
	Confidence evidence.Confidence `json:"confidence"`
	Explicit   bool                `json:"explicit"`
	Reason     string              `json:"reason,omitempty"`
}

type SSHSecuritySummary struct {
	Applicable          bool `json:"applicable"`
	Files               int  `json:"files"`
	FilesWeak           int  `json:"files_weak"`
	FilesUnavailable    int  `json:"files_unavailable"`
	SettingsObserved    int  `json:"settings_observed"`
	SettingsUnavailable int  `json:"settings_unavailable"`
	AlgorithmFamilies   int  `json:"algorithm_families"`
	WeakAlgorithms      int  `json:"weak_algorithms"`
	MatchBlocks         int  `json:"match_blocks"`
}

type SSHSecurity struct {
	Schema           string                `json:"schema"`
	State            string                `json:"state"`
	ConfigPath       string                `json:"config_path,omitempty"`
	DaemonPath       string                `json:"daemon_path,omitempty"`
	EvaluationSource string                `json:"evaluation_source,omitempty"`
	Settings         []SSHSetting          `json:"settings"`
	Files            []SSHFilePosture      `json:"files"`
	Algorithms       []SSHAlgorithmPosture `json:"algorithms"`
	Summary          SSHSecuritySummary    `json:"summary"`
	Degraded         []string              `json:"degraded,omitempty"`
}

type sshParsedConfig struct {
	Settings    map[string]sshParsedValue
	Files       []string
	MatchBlocks int
	Degraded    []string
}

type sshParsedValue struct {
	Value  string
	Source string
}

var sshSettingNames = []string{
	"permitrootlogin",
	"passwordauthentication",
	"kbdinteractiveauthentication",
	"challengeresponseauthentication",
	"permitemptypasswords",
	"allowtcpforwarding",
	"gatewayports",
	"allowagentforwarding",
	"x11forwarding",
	"permittunnel",
	"strictmodes",
}

var sshAlgorithmNames = []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"}

func collectSSHSecurity(ctx context.Context, surfacePresent bool) SSHSecurity {
	out := SSHSecurity{Schema: sshSecuritySchemaVersion, State: sshStateNotApplicable, Settings: []SSHSetting{}, Files: []SSHFilePosture{}, Algorithms: []SSHAlgorithmPosture{}}
	configPath := firstExistingPath(sshCandidateConfigPaths())
	daemonPath := findSSHD()
	if configPath == "" && daemonPath == "" && !surfacePresent {
		out.Summary = summarizeSSH(out)
		return out
	}
	out.State = sshStateComplete
	out.ConfigPath = configPath
	out.DaemonPath = daemonPath

	parsed := sshParsedConfig{Settings: map[string]sshParsedValue{}}
	if configPath != "" {
		parsed = parseSSHConfig(configPath)
		for _, path := range parsed.Files {
			out.Files = append(out.Files, sshFilePosture(ctx, path))
		}
		out.Degraded = append(out.Degraded, parsed.Degraded...)
	} else if surfacePresent {
		out.Degraded = append(out.Degraded, "SSH service/listener is present but the daemon configuration path was not found in standard local locations")
	}

	effective, source, effectiveErr := effectiveSSHDConfig(ctx, daemonPath, configPath)
	if effectiveErr == nil && len(effective) > 0 {
		out.EvaluationSource = source
		out.Settings = settingsFromEffective(effective, source)
		out.Algorithms = algorithmsFromEffective(effective, source)
	} else {
		if effectiveErr != nil && daemonPath != "" {
			out.Degraded = append(out.Degraded, "effective sshd configuration unavailable: "+effectiveErr.Error())
		}
		if configPath != "" {
			out.EvaluationSource = "static global sshd configuration parsing"
			out.Settings = settingsFromParsed(parsed)
			out.Algorithms = algorithmsFromParsed(parsed)
		} else {
			out.EvaluationSource = "SSH configuration unavailable"
			out.Settings = unavailableSSHSettings("effective sshd configuration and local configuration file are unavailable")
			out.Algorithms = unavailableSSHAlgorithms("effective sshd configuration and local configuration file are unavailable")
		}
	}

	out.Summary.MatchBlocks = parsed.MatchBlocks
	out.Degraded = uniqueStrings(out.Degraded)
	out.Summary = summarizeSSH(out)
	if out.Summary.FilesUnavailable > 0 || out.Summary.SettingsUnavailable > 0 || effectiveErr != nil || len(out.Degraded) > 0 {
		out.State = sshStateDegraded
	}
	return normalizeSSHSecurity(out)
}

func findSSHD() string {
	for _, name := range []string{"sshd", "sshd.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range sshCandidateDaemonPaths() {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func firstExistingPath(paths []string) string {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return filepath.Clean(p)
		}
	}
	return ""
}

func effectiveSSHDConfig(ctx context.Context, daemonPath, configPath string) (map[string]string, string, error) {
	if strings.TrimSpace(daemonPath) == "" {
		return nil, "", fmt.Errorf("sshd executable not found")
	}
	args := []string{"-T"}
	if configPath != "" {
		args = append(args, "-f", configPath)
	}
	cmd := exec.CommandContext(ctx, daemonPath, args...)
	// The invocation is a local, read-only configuration expansion. It does not
	// bind sockets or accept connections. A minimal environment avoids locale-
	// dependent parsing while preserving platform essentials such as PATH.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	b, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, "", fmt.Errorf("sshd -T failed: %s", msg)
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if _, exists := values[key]; exists {
			continue
		}
		values[key] = strings.TrimSpace(strings.Join(fields[1:], " "))
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	source := daemonPath + " -T"
	if configPath != "" {
		source += " -f " + configPath
	}
	return values, source, nil
}

func parseSSHConfig(root string) sshParsedConfig {
	result := sshParsedConfig{Settings: map[string]sshParsedValue{}}
	seen := map[string]struct{}{}
	inMatch := false
	var walk func(string, int)
	walk = func(path string, depth int) {
		if depth > 16 {
			result.Degraded = append(result.Degraded, "SSH Include recursion limit reached at "+path)
			return
		}
		clean, err := filepath.Abs(path)
		if err == nil {
			path = clean
		}
		if _, ok := seen[path]; ok {
			return
		}
		if len(seen) >= 128 {
			result.Degraded = append(result.Degraded, "SSH configuration file limit reached while expanding Include directives")
			return
		}
		seen[path] = struct{}{}
		result.Files = append(result.Files, path)
		f, err := os.Open(path)
		if err != nil {
			result.Degraded = append(result.Degraded, path+": "+err.Error())
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(stripSSHComment(scanner.Text()))
			if line == "" {
				continue
			}
			key, value := splitSSHDirective(line)
			if key == "" {
				continue
			}
			lk := strings.ToLower(key)
			if lk == "match" {
				result.MatchBlocks++
				inMatch = true
				continue
			}
			if lk == "include" {
				// Always enumerate included files for permission posture. The
				// shared Match state prevents conditional directives from being
				// misrepresented as global settings.
				for _, pattern := range strings.Fields(value) {
					pattern = strings.Trim(pattern, `"'`)
					if pattern == "" {
						continue
					}
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(filepath.Dir(path), pattern)
					}
					matches, _ := filepath.Glob(pattern)
					sort.Strings(matches)
					for _, match := range matches {
						walk(match, depth+1)
					}
				}
				continue
			}
			if inMatch {
				continue
			}
			if !isSSHTrackedDirective(lk) {
				continue
			}
			if _, exists := result.Settings[lk]; exists {
				// sshd uses the first obtained value for these scalar/list
				// settings, so preserve first-match semantics.
				continue
			}
			result.Settings[lk] = sshParsedValue{Value: strings.TrimSpace(value), Source: fmt.Sprintf("%s:%d", path, lineNo)}
		}
		if err := scanner.Err(); err != nil {
			result.Degraded = append(result.Degraded, path+": "+err.Error())
		}
	}
	walk(root, 0)
	sort.Strings(result.Files)
	result.Degraded = uniqueStrings(result.Degraded)
	return result
}

func stripSSHComment(s string) string {
	inSingle, inDouble, escaped := false, false, false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if r == '#' && !inSingle && !inDouble {
			return s[:i]
		}
	}
	return s
}

func splitSSHDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		key := strings.TrimSpace(line[:i])
		rest := strings.TrimSpace(line[i:])
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
		return key, rest
	}
	return line, ""
}

func isSSHTrackedDirective(k string) bool {
	for _, v := range sshSettingNames {
		if k == v {
			return true
		}
	}
	for _, v := range sshAlgorithmNames {
		if k == v {
			return true
		}
	}
	return false
}

func settingsFromEffective(values map[string]string, source string) []SSHSetting {
	out := make([]SSHSetting, 0, len(sshSettingNames))
	for _, name := range sshSettingNames {
		value, ok := values[name]
		if !ok && name == "kbdinteractiveauthentication" {
			value, ok = values["challengeresponseauthentication"]
		}
		if ok {
			out = append(out, SSHSetting{Name: name, State: evidence.StateObserved, Value: normalizeSSHValue(value), Source: source, Confidence: evidence.ConfidenceHigh, Explicit: false})
		} else {
			out = append(out, SSHSetting{Name: name, State: evidence.StateUnavailable, Source: source, Confidence: evidence.ConfidenceLow, Reason: "setting not returned by sshd -T"})
		}
	}
	return out
}

func settingsFromParsed(parsed sshParsedConfig) []SSHSetting {
	out := make([]SSHSetting, 0, len(sshSettingNames))
	for _, name := range sshSettingNames {
		p, ok := parsed.Settings[name]
		if !ok && name == "kbdinteractiveauthentication" {
			p, ok = parsed.Settings["challengeresponseauthentication"]
		}
		if ok {
			out = append(out, SSHSetting{Name: name, State: evidence.StateObserved, Value: normalizeSSHValue(p.Value), Source: p.Source, Confidence: evidence.ConfidenceMedium, Explicit: true})
		} else {
			out = append(out, SSHSetting{Name: name, State: evidence.StateUnavailable, Source: "static sshd configuration", Confidence: evidence.ConfidenceLow, Reason: "directive is not explicit and effective default is unavailable without sshd -T"})
		}
	}
	return out
}

func unavailableSSHSettings(reason string) []SSHSetting {
	out := make([]SSHSetting, 0, len(sshSettingNames))
	for _, name := range sshSettingNames {
		out = append(out, SSHSetting{Name: name, State: evidence.StateUnavailable, Source: "SSH configuration", Confidence: evidence.ConfidenceLow, Reason: reason})
	}
	return out
}

func algorithmsFromEffective(values map[string]string, source string) []SSHAlgorithmPosture {
	out := make([]SSHAlgorithmPosture, 0, len(sshAlgorithmNames))
	for _, name := range sshAlgorithmNames {
		value, ok := values[name]
		if !ok {
			out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateUnavailable, Source: source, Confidence: evidence.ConfidenceLow, Reason: "algorithm family not returned by sshd -T"})
			continue
		}
		vals := splitAlgorithmList(value)
		out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateObserved, Values: vals, Weak: weakSSHAlgorithms(name, vals), Source: source, Confidence: evidence.ConfidenceHigh})
	}
	return out
}

func algorithmsFromParsed(parsed sshParsedConfig) []SSHAlgorithmPosture {
	out := make([]SSHAlgorithmPosture, 0, len(sshAlgorithmNames))
	for _, name := range sshAlgorithmNames {
		p, ok := parsed.Settings[name]
		if !ok {
			out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateUnavailable, Source: "static sshd configuration", Confidence: evidence.ConfidenceLow, Reason: "directive is not explicit and effective default is unavailable without sshd -T"})
			continue
		}
		if usesRelativeAlgorithmList(p.Value) {
			out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateUnavailable, Source: p.Source, Confidence: evidence.ConfidenceLow, Explicit: true, Reason: "relative OpenSSH algorithm-list modifiers require sshd -T to resolve the effective policy"})
			continue
		}
		vals := splitAlgorithmList(p.Value)
		out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateObserved, Values: vals, Weak: weakSSHAlgorithms(name, vals), Source: p.Source, Confidence: evidence.ConfidenceMedium, Explicit: true})
	}
	return out
}

func unavailableSSHAlgorithms(reason string) []SSHAlgorithmPosture {
	out := make([]SSHAlgorithmPosture, 0, len(sshAlgorithmNames))
	for _, name := range sshAlgorithmNames {
		out = append(out, SSHAlgorithmPosture{Family: name, State: evidence.StateUnavailable, Source: "SSH configuration", Confidence: evidence.ConfidenceLow, Reason: reason})
	}
	return out
}

func usesRelativeAlgorithmList(v string) bool {
	for _, token := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		token = strings.TrimSpace(token)
		if token != "" && strings.ContainsRune("+-^", rune(token[0])) {
			return true
		}
	}
	return false
}

func splitAlgorithmList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		// OpenSSH list modifiers (+/-/^) are configuration syntax, not part of
		// the algorithm identifier itself. Keep the underlying name for weak-
		// algorithm classification when static parsing is the only source.
		f = strings.TrimLeft(f, "+-^")
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func weakSSHAlgorithms(family string, values []string) []string {
	weak := map[string]struct{}{}
	switch strings.ToLower(family) {
	case "ciphers":
		for _, v := range []string{"3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se"} {
			weak[v] = struct{}{}
		}
	case "macs":
		for _, v := range []string{"hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64@openssh.com", "umac-64-etm@openssh.com"} {
			weak[v] = struct{}{}
		}
	case "kexalgorithms":
		for _, v := range []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"} {
			weak[v] = struct{}{}
		}
	case "hostkeyalgorithms":
		for _, v := range []string{"ssh-dss", "ssh-rsa"} {
			weak[v] = struct{}{}
		}
	}
	out := []string{}
	for _, v := range values {
		if _, ok := weak[strings.ToLower(v)]; ok {
			out = append(out, strings.ToLower(v))
		}
	}
	sort.Strings(out)
	return out
}

func normalizeSSHValue(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeSSHSecurity(in SSHSecurity) SSHSecurity {
	sort.Slice(in.Settings, func(i, j int) bool { return in.Settings[i].Name < in.Settings[j].Name })
	sort.Slice(in.Files, func(i, j int) bool { return in.Files[i].Path < in.Files[j].Path })
	sort.Slice(in.Algorithms, func(i, j int) bool { return in.Algorithms[i].Family < in.Algorithms[j].Family })
	in.Degraded = uniqueStrings(in.Degraded)
	in.Summary = summarizeSSH(in)
	return in
}

func summarizeSSH(in SSHSecurity) SSHSecuritySummary {
	s := SSHSecuritySummary{Applicable: in.State != sshStateNotApplicable, Files: len(in.Files), AlgorithmFamilies: len(in.Algorithms)}
	for _, f := range in.Files {
		if f.State != evidence.StateObserved {
			s.FilesUnavailable++
		}
		if f.BroadlyWritable || (f.State == evidence.StateObserved && !f.TrustedOwner) {
			s.FilesWeak++
		}
	}
	for _, setting := range in.Settings {
		if setting.State == evidence.StateObserved {
			s.SettingsObserved++
		} else {
			s.SettingsUnavailable++
		}
	}
	for _, a := range in.Algorithms {
		s.WeakAlgorithms += len(a.Weak)
	}
	// MatchBlocks is set by the parser before this helper is called. Preserve
	// the existing count if present in the input summary.
	s.MatchBlocks = in.Summary.MatchBlocks
	return s
}

func sshFileID(path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return "sshf-" + hex.EncodeToString(sum[:8])
}

func validateSSHSecurity(s SSHSecurity) error {
	if s.Schema != sshSecuritySchemaVersion {
		return fmt.Errorf("unexpected SSH security schema %q", s.Schema)
	}
	switch s.State {
	case sshStateComplete, sshStateDegraded, sshStateNotApplicable:
	default:
		return fmt.Errorf("invalid SSH security state %q", s.State)
	}
	if s.State == sshStateNotApplicable {
		return nil
	}
	last := ""
	for i, setting := range s.Settings {
		if setting.Name == "" || setting.State == "" || setting.Source == "" || setting.Confidence == "" {
			return fmt.Errorf("SSH setting %d is incomplete", i)
		}
		if setting.State != evidence.StateObserved && strings.TrimSpace(setting.Reason) == "" {
			return fmt.Errorf("SSH setting %q requires degradation reason", setting.Name)
		}
		if last != "" && setting.Name < last {
			return fmt.Errorf("SSH settings are not deterministically ordered")
		}
		last = setting.Name
	}
	last = ""
	for i, file := range s.Files {
		if file.ID == "" || file.Path == "" || file.State == "" || file.Source == "" || file.PermissionBasis == "" || file.Confidence == "" {
			return fmt.Errorf("SSH file posture %d is incomplete", i)
		}
		if file.State != evidence.StateObserved && strings.TrimSpace(file.Reason) == "" {
			return fmt.Errorf("SSH file posture %q requires degradation reason", file.Path)
		}
		if last != "" && file.Path < last {
			return fmt.Errorf("SSH file posture is not deterministically ordered")
		}
		last = file.Path
	}
	last = ""
	for i, a := range s.Algorithms {
		if a.Family == "" || a.State == "" || a.Source == "" || a.Confidence == "" {
			return fmt.Errorf("SSH algorithm posture %d is incomplete", i)
		}
		if a.State != evidence.StateObserved && strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("SSH algorithm posture %q requires degradation reason", a.Family)
		}
		if last != "" && a.Family < last {
			return fmt.Errorf("SSH algorithm posture is not deterministically ordered")
		}
		last = a.Family
	}
	return nil
}

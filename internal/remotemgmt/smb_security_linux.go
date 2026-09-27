//go:build linux

package remotemgmt

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

type smbParsedValue struct {
	Value  string
	Source string
}

type smbParsedConfig struct {
	Sections map[string]map[string]smbParsedValue
	Files    []string
	Degraded []string
}

func collectPlatformSMBSecurity(ctx context.Context) smbPlatformResult {
	result := smbPlatformResult{ShareInventoryState: evidence.StateUnavailable, ShareInventorySource: "local Samba configuration"}
	configPath := firstExistingPath([]string{"/etc/samba/smb.conf", "/usr/local/etc/smb4.conf", "/usr/local/etc/smb.conf"})
	daemon := firstExecutable([]string{"smbd", "/usr/sbin/smbd", "/usr/local/sbin/smbd"})
	testparm := firstExecutable([]string{"testparm", "/usr/bin/testparm", "/usr/local/bin/testparm"})
	if configPath == "" && daemon == "" {
		return result
	}
	result.Detected = true

	var parsed smbParsedConfig
	usedEffective := false
	if testparm != "" && configPath != "" {
		if b, err := exec.CommandContext(ctx, testparm, "-s", "--suppress-prompt", configPath).Output(); err == nil {
			parsed = parseSambaText(string(b), testparm+" -s --suppress-prompt "+configPath)
			result.EvaluationSource = testparm + " -s --suppress-prompt " + configPath
			usedEffective = true
		} else {
			result.Degraded = append(result.Degraded, "testparm effective Samba configuration unavailable: "+err.Error())
		}
	}
	if !usedEffective && configPath != "" {
		parsed = parseSambaConfig(configPath)
		result.EvaluationSource = "static Samba configuration parsing: " + configPath
		result.Degraded = append(result.Degraded, parsed.Degraded...)
	}
	if configPath == "" {
		result.EvaluationSource = "Samba service detected; smb.conf unavailable in standard local locations"
		result.Degraded = append(result.Degraded, "Samba service is present but smb.conf was not found in standard local locations")
	}

	if len(parsed.Sections) > 0 {
		result.Settings = sambaSettings(parsed, usedEffective)
		result.Shares = sambaShares(parsed, result.EvaluationSource)
		result.ShareInventoryState = evidence.StateObserved
		result.ShareInventorySource = result.EvaluationSource
	} else {
		result.Settings = unavailableSMBSettingsLinux("Samba configuration could not be resolved")
		result.ShareInventoryState = evidence.StateUnavailable
		result.ShareInventoryReason = "Samba share definitions could not be resolved from local configuration"
	}
	return result
}

func firstExecutable(candidates []string) string {
	for _, c := range candidates {
		if strings.ContainsRune(c, os.PathSeparator) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

func parseSambaConfig(root string) smbParsedConfig {
	result := smbParsedConfig{Sections: map[string]map[string]smbParsedValue{}}
	seen := map[string]struct{}{}
	var walk func(string, int)
	walk = func(path string, depth int) {
		if depth > 16 {
			result.Degraded = append(result.Degraded, "Samba include recursion limit reached at "+path)
			return
		}
		abs, err := filepath.Abs(path)
		if err == nil {
			path = abs
		}
		if _, ok := seen[path]; ok {
			return
		}
		if len(seen) >= 128 {
			result.Degraded = append(result.Degraded, "Samba configuration file limit reached while expanding includes")
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
		section := "global"
		ensureSMBSection(result.Sections, section)
		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(stripSambaComment(scanner.Text()))
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
				end := strings.Index(line, "]")
				name := strings.TrimSpace(line[1:end])
				if name != "" {
					section = strings.ToLower(name)
					ensureSMBSection(result.Sections, section)
				}
				continue
			}
			key, value, ok := splitSambaDirective(line)
			if !ok {
				continue
			}
			lk := canonicalSambaKey(key)
			if lk == "include" {
				pattern := strings.TrimSpace(strings.Trim(value, `"'`))
				if strings.Contains(pattern, "%") {
					result.Degraded = append(result.Degraded, fmt.Sprintf("dynamic Samba include cannot be expanded safely: %s:%d", path, lineNo))
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
				continue
			}
			result.Sections[section][lk] = smbParsedValue{Value: strings.TrimSpace(value), Source: fmt.Sprintf("%s:%d", path, lineNo)}
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

func parseSambaText(text, source string) smbParsedConfig {
	result := smbParsedConfig{Sections: map[string]map[string]smbParsedValue{}}
	section := "global"
	ensureSMBSection(result.Sections, section)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(stripSambaComment(scanner.Text()))
		if line == "" || strings.HasPrefix(strings.ToLower(line), "loaded services file") || strings.HasPrefix(strings.ToLower(line), "server role:") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			end := strings.Index(line, "]")
			name := strings.TrimSpace(line[1:end])
			if name != "" {
				section = strings.ToLower(name)
				ensureSMBSection(result.Sections, section)
			}
			continue
		}
		key, value, ok := splitSambaDirective(line)
		if !ok {
			continue
		}
		result.Sections[section][canonicalSambaKey(key)] = smbParsedValue{Value: strings.TrimSpace(value), Source: source}
	}
	if err := scanner.Err(); err != nil {
		result.Degraded = append(result.Degraded, err.Error())
	}
	return result
}

func ensureSMBSection(m map[string]map[string]smbParsedValue, section string) {
	if m[section] == nil {
		m[section] = map[string]smbParsedValue{}
	}
}

func stripSambaComment(line string) string {
	inSingle, inDouble := false, false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#', ';':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func splitSambaDirective(line string) (string, string, bool) {
	if i := strings.Index(line, "="); i >= 0 {
		key := strings.TrimSpace(line[:i])
		if key == "" {
			return "", "", false
		}
		return key, strings.TrimSpace(line[i+1:]), true
	}
	return "", "", false
}

func canonicalSambaKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Join(strings.Fields(s), " ")
	switch s {
	case "min protocol":
		return "server min protocol"
	case "max protocol":
		return "server max protocol"
	case "public":
		return "guest ok"
	case "writeable":
		return "writable"
	}
	return s
}

func sambaSettings(parsed smbParsedConfig, effective bool) []SMBSetting {
	global := parsed.Sections["global"]
	defs := []struct{ name, key string }{
		{"min_protocol", "server min protocol"},
		{"max_protocol", "server max protocol"},
		{"signing", "server signing"},
		{"encryption", "smb encrypt"},
		{"map_to_guest", "map to guest"},
		{"restrict_anonymous", "restrict anonymous"},
		{"wide_links", "wide links"},
	}
	out := make([]SMBSetting, 0, len(defs))
	for _, d := range defs {
		if v, ok := global[d.key]; ok {
			out = append(out, SMBSetting{Name: d.name, Scope: "server", State: evidence.StateObserved, Value: strings.TrimSpace(v.Value), Source: v.Source, Confidence: evidence.ConfidenceHigh, Explicit: !effective})
			continue
		}
		reason := "setting not explicitly present in local smb.conf"
		conf := evidence.ConfidenceLow
		if effective {
			reason = "effective testparm output did not expose this setting"
			conf = evidence.ConfidenceMedium
		}
		out = append(out, SMBSetting{Name: d.name, Scope: "server", State: evidence.StateUnavailable, Source: "local Samba configuration", Confidence: conf, Reason: reason})
	}
	return out
}

func unavailableSMBSettingsLinux(reason string) []SMBSetting {
	names := []string{"min_protocol", "max_protocol", "signing", "encryption", "map_to_guest", "restrict_anonymous", "wide_links"}
	out := make([]SMBSetting, 0, len(names))
	for _, name := range names {
		out = append(out, SMBSetting{Name: name, Scope: "server", State: evidence.StateUnavailable, Source: "local Samba configuration", Confidence: evidence.ConfidenceLow, Reason: reason})
	}
	return out
}

func sambaShares(parsed smbParsedConfig, source string) []SMBShare {
	global := parsed.Sections["global"]
	globalEncrypt := sambaValue(global, "smb encrypt")
	names := make([]string, 0, len(parsed.Sections))
	for name := range parsed.Sections {
		if name == "global" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]SMBShare, 0, len(names))
	for _, name := range names {
		sec := parsed.Sections[name]
		path := sambaValue(sec, "path")
		guest := sambaBool(firstNonEmpty(sambaValue(sec, "guest ok"), "no"))
		readOnlyRaw := sambaValue(sec, "read only")
		writableRaw := sambaValue(sec, "writable")
		writable, writableKnown := false, false
		if readOnlyRaw != "" {
			writable = !sambaBool(readOnlyRaw)
			writableKnown = true
		} else if writableRaw != "" {
			writable = sambaBool(writableRaw)
			writableKnown = true
		}
		encrypt := firstNonEmpty(sambaValue(sec, "smb encrypt"), globalEncrypt)
		requiredEncrypt := sambaEncryptionRequired(encrypt)
		special := name == "printers" || name == "print$" || name == "ipc$"
		hidden := strings.HasSuffix(name, "$")
		tags := []string{}
		if guest {
			tags = append(tags, "guest-access")
		}
		if guest && writableKnown && writable {
			tags = append(tags, "guest-writable")
		}
		sensitive := smbSensitivePath(path)
		if sensitive && !special {
			tags = append(tags, "sensitive-path")
		}
		if strings.EqualFold(sambaValue(sec, "wide links"), "yes") || strings.EqualFold(sambaValue(sec, "wide links"), "true") {
			tags = append(tags, "wide-links-enabled")
		}
		sh := SMBShare{
			Name: name, Path: path, State: evidence.StateObserved, Special: special, Hidden: hidden,
			GuestAllowed: guest, Writable: writable, WritableKnown: writableKnown,
			EncryptionRequired: requiredEncrypt, BroadRead: guest, BroadWrite: guest && writableKnown && writable, AccessKnown: true,
			SensitivePath: sensitive, RiskTags: tags, Source: source, Confidence: evidence.ConfidenceHigh,
		}
		sh.ID = smbShareID(sh.Name, sh.Path)
		out = append(out, sh)
	}
	return out
}

func sambaValue(m map[string]smbParsedValue, key string) string {
	if v, ok := m[canonicalSambaKey(key)]; ok {
		return strings.TrimSpace(v.Value)
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func sambaBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return true
	default:
		return false
	}
}

func sambaEncryptionRequired(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "required", "mandatory", "yes":
		return true
	default:
		return false
	}
}

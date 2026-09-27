package filesystem

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func parseLinuxNFSExports(text, source string) []NetworkShareRecord {
	out := []NetworkShareRecord{}
	for _, line := range exportLogicalLines(text) {
		fields := exportFields(stripExportComment(line))
		if len(fields) < 2 {
			continue
		}
		path := unescapeExportField(fields[0])
		if strings.TrimSpace(path) == "" {
			continue
		}
		globalOpts := []string{}
		for _, token := range fields[1:] {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if strings.HasPrefix(token, "-") {
				globalOpts = append(globalOpts, splitExportOptions(strings.TrimPrefix(token, "-"))...)
				continue
			}
			client, opts := parseLinuxExportClient(token)
			if client == "" {
				continue
			}
			allOpts := append(append([]string{}, globalOpts...), opts...)
			out = append(out, newNFSExportRecord(path, client, allOpts, source))
		}
	}
	return out
}

func parseDarwinNFSExports(text, source string) []NetworkShareRecord {
	out := []NetworkShareRecord{}
	for _, line := range exportLogicalLines(text) {
		fields := exportFields(stripExportComment(line))
		if len(fields) < 2 {
			continue
		}
		path := unescapeExportField(fields[0])
		if strings.TrimSpace(path) == "" {
			continue
		}
		opts := []string{}
		clients := []string{}
		network := ""
		mask := ""
		for i := 1; i < len(fields); i++ {
			token := strings.TrimSpace(fields[i])
			if token == "" {
				continue
			}
			lower := strings.ToLower(token)
			if lower == "-network" && i+1 < len(fields) {
				i++
				network = strings.TrimSpace(fields[i])
				opts = append(opts, "network="+network)
				continue
			}
			if lower == "-mask" && i+1 < len(fields) {
				i++
				mask = strings.TrimSpace(fields[i])
				opts = append(opts, "mask="+mask)
				continue
			}
			if lower == "-maproot" || lower == "-mapall" {
				if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") {
					i++
					opts = append(opts, strings.TrimPrefix(lower, "-")+"="+strings.TrimSpace(fields[i]))
				} else {
					opts = append(opts, strings.TrimPrefix(lower, "-"))
				}
				continue
			}
			if strings.HasPrefix(token, "-") {
				opts = append(opts, splitExportOptions(strings.TrimPrefix(token, "-"))...)
				continue
			}
			clients = append(clients, token)
		}
		if network != "" {
			remote := network
			if mask != "" {
				remote += "/mask=" + mask
			}
			out = append(out, newNFSExportRecord(path, remote, opts, source))
		}
		for _, client := range clients {
			out = append(out, newNFSExportRecord(path, client, opts, source))
		}
	}
	return out
}

func newNFSExportRecord(path, client string, options []string, source string) NetworkShareRecord {
	security, dangerous, anonymous := nfsExportSecurityOptions(options)
	accessMode := MountAccessUnknown
	if containsStringFold(options, "ro") {
		accessMode = MountAccessReadOnly
	} else if containsStringFold(options, "rw") {
		accessMode = MountAccessReadWrite
	}
	broad := broadNFSAudience(client) || broadDarwinNetwork(client)
	sh := NetworkShareRecord{
		Direction:        NetworkShareDirectionExported,
		Protocol:         NetworkShareProtocolNFS,
		LocalPath:        path,
		Remote:           strings.TrimSpace(client),
		SecurityOptions:  security,
		AccessMode:       accessMode,
		ReadOnly:         accessMode == MountAccessReadOnly,
		Writable:         accessMode == MountAccessReadWrite,
		AccessKnown:      accessMode != MountAccessUnknown,
		AnonymousAllowed: anonymous,
		BroadAccess:      broad,
		BroadWrite:       broad && accessMode == MountAccessReadWrite,
		DangerousOptions: dangerous,
		State:            evidence.StateObserved,
		CollectionSource: source,
		Confidence:       evidence.ConfidenceHigh,
	}
	sh.ID = stableNetworkShareID(sh)
	return sh
}

func nfsExportSecurityOptions(options []string) (safe, dangerous []string, anonymous bool) {
	for _, raw := range options {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value := splitOption(strings.ToLower(strings.TrimPrefix(raw, "-")))
		switch name {
		case "ro", "rw", "root_squash", "no_root_squash", "all_squash", "insecure", "secure", "sec", "anonuid", "anongid", "maproot", "mapall", "network", "mask":
			if value == "" {
				safe = append(safe, name)
			} else {
				safe = append(safe, name+"="+sanitizeNetworkOptionValue(value))
			}
		}
		switch name {
		case "no_root_squash":
			dangerous = append(dangerous, "no_root_squash")
		case "insecure":
			dangerous = append(dangerous, "insecure-client-port")
		case "anonuid":
			if strings.TrimSpace(value) == "0" {
				dangerous = append(dangerous, "anonymous-uid-0")
			}
		case "anongid":
			if strings.TrimSpace(value) == "0" {
				dangerous = append(dangerous, "anonymous-gid-0")
			}
		case "sec":
			if strings.EqualFold(strings.TrimSpace(value), "none") {
				anonymous = true
				dangerous = append(dangerous, "sec=none")
			}
		case "maproot", "mapall":
			v := strings.ToLower(strings.TrimSpace(value))
			if v == "root" || strings.HasPrefix(v, "root:") || v == "0" || strings.HasPrefix(v, "0:") {
				dangerous = append(dangerous, name+"-to-root")
			}
		}
	}
	return uniqueSorted(safe), uniqueSorted(dangerous), anonymous
}

func parseLinuxExportClient(token string) (string, []string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil
	}
	if open := strings.Index(token, "("); open >= 0 && strings.HasSuffix(token, ")") {
		client := strings.TrimSpace(token[:open])
		return client, splitExportOptions(token[open+1 : len(token)-1])
	}
	return token, nil
}

func splitExportOptions(v string) []string {
	out := []string{}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(strings.TrimPrefix(item, "-"))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func exportLogicalLines(text string) []string {
	physical := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := []string{}
	current := ""
	for _, line := range physical {
		trimmed := strings.TrimRight(line, " \t")
		continued := strings.HasSuffix(trimmed, `\`)
		if continued {
			trimmed = strings.TrimSuffix(trimmed, `\`)
		}
		if current == "" {
			current = trimmed
		} else {
			current += " " + strings.TrimSpace(trimmed)
		}
		if !continued {
			out = append(out, current)
			current = ""
		}
	}
	if strings.TrimSpace(current) != "" {
		out = append(out, current)
	}
	return out
}

func stripExportComment(line string) string {
	quoted := rune(0)
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quoted != 0 {
			if r == quoted {
				quoted = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quoted = r
			continue
		}
		if r == '#' {
			return line[:i]
		}
	}
	return line
}

func exportFields(line string) []string {
	out := []string{}
	var b strings.Builder
	quoted := rune(0)
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range strings.TrimSpace(line) {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quoted != 0 {
			if r == quoted {
				quoted = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quoted = r
			continue
		}
		if r == ' ' || r == '\t' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	flush()
	return out
}

func unescapeExportField(v string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(v)
}

func broadDarwinNetwork(client string) bool {
	v := strings.ToLower(strings.TrimSpace(client))
	if v == "0.0.0.0" || v == "0" || v == "::" {
		return true
	}
	if strings.Contains(v, "/mask=0.0.0.0") || strings.Contains(v, "/mask=0") {
		return true
	}
	return false
}

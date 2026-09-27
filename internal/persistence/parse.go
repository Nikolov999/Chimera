package persistence

import "strings"

// firstCommandToken extracts only the executable token and whether additional
// command material was present. Argument values are intentionally discarded so
// Run keys, desktop entries, and similar persistence metadata cannot leak
// credentials or tokens embedded in command lines.
func firstCommandToken(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, `"`) {
		rest := s[1:]
		if end := strings.Index(rest, `"`); end >= 0 {
			exe := strings.TrimSpace(rest[:end])
			tail := strings.TrimSpace(rest[end+1:])
			return exe, tail != ""
		}
	}
	// Windows Run values are frequently unquoted even when an absolute executable
	// path contains spaces. Only apply suffix recovery when the command itself
	// starts like an absolute/environment-expanded path; otherwise a later
	// script argument such as "powershell -File C:\\x.ps1" must not be
	// mistaken for the executable or copied into output.
	lower := strings.ToLower(s)
	windowsPathLike := (len(s) >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) || strings.HasPrefix(s, `%`) || strings.HasPrefix(s, `\\`)
	if windowsPathLike {
		for _, ext := range []string{".exe", ".com", ".bat", ".cmd", ".ps1"} {
			if i := strings.Index(lower, ext); i >= 0 {
				end := i + len(ext)
				exe := strings.Trim(strings.TrimSpace(s[:end]), `"'`)
				tail := strings.TrimSpace(s[end:])
				return exe, tail != ""
			}
		}
	}
	// Preserve environment-variable and path tokens as observed; do not expand
	// them because expansion may depend on a different user/session context.
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", false
	}
	return strings.Trim(fields[0], `"'`), len(fields) > 1
}

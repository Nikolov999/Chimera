package filesystem

import "strings"

// splitWindowsTempPathValue repairs malformed Windows temporary-directory
// environment values without splitting legitimate spaces inside a path. Some
// hosts expose multiple absolute paths in one TEMP/TMP value separated by
// whitespace instead of ';'. A new token is started only at another absolute
// drive-root (for example " C:\\") or at a semicolon/newline boundary.
func splitWindowsTempPathValue(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.NewReplacer("\r", ";", "\n", ";", "\t", ";").Replace(raw)
	var out []string
	for _, chunk := range strings.Split(raw, ";") {
		out = append(out, splitRepeatedWindowsDriveRoots(chunk)...)
	}
	return uniqueSorted(out)
}

func splitRepeatedWindowsDriveRoots(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	roots := make([]int, 0, 2)
	for i := 0; i+2 < len(raw); i++ {
		c := raw[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) || raw[i+1] != ':' || (raw[i+2] != '\\' && raw[i+2] != '/') {
			continue
		}
		if i == 0 || isWindowsTempBoundary(raw[i-1]) {
			roots = append(roots, i)
		}
	}
	if len(roots) == 0 {
		if token := trimWindowsTempToken(raw); token != "" {
			return []string{token}
		}
		return nil
	}
	out := make([]string, 0, len(roots))
	for i, start := range roots {
		end := len(raw)
		if i+1 < len(roots) {
			end = roots[i+1]
		}
		if token := trimWindowsTempToken(raw[start:end]); token != "" {
			out = append(out, token)
		}
	}
	return out
}

func isWindowsTempBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'':
		return true
	default:
		return false
	}
}

func trimWindowsTempToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	return strings.TrimSpace(s)
}

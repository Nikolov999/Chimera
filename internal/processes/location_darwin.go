//go:build darwin

package processes

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func platformLocationHints(path string) locationHints {
	p := strings.ToLower(cleanLocationPath(path))
	h := locationHints{Confidence: evidence.ConfidenceHigh}
	if hasDarwinPrefix(p, "/tmp") || hasDarwinPrefix(p, "/private/tmp") || hasDarwinPrefix(p, "/private/var/folders") {
		h.Temporary = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "macOS temporary/per-user cache execution root")
	}
	if strings.Contains(p, "/downloads/") || strings.HasSuffix(p, "/downloads") {
		h.Downloads = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "macOS user Downloads execution path")
	}
	if hasDarwinPrefix(p, "/users") {
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "macOS per-user home execution path")
	}
	if hasDarwinPrefix(p, "/volumes") {
		h.Removable = true
		h.WeakControl = true
		h.Confidence = evidence.ConfidenceMedium
		h.Reasons = append(h.Reasons, "macOS mounted-volume execution path; pathname alone cannot prove physical removability")
	}
	return h
}

func hasDarwinPrefix(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

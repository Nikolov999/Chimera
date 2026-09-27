//go:build linux

package processes

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func platformLocationHints(path string) locationHints {
	p := strings.ToLower(cleanLocationPath(path))
	h := locationHints{Confidence: evidence.ConfidenceHigh}
	switch {
	case hasPathPrefix(p, "/tmp"), hasPathPrefix(p, "/var/tmp"), hasPathPrefix(p, "/dev/shm"), hasPathPrefix(p, "/run/user"):
		h.Temporary = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Linux temporary/runtime user-writable execution root")
	}
	if strings.Contains(p, "/downloads/") || strings.HasSuffix(p, "/downloads") {
		h.Downloads = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Linux user Downloads execution path")
	}
	if hasPathPrefix(p, "/home") {
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Linux per-user home execution path")
	}
	if hasPathPrefix(p, "/media") || hasPathPrefix(p, "/run/media") {
		h.Removable = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Linux removable-media convention path")
	} else if hasPathPrefix(p, "/mnt") {
		h.WeakControl = true
		h.Confidence = evidence.ConfidenceMedium
		h.Reasons = append(h.Reasons, "Linux administrator mount-point path; backing type is not proven by pathname alone")
	}
	return h
}

func hasPathPrefix(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

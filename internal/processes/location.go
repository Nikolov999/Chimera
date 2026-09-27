package processes

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// LocationContext is additive evidence describing only the execution
// location of an already-observed process. It does not replace or mutate the
// chimera.processes/v1 process record.
type LocationContext struct {
	ProcessID      string              `json:"process_id"`
	Platform       string              `json:"platform"`
	PID            int                 `json:"pid"`
	Path           string              `json:"path"`
	State          string              `json:"state"`
	Temporary      bool                `json:"temporary"`
	Downloads      bool                `json:"downloads"`
	UserWritable   bool                `json:"user_writable"`
	Removable      bool                `json:"removable"`
	NetworkBacked  bool                `json:"network_backed"`
	DeletedBacking bool                `json:"deleted_backing"`
	WeakControl    bool                `json:"weak_control"`
	Reasons        []string            `json:"reasons,omitempty"`
	Source         string              `json:"source"`
	Confidence     evidence.Confidence `json:"confidence"`
}

func classifyExecutionLocation(p Process, platform string) LocationContext {
	c := LocationContext{
		ProcessID:  p.ID,
		PID:        p.PID,
		Platform:   platform,
		Path:       strings.TrimSpace(p.ExecutablePath),
		State:      "UNKNOWN",
		Source:     "local executable-path classification",
		Confidence: evidence.ConfidenceMedium,
	}
	if p.Trust.DeletedBacking {
		c.DeletedBacking = true
		c.WeakControl = true
		c.Reasons = append(c.Reasons, "executable backing is marked deleted while the process remains live")
	}
	if c.Path == "" {
		if c.DeletedBacking {
			c.State = "WEAK"
			c.Confidence = evidence.ConfidenceHigh
		} else {
			c.Reasons = append(c.Reasons, "executable path unavailable")
			c.Confidence = evidence.ConfidenceLow
		}
		return c
	}

	hints := platformLocationHints(c.Path)
	c.Temporary = hints.Temporary
	c.Downloads = hints.Downloads
	c.UserWritable = hints.UserWritable
	c.Removable = hints.Removable
	c.NetworkBacked = hints.NetworkBacked
	c.WeakControl = c.WeakControl || hints.WeakControl
	c.Reasons = append(c.Reasons, hints.Reasons...)
	c.Confidence = lowerConfidence(c.Confidence, hints.Confidence)

	// Trust state from earlier phases is valid evidence that can strengthen a
	// location classification without turning into ACL
	// analysis. Detailed file/directory permission evaluation is provided by .
	switch strings.ToUpper(strings.TrimSpace(p.Trust.State)) {
	case "TEMPORARY_PATH":
		c.Temporary = true
		c.UserWritable = true
		c.WeakControl = true
		c.Reasons = append(c.Reasons, "existing process trust metadata identifies a temporary execution path")
		c.Confidence = higherConfidence(c.Confidence, evidence.ConfidenceHigh)
	case "DELETED_BACKING":
		c.DeletedBacking = true
		c.WeakControl = true
		c.Reasons = append(c.Reasons, "existing process trust metadata identifies deleted executable backing")
		c.Confidence = higherConfidence(c.Confidence, evidence.ConfidenceHigh)
	}

	c.Reasons = uniqueStrings(c.Reasons)
	switch {
	case c.DeletedBacking || c.Temporary || c.Downloads || c.UserWritable || c.Removable || c.NetworkBacked || c.WeakControl:
		c.State = "WEAK"
	default:
		c.State = "NORMAL"
	}
	return c
}

type locationHints struct {
	Temporary     bool
	Downloads     bool
	UserWritable  bool
	Removable     bool
	NetworkBacked bool
	WeakControl   bool
	Reasons       []string
	Confidence    evidence.Confidence
}

func cleanLocationPath(path string) string {
	p := filepath.Clean(strings.TrimSpace(path))
	return strings.ReplaceAll(p, `\\`, `/`)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func lowerConfidence(a, b evidence.Confidence) evidence.Confidence {
	if b == "" {
		return a
	}
	if confidenceRank(b) < confidenceRank(a) {
		return b
	}
	return a
}

func higherConfidence(a, b evidence.Confidence) evidence.Confidence {
	if confidenceRank(b) > confidenceRank(a) {
		return b
	}
	return a
}

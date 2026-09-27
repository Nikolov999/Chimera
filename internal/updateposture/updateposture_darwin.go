//go:build darwin

package updateposture

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type macPayload map[string]any

func collectPlatform(ctx context.Context, r *Result) {
	path := "/Library/Preferences/com.apple.SoftwareUpdate.plist"
	st, statErr := os.Stat(path)
	if statErr != nil {
		addProvider(r, "macos-softwareupdate", evidence.StateUnavailable, "local com.apple.SoftwareUpdate preferences", 0, 0, time.Time{}, FreshnessUnknown, statErr.Error())
		return
	}
	if !commandAvailable("plutil") {
		addProvider(r, "macos-softwareupdate", evidence.StateUnavailable, "local com.apple.SoftwareUpdate preferences", 0, 0, st.ModTime().UTC(), freshness(st.ModTime(), r.CollectedAt), "plutil is unavailable")
		return
	}
	text, err := run(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		addProvider(r, "macos-softwareupdate", stateForError(ctx, err), "local com.apple.SoftwareUpdate preferences", 0, 0, st.ModTime().UTC(), freshness(st.ModTime(), r.CollectedAt), err.Error())
		return
	}
	var p macPayload
	if json.Unmarshal([]byte(text), &p) != nil {
		addProvider(r, "macos-softwareupdate", evidence.StateDegraded, "local com.apple.SoftwareUpdate preferences", 0, 0, st.ModTime().UTC(), freshness(st.ModTime(), r.CollectedAt), "could not parse local SoftwareUpdate plist")
		return
	}
	start := len(r.Updates)
	sec := 0
	if arr, ok := p["RecommendedUpdates"].([]any); ok {
		for _, raw := range arr {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := firstString(m, "Display Name", "DisplayName", "Product Key", "ProductKey")
			ver := firstString(m, "Display Version", "DisplayVersion", "Version")
			if name == "" {
				continue
			}
			cls := ClassificationUnknown
			reason := "macOS local SoftwareUpdate cache lists this update as recommended"
			low := strings.ToLower(name)
			if strings.Contains(low, "security update") || strings.Contains(low, "rapid security response") {
				cls = ClassificationSecurity
				sec++
				reason = "macOS local SoftwareUpdate cache explicitly labels this as a security update"
			}
			r.Updates = append(r.Updates, Update{Product: name, PackageID: firstNonempty(firstString(m, "Product Key", "ProductKey"), name), CandidateVersion: ver, Classification: cls, Source: "com.apple.SoftwareUpdate RecommendedUpdates cache", Confidence: evidence.ConfidenceHigh, Reason: reason})
		}
	}
	addProvider(r, "macos-softwareupdate", evidence.StateObserved, "local com.apple.SoftwareUpdate preferences", len(r.Updates)-start, sec, st.ModTime().UTC(), freshness(st.ModTime(), r.CollectedAt), "recommended updates reflect the last local SoftwareUpdate metadata refresh; Chimera does not run softwareupdate --list or contact Apple")
	r.Limitations = append(r.Limitations, "macOS pending-update results reflect cached RecommendedUpdates only; ordinary Chimera scans never contact Apple Software Update")
}
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func firstNonempty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "UNKNOWN"
}

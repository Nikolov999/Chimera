//go:build darwin

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectMacOSLoginItems(ctx, inv)
}

func collectMacOSLoginItems(ctx context.Context, inv *Inventory) {
	profiler, err := exec.LookPath("system_profiler")
	if err != nil {
		addSource(inv, "macos-login-items", evidence.StateUnavailable, "system_profiler SPLoginItemDataType", 0, "system_profiler was not found")
		return
	}
	raw, err := exec.CommandContext(ctx, profiler, "SPLoginItemDataType", "-json", "-detailLevel", "mini").Output()
	if err != nil {
		if ctx.Err() != nil {
			addSource(inv, "macos-login-items", evidence.StateUnavailable, "system_profiler SPLoginItemDataType", 0, ctx.Err().Error())
		} else {
			addSource(inv, "macos-login-items", evidence.StateUnavailable, "system_profiler SPLoginItemDataType", 0, err.Error())
		}
		return
	}
	items, err := parseMacOSLoginItems(raw)
	if err != nil {
		addSource(inv, "macos-login-items", evidence.StateUnavailable, "system_profiler SPLoginItemDataType", 0, err.Error())
		return
	}
	inv.Entries = append(inv.Entries, items...)
	addSource(inv, "macos-login-items", evidence.StateObserved, "system_profiler SPLoginItemDataType", len(items), "")
}

func parseMacOSLoginItems(raw []byte) ([]Entry, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse login-item metadata: %w", err)
	}
	out := []Entry{}
	var walk func(any)
	walk = func(node any) {
		switch x := node.(type) {
		case []any:
			for _, child := range x {
				walk(child)
			}
		case map[string]any:
			name := firstMapString(x, "_name", "name", "Name")
			path := firstMapString(x, "path", "Path", "location", "Location")
			if name != "" && path != "" {
				out = append(out, Entry{
					Name: name, Mechanism: "LOGIN_ITEM", Manager: "loginwindow", Scope: "USER",
					EnabledState: "ENABLED", RuntimeState: "NOT_ASSESSED", Account: "CURRENT_USER", PrivilegeContext: "USER",
					ExecutablePath: cleanPath(path), DefinitionPath: cleanPath(path), ConfigurationSource: "macOS login-item metadata",
					CollectionSource: "system_profiler SPLoginItemDataType", Confidence: evidence.ConfidenceHigh,
				})
			}
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	// system_profiler can expose the same record through nested summary/detail
	// nodes. normalizeEntries performs stable-ID deduplication later.
	return out, nil
}

func firstMapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

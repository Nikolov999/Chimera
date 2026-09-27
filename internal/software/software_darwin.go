//go:build darwin

package software

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type macApplication struct {
	Name     string   `json:"_name"`
	Version  string   `json:"version"`
	Path     string   `json:"path"`
	Arch     string   `json:"arch_kind"`
	Obtained string   `json:"obtained_from"`
	SignedBy []string `json:"signed_by"`
}

type macApplicationsPayload struct {
	Applications []macApplication `json:"SPApplicationsDataType"`
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	if !commandAvailable("system_profiler") {
		addSource(inv, "macos-applications", evidence.StateUnavailable, "system_profiler SPApplicationsDataType", 0, "system_profiler is unavailable")
		return
	}
	text, err := run(ctx, "system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		state := evidence.StateDegraded
		if ctx.Err() != nil {
			state = evidence.StateDegraded
		}
		addSource(inv, "macos-applications", state, "system_profiler SPApplicationsDataType", 0, err.Error())
		return
	}
	var payload macApplicationsPayload
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		addSource(inv, "macos-applications", evidence.StateDegraded, "system_profiler SPApplicationsDataType", 0, "parse provider output: "+err.Error())
		return
	}
	start := len(inv.Items)
	for _, a := range payload.Applications {
		if strings.TrimSpace(a.Name) == "" {
			continue
		}
		vendor := "UNKNOWN"
		if len(a.SignedBy) > 0 && strings.TrimSpace(a.SignedBy[0]) != "" {
			vendor = a.SignedBy[0]
		}
		source := "macos-application-bundle"
		if strings.TrimSpace(a.Obtained) != "" {
			source += ":" + a.Obtained
		}
		inv.Items = append(inv.Items, Item{Kind: "application", Product: a.Name, PackageID: a.Name, Version: a.Version, Architecture: normalizeMacArch(a.Arch), Vendor: vendor, PackageSource: source, InstallPath: a.Path, SupportState: "UNKNOWN", SupportReason: "application lifecycle intelligence is introduced in ", CollectionSource: "system_profiler SPApplicationsDataType", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "macos-applications", evidence.StateObserved, "system_profiler SPApplicationsDataType", len(inv.Items)-start, "")
}

func normalizeMacArch(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "arch_arm_i64", "arm64":
		return "arm64"
	case "arch_i64", "x86_64":
		return "amd64"
	case "arch_i32", "i386":
		return "386"
	case "arch_universal", "universal":
		return "universal"
	default:
		return normalizedOr(v, "UNKNOWN")
	}
}

package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion     = "chimera.software/v5"
	CollectorName     = "software"
	CollectorVersion  = "software/v5"
	maxInventoryItems = 50000
)

// Item is the normalized installed-software record. Unknown fields
// remain explicit instead of being guessed from product names or paths.
type Item struct {
	ID               string              `json:"id"`
	Kind             string              `json:"kind"`
	Product          string              `json:"product"`
	PackageID        string              `json:"package_id"`
	Version          string              `json:"version"`
	Architecture     string              `json:"architecture"`
	Vendor           string              `json:"vendor"`
	PackageSource    string              `json:"package_source"`
	InstallPath      string              `json:"install_path"`
	SupportState     string              `json:"support_state"`
	SupportReason    string              `json:"support_reason"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

// SourceStatus records which native inventory providers participated and
// whether their output was usable. Optional providers that are not installed
// are simply not attempted and therefore do not make the host look degraded.
type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Inventory struct {
	Schema                string                 `json:"software_schema"`
	EvidenceSchema        string                 `json:"evidence_schema"`
	CollectedAt           time.Time              `json:"collected_at"`
	Platform              string                 `json:"platform"`
	Architecture          string                 `json:"architecture"`
	Items                 []Item                 `json:"items"`
	Sources               []SourceStatus         `json:"sources"`
	Runtimes              []RuntimeItem          `json:"runtimes"`
	RuntimeSources        []SourceStatus         `json:"runtime_sources"`
	Infrastructure        []InfrastructureItem   `json:"infrastructure"`
	InfrastructureSources []SourceStatus         `json:"infrastructure_sources"`
	Browsers              []BrowserItem          `json:"browsers"`
	HighRiskClients       []HighRiskClientItem   `json:"high_risk_clients"`
	ClientSources         []SourceStatus         `json:"client_sources"`
	BinaryAttributions    []BinaryAttribution    `json:"binary_attributions"`
	AttributionSources    []SourceStatus         `json:"attribution_sources"`
	Evidence              []evidence.Observation `json:"evidence"`
	Degraded              []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	return collect(ctx, nil)
}

// CollectWithHostActivity is used by the Windows full-assessment graph after
// dedicated process and service providers have completed. Standalone software
// collection retains Collect and its platform-specific discovery behavior.
func CollectWithHostActivity(ctx context.Context, activity []HostActivityHint) Inventory {
	return collect(ctx, activity)
}

func collect(ctx context.Context, activity []HostActivityHint) Inventory {
	inv := Inventory{
		Schema:                SchemaVersion,
		EvidenceSchema:        evidence.SchemaVersion,
		CollectedAt:           time.Now().UTC(),
		Platform:              runtime.GOOS,
		Architecture:          runtime.GOARCH,
		Items:                 make([]Item, 0),
		Sources:               make([]SourceStatus, 0),
		Runtimes:              make([]RuntimeItem, 0),
		RuntimeSources:        make([]SourceStatus, 0),
		Infrastructure:        make([]InfrastructureItem, 0),
		InfrastructureSources: make([]SourceStatus, 0),
		Browsers:              make([]BrowserItem, 0),
		HighRiskClients:       make([]HighRiskClientItem, 0),
		ClientSources:         make([]SourceStatus, 0),
		BinaryAttributions:    make([]BinaryAttribution, 0),
		AttributionSources:    make([]SourceStatus, 0),
	}
	collectPlatform(ctx, &inv)
	inv.Items = normalizeItems(inv.Items)
	collectRuntimeInventory(ctx, &inv)
	collectInfrastructureInventoryWithActivity(ctx, &inv, activity)
	collectClientInventory(&inv)
	collectBinaryAttributions(ctx, &inv)
	sort.Slice(inv.Sources, func(i, j int) bool { return inv.Sources[i].ID < inv.Sources[j].ID })
	inv.Degraded = uniqueSorted(inv.Degraded)
	if err := ctx.Err(); err != nil {
		inv.Degraded = uniqueSorted(append(inv.Degraded, "collection timeout reached: "+err.Error()))
	}
	inv.Evidence = buildEvidence(inv)
	return inv
}

func normalizeItems(in []Item) []Item {
	seen := make(map[string]Item, len(in))
	for _, item := range in {
		item.Kind = normalizedOr(item.Kind, "package")
		item.Product = strings.TrimSpace(item.Product)
		if item.Product == "" {
			continue
		}
		item.PackageID = normalizedOr(item.PackageID, item.Product)
		item.Version = normalizedOr(item.Version, "UNKNOWN")
		item.Architecture = normalizedOr(item.Architecture, "UNKNOWN")
		item.Vendor = normalizedOr(item.Vendor, "UNKNOWN")
		item.PackageSource = normalizedOr(item.PackageSource, "UNKNOWN")
		item.InstallPath = normalizedOr(item.InstallPath, "UNKNOWN")
		item.SupportState = normalizedOr(strings.ToUpper(item.SupportState), "UNKNOWN")
		item.SupportReason = normalizedOr(item.SupportReason, "raw inventory does not infer lifecycle; lifecycle assessment reports support state separately")
		item.CollectionSource = normalizedOr(item.CollectionSource, "platform software inventory")
		if item.Confidence == "" {
			item.Confidence = evidence.ConfidenceHigh
		}
		item.ID = stableID(item)
		key := strings.ToLower(strings.Join([]string{item.Kind, item.PackageID, item.Version, item.Architecture, item.InstallPath, item.PackageSource}, "\x00"))
		if old, ok := seen[key]; !ok || confidenceRank(item.Confidence) > confidenceRank(old.Confidence) {
			seen[key] = item
		}
	}
	out := make([]Item, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if strings.ToLower(a.Product) != strings.ToLower(b.Product) {
			return strings.ToLower(a.Product) < strings.ToLower(b.Product)
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.PackageSource != b.PackageSource {
			return a.PackageSource < b.PackageSource
		}
		return a.ID < b.ID
	})
	if len(out) > maxInventoryItems {
		out = out[:maxInventoryItems]
	}
	return out
}

func stableID(item Item) string {
	identity := strings.ToLower(strings.Join([]string{
		strings.TrimSpace(item.Kind), strings.TrimSpace(item.PackageID), strings.TrimSpace(item.Product),
		strings.TrimSpace(item.Version), strings.TrimSpace(item.Architecture), strings.TrimSpace(item.InstallPath),
		strings.TrimSpace(item.PackageSource),
	}, "\x00"))
	sum := sha256.Sum256([]byte(identity))
	return "sw-" + hex.EncodeToString(sum[:10])
}

func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := make([]evidence.Observation, 0, 8+len(inv.Sources)+len(inv.Items)+len(inv.RuntimeSources)+len(inv.Runtimes)+len(inv.InfrastructureSources)+len(inv.Infrastructure)+len(inv.ClientSources)+len(inv.Browsers)+len(inv.HighRiskClients)+len(inv.AttributionSources)+len(inv.BinaryAttributions))
	out = append(out,
		evidence.NewObserved("software.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.inventory.count", len(inv.Items), "normalized software inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.runtime.count", len(inv.Runtimes), "normalized runtime/framework inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.infrastructure.count", len(inv.Infrastructure), "normalized server/infrastructure inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.browser.count", len(inv.Browsers), "normalized browser inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.high_risk_client.count", len(inv.HighRiskClients), "normalized high-risk client inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("software.binary_attribution.count", len(inv.BinaryAttributions), "normalized package/application binary attribution", at, evidence.ConfidenceExact),
	)
	if len(inv.Sources) == 0 {
		out = append(out, evidence.NewState("software.inventory.provider", evidence.StateUnavailable, "platform software inventory", at, evidence.ConfidenceLow, "no supported local software inventory provider was available"))
	}
	for _, src := range inv.Sources {
		key := "software.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else if src.State == evidence.StateNotApplicable {
			out = append(out, evidence.NewState(key, src.State, src.Source, at, evidence.ConfidenceMedium, normalizedOr(src.Reason, "provider is not applicable on this host")))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, normalizedOr(src.Reason, "provider did not return usable inventory")))
		}
	}
	for _, item := range inv.Items {
		out = append(out, evidence.NewObserved("software.item."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	for _, src := range inv.RuntimeSources {
		key := "software.runtime_source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, normalizedOr(src.Reason, "runtime/framework provider did not return usable metadata")))
		}
	}
	for _, item := range inv.Runtimes {
		out = append(out, evidence.NewObserved("software.runtime."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	for _, src := range inv.InfrastructureSources {
		key := "software.infrastructure_source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, normalizedOr(src.Reason, "server/infrastructure provider did not return usable metadata")))
		}
	}
	for _, item := range inv.Infrastructure {
		out = append(out, evidence.NewObserved("software.infrastructure."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	for _, src := range inv.ClientSources {
		key := "software.client_source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, normalizedOr(src.Reason, "browser/high-risk-client classifier did not return usable metadata")))
		}
	}
	for _, item := range inv.Browsers {
		out = append(out, evidence.NewObserved("software.browser."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	for _, item := range inv.HighRiskClients {
		out = append(out, evidence.NewObserved("software.high_risk_client."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	for _, src := range inv.AttributionSources {
		key := "software.attribution_source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			state := src.State
			if state == "" {
				state = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, state, src.Source, at, evidence.ConfidenceLow, normalizedOr(src.Reason, "binary attribution provider did not return usable metadata")))
		}
	}
	for _, item := range inv.BinaryAttributions {
		out = append(out, evidence.NewObserved("software.attribution."+item.ID, item, item.CollectionSource, at, item.Confidence))
	}
	return out
}

func normalizedOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	inv.Sources = append(inv.Sources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)})
	if state == evidence.StateDenied || state == evidence.StateDegraded || state == evidence.StateUnavailable || state == evidence.StateUnsupported {
		if strings.TrimSpace(reason) != "" {
			inv.Degraded = append(inv.Degraded, fmt.Sprintf("%s: %s", id, strings.TrimSpace(reason)))
		}
	}
}

func uniqueSorted(in []string) []string {
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

func confidenceRank(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceExact:
		return 4
	case evidence.ConfidenceHigh:
		return 3
	case evidence.ConfidenceMedium:
		return 2
	case evidence.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	sep := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			sep = false
		} else if !sep {
			b.WriteByte('_')
			sep = true
		}
	}
	return strings.Trim(b.String(), "_")
}

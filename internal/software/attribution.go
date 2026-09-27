package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxAttributionItems = 512

const (
	OwnershipPackage     = "PACKAGE_MANAGED"
	OwnershipApplication = "APPLICATION_MANAGED"
	OwnershipUnmanaged   = "UNMANAGED"
	OwnershipUnknown     = "UNKNOWN"

	DistributionManaged  = "MANAGED"
	DistributionPortable = "PORTABLE_CANDIDATE"
	DistributionUnknown  = "UNKNOWN"

	PathPresent = "PRESENT"
	PathMissing = "MISSING"
	PathUnknown = "UNKNOWN"
)

// AttributionTarget records why a binary path is important enough to resolve.
// currently draws targets from observed runtime executables and
// recognized running infrastructure/service executables. Later service/process
// phases can add more target kinds without changing the ownership semantics.
type AttributionTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// BinaryAttribution is the package/application provenance record.
// Ownership and distribution are deliberately separate: an executable can be
// unowned by a native package manager while still being a defensible portable
// candidate, and provider limitations remain UNKNOWN instead of becoming an
// unmanaged claim.
type BinaryAttribution struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	ResolvedPath     string              `json:"resolved_path"`
	PathState        string              `json:"path_state"`
	Targets          []AttributionTarget `json:"targets"`
	Ownership        string              `json:"ownership"`
	Distribution     string              `json:"distribution"`
	PackageID        string              `json:"package_id"`
	Product          string              `json:"product"`
	Version          string              `json:"version"`
	PackageSource    string              `json:"package_source"`
	InstallPath      string              `json:"install_path"`
	Provider         string              `json:"provider"`
	ProviderState    evidence.State      `json:"provider_state"`
	Method           string              `json:"method"`
	Reason           string              `json:"reason"`
	EvidenceRefs     []string            `json:"evidence_refs"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type attributionCandidate struct {
	Path    string
	Targets []AttributionTarget
	Refs    []string
}

type ownershipResult struct {
	Ownership     string
	PackageID     string
	Product       string
	Version       string
	PackageSource string
	InstallPath   string
	Provider      string
	ProviderState evidence.State
	Method        string
	Reason        string
	Confidence    evidence.Confidence
}

func collectBinaryAttributions(ctx context.Context, inv *Inventory) {
	candidates := attributionCandidates(inv)
	inv.BinaryAttributions = make([]BinaryAttribution, 0, len(candidates))
	inv.AttributionSources = append(inv.AttributionSources, SourceStatus{
		ID: "candidate-discovery", State: evidence.StateObserved,
		Source: "runtime/infrastructure executable targets", ItemCount: len(candidates),
	})

	sourceAgg := map[string]SourceStatus{}
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		rec := attributeCandidate(ctx, candidate, inv.Items)
		inv.BinaryAttributions = append(inv.BinaryAttributions, rec)
		if rec.Provider != "" {
			id := slug(rec.Provider)
			if id == "" {
				id = "ownership-provider"
			}
			cur, ok := sourceAgg[id]
			if !ok {
				cur = SourceStatus{ID: id, State: rec.ProviderState, Source: rec.Provider}
			}
			cur.ItemCount++
			cur.State = worseSourceState(cur.State, rec.ProviderState)
			if rec.ProviderState != evidence.StateObserved && rec.Reason != "" {
				cur.Reason = rec.Reason
			}
			sourceAgg[id] = cur
		}
	}
	for _, src := range sourceAgg {
		inv.AttributionSources = append(inv.AttributionSources, src)
		if src.State == evidence.StateDenied || src.State == evidence.StateDegraded || src.State == evidence.StateUnavailable || src.State == evidence.StateUnsupported {
			if strings.TrimSpace(src.Reason) != "" {
				inv.Degraded = append(inv.Degraded, "attribution "+src.ID+": "+strings.TrimSpace(src.Reason))
			}
		}
	}
	sort.Slice(inv.BinaryAttributions, func(i, j int) bool {
		a, b := inv.BinaryAttributions[i], inv.BinaryAttributions[j]
		ak, bk := pathComparisonKey(a.Path), pathComparisonKey(b.Path)
		if ak != bk {
			return ak < bk
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.ID < b.ID
	})
	if len(inv.BinaryAttributions) > maxAttributionItems {
		inv.BinaryAttributions = inv.BinaryAttributions[:maxAttributionItems]
	}
	inv.AttributionSources = normalizeSourceStatuses(inv.AttributionSources)
}

func attributionCandidates(inv *Inventory) []attributionCandidate {
	type aggregate struct {
		path    string
		targets map[string]AttributionTarget
		refs    map[string]struct{}
	}
	byPath := map[string]*aggregate{}
	add := func(path string, target AttributionTarget, ref string) {
		path = cleanCandidatePath(path)
		if path == "" || path == "UNKNOWN" || path == "N/A" {
			return
		}
		if !defensibleExecutablePath(path) {
			return
		}
		key := pathComparisonKey(path)
		a := byPath[key]
		if a == nil {
			a = &aggregate{path: path, targets: map[string]AttributionTarget{}, refs: map[string]struct{}{}}
			byPath[key] = a
		}
		tk := strings.ToLower(target.Kind + "\x00" + target.ID + "\x00" + target.Name)
		a.targets[tk] = target
		if strings.TrimSpace(ref) != "" {
			a.refs[ref] = struct{}{}
		}
	}

	for _, rt := range inv.Runtimes {
		add(rt.ExecutablePath, AttributionTarget{Kind: "runtime-executable", ID: rt.ID, Name: rt.Product}, "software.runtime."+rt.ID)
	}
	for _, infra := range inv.Infrastructure {
		for _, p := range infra.ExecutablePaths {
			add(p, AttributionTarget{Kind: "infrastructure-executable", ID: infra.ID, Name: infra.Product}, "software.infrastructure."+infra.ID)
		}
	}

	out := make([]attributionCandidate, 0, len(byPath))
	for _, a := range byPath {
		targets := make([]AttributionTarget, 0, len(a.targets))
		for _, t := range a.targets {
			targets = append(targets, t)
		}
		sort.Slice(targets, func(i, j int) bool {
			if targets[i].Kind != targets[j].Kind {
				return targets[i].Kind < targets[j].Kind
			}
			if targets[i].ID != targets[j].ID {
				return targets[i].ID < targets[j].ID
			}
			return targets[i].Name < targets[j].Name
		})
		refs := make([]string, 0, len(a.refs))
		for ref := range a.refs {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		out = append(out, attributionCandidate{Path: a.path, Targets: targets, Refs: refs})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := pathComparisonKey(out[i].Path), pathComparisonKey(out[j].Path)
		if a != b {
			return a < b
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > maxAttributionItems {
		out = out[:maxAttributionItems]
	}
	return out
}

func attributeCandidate(ctx context.Context, candidate attributionCandidate, items []Item) BinaryAttribution {
	raw := cleanCandidatePath(candidate.Path)
	resolved := raw
	pathState := PathUnknown
	if info, err := os.Stat(raw); err == nil && !info.IsDir() {
		pathState = PathPresent
		if p, err := filepath.EvalSymlinks(raw); err == nil && strings.TrimSpace(p) != "" {
			resolved = filepath.Clean(p)
		}
	} else if err != nil && os.IsNotExist(err) {
		pathState = PathMissing
	}

	result := resolvePlatformOwnership(ctx, resolved, items)
	if result.Ownership == "" {
		result.Ownership = OwnershipUnknown
	}
	if result.PackageID == "" {
		result.PackageID = "UNKNOWN"
	}
	if result.Product == "" {
		result.Product = "UNKNOWN"
	}
	if result.Version == "" {
		result.Version = "UNKNOWN"
	}
	if result.PackageSource == "" {
		result.PackageSource = "UNKNOWN"
	}
	if result.InstallPath == "" {
		result.InstallPath = "UNKNOWN"
	}
	if result.Provider == "" {
		result.Provider = "platform ownership resolver"
	}
	if result.ProviderState == "" {
		result.ProviderState = evidence.StateUnavailable
	}
	if result.Method == "" {
		result.Method = "unresolved"
	}
	if result.Confidence == "" {
		result.Confidence = evidence.ConfidenceLow
	}

	distribution := DistributionUnknown
	switch result.Ownership {
	case OwnershipPackage, OwnershipApplication:
		distribution = DistributionManaged
	case OwnershipUnmanaged:
		if portableCandidatePath(resolved) {
			distribution = DistributionPortable
		}
	}

	rec := BinaryAttribution{
		Path: raw, ResolvedPath: normalizedOr(resolved, raw), PathState: pathState,
		Targets: candidate.Targets, Ownership: result.Ownership, Distribution: distribution,
		PackageID: result.PackageID, Product: result.Product, Version: result.Version,
		PackageSource: result.PackageSource, InstallPath: result.InstallPath,
		Provider: result.Provider, ProviderState: result.ProviderState, Method: result.Method,
		Reason:           normalizedOr(result.Reason, "package/application ownership could not be established from available local metadata"),
		EvidenceRefs:     append([]string(nil), candidate.Refs...),
		CollectionSource: "local package/application attribution", Confidence: result.Confidence,
	}
	rec.ID = stableAttributionID(rec)
	return rec
}

func matchInstalledPath(path string, items []Item) *Item {
	clean := cleanComparablePath(path)
	if clean == "" {
		return nil
	}
	var best *Item
	bestLen := -1
	for i := range items {
		root := cleanComparablePath(items[i].InstallPath)
		if root == "" || strings.EqualFold(root, "UNKNOWN") || strings.EqualFold(root, "N/A") {
			continue
		}
		if !pathWithin(clean, root) {
			continue
		}
		if len(root) > bestLen || (len(root) == bestLen && best != nil && confidenceRank(items[i].Confidence) > confidenceRank(best.Confidence)) {
			cp := items[i]
			best = &cp
			bestLen = len(root)
		}
	}
	return best
}

func findItemByPackageID(items []Item, id string) *Item {
	id = strings.TrimSpace(id)
	idNoArch := strings.SplitN(id, ":", 2)[0]
	var best *Item
	for i := range items {
		pkg := strings.TrimSpace(items[i].PackageID)
		if strings.EqualFold(pkg, id) || strings.EqualFold(strings.SplitN(pkg, ":", 2)[0], idNoArch) {
			if best == nil || confidenceRank(items[i].Confidence) > confidenceRank(best.Confidence) {
				cp := items[i]
				best = &cp
			}
		}
	}
	return best
}

func resultFromItem(item *Item, provider, method, reason string, confidence evidence.Confidence) ownershipResult {
	if item == nil {
		return ownershipResult{}
	}
	if confidence == "" {
		confidence = item.Confidence
	}
	ownership := OwnershipPackage
	if strings.EqualFold(item.Kind, "application") {
		ownership = OwnershipApplication
	}
	return ownershipResult{
		Ownership: ownership, PackageID: item.PackageID, Product: item.Product,
		Version: item.Version, PackageSource: item.PackageSource, InstallPath: item.InstallPath,
		Provider: provider, ProviderState: evidence.StateObserved, Method: method,
		Reason: reason, Confidence: confidence,
	}
}

func runAttributionProbe(ctx context.Context, name string, args ...string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return run(probeCtx, name, args...)
}

func cleanCandidatePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.HasSuffix(path, " (deleted)") {
		path = strings.TrimSpace(strings.TrimSuffix(path, " (deleted)"))
	}
	return filepath.Clean(path)
}

func cleanComparablePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.TrimRight(filepath.Clean(path), string(filepath.Separator))
	return pathComparisonKey(path)
}

func pathWithin(path, root string) bool {
	if path == root {
		return true
	}
	sep := strings.ToLower(string(filepath.Separator))
	if sep == "" {
		sep = "/"
	}
	return strings.HasPrefix(path, root+sep)
}

func pathComparisonKey(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func defensibleExecutablePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || strings.EqualFold(path, "UNKNOWN") || strings.EqualFold(path, "N/A") {
		return false
	}
	return filepath.IsAbs(path)
}

func portableCandidatePath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "\\", "/"))
	home, _ := os.UserHomeDir()
	h := strings.ToLower(strings.ReplaceAll(filepath.Clean(home), "\\", "/"))
	if h != "" && h != "." && pathWithinSlash(p, h) {
		return true
	}
	prefixes := []string{"/tmp/", "/var/tmp/", "/private/tmp/", "/opt/", "/usr/local/", "/users/shared/", "c:/users/public/", "c:/windows/temp/", "c:/tools/", "c:/portableapps/"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return strings.Contains(p, "/downloads/") || strings.Contains(p, "/desktop/")
}

func pathWithinSlash(path, root string) bool {
	root = strings.TrimRight(root, "/")
	return path == root || strings.HasPrefix(path, root+"/")
}

func stableAttributionID(item BinaryAttribution) string {
	identity := strings.Join([]string{pathComparisonKey(item.Path), pathComparisonKey(item.ResolvedPath)}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	return "attr-" + hex.EncodeToString(sum[:10])
}

func worseSourceState(a, b evidence.State) evidence.State {
	rank := func(s evidence.State) int {
		switch s {
		case evidence.StateDenied:
			return 6
		case evidence.StateDegraded:
			return 5
		case evidence.StateUnavailable:
			return 4
		case evidence.StateUnsupported:
			return 3
		case evidence.StateNotApplicable:
			return 2
		case evidence.StateObserved:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

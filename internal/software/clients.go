package software

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxClientItems = 256

// BrowserItem is the normalized browser record. Channel is based on
// local product/package identity only; it is never derived from a version-number
// guess or an online release lookup.
type BrowserItem struct {
	ID               string              `json:"id"`
	Family           string              `json:"family"`
	Product          string              `json:"product"`
	Version          string              `json:"version"`
	Channel          string              `json:"channel"`
	Architecture     string              `json:"architecture"`
	PackageID        string              `json:"package_id"`
	InstallPath      string              `json:"install_path"`
	DetectionSources []string            `json:"detection_sources"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

// HighRiskClientItem captures common local applications that routinely parse
// untrusted documents, messages, or archives. inventories these
// surfaces; it does not claim vulnerability or lifecycle status.
type HighRiskClientItem struct {
	ID               string              `json:"id"`
	Category         string              `json:"category"`
	Family           string              `json:"family"`
	Product          string              `json:"product"`
	Version          string              `json:"version"`
	Architecture     string              `json:"architecture"`
	PackageID        string              `json:"package_id"`
	InstallPath      string              `json:"install_path"`
	ContentSurfaces  []string            `json:"content_surfaces"`
	DetectionSources []string            `json:"detection_sources"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type clientSignature struct {
	Family          string
	Product         string
	Category        string
	Channel         string
	ExactAliases    []string
	PrefixAliases   []string
	ContentSurfaces []string
	Platforms       []string
	ExcludeTerms    []string
}

// Browser aliases are intentionally split by channel so side-by-side stable,
// beta/dev/canary/nightly installations remain distinct. Exact matching avoids
// classifying helper/plugin packages as browsers.
var browserSignatures = []clientSignature{
	{Family: "chrome", Product: "Google Chrome", Channel: "stable", ExactAliases: []string{"google chrome", "google-chrome-stable", "com.google.chrome"}},
	{Family: "chrome", Product: "Google Chrome Beta", Channel: "beta", ExactAliases: []string{"google chrome beta", "google-chrome-beta", "com.google.chrome.beta"}},
	{Family: "chrome", Product: "Google Chrome Dev", Channel: "dev", ExactAliases: []string{"google chrome dev", "google-chrome-unstable", "com.google.chrome.dev"}},
	{Family: "chrome", Product: "Google Chrome Canary", Channel: "canary", ExactAliases: []string{"google chrome canary", "com.google.chrome.canary"}},
	{Family: "chromium", Product: "Chromium", Channel: "stable", ExactAliases: []string{"chromium", "chromium-browser", "org.chromium.chromium"}},
	{Family: "edge", Product: "Microsoft Edge", Channel: "stable", ExactAliases: []string{"microsoft edge", "microsoft-edge-stable", "com.microsoft.edgemac"}},
	{Family: "edge", Product: "Microsoft Edge Beta", Channel: "beta", ExactAliases: []string{"microsoft edge beta", "microsoft-edge-beta", "com.microsoft.edgemac.beta"}},
	{Family: "edge", Product: "Microsoft Edge Dev", Channel: "dev", ExactAliases: []string{"microsoft edge dev", "microsoft-edge-dev", "com.microsoft.edgemac.dev"}},
	{Family: "edge", Product: "Microsoft Edge Canary", Channel: "canary", ExactAliases: []string{"microsoft edge canary", "microsoft-edge-canary", "com.microsoft.edgemac.canary"}},
	{Family: "firefox", Product: "Mozilla Firefox", Channel: "stable", ExactAliases: []string{"mozilla firefox", "firefox", "org.mozilla.firefox"}},
	{Family: "firefox", Product: "Mozilla Firefox ESR", Channel: "esr", ExactAliases: []string{"mozilla firefox esr", "firefox-esr", "org.mozilla.firefoxesr"}},
	{Family: "firefox", Product: "Firefox Developer Edition", Channel: "developer", ExactAliases: []string{"firefox developer edition", "firefox-developer-edition", "org.mozilla.firefoxdeveloperedition"}},
	{Family: "firefox", Product: "Firefox Nightly", Channel: "nightly", ExactAliases: []string{"firefox nightly", "firefox-nightly", "org.mozilla.firefoxnightly"}},
	{Family: "safari", Product: "Safari", Channel: "stable", ExactAliases: []string{"safari", "com.apple.safari"}},
	{Family: "safari", Product: "Safari Technology Preview", Channel: "technology-preview", ExactAliases: []string{"safari technology preview", "com.apple.safaritechnologypreview"}},
	{Family: "brave", Product: "Brave Browser", Channel: "stable", ExactAliases: []string{"brave", "brave browser", "brave-browser", "com.brave.browser"}},
	{Family: "brave", Product: "Brave Browser Beta", Channel: "beta", ExactAliases: []string{"brave browser beta", "brave-browser-beta", "com.brave.browser.beta"}},
	{Family: "brave", Product: "Brave Browser Nightly", Channel: "nightly", ExactAliases: []string{"brave browser nightly", "brave-browser-nightly", "com.brave.browser.nightly"}},
	{Family: "opera", Product: "Opera", Channel: "stable", ExactAliases: []string{"opera", "com.opera.opera"}},
	{Family: "opera", Product: "Opera Beta", Channel: "beta", ExactAliases: []string{"opera beta", "opera-beta", "com.opera.operabeta"}},
	{Family: "opera", Product: "Opera Developer", Channel: "developer", ExactAliases: []string{"opera developer", "opera-developer", "com.opera.operadeveloper"}},
	{Family: "vivaldi", Product: "Vivaldi", Channel: "stable", ExactAliases: []string{"vivaldi", "vivaldi-stable", "com.vivaldi.vivaldi"}},
	{Family: "vivaldi", Product: "Vivaldi Snapshot", Channel: "snapshot", ExactAliases: []string{"vivaldi snapshot", "vivaldi-snapshot", "com.vivaldi.vivaldi.snapshot"}},
}

var highRiskClientSignatures = []clientSignature{
	{Category: "pdf-reader", Family: "adobe-acrobat", Product: "Adobe Acrobat/Reader", ExactAliases: []string{"adobe acrobat", "adobe acrobat reader", "adobe acrobat reader dc", "acrobat reader", "acrobat reader dc"}, PrefixAliases: []string{"adobe acrobat", "adobe acrobat reader"}, ContentSurfaces: []string{"pdf"}, ExcludeTerms: []string{"update", "updater", "helper", "plugin", "extension"}},
	{Category: "pdf-reader", Family: "foxit", Product: "Foxit PDF Reader", ExactAliases: []string{"foxit pdf reader", "foxit reader"}, PrefixAliases: []string{"foxit pdf reader "}, ContentSurfaces: []string{"pdf"}},
	{Category: "pdf-reader", Family: "sumatrapdf", Product: "SumatraPDF", ExactAliases: []string{"sumatrapdf", "sumatra pdf"}, ContentSurfaces: []string{"pdf", "ebook", "document"}},
	{Category: "office-suite", Family: "microsoft-office", Product: "Microsoft Office / Microsoft 365", ExactAliases: []string{"microsoft office", "microsoft 365 apps", "microsoft 365"}, PrefixAliases: []string{"microsoft office ", "microsoft 365 apps ", "microsoft 365 "}, ContentSurfaces: []string{"office-document", "spreadsheet", "presentation"}},
	{Category: "office-suite", Family: "libreoffice", Product: "LibreOffice", ExactAliases: []string{"libreoffice", "org.libreoffice.libreoffice"}, PrefixAliases: []string{"libreoffice"}, ContentSurfaces: []string{"office-document", "spreadsheet", "presentation"}, ExcludeTerms: []string{"help", "language", "langpack", "sdk", "dev", "core", "common"}},
	{Category: "office-suite", Family: "openoffice", Product: "Apache OpenOffice", ExactAliases: []string{"apache openoffice", "openoffice", "org.openoffice.openoffice"}, PrefixAliases: []string{"apache openoffice "}, ContentSurfaces: []string{"office-document", "spreadsheet", "presentation"}},
	{Category: "email-client", Family: "outlook", Product: "Microsoft Outlook", ExactAliases: []string{"microsoft outlook", "outlook", "microsoft outlook for mac"}, PrefixAliases: []string{"microsoft outlook "}, ContentSurfaces: []string{"email", "calendar", "attachment"}},
	{Category: "email-client", Family: "thunderbird", Product: "Mozilla Thunderbird", ExactAliases: []string{"mozilla thunderbird", "thunderbird", "org.mozilla.thunderbird"}, PrefixAliases: []string{"mozilla thunderbird "}, ContentSurfaces: []string{"email", "attachment"}},
	{Category: "email-client", Family: "apple-mail", Product: "Apple Mail", ExactAliases: []string{"mail", "apple mail", "com.apple.mail"}, ContentSurfaces: []string{"email", "attachment"}, Platforms: []string{"darwin"}},
	{Category: "archive-client", Family: "7zip", Product: "7-Zip", ExactAliases: []string{"7-zip", "7zip", "p7zip", "p7zip-full"}, PrefixAliases: []string{"7-zip "}, ContentSurfaces: []string{"archive"}},
	{Category: "archive-client", Family: "winrar", Product: "WinRAR", ExactAliases: []string{"winrar"}, PrefixAliases: []string{"winrar "}, ContentSurfaces: []string{"archive"}},
	{Category: "archive-client", Family: "winzip", Product: "WinZip", ExactAliases: []string{"winzip"}, PrefixAliases: []string{"winzip "}, ContentSurfaces: []string{"archive"}},
}

func collectClientInventory(inv *Inventory) {
	inv.Browsers = classifyBrowsers(inv.Items, inv.Platform)
	inv.HighRiskClients = classifyHighRiskClients(inv.Items, inv.Platform)
	state, reason := clientClassifierState(inv.Sources)
	inv.ClientSources = normalizeSourceStatuses([]SourceStatus{{
		ID:        "installed-software-classifier",
		State:     state,
		Source:    "normalized installed-software inventory",
		ItemCount: len(inv.Browsers) + len(inv.HighRiskClients),
		Reason:    reason,
	}})
}

func classifyBrowsers(items []Item, platform string) []BrowserItem {
	out := make([]BrowserItem, 0)
	for _, sig := range browserSignatures {
		if !clientSignatureApplies(sig, platform) {
			continue
		}
		matches := matchingClientItems(items, sig)
		if len(matches) == 0 {
			continue
		}
		best := chooseBestClientItem(matches)
		rec := BrowserItem{
			Family:           sig.Family,
			Product:          sig.Product,
			Version:          normalizedOr(best.Version, "UNKNOWN"),
			Channel:          normalizedOr(sig.Channel, "UNKNOWN"),
			Architecture:     normalizedOr(best.Architecture, "UNKNOWN"),
			PackageID:        normalizedOr(best.PackageID, "UNKNOWN"),
			InstallPath:      normalizedOr(best.InstallPath, "UNKNOWN"),
			DetectionSources: detectionIDs(matches),
			CollectionSource: "installed browser classification",
			Confidence:       best.Confidence,
		}
		rec.ID = stableClientID("browser", rec.Family, rec.Channel, rec.Product)
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		if out[i].Channel != out[j].Channel {
			return out[i].Channel < out[j].Channel
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxClientItems {
		out = out[:maxClientItems]
	}
	return out
}

func classifyHighRiskClients(items []Item, platform string) []HighRiskClientItem {
	out := make([]HighRiskClientItem, 0)
	for _, sig := range highRiskClientSignatures {
		if !clientSignatureApplies(sig, platform) {
			continue
		}
		matches := matchingClientItems(items, sig)
		if len(matches) == 0 {
			continue
		}
		best := chooseBestClientItem(matches)
		rec := HighRiskClientItem{
			Category:         sig.Category,
			Family:           sig.Family,
			Product:          sig.Product,
			Version:          normalizedOr(best.Version, "UNKNOWN"),
			Architecture:     normalizedOr(best.Architecture, "UNKNOWN"),
			PackageID:        normalizedOr(best.PackageID, "UNKNOWN"),
			InstallPath:      normalizedOr(best.InstallPath, "UNKNOWN"),
			ContentSurfaces:  uniqueSorted(sig.ContentSurfaces),
			DetectionSources: detectionIDs(matches),
			CollectionSource: "high-risk client classification",
			Confidence:       best.Confidence,
		}
		rec.ID = stableClientID("client", rec.Category, rec.Family, rec.Product)
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxClientItems {
		out = out[:maxClientItems]
	}
	return out
}

func matchingClientItems(items []Item, sig clientSignature) []Item {
	out := make([]Item, 0)
	for _, item := range items {
		if clientItemMatches(item, sig) {
			out = append(out, item)
		}
	}
	return out
}

func clientItemMatches(item Item, sig clientSignature) bool {
	product := normalizeMatchText(item.Product)
	packageID := normalizeMatchText(item.PackageID)
	for _, alias := range sig.ExactAliases {
		needle := normalizeMatchText(alias)
		if needle != "" && (product == needle || packageID == needle) {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(item.Kind), "application") && !containsExcludedClientTerm(product, sig.ExcludeTerms) {
		for _, alias := range sig.PrefixAliases {
			needle := normalizeMatchText(alias)
			if needle != "" && (strings.HasPrefix(product, needle+" ") || product == needle) {
				return true
			}
		}
	}
	return false
}

func clientSignatureApplies(sig clientSignature, platform string) bool {
	if len(sig.Platforms) == 0 {
		return true
	}
	platform = strings.ToLower(strings.TrimSpace(platform))
	for _, allowed := range sig.Platforms {
		if platform == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func containsExcludedClientTerm(product string, terms []string) bool {
	wrapped := " " + normalizeMatchText(product) + " "
	for _, term := range terms {
		needle := normalizeMatchText(term)
		if needle != "" && strings.Contains(wrapped, " "+needle+" ") {
			return true
		}
	}
	return false
}

func clientClassifierState(sources []SourceStatus) (evidence.State, string) {
	if len(sources) == 0 {
		return evidence.StateUnavailable, "no installed-software provider state was available"
	}
	for _, src := range sources {
		if src.State == evidence.StateObserved {
			return evidence.StateObserved, ""
		}
	}
	priority := []evidence.State{evidence.StateDenied, evidence.StateDegraded, evidence.StateUnavailable, evidence.StateUnsupported}
	for _, want := range priority {
		for _, src := range sources {
			if src.State == want {
				reason := strings.TrimSpace(src.Reason)
				if reason == "" {
					reason = "installed-software evidence was not fully available"
				}
				return want, reason
			}
		}
	}
	return evidence.StateUnavailable, "installed-software evidence was not fully available"
}

func chooseBestClientItem(items []Item) Item {
	best := items[0]
	for _, item := range items[1:] {
		if clientItemScore(item) > clientItemScore(best) || (clientItemScore(item) == clientItemScore(best) && item.ID < best.ID) {
			best = item
		}
	}
	return best
}

func clientItemScore(item Item) int {
	score := confidenceRank(item.Confidence) * 100
	if strings.TrimSpace(item.Version) != "" && !strings.EqualFold(strings.TrimSpace(item.Version), "UNKNOWN") {
		score += 20
	}
	if strings.TrimSpace(item.InstallPath) != "" && !strings.EqualFold(strings.TrimSpace(item.InstallPath), "UNKNOWN") {
		score += 5
	}
	return score
}

func detectionIDs(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ID) != "" {
			out = append(out, "installed-software:"+item.ID)
		}
	}
	return uniqueSorted(out)
}

func stableClientID(parts ...string) string {
	identity := strings.ToLower(strings.Join(parts, "\x00"))
	sum := sha256.Sum256([]byte(identity))
	return "client-" + hex.EncodeToString(sum[:10])
}

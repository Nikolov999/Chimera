package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxRuntimeItems = 2048

// RuntimeItem is the normalized runtime/framework/toolchain record.
// It records locally observable identity only; support status and CVE matching
// remain separate later-phase concerns.
type RuntimeItem struct {
	ID               string              `json:"id"`
	Family           string              `json:"family"`
	Kind             string              `json:"kind"`
	Product          string              `json:"product"`
	Version          string              `json:"version"`
	Architecture     string              `json:"architecture"`
	Executable       string              `json:"executable"`
	ExecutablePath   string              `json:"executable_path"`
	InstallPath      string              `json:"install_path"`
	Distribution     string              `json:"distribution"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type runtimeProbe struct {
	ID         string
	Family     string
	Kind       string
	Product    string
	Executable string
	Args       []string
	Parser     func(string) []RuntimeItem
}

var versionTokenRE = regexp.MustCompile(`(?i)\bv?([0-9]+(?:\.[0-9]+){0,4}(?:[-+._a-z0-9]*)?)\b`)

func collectRuntimeInventory(ctx context.Context, inv *Inventory) {
	probes := []runtimeProbe{
		{ID: "dotnet", Family: "dotnet", Kind: "runtime", Product: ".NET", Executable: "dotnet", Args: []string{"--list-runtimes"}, Parser: parseDotNetRuntimes},
		{ID: "dotnet-sdk", Family: "dotnet", Kind: "toolchain", Product: ".NET SDK", Executable: "dotnet", Args: []string{"--list-sdks"}, Parser: parseDotNetSDKs},
		{ID: "java", Family: "java", Kind: "runtime", Product: "Java Runtime", Executable: "java", Args: []string{"-version"}, Parser: parseJava},
		{ID: "python3", Family: "python", Kind: "interpreter", Product: "Python", Executable: "python3", Args: []string{"--version"}, Parser: parseSimpleVersion("Python")},
		{ID: "python", Family: "python", Kind: "interpreter", Product: "Python", Executable: "python", Args: []string{"--version"}, Parser: parseSimpleVersion("Python")},
		{ID: "node", Family: "nodejs", Kind: "runtime", Product: "Node.js", Executable: "node", Args: []string{"--version"}, Parser: parseSimpleVersion("Node.js")},
		{ID: "go", Family: "go", Kind: "toolchain", Product: "Go Toolchain", Executable: "go", Args: []string{"version"}, Parser: parseGo},
		{ID: "openssl", Family: "openssl", Kind: "crypto-runtime", Product: "OpenSSL-family", Executable: "openssl", Args: []string{"version"}, Parser: parseOpenSSL},
		{ID: "php", Family: "php", Kind: "web-runtime", Product: "PHP", Executable: "php", Args: []string{"--version"}, Parser: parseSimpleVersion("PHP")},
		{ID: "ruby", Family: "ruby", Kind: "interpreter", Product: "Ruby", Executable: "ruby", Args: []string{"--version"}, Parser: parseSimpleVersion("Ruby")},
		{ID: "perl", Family: "perl", Kind: "interpreter", Product: "Perl", Executable: "perl", Args: []string{"-v"}, Parser: parsePerl},
		{ID: "lua", Family: "lua", Kind: "interpreter", Product: "Lua", Executable: "lua", Args: []string{"-v"}, Parser: parseSimpleVersion("Lua")},
		{ID: "deno", Family: "deno", Kind: "runtime", Product: "Deno", Executable: "deno", Args: []string{"--version"}, Parser: parseSimpleVersion("Deno")},
		{ID: "bun", Family: "bun", Kind: "runtime", Product: "Bun", Executable: "bun", Args: []string{"--version"}, Parser: parseSimpleVersion("Bun")},
		{ID: "pwsh", Family: "powershell", Kind: "interpreter", Product: "PowerShell", Executable: "pwsh", Args: []string{"-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"}, Parser: parseSimpleVersion("PowerShell")},
		{ID: "powershell", Family: "powershell", Kind: "interpreter", Product: "Windows PowerShell", Executable: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"}, Parser: parseSimpleVersion("Windows PowerShell")},
	}

	anyProvider := false
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		path, err := exec.LookPath(p.Executable)
		if err != nil {
			continue
		}
		anyProvider = true
		canonical := canonicalExecutablePath(path)
		output, err := runRuntimeProbe(ctx, path, p.Args...)
		if err != nil {
			addRuntimeSource(inv, p.ID, runtimeStateForError(ctx, err), "runtime executable: "+canonical, 0, err.Error())
			continue
		}
		records := p.Parser(output)
		for i := range records {
			records[i].Family = normalizedOr(records[i].Family, p.Family)
			records[i].Kind = normalizedOr(records[i].Kind, p.Kind)
			records[i].Product = normalizedOr(records[i].Product, p.Product)
			records[i].Executable = p.Executable
			records[i].ExecutablePath = canonical
			if records[i].InstallPath == "" {
				records[i].InstallPath = filepath.Dir(canonical)
			}
			records[i].CollectionSource = "local runtime version metadata via " + p.Executable
			if records[i].Confidence == "" {
				records[i].Confidence = evidence.ConfidenceHigh
			}
			inv.Runtimes = append(inv.Runtimes, records[i])
		}
		addRuntimeSource(inv, p.ID, evidence.StateObserved, "runtime executable: "+canonical, len(records), "")
	}

	collectPlatformRuntimes(ctx, inv)
	inv.Runtimes = normalizeRuntimes(inv.Runtimes)
	sort.Slice(inv.RuntimeSources, func(i, j int) bool { return inv.RuntimeSources[i].ID < inv.RuntimeSources[j].ID })

	if !anyProvider && len(inv.RuntimeSources) == 0 {
		addRuntimeSource(inv, "runtime-discovery", evidence.StateObserved, "local executable and platform runtime metadata", 0, "no supported runtime/framework executable was present in PATH and no platform runtime metadata provider returned records")
	}
}

func runRuntimeProbe(ctx context.Context, name string, args ...string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(probeCtx, name, args...).CombinedOutput()
	if err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return "", context.DeadlineExceeded
		}
		if msg := strings.TrimSpace(string(b)); msg != "" {
			return "", errors.New(msg)
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func canonicalExecutablePath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Clean(path)
}

func parseDotNetRuntimes(text string) []RuntimeItem {
	out := make([]RuntimeItem, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		product, version := fields[0], fields[1]
		install := "UNKNOWN"
		if i := strings.Index(line, "["); i >= 0 {
			if j := strings.LastIndex(line, "]"); j > i {
				install = strings.TrimSpace(line[i+1 : j])
			}
		}
		out = append(out, RuntimeItem{Family: "dotnet", Kind: "framework-runtime", Product: product, Version: version, Architecture: "UNKNOWN", InstallPath: install, Distribution: "Microsoft .NET", Confidence: evidence.ConfidenceExact})
	}
	return out
}

func parseDotNetSDKs(text string) []RuntimeItem {
	out := make([]RuntimeItem, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		version := fields[0]
		install := "UNKNOWN"
		if i := strings.Index(line, "["); i >= 0 {
			if j := strings.LastIndex(line, "]"); j > i {
				install = strings.TrimSpace(line[i+1 : j])
			}
		}
		out = append(out, RuntimeItem{Family: "dotnet", Kind: "toolchain", Product: ".NET SDK", Version: version, Architecture: "UNKNOWN", InstallPath: install, Distribution: "Microsoft .NET", Confidence: evidence.ConfidenceExact})
	}
	return out
}

func parseJava(text string) []RuntimeItem {
	line := firstNonEmptyLine(text)
	if line == "" {
		return nil
	}
	product := "Java Runtime"
	lower := strings.ToLower(line)
	distribution := "UNKNOWN"
	switch {
	case strings.Contains(lower, "openjdk"):
		distribution = "OpenJDK"
	case strings.Contains(lower, "java"):
		distribution = "Java"
	}
	return []RuntimeItem{{Family: "java", Kind: "runtime", Product: product, Version: firstVersionToken(line), Architecture: "UNKNOWN", Distribution: distribution, Confidence: evidence.ConfidenceHigh}}
}

func parseGo(text string) []RuntimeItem {
	line := firstNonEmptyLine(text)
	fields := strings.Fields(line)
	version := "UNKNOWN"
	if len(fields) >= 3 && strings.HasPrefix(fields[2], "go") {
		version = normalizedOr(strings.TrimPrefix(fields[2], "go"), "UNKNOWN")
	}
	item := RuntimeItem{Family: "go", Kind: "toolchain", Product: "Go Toolchain", Version: version, Architecture: "UNKNOWN", Distribution: "Go", Confidence: evidence.ConfidenceHigh}
	if len(fields) >= 4 && strings.Contains(fields[len(fields)-1], "/") {
		parts := strings.Split(fields[len(fields)-1], "/")
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			item.Architecture = strings.TrimSpace(parts[1])
		}
	}
	return []RuntimeItem{item}
}

func parsePerl(text string) []RuntimeItem {
	version := "UNKNOWN"
	if m := regexp.MustCompile(`\bv([0-9]+(?:\.[0-9]+){1,4})\b`).FindStringSubmatch(text); len(m) >= 2 {
		version = m[1]
	} else {
		version = firstVersionToken(text)
	}
	return []RuntimeItem{{Family: "perl", Kind: "interpreter", Product: "Perl", Version: version, Architecture: "UNKNOWN", Distribution: "Perl", Confidence: evidence.ConfidenceHigh}}
}

func parseOpenSSL(text string) []RuntimeItem {
	line := firstNonEmptyLine(text)
	if line == "" {
		return nil
	}
	product := "OpenSSL-family"
	fields := strings.Fields(line)
	if len(fields) > 0 {
		switch strings.ToLower(fields[0]) {
		case "openssl":
			product = "OpenSSL"
		case "libressl":
			product = "LibreSSL"
		case "boringssl":
			product = "BoringSSL"
		}
	}
	return []RuntimeItem{{Family: "openssl", Kind: "crypto-runtime", Product: product, Version: firstVersionToken(line), Architecture: "UNKNOWN", Distribution: product, Confidence: evidence.ConfidenceHigh}}
}

func parseSimpleVersion(product string) func(string) []RuntimeItem {
	return func(text string) []RuntimeItem {
		line := firstNonEmptyLine(text)
		if line == "" {
			return nil
		}
		version := firstVersionToken(text)
		return []RuntimeItem{{Product: product, Version: version, Architecture: "UNKNOWN", Distribution: product, Confidence: evidence.ConfidenceHigh}}
	}
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

func firstVersionToken(text string) string {
	m := versionTokenRE.FindStringSubmatch(text)
	if len(m) >= 2 && strings.TrimSpace(m[1]) != "" {
		return strings.TrimSpace(m[1])
	}
	return "UNKNOWN"
}

func normalizeRuntimes(in []RuntimeItem) []RuntimeItem {
	seen := make(map[string]RuntimeItem, len(in))
	for _, item := range in {
		item.Family = normalizedOr(strings.ToLower(item.Family), "unknown")
		item.Kind = normalizedOr(strings.ToLower(item.Kind), "runtime")
		item.Product = normalizedOr(item.Product, "UNKNOWN")
		item.Version = normalizedOr(strings.TrimPrefix(strings.TrimSpace(item.Version), "v"), "UNKNOWN")
		item.Architecture = normalizedOr(item.Architecture, "UNKNOWN")
		item.Executable = normalizedOr(item.Executable, "UNKNOWN")
		item.ExecutablePath = normalizedOr(item.ExecutablePath, "UNKNOWN")
		item.InstallPath = normalizedOr(item.InstallPath, "UNKNOWN")
		item.Distribution = normalizedOr(item.Distribution, "UNKNOWN")
		item.CollectionSource = normalizedOr(item.CollectionSource, "local runtime/framework metadata")
		if item.Confidence == "" {
			item.Confidence = evidence.ConfidenceHigh
		}
		item.ID = stableRuntimeID(item)
		key := strings.ToLower(strings.Join([]string{item.Family, item.Kind, item.Product, item.Version, item.ExecutablePath, item.InstallPath}, "\x00"))
		if old, ok := seen[key]; !ok || confidenceRank(item.Confidence) > confidenceRank(old.Confidence) {
			seen[key] = item
		}
	}
	out := make([]RuntimeItem, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if strings.ToLower(a.Product) != strings.ToLower(b.Product) {
			return strings.ToLower(a.Product) < strings.ToLower(b.Product)
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ID < b.ID
	})
	if len(out) > maxRuntimeItems {
		out = out[:maxRuntimeItems]
	}
	return out
}

func stableRuntimeID(item RuntimeItem) string {
	identity := strings.ToLower(strings.Join([]string{item.Family, item.Kind, item.Product, item.Version, item.Architecture, item.ExecutablePath, item.InstallPath}, "\x00"))
	sum := sha256.Sum256([]byte(identity))
	return "rt-" + hex.EncodeToString(sum[:10])
}

func addRuntimeSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	inv.RuntimeSources = append(inv.RuntimeSources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)})
	if state == evidence.StateDenied || state == evidence.StateDegraded || state == evidence.StateUnavailable || state == evidence.StateUnsupported {
		if strings.TrimSpace(reason) != "" {
			inv.Degraded = append(inv.Degraded, "runtime "+id+": "+strings.TrimSpace(reason))
		}
	}
}

func runtimeStateForError(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return evidence.StateDegraded
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access is denied") || strings.Contains(msg, "unauthorized") {
		return evidence.StateDenied
	}
	return evidence.StateDegraded
}

// defaultRuntimeArch exists for platform metadata that is known to match the
// current process architecture; executable probes otherwise leave architecture
// explicit as UNKNOWN instead of assuming it.
func defaultRuntimeArch() string { return runtime.GOARCH }

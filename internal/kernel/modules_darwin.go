//go:build darwin

package kernel

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type darwinLoadedModule struct {
	Identifier string
	Version    string
}

func collectLoadedModulesPlatform(ctx context.Context, _ Inventory) []ModuleAssessment {
	const provider = "macOS kmutil/kextstat + kextfind/codesign"
	var raw string
	var err error
	source := ""
	if commandAvailable("kmutil") {
		raw, err = run(ctx, "kmutil", "showloaded", "--list-only")
		source = "kmutil showloaded --list-only"
	}
	if (err != nil || strings.TrimSpace(raw) == "") && commandAvailable("kextstat") {
		raw, err = run(ctx, "kextstat", "-l")
		source = "kextstat -l"
	}
	if strings.TrimSpace(raw) == "" {
		state := evidence.StateUnavailable
		reason := "no usable loaded-kernel-extension provider was available"
		if err != nil {
			reason = "loaded kernel extension inventory failed: " + err.Error()
		}
		return []ModuleAssessment{{ID: "darwin.loaded_modules", Name: "macOS loaded kernel extensions", Kind: "kernel-extension-set", CollectionState: state, LoadState: "UNKNOWN", Provider: provider, Source: source, SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceLow, Reason: reason}}
	}

	parsed := parseDarwinLoadedModules(raw)
	if len(parsed) == 0 {
		return []ModuleAssessment{{ID: "darwin.loaded_modules", Name: "macOS loaded kernel extensions", Kind: "kernel-extension-set", CollectionState: evidence.StateObserved, LoadState: "EMPTY_OR_UNPARSED", Provider: provider, Source: source, SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceMedium, Reason: "provider returned no parseable loaded kernel-extension identifiers"}}
	}

	out := make([]ModuleAssessment, 0, len(parsed))
	for _, r := range parsed {
		if err := ctx.Err(); err != nil {
			break
		}
		m := ModuleAssessment{ID: "darwin.kext." + slug(r.Identifier), Name: r.Identifier, Kind: "macos-kernel-extension", CollectionState: evidence.StateObserved, LoadState: "LOADED", Version: r.Version, Provider: provider, Source: source, SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceHigh}
		if strings.HasPrefix(r.Identifier, "com.apple.") {
			m.Provenance = "Apple bundle identifier"
			m.TrustState = "PLATFORM_IDENTIFIER"
		}
		if commandAvailable("kextfind") {
			if p, e := run(ctx, "kextfind", "-b", r.Identifier, "-print"); e == nil {
				line := strings.TrimSpace(strings.Split(p, "\n")[0])
				if line != "" {
					m.Path = line
					if _, se := os.Stat(line); se == nil {
						m.BackingState = "PRESENT"
					} else if errors.Is(se, os.ErrNotExist) {
						m.BackingState = "DELETED_OR_MISSING"
						m.Flags = append(m.Flags, "DELETED_BACKING")
					} else if errors.Is(se, os.ErrPermission) {
						m.BackingState = "DENIED"
					}
				}
			}
		}
		if m.Path == "" {
			m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
		} else if commandAvailable("codesign") {
			sig, e := run(ctx, "codesign", "-dv", "--verbose=4", m.Path)
			if e == nil {
				m.SignatureState = "SIGNED"
				team, authority := parseCodesignIdentity(sig)
				if authority != "" {
					m.Signer = authority
				} else {
					m.Signer = team
				}
				if strings.HasPrefix(r.Identifier, "com.apple.") || strings.Contains(strings.ToLower(m.Signer), "apple") {
					m.TrustState = "PLATFORM_SIGNED"
				} else {
					m.TrustState = "THIRD_PARTY_SIGNED"
				}
				if looksDarwinTestSigner(m.Signer) {
					m.TrustState = "TEST_SIGNED"
					m.Flags = append(m.Flags, "TEST_SIGNED")
				}
			} else if strings.Contains(strings.ToLower(e.Error()), "not signed at all") {
				m.SignatureState = "UNSIGNED"
				m.TrustState = "UNSIGNED"
				m.Flags = append(m.Flags, "UNSIGNED")
			} else {
				m.CollectionState = evidence.StateDegraded
				m.Confidence = evidence.ConfidenceMedium
				m.Reason = "codesign provenance could not be resolved: " + e.Error()
			}
		}
		out = append(out, m)
	}
	return out
}

func parseDarwinLoadedModules(text string) []darwinLoadedModule {
	out := []darwinLoadedModule{}
	seen := map[string]struct{}{}
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "Index ") || strings.HasPrefix(line, "No variant") {
			continue
		}
		open := strings.Index(line, "(")
		close := strings.Index(line, ")")
		if open < 1 || close <= open {
			continue
		}
		before := strings.Fields(strings.TrimSpace(line[:open]))
		if len(before) == 0 {
			continue
		}
		id := before[len(before)-1]
		if !strings.Contains(id, ".") {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, darwinLoadedModule{Identifier: id, Version: strings.TrimSpace(line[open+1 : close])})
	}
	return out
}

func parseCodesignIdentity(text string) (team, authority string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TeamIdentifier=") {
			team = strings.TrimPrefix(line, "TeamIdentifier=")
		}
		if strings.HasPrefix(line, "Authority=") && authority == "" {
			authority = strings.TrimPrefix(line, "Authority=")
		}
	}
	return team, authority
}

func looksDarwinTestSigner(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "test") || strings.Contains(s, "development") || strings.Contains(s, "debug")
}

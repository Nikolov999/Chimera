//go:build darwin

package processes

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxDarwinTrustEnrichmentPaths = 1024

func enrichTrust(ctx context.Context, inv *Inventory) {
	codesign, codesignErr := exec.LookPath("codesign")
	pkgutil, pkgutilErr := exec.LookPath("pkgutil")
	cache := map[string]TrustContext{}
	probed := 0
	degraded := 0
	for i := range inv.Processes {
		if ctx.Err() != nil {
			inv.Degraded = append(inv.Degraded, "process trust enrichment: "+ctx.Err().Error())
			break
		}
		p := &inv.Processes[i]
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" || p.Trust.DeletedBacking {
			continue
		}
		key := filepath.Clean(path)
		if cached, ok := cache[key]; ok {
			p.Trust = cached
			continue
		}
		if probed >= maxDarwinTrustEnrichmentPaths {
			if p.Trust.Reason == "" {
				p.Trust.Reason = fmt.Sprintf("trust enrichment bounded at %d unique executable paths", maxDarwinTrustEnrichmentPaths)
			}
			continue
		}
		probed++
		t := p.Trust
		if codesignErr == nil {
			state, sig, basis, reason := verifyDarwinCodeSignature(ctx, codesign, key)
			t.State, t.Signature, t.Basis, t.Reason = state, sig, basis, reason
			if state == "UNKNOWN" {
				degraded++
			}
		} else if pkgutilErr == nil {
			if pkg := darwinPackageOwner(ctx, pkgutil, key); pkg != "" {
				t.State = "PACKAGE_MANAGED"
				t.Basis = "macOS package receipt provenance via pkgutil: " + pkg
				t.Reason = ""
			} else if t.Reason == "" {
				t.Reason = "codesign unavailable and package receipt provenance was not established"
			}
		} else if t.Reason == "" {
			t.Reason = "codesign and pkgutil are unavailable"
		}
		cache[key] = t
		p.Trust = t
	}

	state := evidence.StateObserved
	reason := ""
	source := "macOS codesign executable trust verification"
	if codesignErr != nil && pkgutilErr != nil {
		state = evidence.StateUnavailable
		source = "macOS executable trust provenance"
		reason = "codesign and pkgutil executables were not found"
	} else if codesignErr != nil {
		state = evidence.StateDegraded
		source = "macOS package receipt provenance via pkgutil"
		reason = "codesign executable was not found; package provenance used as a fallback"
	} else if degraded > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("%d executable signature verification result(s) were unresolved", degraded)
	}
	addSource(inv, "macos-executable-trust", state, source, probed, reason)
}

func verifyDarwinCodeSignature(ctx context.Context, codesign, path string) (state, signature, basis, reason string) {
	cmd := exec.CommandContext(ctx, codesign, "--verify", "--strict", "--verbose=2", path)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		return "SIGNED_VALID", "VALID", "macOS codesign verification", ""
	}
	if ctx.Err() != nil {
		return "UNKNOWN", "UNKNOWN", "macOS codesign verification", ctx.Err().Error()
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "code object is not signed at all"), strings.Contains(lower, "not signed"):
		return "UNSIGNED", "NOT_SIGNED", "macOS codesign verification", "codesign reports that the executable is not signed"
	case strings.Contains(lower, "invalid signature"), strings.Contains(lower, "a sealed resource is missing or invalid"), strings.Contains(lower, "resource envelope is obsolete"), strings.Contains(lower, "code or signature modified"), strings.Contains(lower, "cssmerr_tp_not_trusted"):
		return "SIGNATURE_UNTRUSTED", "INVALID", "macOS codesign verification", normalizedTrustReason(text, err)
	default:
		return "UNKNOWN", "UNKNOWN", "macOS codesign verification", normalizedTrustReason(text, err)
	}
}

func darwinPackageOwner(ctx context.Context, pkgutil, path string) string {
	out, err := exec.CommandContext(ctx, pkgutil, "--file-info", path).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "pkgid:") {
			return strings.TrimSpace(line[len("pkgid:"):])
		}
	}
	return ""
}

func normalizedTrustReason(text string, err error) string {
	text = strings.TrimSpace(text)
	if text != "" {
		return text
	}
	if err != nil {
		return err.Error()
	}
	return "trust verification failed without diagnostic output"
}

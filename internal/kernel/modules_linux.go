//go:build linux

package kernel

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type linuxLoadedModule struct {
	Name  string
	State string
	Taint string
}

func collectLoadedModulesPlatform(ctx context.Context, _ Inventory) []ModuleAssessment {
	const provider = "Linux /proc/modules + sysfs/modinfo"
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		state := evidence.StateUnavailable
		if errors.Is(err, os.ErrPermission) {
			state = evidence.StateDenied
		} else if errors.Is(err, os.ErrNotExist) {
			state = evidence.StateUnsupported
		}
		return []ModuleAssessment{{
			ID: "linux.loaded_modules", Name: "Linux loaded kernel modules", Kind: "kernel-module-set",
			CollectionState: state, LoadState: "UNKNOWN", Provider: provider, Source: "/proc/modules",
			SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN",
			Confidence: evidence.ConfidenceLow, Reason: "loaded module inventory could not be read: " + err.Error(),
		}}
	}

	parsed := parseProcModules(string(b))
	if len(parsed) == 0 {
		return []ModuleAssessment{{
			ID: "linux.loaded_modules", Name: "Linux loaded kernel modules", Kind: "kernel-module-set",
			CollectionState: evidence.StateObserved, LoadState: "EMPTY", Provider: provider, Source: "/proc/modules",
			SignatureState: "NOT_APPLICABLE", TrustState: "NOT_APPLICABLE", BackingState: "NOT_APPLICABLE",
			Confidence: evidence.ConfidenceExact, Reason: "no loadable kernel modules are listed in /proc/modules",
		}}
	}

	out := make([]ModuleAssessment, 0, len(parsed))
	haveModinfo := commandAvailable("modinfo")
	for _, lm := range parsed {
		if err := ctx.Err(); err != nil {
			break
		}
		m := ModuleAssessment{
			ID: "linux.module." + slug(lm.Name), Name: lm.Name, Kind: "linux-kernel-module",
			CollectionState: evidence.StateObserved, LoadState: strings.ToUpper(lm.State),
			Provider: provider, Source: "/proc/modules", SignatureState: "UNKNOWN", TrustState: "UNKNOWN",
			BackingState: "UNKNOWN", Taint: lm.Taint, Confidence: evidence.ConfidenceHigh,
		}
		applyLinuxTaint(&m, lm.Taint)

		if !haveModinfo {
			m.Provenance = "modinfo unavailable"
			m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
			m.Reason = "module is loaded, but modinfo is unavailable for backing-file and signing provenance"
			out = append(out, m)
			continue
		}

		path, pathErr := modinfoField(ctx, lm.Name, "filename")
		version, _ := modinfoField(ctx, lm.Name, "version")
		signer, signerErr := modinfoField(ctx, lm.Name, "signer")
		sigID, _ := modinfoField(ctx, lm.Name, "sig_id")
		intree, _ := modinfoField(ctx, lm.Name, "intree")
		license, _ := modinfoField(ctx, lm.Name, "license")

		m.Version = strings.TrimSpace(version)
		if license != "" {
			m.Provenance = "license=" + license
		}
		if pathErr == nil {
			m.Path = strings.TrimSpace(path)
			if m.Path == "(builtin)" {
				m.BackingState = "BUILT_IN"
			} else if m.Path != "" {
				if _, statErr := os.Stat(m.Path); statErr == nil {
					m.BackingState = "PRESENT"
				} else if errors.Is(statErr, os.ErrNotExist) {
					m.BackingState = "DELETED_OR_MISSING"
					m.Flags = append(m.Flags, "DELETED_BACKING")
				} else if errors.Is(statErr, os.ErrPermission) {
					m.BackingState = "DENIED"
				} else {
					m.BackingState = "UNAVAILABLE"
				}
			}
		}
		if m.Path == "" && pathErr != nil {
			m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
		}

		if signerErr == nil {
			m.Signer = strings.TrimSpace(signer)
			if m.Signer != "" || strings.TrimSpace(sigID) != "" {
				m.SignatureState = "SIGNED"
				m.TrustState = "SIGNED"
				if looksTestSigner(m.Signer) {
					m.TrustState = "TEST_SIGNED"
					m.Flags = append(m.Flags, "TEST_SIGNED")
				}
			} else {
				m.SignatureState = "UNSIGNED"
				if !containsFlag(m.Flags, "UNSIGNED") {
					m.Flags = append(m.Flags, "UNSIGNED")
				}
				if m.TrustState == "UNKNOWN" {
					m.TrustState = "UNSIGNED"
				}
			}
		}

		switch strings.ToLower(strings.TrimSpace(intree)) {
		case "y", "yes", "1", "true":
			v := false
			m.OutOfTree = &v
			if m.TrustState == "UNKNOWN" && m.SignatureState == "SIGNED" {
				m.TrustState = "SIGNED_IN_TREE"
			}
		case "n", "no", "0", "false":
			v := true
			m.OutOfTree = &v
			m.Flags = append(m.Flags, "OUT_OF_TREE")
			if m.TrustState == "UNKNOWN" {
				m.TrustState = "OUT_OF_TREE"
			}
		}

		if m.Path == "" && m.BackingState == "UNKNOWN" {
			m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
		}
		out = append(out, m)
	}
	return out
}

func parseProcModules(text string) []linuxLoadedModule {
	out := []linuxLoadedModule{}
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 5 {
			continue
		}
		state := f[4]
		taint := ""
		for _, token := range f[5:] {
			if strings.HasPrefix(token, "(") && strings.HasSuffix(token, ")") {
				taint = strings.Trim(token, "()")
			}
		}
		out = append(out, linuxLoadedModule{Name: f[0], State: state, Taint: taint})
	}
	return out
}

func applyLinuxTaint(m *ModuleAssessment, taint string) {
	for _, r := range taint {
		switch r {
		case 'E':
			m.SignatureState = "UNSIGNED"
			m.TrustState = "UNSIGNED"
			m.Flags = append(m.Flags, "UNSIGNED")
		case 'O':
			v := true
			m.OutOfTree = &v
			m.Flags = append(m.Flags, "OUT_OF_TREE")
			if m.TrustState == "UNKNOWN" {
				m.TrustState = "OUT_OF_TREE"
			}
		}
	}
}

func modinfoField(ctx context.Context, name, field string) (string, error) {
	s, err := run(ctx, "modinfo", "-F", field, name)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return "", nil
	}
	return strings.TrimSpace(lines[0]), nil
}

func looksTestSigner(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "test") || strings.Contains(s, "development") || strings.Contains(s, "debug")
}

func containsFlag(in []string, want string) bool {
	for _, s := range in {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

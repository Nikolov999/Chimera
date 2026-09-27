//go:build linux

package kernel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectIntegrityControls(ctx context.Context, k Inventory) []ControlAssessment {
	_ = ctx
	return []ControlAssessment{
		collectLinuxLockdown(),
		collectLinuxModuleSignatureEnforcement(k),
	}
}

func collectLinuxLockdown() ControlAssessment {
	const id = "linux.kernel_lockdown"
	const name = "Linux kernel lockdown"
	const provider = "Linux Security Framework lockdown state"
	const source = "/sys/kernel/security/lockdown"

	b, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return unavailableControl(id, name, evidence.StateDenied, provider, source, "permission denied while reading kernel lockdown state", evidence.ConfidenceHigh)
		}
		if errors.Is(err, os.ErrNotExist) {
			return unavailableControl(id, name, evidence.StateUnsupported, provider, source, "kernel lockdown state is not exposed by this running kernel", evidence.ConfidenceHigh)
		}
		return unavailableControl(id, name, evidence.StateUnavailable, provider, source, "kernel lockdown state could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	mode, ok := parseLinuxLockdownMode(string(b))
	if !ok {
		return unavailableControl(id, name, evidence.StateDegraded, provider, source, "kernel lockdown provider returned an unrecognized state", evidence.ConfidenceLow)
	}
	enabled := mode != "none"
	state := strings.ToUpper(mode)
	if mode == "none" {
		state = "DISABLED"
	}
	return observedControl(id, name, state, mode, provider, source, boolPtr(enabled), evidence.ConfidenceExact)
}

func parseLinuxLockdownMode(text string) (string, bool) {
	// The kernel exposes choices such as: "none [integrity] confidentiality".
	// The active choice is enclosed in square brackets.
	fields := strings.Fields(strings.TrimSpace(text))
	for _, f := range fields {
		if strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]") && len(f) > 2 {
			v := strings.ToLower(strings.Trim(f, "[]"))
			switch v {
			case "none", "integrity", "confidentiality":
				return v, true
			}
		}
	}
	// Some providers/tests may expose only the active token.
	if len(fields) == 1 {
		v := strings.ToLower(strings.Trim(fields[0], "[]"))
		switch v {
		case "none", "integrity", "confidentiality":
			return v, true
		}
	}
	return "", false
}

func collectLinuxModuleSignatureEnforcement(k Inventory) ControlAssessment {
	const id = "linux.module_signature_enforcement"
	const name = "Linux module signature enforcement"
	const provider = "Linux module loader signature policy"

	runtimePaths := []string{
		"/sys/module/module/parameters/sig_enforce",
		"/proc/sys/kernel/module_sig_enforce",
	}
	for _, path := range runtimePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return unavailableControl(id, name, evidence.StateDenied, provider, path, "permission denied while reading module signature enforcement state", evidence.ConfidenceHigh)
			}
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return unavailableControl(id, name, evidence.StateUnavailable, provider, path, "module signature enforcement state could not be read: "+err.Error(), evidence.ConfidenceLow)
		}
		enabled, ok := parseBoolControl(string(b))
		if !ok {
			return unavailableControl(id, name, evidence.StateDegraded, provider, path, "module signature enforcement provider returned an unrecognized value", evidence.ConfidenceLow)
		}
		state := "DISABLED"
		if enabled {
			state = "ENFORCED"
		}
		return observedControl(id, name, state, "runtime", provider, path, boolPtr(enabled), evidence.ConfidenceExact)
	}

	// Runtime policy is preferable. A locally installed kernel configuration is
	// used only as a high-confidence fallback when the runtime parameter is not
	// exposed. CONFIG_MODULE_SIG_FORCE=y means unsigned modules are rejected by
	// the module loader by build-time policy.
	configCandidates := []string{}
	if strings.TrimSpace(k.KernelRelease) != "" {
		configCandidates = append(configCandidates, filepath.Join("/boot", "config-"+strings.TrimSpace(k.KernelRelease)))
	}
	configCandidates = append(configCandidates, "/proc/config")
	for _, path := range configCandidates {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		force, found := kernelConfigBool(string(b), "CONFIG_MODULE_SIG_FORCE")
		if found {
			state := "DISABLED"
			if force {
				state = "ENFORCED"
			}
			return observedControl(id, name, state, "build-time kernel policy", provider, path+":CONFIG_MODULE_SIG_FORCE", boolPtr(force), evidence.ConfidenceHigh)
		}
		if supported, found := kernelConfigBool(string(b), "CONFIG_MODULE_SIG"); found && !supported {
			return unavailableControl(id, name, evidence.StateUnsupported, provider, path+":CONFIG_MODULE_SIG", "running kernel configuration reports module signature support disabled", evidence.ConfidenceHigh)
		}
	}

	return unavailableControl(id, name, evidence.StateUnavailable, provider, strings.Join(runtimePaths, ", "), "running kernel did not expose a readable module signature enforcement state and no readable kernel configuration fallback was found", evidence.ConfidenceMedium)
}

func kernelConfigBool(text, key string) (bool, bool) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == key+"=y" {
			return true, true
		}
		if line == key+"=n" || line == "# "+key+" is not set" {
			return false, true
		}
	}
	return false, false
}

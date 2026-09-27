//go:build linux

package kernel

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMandatoryAccessPlatform(ctx context.Context, _ Inventory) []MandatoryAccessAssessment {
	_ = ctx
	const lsmPath = "/sys/kernel/security/lsm"
	active, lsmState, lsmReason := readLinuxLSMStack(lsmPath)

	out := []MandatoryAccessAssessment{
		linuxLSMStackAssessment(active, lsmState, lsmReason),
		linuxSELinuxAssessment(active, lsmState),
		linuxAppArmorAssessment(active, lsmState),
	}
	return out
}

func readLinuxLSMStack(path string) ([]string, evidence.State, string) {
	b, err := os.ReadFile(path)
	if err == nil {
		return parseLinuxLSMList(string(b)), evidence.StateObserved, ""
	}
	if os.IsPermission(err) {
		return nil, evidence.StateDenied, "permission denied while reading active Linux Security Module stack"
	}
	if os.IsNotExist(err) {
		return nil, evidence.StateUnavailable, "kernel did not expose /sys/kernel/security/lsm"
	}
	return nil, evidence.StateUnavailable, "active Linux Security Module stack could not be read: " + err.Error()
}

func linuxLSMStackAssessment(active []string, state evidence.State, reason string) MandatoryAccessAssessment {
	const id = "linux.lsm.stack"
	const name = "Linux Security Module stack"
	const provider = "Linux securityfs"
	const source = "/sys/kernel/security/lsm"
	if state != evidence.StateObserved {
		return unavailableMandatoryAccess(id, name, "LSM", state, provider, source, reason, evidence.ConfidenceHigh)
	}
	if len(active) == 0 {
		return unavailableMandatoryAccess(id, name, "LSM", evidence.StateDegraded, provider, source, "LSM provider returned an empty active-module list", evidence.ConfidenceLow)
	}
	return observedMandatoryAccess(id, name, "LSM", "ACTIVE", strings.Join(active, ","), provider, source, boolPtr(true), evidence.ConfidenceExact)
}

func linuxSELinuxAssessment(active []string, lsmState evidence.State) MandatoryAccessAssessment {
	const id = "linux.selinux"
	const name = "SELinux mandatory access control"
	const provider = "SELinux securityfs and active LSM stack"
	const source = "/sys/fs/selinux/enforce; /sys/kernel/security/lsm"

	b, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err == nil {
		switch strings.TrimSpace(string(b)) {
		case "1":
			return observedMandatoryAccess(id, name, "SELinux", "ENFORCING", "enforcing", provider, source, boolPtr(true), evidence.ConfidenceExact)
		case "0":
			return observedMandatoryAccess(id, name, "SELinux", "PERMISSIVE", "permissive", provider, source, boolPtr(true), evidence.ConfidenceExact)
		default:
			return unavailableMandatoryAccess(id, name, "SELinux", evidence.StateDegraded, provider, source, "SELinux enforce provider returned an unrecognized value", evidence.ConfidenceLow)
		}
	}
	if os.IsPermission(err) {
		return unavailableMandatoryAccess(id, name, "SELinux", evidence.StateDenied, provider, source, "permission denied while reading SELinux enforcement mode", evidence.ConfidenceHigh)
	}
	if lsmState == evidence.StateObserved && !containsFold(active, "selinux") {
		return observedMandatoryAccess(id, name, "SELinux", "INACTIVE", "not present in active LSM stack", provider, source, boolPtr(false), evidence.ConfidenceExact)
	}
	if lsmState == evidence.StateObserved && containsFold(active, "selinux") {
		return unavailableMandatoryAccess(id, name, "SELinux", evidence.StateDegraded, provider, source, "SELinux is active in the LSM stack but enforcement mode was not observable", evidence.ConfidenceMedium)
	}
	return unavailableMandatoryAccess(id, name, "SELinux", evidence.StateUnavailable, provider, source, "SELinux mode and active-LSM membership could not be determined", evidence.ConfidenceLow)
}

func linuxAppArmorAssessment(active []string, lsmState evidence.State) MandatoryAccessAssessment {
	const id = "linux.apparmor"
	const name = "AppArmor mandatory access control"
	const provider = "AppArmor kernel parameters/securityfs and active LSM stack"
	const source = "/sys/module/apparmor/parameters/enabled; /sys/kernel/security/apparmor/profiles; /sys/kernel/security/lsm"

	enabledPath := "/sys/module/apparmor/parameters/enabled"
	b, err := os.ReadFile(enabledPath)
	if err == nil {
		enabled, ok := parseBoolControl(string(b))
		if !ok {
			return unavailableMandatoryAccess(id, name, "AppArmor", evidence.StateDegraded, provider, source, "AppArmor enabled provider returned an unrecognized value", evidence.ConfidenceLow)
		}
		if !enabled {
			return observedMandatoryAccess(id, name, "AppArmor", "DISABLED", "kernel parameter disabled", provider, source, boolPtr(false), evidence.ConfidenceExact)
		}
		mode := "enabled; profile enforcement counts unavailable"
		confidence := evidence.ConfidenceHigh
		if profiles, perr := os.ReadFile("/sys/kernel/security/apparmor/profiles"); perr == nil {
			total, enforce, complain, other := summarizeAppArmorProfiles(string(profiles))
			mode = fmt.Sprintf("enabled; profiles=%d; enforce=%d; complain=%d; other=%d", total, enforce, complain, other)
			confidence = evidence.ConfidenceExact
		} else if os.IsPermission(perr) {
			mode = "enabled; profile list denied"
		}
		return observedMandatoryAccess(id, name, "AppArmor", "ENABLED", mode, provider, source, boolPtr(true), confidence)
	}
	if os.IsPermission(err) {
		return unavailableMandatoryAccess(id, name, "AppArmor", evidence.StateDenied, provider, source, "permission denied while reading AppArmor enabled state", evidence.ConfidenceHigh)
	}
	if lsmState == evidence.StateObserved && containsFold(active, "apparmor") {
		return observedMandatoryAccess(id, name, "AppArmor", "ACTIVE", "present in active LSM stack; detailed provider unavailable", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	}
	if lsmState == evidence.StateObserved && !containsFold(active, "apparmor") {
		return observedMandatoryAccess(id, name, "AppArmor", "INACTIVE", "not present in active LSM stack", provider, source, boolPtr(false), evidence.ConfidenceExact)
	}
	return unavailableMandatoryAccess(id, name, "AppArmor", evidence.StateUnavailable, provider, source, "AppArmor state and active-LSM membership could not be determined", evidence.ConfidenceLow)
}

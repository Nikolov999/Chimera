package overview

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type evidenceSources struct {
	OS        string
	Kernel    string
	Boot      string
	Privilege string
	CPU       string
	Memory    string
	Processes string
	Listeners string
}

func buildEvidence(o Overview) []evidence.Observation {
	s := sourcesForPlatform()
	at := o.CollectedAt
	out := make([]evidence.Observation, 0, 28+len(o.SecurityControls))

	out = append(out, stringObservation("host.hostname", o.Hostname, "os.Hostname", at, evidence.ConfidenceExact, degradationReason(o, "hostname")))
	out = append(out, stringObservation("host.current_user", o.CurrentUser, "os/user.Current", at, evidence.ConfidenceHigh, degradationReason(o, "current user")))
	out = append(out, stringObservation("host.os.name", o.OS, s.OS, at, evidence.ConfidenceHigh, degradationReason(o, "os-release", "os metadata")))
	out = append(out, optionalStringObservation("host.os.version", o.OSVersion, s.OS, at, evidence.ConfidenceHigh, degradationReason(o, "os-release", "os metadata"), "OS version was not observable"))
	out = append(out, optionalStringObservation("host.os.build", o.OSBuild, s.OS, at, evidence.ConfidenceHigh, degradationReason(o, "os-release", "os metadata"), "OS build was not observable"))
	out = append(out, stringObservation("host.kernel", o.Kernel, s.Kernel, at, evidence.ConfidenceHigh, degradationReason(o, "kernel")))
	out = append(out, stringObservation("host.architecture", o.Architecture, "Go runtime", at, evidence.ConfidenceExact, ""))

	if o.BootTime != nil {
		out = append(out, evidence.NewObserved("host.boot_time", o.BootTime.UTC(), s.Boot, at, evidence.ConfidenceHigh))
	} else {
		out = append(out, evidence.NewState("host.boot_time", evidence.StateUnavailable, s.Boot, at, evidence.ConfidenceHigh, fallbackReason(degradationReason(o, "uptime", "os metadata"), "boot time was not observable")))
	}
	if o.UptimeSeconds > 0 {
		out = append(out, evidence.NewObserved("host.uptime_seconds", o.UptimeSeconds, s.Boot, at, evidence.ConfidenceHigh))
	} else {
		out = append(out, evidence.NewState("host.uptime_seconds", evidence.StateUnavailable, s.Boot, at, evidence.ConfidenceHigh, fallbackReason(degradationReason(o, "uptime", "os metadata"), "uptime was not observable")))
	}

	privilegeKnown := strings.TrimSpace(o.Privilege.Level) != "" && !strings.EqualFold(o.Privilege.Level, "unknown")
	if privilegeKnown {
		out = append(out, evidence.NewObserved("host.privilege", o.Privilege, s.Privilege, at, evidence.ConfidenceHigh))
		out = append(out, evidence.NewObserved("host.privilege.schema", o.Privilege.Schema, "privilege context", at, evidence.ConfidenceExact))
		out = append(out, evidence.NewObserved("host.privilege.elevated", o.Privilege.Elevated, s.Privilege, at, evidence.ConfidenceExact))
		out = append(out, evidence.NewObserved("host.privilege.collection_tier", o.Privilege.CollectionTier, s.Privilege, at, evidence.ConfidenceExact))
		out = append(out, evidence.NewObserved("host.privilege.administrative_group_state", o.Privilege.AdministrativeGroup, s.Privilege, at, evidence.ConfidenceHigh))
		out = append(out, evidence.NewObserved("host.privilege.deeper_evidence_available", o.Privilege.DeeperEvidenceAvailable, "privilege-aware collection policy", at, evidence.ConfidenceExact))
		out = append(out, evidence.NewObserved("host.privilege.elevation_note", o.Privilege.ElevationNote, "privilege-aware collection policy", at, evidence.ConfidenceExact))
		if strings.TrimSpace(o.Privilege.ElevationState) != "" {
			out = append(out, evidence.NewObserved("host.privilege.elevation_state", o.Privilege.ElevationState, s.Privilege, at, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState("host.privilege.elevation_state", evidence.StateUnavailable, s.Privilege, at, evidence.ConfidenceMedium, "platform did not expose a more specific elevation state"))
		}
		if strings.TrimSpace(o.Privilege.IntegrityLevel) != "" {
			out = append(out, evidence.NewObserved("host.privilege.integrity_level", o.Privilege.IntegrityLevel, s.Privilege, at, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState("host.privilege.integrity_level", evidence.StateNotApplicable, s.Privilege, at, evidence.ConfidenceExact, "integrity levels are not exposed as a normalized privilege concept on this platform"))
		}
	} else {
		reason := strings.TrimSpace(o.Privilege.Detail)
		if reason == "" {
			reason = "effective privilege could not be determined"
		}
		out = append(out, evidence.NewState("host.privilege", evidence.StateUnavailable, s.Privilege, at, evidence.ConfidenceMedium, reason))
		out = append(out, evidence.NewObserved("host.privilege.schema", o.Privilege.Schema, "privilege context", at, evidence.ConfidenceExact))
		out = append(out, evidence.NewState("host.privilege.elevated", evidence.StateUnavailable, s.Privilege, at, evidence.ConfidenceMedium, reason))
		out = append(out, evidence.NewObserved("host.privilege.collection_tier", o.Privilege.CollectionTier, s.Privilege, at, evidence.ConfidenceExact))
		out = append(out, evidence.NewObserved("host.privilege.administrative_group_state", o.Privilege.AdministrativeGroup, s.Privilege, at, evidence.ConfidenceMedium))
		out = append(out, evidence.NewState("host.privilege.deeper_evidence_available", evidence.StateUnavailable, "privilege-aware collection policy", at, evidence.ConfidenceMedium, "elevation benefit cannot be determined while effective privilege is unknown"))
		out = append(out, evidence.NewObserved("host.privilege.elevation_note", o.Privilege.ElevationNote, "privilege-aware collection policy", at, evidence.ConfidenceExact))
		out = append(out, evidence.NewState("host.privilege.elevation_state", evidence.StateUnavailable, s.Privilege, at, evidence.ConfidenceMedium, reason))
		out = append(out, evidence.NewState("host.privilege.integrity_level", evidence.StateUnavailable, s.Privilege, at, evidence.ConfidenceLow, "effective privilege context unavailable"))
	}

	out = append(out, optionalStringObservation("host.cpu.model", o.CPUModel, s.CPU, at, evidence.ConfidenceHigh, "", "CPU model was not observable"))
	if o.LogicalCPUs > 0 {
		out = append(out, evidence.NewObserved("host.cpu.logical_count", o.LogicalCPUs, "Go runtime", at, evidence.ConfidenceExact))
	} else {
		out = append(out, evidence.NewState("host.cpu.logical_count", evidence.StateUnavailable, "Go runtime", at, evidence.ConfidenceExact, "logical CPU count was not observable"))
	}
	if o.MemoryTotalBytes > 0 {
		out = append(out, evidence.NewObserved("host.memory.total_bytes", o.MemoryTotalBytes, s.Memory, at, evidence.ConfidenceHigh))
	} else {
		out = append(out, evidence.NewState("host.memory.total_bytes", evidence.StateUnavailable, s.Memory, at, evidence.ConfidenceHigh, fallbackReason(degradationReason(o, "os metadata"), "total memory was not observable")))
	}
	if o.ProcessCount > 0 {
		out = append(out, evidence.NewObserved("host.process.count", o.ProcessCount, s.Processes, at, evidence.ConfidenceHigh))
	} else {
		out = append(out, evidence.NewState("host.process.count", evidence.StateUnavailable, s.Processes, at, evidence.ConfidenceHigh, fallbackReason(degradationReason(o, "process count"), "process count was not observable")))
	}
	if reason := degradationReason(o, "listeners"); reason != "" {
		out = append(out, evidence.NewState("host.network.tcp_listener_count", evidence.StateUnavailable, s.Listeners, at, evidence.ConfidenceHigh, reason))
	} else {
		// Zero listeners is a legitimate observed value.
		out = append(out, evidence.NewObserved("host.network.tcp_listener_count", o.ListenerCount, s.Listeners, at, evidence.ConfidenceHigh))
	}
	out = append(out, stringObservation("host.network.listener_scope", o.ListenerScope, "overview collector", at, evidence.ConfidenceExact, ""))

	seenControls := map[string]int{}
	for _, c := range o.SecurityControls {
		base := slug(c.Name)
		if base == "" {
			base = "unnamed"
		}
		seenControls[base]++
		key := "security.control." + base
		if seenControls[base] > 1 {
			key = fmt.Sprintf("%s.%d", key, seenControls[base])
		}
		out = append(out, controlObservation(key, c, at))
	}

	if len(o.Degraded) == 0 {
		out = append(out, evidence.NewObserved("overview.collection_health", "complete", "overview collector", at, evidence.ConfidenceExact))
	} else {
		out = append(out, evidence.NewState("overview.collection_health", evidence.StateDegraded, "overview collector", at, evidence.ConfidenceExact, strings.Join(o.Degraded, "; ")))
	}
	return out
}

func stringObservation(key, value, source string, at time.Time, confidence evidence.Confidence, reason string) evidence.Observation {
	if strings.TrimSpace(value) != "" {
		return evidence.NewObserved(key, value, source, at, confidence)
	}
	return evidence.NewState(key, evidence.StateUnavailable, source, at, confidence, fallbackReason(reason, key+" was not observable"))
}

func optionalStringObservation(key, value, source string, at time.Time, confidence evidence.Confidence, reason, fallback string) evidence.Observation {
	if strings.TrimSpace(value) != "" {
		return evidence.NewObserved(key, value, source, at, confidence)
	}
	return evidence.NewState(key, evidence.StateUnavailable, source, at, confidence, fallbackReason(reason, fallback))
}

func controlObservation(key string, c Control, at time.Time) evidence.Observation {
	source := strings.TrimSpace(c.Source)
	if source == "" {
		source = "platform security-control collector"
	}
	state := strings.ToLower(strings.TrimSpace(c.State))
	switch state {
	case "denied":
		return evidence.NewState(key, evidence.StateDenied, source, at, evidence.ConfidenceHigh, fallbackReason(c.Detail, "access to control state was denied"))
	case "unavailable":
		return evidence.NewState(key, evidence.StateUnavailable, source, at, evidence.ConfidenceHigh, fallbackReason(c.Detail, "control state was unavailable"))
	case "unsupported":
		return evidence.NewState(key, evidence.StateUnsupported, source, at, evidence.ConfidenceExact, fallbackReason(c.Detail, "control is unsupported on this platform"))
	case "not_applicable", "not-applicable", "n/a":
		return evidence.NewState(key, evidence.StateNotApplicable, source, at, evidence.ConfidenceExact, fallbackReason(c.Detail, "control is not applicable"))
	case "unknown", "":
		return evidence.NewState(key, evidence.StateDegraded, source, at, evidence.ConfidenceMedium, fallbackReason(c.Detail, "control was detected but its state could not be determined"))
	default:
		return evidence.NewObserved(key, c.State, source, at, evidence.ConfidenceHigh)
	}
}

func degradationReason(o Overview, prefixes ...string) string {
	for _, d := range o.Degraded {
		trimmed := strings.TrimSpace(d)
		lower := strings.ToLower(trimmed)
		for _, p := range prefixes {
			if strings.HasPrefix(lower, strings.ToLower(strings.TrimSpace(p))+":") {
				return trimmed
			}
		}
	}
	return ""
}

func fallbackReason(reason, fallback string) string {
	if strings.TrimSpace(reason) != "" {
		return strings.TrimSpace(reason)
	}
	return fallback
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	underscore := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			underscore = false
		default:
			if b.Len() > 0 && !underscore {
				b.WriteByte('_')
				underscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func sourcesForPlatform() evidenceSources {
	switch runtime.GOOS {
	case "linux":
		return evidenceSources{
			OS: "/etc/os-release", Kernel: "uname -r", Boot: "/proc/uptime",
			Privilege: "os.Geteuid/os.Getegid", CPU: "/proc/cpuinfo", Memory: "/proc/meminfo",
			Processes: "/proc", Listeners: "/proc/net/tcp,/proc/net/tcp6",
		}
	case "windows":
		return evidenceSources{
			OS: "Win32_OperatingSystem/CIM", Kernel: "Environment.OSVersion", Boot: "Win32_OperatingSystem/CIM",
			Privilege: "WindowsIdentity/WindowsPrincipal token metadata", CPU: "Win32_Processor/CIM", Memory: "Win32_OperatingSystem/CIM",
			Processes: "Get-Process", Listeners: "Get-NetTCPConnection",
		}
	case "darwin":
		return evidenceSources{
			OS: "sw_vers", Kernel: "sysctl kern.osrelease", Boot: "sysctl kern.boottime",
			Privilege: "os.Geteuid/os.Getegid", CPU: "sysctl", Memory: "sysctl hw.memsize",
			Processes: "ps", Listeners: "netstat",
		}
	default:
		return evidenceSources{
			OS: "Go runtime", Kernel: "platform collector", Boot: "platform collector",
			Privilege: "platform collector", CPU: "platform collector", Memory: "platform collector",
			Processes: "platform collector", Listeners: "platform collector",
		}
	}
}

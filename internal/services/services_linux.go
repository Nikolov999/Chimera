//go:build linux

package services

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	if path, err := exec.LookPath("systemctl"); err == nil {
		records, reason := collectSystemd(ctx, path)
		if len(records) > 0 {
			inv.Services = append(inv.Services, records...)
			state := evidence.StateObserved
			if reason != "" {
				state = evidence.StateDegraded
			}
			addSource(inv, "linux-systemd", state, "systemctl local service metadata", len(records), reason)
			hardeningCount, hardeningDegraded := systemdHardeningSourceState(records)
			hardeningState := evidence.StateObserved
			if hardeningDegraded != "" {
				hardeningState = evidence.StateDegraded
			}
			addSource(inv, "linux-systemd-hardening", hardeningState, "systemctl effective hardening properties", hardeningCount, hardeningDegraded)
			return
		}
		if reason != "" {
			addSource(inv, "linux-systemd", evidence.StateUnavailable, "systemctl local service metadata", 0, reason)
		}
	}

	records, reason := collectSystemdUnitFiles(ctx)
	if len(records) > 0 {
		inv.Services = append(inv.Services, records...)
		state := evidence.StateObserved
		if reason != "" {
			state = evidence.StateDegraded
		}
		addSource(inv, "linux-systemd-unit-files", state, "local systemd unit files", len(records), reason)
		hardeningCount, hardeningDegraded := systemdHardeningSourceState(records)
		if hardeningDegraded == "" {
			hardeningDegraded = "effective merged systemd properties unavailable; direct unit-file directives only"
		}
		addSource(inv, "linux-systemd-hardening", evidence.StateDegraded, "local systemd unit-file hardening directives", hardeningCount, hardeningDegraded)
		return
	}
	if reason != "" {
		addSource(inv, "linux-systemd-unit-files", evidence.StateUnavailable, "local systemd unit files", 0, reason)
	}

	records, reason = collectSysVInit(ctx)
	if len(records) > 0 {
		inv.Services = append(inv.Services, records...)
		addSource(inv, "linux-sysv-init", evidence.StateObserved, "/etc/init.d metadata", len(records), reason)
		return
	}
	if reason == "" {
		reason = "no supported systemd or SysV service definitions were observable"
	}
	addSource(inv, "linux-services", evidence.StateUnavailable, "Linux local service metadata", 0, reason)
}

func collectSystemd(ctx context.Context, systemctl string) ([]Service, string) {
	listCmd := exec.CommandContext(ctx, systemctl, "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	raw, err := listCmd.Output()
	if err != nil {
		return nil, commandReason(ctx, "systemctl list-unit-files", err)
	}
	names := parseSystemdUnitFileNames(string(raw))
	if len(names) == 0 {
		return nil, "systemctl returned no service unit files"
	}
	if len(names) > maxServices {
		names = names[:maxServices]
	}

	all := make([]Service, 0, len(names))
	reasons := []string{}
	const batchSize = 96
	for start := 0; start < len(names); start += batchSize {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		end := start + batchSize
		if end > len(names) {
			end = len(names)
		}
		args := []string{"show", "--no-pager",
			"--property=Id", "--property=Description", "--property=LoadState", "--property=ActiveState", "--property=SubState",
			"--property=UnitFileState", "--property=MainPID", "--property=User", "--property=Group", "--property=ExecStart",
			"--property=ExecCondition", "--property=ExecStartPre", "--property=ExecStartPost", "--property=ExecReload", "--property=ExecStop", "--property=ExecStopPost",
			"--property=FragmentPath", "--property=SourcePath", "--property=Type",
			"--property=DynamicUser", "--property=NoNewPrivileges", "--property=ProtectSystem", "--property=ProtectHome",
			"--property=PrivateTmp", "--property=PrivateDevices", "--property=PrivateNetwork", "--property=CapabilityBoundingSet",
			"--property=AmbientCapabilities", "--property=RestrictNamespaces", "--property=ProtectKernelTunables", "--property=ProtectKernelModules",
			"--property=ProtectControlGroups", "--property=RestrictSUIDSGID", "--property=LockPersonality", "--property=MemoryDenyWriteExecute",
			"--property=UMask"}
		args = append(args, names[start:end]...)
		cmd := exec.CommandContext(ctx, systemctl, args...)
		out, err := cmd.Output()
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("systemctl show batch %d-%d: %s", start, end-1, commandReason(ctx, "systemctl show", err)))
			continue
		}
		all = append(all, parseSystemdShow(string(out))...)
	}
	if len(all) == 0 {
		return nil, fallback(strings.Join(reasons, "; "), "systemctl show returned no usable service records")
	}
	// systemctl can return the same canonical Id for multiple unit-file aliases.
	// Collapse those aliases before path-integrity enrichment so identical
	// services are not assessed repeatedly and alias count differences are not
	// reported as missing service metadata. Failed batches remain explicit in
	// reasons above.
	all = normalize(all)
	return all, strings.Join(uniqueSorted(reasons), "; ")
}

func parseSystemdUnitFileNames(raw string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	s := bufio.NewScanner(strings.NewReader(raw))
	for s.Scan() {
		fields := strings.Fields(strings.TrimSpace(s.Text()))
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if !strings.HasSuffix(name, ".service") || strings.Contains(name, "@.") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func parseSystemdShow(raw string) []Service {
	blocks := splitSystemdShow(raw)
	out := make([]Service, 0, len(blocks))
	for _, m := range blocks {
		name := strings.TrimSpace(m["Id"])
		if name == "" || !strings.HasSuffix(name, ".service") {
			continue
		}
		account := strings.TrimSpace(m["User"])
		if account == "" {
			account = "root"
		}
		privilege := linuxServicePrivilege(account)
		path := systemdLifecycleExecPath(m)
		config := firstNonEmpty(m["FragmentPath"], m["SourcePath"], "systemctl service properties")
		definitionPath := firstNonEmpty(m["FragmentPath"], m["SourcePath"])
		hardening := systemdHardeningFromProperties(m, true)
		out = append(out, Service{
			Name: name, DisplayName: name, Description: m["Description"], Manager: "systemd", ServiceType: m["Type"],
			ExecutablePath: path, Account: account, AccountGroup: m["Group"], StartMode: systemdStartMode(m["UnitFileState"]),
			RuntimePID: parsePID(m["MainPID"]), RuntimeState: systemdRuntimeState(m["ActiveState"]), SubState: m["SubState"],
			PrivilegeContext: privilege, DefinitionState: m["LoadState"], DefinitionPath: definitionPath,
			ConfigurationSource: config, CollectionSource: "systemctl show", Confidence: evidence.ConfidenceHigh, SystemdHardening: hardening,
		})
	}
	return out
}

func splitSystemdShow(raw string) []map[string]string {
	out := []map[string]string{}
	current := map[string]string{}
	flush := func() {
		if len(current) > 0 {
			out = append(out, current)
			current = map[string]string{}
		}
	}
	s := bufio.NewScanner(strings.NewReader(raw))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Some systemctl versions omit blank separators when multiple units are
		// requested. A second Id starts a new record deterministically.
		if key == "Id" {
			if _, exists := current["Id"]; exists {
				flush()
			}
		}
		current[key] = value
	}
	flush()
	return out
}

func systemdExecPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" || raw == "{}" {
		return ""
	}
	if i := strings.Index(raw, "path="); i >= 0 {
		rest := strings.TrimSpace(raw[i+len("path="):])
		if j := strings.Index(rest, ";"); j >= 0 {
			rest = rest[:j]
		}
		return normalizeSystemdExecToken(strings.TrimSpace(strings.Trim(rest, "\"'{} ")))
	}
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "\"") {
		if end := strings.Index(raw[1:], "\""); end >= 0 {
			return normalizeSystemdExecToken(raw[1 : end+1])
		}
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	return normalizeSystemdExecToken(strings.Trim(fields[0], "\"'{}"))
}

// normalizeSystemdExecToken removes only the documented Exec*= executable
// prefixes that modify invocation semantics but are not part of the executable
// path itself. systemctl's effective path= form normally strips them already;
// the normalization is primarily for direct unit-file fallback parsing.
func normalizeSystemdExecToken(token string) string {
	token = strings.TrimSpace(token)
	for token != "" {
		switch token[0] {
		case '-', '@', ':', '+', '!':
			token = strings.TrimSpace(token[1:])
		default:
			return token
		}
	}
	return token
}

func systemdLifecycleExecPath(values map[string]string) string {
	for _, key := range []string{"ExecStart", "Service.ExecStart", "ExecCondition", "Service.ExecCondition", "ExecStartPre", "Service.ExecStartPre", "ExecStartPost", "Service.ExecStartPost", "ExecReload", "Service.ExecReload", "ExecStop", "Service.ExecStop", "ExecStopPost", "Service.ExecStopPost"} {
		if path := systemdExecPath(values[key]); path != "" {
			return path
		}
	}
	return ""
}

func systemdStartMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "enabled", "enabled-runtime":
		return v
	case "disabled", "masked", "static", "indirect", "generated", "transient", "linked", "linked-runtime", "alias", "bad":
		return v
	case "":
		return "UNKNOWN"
	default:
		return v
	}
}

func systemdRuntimeState(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "active", "reloading", "activating":
		return "RUNNING"
	case "inactive", "deactivating", "failed":
		return "STOPPED"
	case "":
		return "UNKNOWN"
	default:
		return v
	}
}

func linuxServicePrivilege(account string) string {
	a := strings.ToLower(strings.TrimSpace(account))
	switch a {
	case "root", "0":
		return "ROOT"
	case "", "unknown":
		return "UNKNOWN"
	default:
		return "SERVICE_ACCOUNT"
	}
}

func collectSystemdUnitFiles(ctx context.Context) ([]Service, string) {
	dirs := []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	selected := map[string]string{}
	denied := 0
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return nil, "collection deadline reached: " + err.Error()
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") || strings.Contains(entry.Name(), "@.") {
				continue
			}
			if _, exists := selected[entry.Name()]; exists {
				continue
			}
			selected[entry.Name()] = filepath.Join(dir, entry.Name())
			if len(selected) >= maxServices {
				break
			}
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Service, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			break
		}
		path := selected[name]
		rec, err := parseSystemdUnitFile(path, name)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		out = append(out, rec)
	}
	reason := ""
	if denied > 0 {
		reason = fmt.Sprintf("%d systemd unit-file locations were permission-restricted", denied)
	}
	return out, reason
}

func parseSystemdUnitFile(path, name string) (Service, error) {
	f, err := os.Open(path)
	if err != nil {
		return Service{}, err
	}
	defer f.Close()
	section := ""
	values := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch section + "." + key {
		case "Unit.Description", "Service.ExecStart", "Service.ExecCondition", "Service.ExecStartPre", "Service.ExecStartPost", "Service.ExecReload", "Service.ExecStop", "Service.ExecStopPost", "Service.User", "Service.Group", "Service.Type",
			"Service.DynamicUser", "Service.NoNewPrivileges", "Service.ProtectSystem", "Service.ProtectHome",
			"Service.PrivateTmp", "Service.PrivateDevices", "Service.PrivateNetwork", "Service.CapabilityBoundingSet",
			"Service.AmbientCapabilities", "Service.RestrictNamespaces", "Service.ProtectKernelTunables", "Service.ProtectKernelModules",
			"Service.ProtectControlGroups", "Service.RestrictSUIDSGID", "Service.LockPersonality", "Service.MemoryDenyWriteExecute",
			"Service.UMask":
			values[section+"."+key] = value
		}
	}
	if err := s.Err(); err != nil {
		return Service{}, err
	}
	account := values["Service.User"]
	if account == "" {
		account = "root"
	}
	mode := inferSystemdUnitFileMode(path, name)
	props := make(map[string]string)
	for key, value := range values {
		if strings.HasPrefix(key, "Service.") {
			props[strings.TrimPrefix(key, "Service.")] = value
		}
	}
	hardening := systemdHardeningFromProperties(props, false)
	return Service{
		Name: name, DisplayName: name, Description: values["Unit.Description"], Manager: "systemd", ServiceType: values["Service.Type"],
		ExecutablePath: systemdLifecycleExecPath(values), Account: account, AccountGroup: values["Service.Group"], StartMode: mode,
		RuntimeState: "UNKNOWN", PrivilegeContext: linuxServicePrivilege(account), DefinitionState: "LOADED_FROM_FILE", DefinitionPath: path,
		ConfigurationSource: path, CollectionSource: "systemd unit-file metadata", Confidence: evidence.ConfidenceMedium, SystemdHardening: hardening,
	}, nil
}

func inferSystemdUnitFileMode(path, name string) string {
	if target, err := os.Readlink(path); err == nil && target == "/dev/null" {
		return "MASKED"
	}
	patterns := []string{
		filepath.Join("/etc/systemd/system", "*.wants", name),
		filepath.Join("/etc/systemd/system", "*.requires", name),
		filepath.Join("/run/systemd/system", "*.wants", name),
		filepath.Join("/run/systemd/system", "*.requires", name),
	}
	for _, p := range patterns {
		if matches, _ := filepath.Glob(p); len(matches) > 0 {
			return "ENABLED"
		}
	}
	return "UNKNOWN"
}

func collectSysVInit(ctx context.Context) ([]Service, string) {
	entries, err := os.ReadDir("/etc/init.d")
	if err != nil {
		return nil, err.Error()
	}
	out := []Service{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return out, "collection deadline reached: " + err.Error()
		}
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join("/etc/init.d", entry.Name())
		info, err := entry.Info()
		if err != nil || info.Mode()&0111 == 0 {
			continue
		}
		out = append(out, Service{
			Name: entry.Name(), DisplayName: entry.Name(), Manager: "sysv-init", ServiceType: "init-script",
			Executable: entry.Name(), ExecutablePath: path, Account: "root", StartMode: "UNKNOWN", RuntimeState: "UNKNOWN",
			PrivilegeContext: "ROOT", DefinitionState: "PRESENT", DefinitionPath: path,
			ConfigurationSource: path, CollectionSource: "/etc/init.d metadata", Confidence: evidence.ConfidenceMedium,
		})
		if len(out) >= maxServices {
			break
		}
	}
	return out, "runtime state and enablement are unavailable from file-only SysV metadata"
}

func commandReason(ctx context.Context, operation string, err error) string {
	if ctx != nil && ctx.Err() != nil {
		return operation + ": " + ctx.Err().Error()
	}
	return operation + ": " + err.Error()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func systemdHardeningFromProperties(m map[string]string, effective bool) *SystemdHardening {
	userRaw := strings.TrimSpace(m["User"])
	groupRaw := strings.TrimSpace(m["Group"])
	user := userRaw
	if user == "" {
		user = "root"
	}
	group := groupRaw
	if group == "" {
		group = user
		if group == "root" {
			group = "root"
		}
	}
	caps := strings.Fields(strings.TrimSpace(m["CapabilityBoundingSet"]))
	ambient := strings.Fields(strings.TrimSpace(m["AmbientCapabilities"]))
	namespaces := strings.Fields(strings.TrimSpace(m["RestrictNamespaces"]))

	h := &SystemdHardening{
		State:                      "COMPLETE",
		User:                       user,
		Group:                      group,
		UserConfigured:             userRaw != "",
		GroupConfigured:            groupRaw != "",
		DynamicUser:                normalizeBoolState(m["DynamicUser"]),
		NoNewPrivileges:            normalizeBoolState(m["NoNewPrivileges"]),
		ProtectSystem:              normalizeProtectSystem(m["ProtectSystem"]),
		ProtectHome:                normalizeProtectHome(m["ProtectHome"]),
		PrivateTmp:                 normalizePrivateTmp(m["PrivateTmp"]),
		PrivateDevices:             normalizeBoolState(m["PrivateDevices"]),
		PrivateNetwork:             normalizeBoolState(m["PrivateNetwork"]),
		CapabilityBoundingSetState: capabilitySetState(caps, m["CapabilityBoundingSet"]),
		CapabilityBoundingSet:      caps,
		AmbientCapabilities:        ambient,
		RestrictNamespacesState:    namespaceRestrictionState(m["RestrictNamespaces"]),
		RestrictNamespaces:         namespaces,
		ProtectKernelTunables:      normalizeBoolState(m["ProtectKernelTunables"]),
		ProtectKernelModules:       normalizeBoolState(m["ProtectKernelModules"]),
		ProtectControlGroups:       normalizeBoolState(m["ProtectControlGroups"]),
		RestrictSUIDSGID:           normalizeBoolState(m["RestrictSUIDSGID"]),
		LockPersonality:            normalizeBoolState(m["LockPersonality"]),
		MemoryDenyWriteExecute:     normalizeBoolState(m["MemoryDenyWriteExecute"]),
		UMask:                      strings.TrimSpace(m["UMask"]),
	}
	if !effective {
		// Direct unit-file parsing cannot account for drop-ins, generated units,
		// manager defaults, or runtime property overrides. Preserve explicitly
		// configured directives but never turn absent directives into false passes.
		h.State = "DEGRADED"
		h.Degraded = append(h.Degraded, "effective merged systemd properties unavailable; direct unit-file directives only")
		if strings.TrimSpace(m["DynamicUser"]) == "" {
			h.DynamicUser = "UNKNOWN"
		}
		if strings.TrimSpace(m["NoNewPrivileges"]) == "" {
			h.NoNewPrivileges = "UNKNOWN"
		}
		if strings.TrimSpace(m["ProtectSystem"]) == "" {
			h.ProtectSystem = "UNKNOWN"
		}
		if strings.TrimSpace(m["ProtectHome"]) == "" {
			h.ProtectHome = "UNKNOWN"
		}
		if strings.TrimSpace(m["PrivateTmp"]) == "" {
			h.PrivateTmp = "UNKNOWN"
		}
		if strings.TrimSpace(m["PrivateDevices"]) == "" {
			h.PrivateDevices = "UNKNOWN"
		}
		if strings.TrimSpace(m["PrivateNetwork"]) == "" {
			h.PrivateNetwork = "UNKNOWN"
		}
		if strings.TrimSpace(m["CapabilityBoundingSet"]) == "" {
			h.CapabilityBoundingSetState = "UNKNOWN"
		}
		if strings.TrimSpace(m["RestrictNamespaces"]) == "" {
			h.RestrictNamespacesState = "UNKNOWN"
		}
		if strings.TrimSpace(m["ProtectKernelTunables"]) == "" {
			h.ProtectKernelTunables = "UNKNOWN"
		}
		if strings.TrimSpace(m["ProtectKernelModules"]) == "" {
			h.ProtectKernelModules = "UNKNOWN"
		}
		if strings.TrimSpace(m["ProtectControlGroups"]) == "" {
			h.ProtectControlGroups = "UNKNOWN"
		}
		if strings.TrimSpace(m["RestrictSUIDSGID"]) == "" {
			h.RestrictSUIDSGID = "UNKNOWN"
		}
		if strings.TrimSpace(m["LockPersonality"]) == "" {
			h.LockPersonality = "UNKNOWN"
		}
		if strings.TrimSpace(m["MemoryDenyWriteExecute"]) == "" {
			h.MemoryDenyWriteExecute = "UNKNOWN"
		}
	}
	h.normalize()
	return h
}

func systemdHardeningSourceState(records []Service) (int, string) {
	count := 0
	degraded := 0
	for _, svc := range records {
		if svc.SystemdHardening == nil {
			continue
		}
		count++
		if svc.SystemdHardening.State != "COMPLETE" {
			degraded++
		}
	}
	if count == 0 {
		return 0, "no systemd hardening records were observable"
	}
	if degraded > 0 {
		return count, fmt.Sprintf("%d of %d systemd hardening records are degraded", degraded, count)
	}
	return count, ""
}

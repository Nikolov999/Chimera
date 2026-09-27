package containers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	networkinv "github.com/Nikolov999/chimera/internal/network"
)

const (
	maxDeveloperProcesses = 65536
	maxDeveloperSurfaces  = 512
	maxDeveloperCmdBytes  = 64 * 1024
)

// DeveloperSurface is a normalized, redacted description of a locally active
// developer/debug control surface. Full command lines, tokens, notebook URLs,
// browser profile paths, and other argument values are never retained.
type DeveloperSurface struct {
	ID               string              `json:"id"`
	Kind             string              `json:"kind"`
	Product          string              `json:"product"`
	PID              int                 `json:"pid,omitempty"`
	ProcessName      string              `json:"process_name,omitempty"`
	Executable       string              `json:"executable,omitempty"`
	State            evidence.State      `json:"state"`
	ActivationState  string              `json:"activation_state"`
	ListenerState    string              `json:"listener_state"`
	BindingState     string              `json:"binding_state"`
	LocalAddress     string              `json:"local_address,omitempty"`
	LocalPort        uint16              `json:"local_port,omitempty"`
	Transport        string              `json:"transport,omitempty"`
	ExposureState    string              `json:"exposure_state"`
	DetectionBasis   []string            `json:"detection_basis,omitempty"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type developerProcess struct {
	PID        int
	Name       string
	Executable string
	Command    string
}

type developerCandidate struct {
	Kind           string
	Product        string
	RequestedHost  string
	RequestedPort  uint16
	DetectionBasis []string
	Confidence     evidence.Confidence
}

func collectDeveloperSurfaces(ctx context.Context, inv *Inventory, sharedNetwork *networkinv.Inventory) {
	procs, procState, procReason := collectDeveloperProcesses(ctx)
	if len(procs) > maxDeveloperProcesses {
		procs = procs[:maxDeveloperProcesses]
	}

	netInv := networkinv.Inventory{}
	netSource := "normalized local network listener inventory"
	if sharedNetwork != nil {
		netInv = *sharedNetwork
		netSource = "shared normalized local network listener inventory"
	} else {
		netInv = networkinv.Collect(ctx)
	}
	netState, netReason := developerNetworkState(netInv)
	byPID := map[int][]networkinv.Endpoint{}
	if netState == evidence.StateObserved || netState == evidence.StateDegraded {
		for _, ep := range netInv.Endpoints {
			if ep.Owner.PID > 0 {
				byPID[ep.Owner.PID] = append(byPID[ep.Owner.PID], ep)
			}
		}
	}

	for _, p := range procs {
		if len(inv.DeveloperSurfaces) >= maxDeveloperSurfaces {
			break
		}
		candidates := classifyDeveloperProcess(p)
		for _, c := range candidates {
			if len(inv.DeveloperSurfaces) >= maxDeveloperSurfaces {
				break
			}
			rec := buildDeveloperSurface(p, c, byPID[p.PID], netState)
			inv.DeveloperSurfaces = append(inv.DeveloperSurfaces, rec)
		}
	}

	if procState == evidence.StateObserved {
		addSource(inv, "developer-process-metadata", evidence.StateObserved, "local process metadata with transient redacted command-line classification", len(procs), "")
	} else {
		addSource(inv, "developer-process-metadata", procState, "local process metadata", len(procs), fallback(procReason, "process metadata unavailable"))
	}
	if netState == evidence.StateObserved {
		addSource(inv, "developer-listener-correlation", evidence.StateObserved, netSource, len(netInv.Endpoints), "")
	} else {
		addSource(inv, "developer-listener-correlation", netState, netSource, len(netInv.Endpoints), fallback(netReason, "listener metadata unavailable"))
	}
	if len(inv.DeveloperSurfaces) > 0 {
		addSource(inv, "developer-surfaces", evidence.StateObserved, "local process/debug flag and listener correlation", len(inv.DeveloperSurfaces), "")
	} else if procState == evidence.StateObserved {
		addSource(inv, "developer-surfaces", evidence.StateNotApplicable, "local process/debug flag and listener correlation", 0, "no supported active developer/debug surface was observed")
	} else {
		addSource(inv, "developer-surfaces", evidence.StateUnavailable, "local process/debug flag and listener correlation", 0, "developer surface inventory could not be completed because process metadata was unavailable")
	}
}

func developerNetworkState(inv networkinv.Inventory) (evidence.State, string) {
	if err := inv.Validate(); err != nil {
		return evidence.StateUnavailable, "local listener inventory failed validation: " + shortErr(err)
	}
	if len(inv.Sources) == 0 {
		return evidence.StateUnavailable, "local listener inventory did not report a collection source"
	}
	observed := false
	degradedReasons := make([]string, 0, len(inv.Sources))
	for _, src := range inv.Sources {
		switch src.State {
		case evidence.StateObserved:
			observed = true
		case evidence.StateNotApplicable:
			continue
		case evidence.StateDegraded:
			observed = true
			degradedReasons = append(degradedReasons, fallback(src.Reason, src.ID+" was degraded"))
		case evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported:
			degradedReasons = append(degradedReasons, fallback(src.Reason, src.ID+" was unavailable"))
		}
	}
	if observed && len(degradedReasons) == 0 {
		return evidence.StateObserved, ""
	}
	if observed || len(inv.Endpoints) > 0 {
		return evidence.StateDegraded, strings.Join(uniqueSorted(degradedReasons), "; ")
	}
	return evidence.StateUnavailable, fallback(strings.Join(uniqueSorted(degradedReasons), "; "), "local listener inventory was unavailable")
}

func buildDeveloperSurface(p developerProcess, c developerCandidate, endpoints []networkinv.Endpoint, netState evidence.State) DeveloperSurface {
	rec := DeveloperSurface{
		Kind: c.Kind, Product: c.Product, PID: p.PID, ProcessName: filepath.Base(p.Name), Executable: p.Executable,
		State: evidence.StateObserved, ActivationState: "ENABLED", ListenerState: "UNKNOWN", BindingState: "UNKNOWN", ExposureState: "UNKNOWN",
		DetectionBasis: uniqueSorted(c.DetectionBasis), CollectionSource: "local process metadata and normalized listener correlation", Confidence: c.Confidence,
	}
	matches := matchingDeveloperEndpoints(c, endpoints)
	if len(matches) > 0 {
		ep := matches[0]
		rec.ListenerState = "LISTENING"
		rec.LocalAddress = ep.LocalAddress
		rec.LocalPort = ep.LocalPort
		rec.Transport = ep.Protocol
		rec.BindingState = developerBindingState(ep.InterfaceBinding.Class)
		switch rec.BindingState {
		case "LOOPBACK":
			rec.ExposureState = "LOCAL_ONLY"
		case "ALL_INTERFACES", "NON_LOOPBACK":
			rec.ExposureState = "NETWORK_REACHABLE"
		default:
			rec.ExposureState = "UNKNOWN"
		}
		rec.Confidence = evidence.ConfidenceExact
	} else if netState == evidence.StateObserved {
		rec.ListenerState = "NOT_OBSERVED"
		if c.RequestedHost != "" {
			rec.BindingState = hostBindingState(c.RequestedHost)
		}
		if c.RequestedPort > 0 {
			rec.LocalPort = c.RequestedPort
		}
		rec.Reason = "debug/developer activation metadata was observed, but no matching local listener owned by the process was observed at collection time"
	} else {
		rec.Reason = "debug/developer activation metadata was observed, but local listener correlation was unavailable"
	}
	if rec.LocalAddress == "" && c.RequestedHost != "" {
		rec.LocalAddress = normalizeRequestedHost(c.RequestedHost)
	}
	rec.ID = stableID("developer-surface", strconv.Itoa(rec.PID), rec.Kind, rec.Product, rec.LocalAddress, strconv.Itoa(int(rec.LocalPort)))
	return rec
}

func matchingDeveloperEndpoints(c developerCandidate, endpoints []networkinv.Endpoint) []networkinv.Endpoint {
	out := make([]networkinv.Endpoint, 0)
	for _, ep := range endpoints {
		if ep.Protocol != "TCP" {
			continue
		}
		if c.RequestedPort > 0 && ep.LocalPort != c.RequestedPort {
			continue
		}
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool {
		rank := func(e networkinv.Endpoint) int {
			switch e.InterfaceBinding.Class {
			case "ALL_INTERFACES":
				return 0
			case "NON_LOOPBACK":
				return 1
			case "LOOPBACK":
				return 2
			default:
				return 3
			}
		}
		if rank(out[i]) != rank(out[j]) {
			return rank(out[i]) < rank(out[j])
		}
		if out[i].LocalPort != out[j].LocalPort {
			return out[i].LocalPort < out[j].LocalPort
		}
		return out[i].LocalAddress < out[j].LocalAddress
	})
	return out
}

func developerBindingState(class string) string {
	switch strings.ToUpper(strings.TrimSpace(class)) {
	case "LOOPBACK":
		return "LOOPBACK"
	case "ALL_INTERFACES":
		return "ALL_INTERFACES"
	case "NON_LOOPBACK":
		return "NON_LOOPBACK"
	default:
		return "UNKNOWN"
	}
}

func hostBindingState(host string) string {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return "LOOPBACK"
	case "0.0.0.0", "::", "*":
		return "ALL_INTERFACES"
	case "":
		return "UNKNOWN"
	default:
		return "NON_LOOPBACK"
	}
}

func normalizeRequestedHost(host string) string {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(h, "localhost") {
		return "localhost"
	}
	return h
}

func classifyDeveloperProcess(p developerProcess) []developerCandidate {
	name := strings.ToLower(filepath.Base(p.Name))
	if name == "" {
		name = strings.ToLower(filepath.Base(p.Executable))
	}
	cmd := strings.TrimSpace(p.Command)
	low := strings.ToLower(cmd)
	out := make([]developerCandidate, 0, 2)
	add := func(c developerCandidate) {
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		out = append(out, c)
	}

	browser := strings.Contains(name, "chrome") || strings.Contains(name, "chromium") || strings.Contains(name, "msedge") || strings.Contains(name, "brave")
	if browser && strings.Contains(low, "--remote-debugging-port") {
		host, _ := flagValue(cmd, "--remote-debugging-address")
		port := uint16(9222)
		if v, ok := flagValue(cmd, "--remote-debugging-port"); ok {
			if n := parsePort(v); n > 0 {
				port = n
			}
		}
		if host == "" {
			host = "127.0.0.1"
		}
		add(developerCandidate{Kind: "BROWSER_REMOTE_DEBUG", Product: browserProduct(name), RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"flag:--remote-debugging-port", optionalBasis(cmd, "--remote-debugging-address")}, Confidence: evidence.ConfidenceExact})
	}

	if strings.Contains(name, "jupyter") || strings.Contains(low, " jupyter ") || strings.HasPrefix(low, "jupyter ") || strings.Contains(low, "-m jupyter") {
		host := firstFlagValue(cmd, []string{"--ip", "--ServerApp.ip", "--NotebookApp.ip"})
		port := parsePort(firstFlagValue(cmd, []string{"--port", "--ServerApp.port", "--NotebookApp.port"}))
		if host == "" {
			host = "localhost"
		}
		if port == 0 {
			port = 8888
		}
		add(developerCandidate{Kind: "JUPYTER", Product: "Jupyter", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"process:jupyter", optionalAnyBasis(cmd, []string{"--ip", "--ServerApp.ip", "--NotebookApp.ip"}), optionalAnyBasis(cmd, []string{"--port", "--ServerApp.port", "--NotebookApp.port"})}, Confidence: evidence.ConfidenceHigh})
	}

	if strings.Contains(low, "debugpy") {
		if value, ok := flagValue(cmd, "--listen"); ok {
			host, port := parseHostPort(value, "127.0.0.1", 5678)
			add(developerCandidate{Kind: "LANGUAGE_DEBUGGER", Product: "debugpy", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"module:debugpy", "flag:--listen"}, Confidence: evidence.ConfidenceExact})
		}
	}

	if strings.Contains(name, "node") && (containsFlag(low, "--inspect") || containsFlag(low, "--inspect-brk")) {
		value, _ := firstPresentFlagValue(cmd, []string{"--inspect", "--inspect-brk"})
		host, port := parseHostPort(value, "127.0.0.1", 9229)
		basis := "flag:--inspect"
		if containsFlag(low, "--inspect-brk") {
			basis = "flag:--inspect-brk"
		}
		add(developerCandidate{Kind: "LANGUAGE_DEBUGGER", Product: "Node.js inspector", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{basis}, Confidence: evidence.ConfidenceExact})
	}

	if name == "dlv" || strings.HasPrefix(name, "dlv.") {
		if value, ok := flagValue(cmd, "--listen"); ok {
			host, port := parseHostPort(value, "127.0.0.1", 0)
			add(developerCandidate{Kind: "LANGUAGE_DEBUGGER", Product: "Delve", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"process:dlv", "flag:--listen", optionalBasis(cmd, "--headless")}, Confidence: evidence.ConfidenceExact})
		}
	}

	if name == "code-server" || strings.Contains(low, " code-server ") || strings.HasPrefix(low, "code-server ") {
		value := firstFlagValue(cmd, []string{"--bind-addr", "--host"})
		host, port := parseHostPort(value, "127.0.0.1", 8080)
		if p := parsePort(firstFlagValue(cmd, []string{"--port"})); p > 0 {
			port = p
		}
		add(developerCandidate{Kind: "IDE_REMOTE", Product: "code-server", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"process:code-server", optionalAnyBasis(cmd, []string{"--bind-addr", "--host", "--port"})}, Confidence: evidence.ConfidenceHigh})
	}
	if strings.Contains(name, "remote-dev-server") || strings.Contains(low, "remote-dev-server") {
		add(developerCandidate{Kind: "IDE_REMOTE", Product: "JetBrains Remote Development", DetectionBasis: []string{"process:remote-dev-server"}, Confidence: evidence.ConfidenceHigh})
	}

	if name == "adb" || name == "adb.exe" {
		if strings.Contains(low, "fork-server") || containsWord(low, "server") {
			host := "127.0.0.1"
			if containsFlag(low, "-a") {
				host = "0.0.0.0"
			}
			port := uint16(5037)
			if value, ok := flagValue(cmd, "-P"); ok {
				if n := parsePort(value); n > 0 {
					port = n
				}
			}
			add(developerCandidate{Kind: "ADB", Product: "Android Debug Bridge", RequestedHost: host, RequestedPort: port, DetectionBasis: []string{"process:adb-server", optionalBasis(cmd, "-a"), optionalBasis(cmd, "-P")}, Confidence: evidence.ConfidenceHigh})
		}
	}

	return normalizeDeveloperCandidates(out)
}

func browserProduct(name string) string {
	switch {
	case strings.Contains(name, "msedge"):
		return "Microsoft Edge DevTools"
	case strings.Contains(name, "brave"):
		return "Brave DevTools"
	case strings.Contains(name, "chromium"):
		return "Chromium DevTools"
	default:
		return "Chrome DevTools"
	}
}

func flagValue(command, flag string) (string, bool) {
	fields := splitCommandFields(command)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if strings.EqualFold(f, flag) {
			if i+1 < len(fields) {
				return trimArgValue(fields[i+1]), true
			}
			return "", true
		}
		prefix := flag + "="
		if len(f) >= len(prefix) && strings.EqualFold(f[:len(prefix)], prefix) {
			return trimArgValue(f[len(prefix):]), true
		}
	}
	return "", false
}

func firstFlagValue(command string, flags []string) string {
	for _, f := range flags {
		if v, ok := flagValue(command, f); ok {
			return v
		}
	}
	return ""
}
func firstPresentFlagValue(command string, flags []string) (string, bool) {
	for _, f := range flags {
		if v, ok := flagValue(command, f); ok {
			return v, true
		}
	}
	return "", false
}
func optionalBasis(command, flag string) string {
	if _, ok := flagValue(command, flag); ok {
		return "flag:" + flag
	}
	return ""
}
func optionalAnyBasis(command string, flags []string) string {
	for _, f := range flags {
		if _, ok := flagValue(command, f); ok {
			return "flag:" + f
		}
	}
	return ""
}
func containsFlag(lowCommand, flag string) bool {
	for _, f := range splitCommandFields(lowCommand) {
		if f == strings.ToLower(flag) || strings.HasPrefix(f, strings.ToLower(flag)+"=") {
			return true
		}
	}
	return false
}
func containsWord(lowCommand, word string) bool {
	for _, f := range splitCommandFields(lowCommand) {
		if strings.EqualFold(strings.TrimSpace(f), word) {
			return true
		}
	}
	return false
}
func trimArgValue(v string) string { return strings.Trim(strings.TrimSpace(v), "\"'") }

func splitCommandFields(command string) []string {
	return strings.Fields(strings.ReplaceAll(command, "\x00", " "))
}

func parseHostPort(value, defaultHost string, defaultPort uint16) (string, uint16) {
	v := trimArgValue(value)
	if v == "" {
		return defaultHost, defaultPort
	}
	if strings.HasPrefix(v, ":") {
		if p := parsePort(strings.TrimPrefix(v, ":")); p > 0 {
			return "0.0.0.0", p
		}
	}
	if p := parsePort(v); p > 0 {
		return defaultHost, p
	}
	if strings.HasPrefix(v, "[") {
		if end := strings.LastIndex(v, "]:"); end > 0 {
			return strings.Trim(v[:end+1], "[]"), parsePort(v[end+2:])
		}
	}
	if idx := strings.LastIndex(v, ":"); idx > 0 {
		host := strings.Trim(v[:idx], "[]")
		port := parsePort(v[idx+1:])
		if port > 0 {
			return host, port
		}
	}
	return v, defaultPort
}

func parsePort(v string) uint16 {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return uint16(n)
}

func normalizeDeveloperCandidates(in []developerCandidate) []developerCandidate {
	seen := map[string]struct{}{}
	out := make([]developerCandidate, 0, len(in))
	for _, c := range in {
		c.Kind = normalizeWord(c.Kind)
		c.Product = strings.TrimSpace(c.Product)
		c.RequestedHost = strings.TrimSpace(c.RequestedHost)
		c.DetectionBasis = uniqueSorted(c.DetectionBasis)
		key := c.Kind + "\x00" + c.Product + "\x00" + c.RequestedHost + "\x00" + strconv.Itoa(int(c.RequestedPort))
		if c.Kind == "" || c.Product == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func normalizeDeveloperSurfaces(in []DeveloperSurface) []DeveloperSurface {
	byID := map[string]DeveloperSurface{}
	for _, r := range in {
		r.Kind = normalizeWord(r.Kind)
		r.Product = strings.TrimSpace(r.Product)
		r.ProcessName = strings.TrimSpace(r.ProcessName)
		r.Executable = strings.TrimSpace(r.Executable)
		r.ActivationState = normalizeWord(r.ActivationState)
		r.ListenerState = normalizeWord(r.ListenerState)
		r.BindingState = normalizeWord(r.BindingState)
		r.ExposureState = normalizeWord(r.ExposureState)
		r.DetectionBasis = uniqueSorted(r.DetectionBasis)
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceHigh
		}
		if r.State == "" {
			r.State = evidence.StateObserved
		}
		if r.CollectionSource == "" {
			r.CollectionSource = "local developer surface metadata"
		}
		if r.ID == "" {
			r.ID = stableID("developer-surface", strconv.Itoa(r.PID), r.Kind, r.Product, r.LocalAddress, strconv.Itoa(int(r.LocalPort)))
		}
		if r.Kind == "" || r.Product == "" {
			continue
		}
		byID[r.ID] = r
	}
	out := make([]DeveloperSurface, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a := fmt.Sprintf("%010d\x00%s\x00%s\x00%s\x00%05d", out[i].PID, out[i].Kind, out[i].Product, out[i].LocalAddress, out[i].LocalPort)
		b := fmt.Sprintf("%010d\x00%s\x00%s\x00%s\x00%05d", out[j].PID, out[j].Kind, out[j].Product, out[j].LocalAddress, out[j].LocalPort)
		return a < b
	})
	if len(out) > maxDeveloperSurfaces {
		out = out[:maxDeveloperSurfaces]
	}
	return out
}

func collectDeveloperProcesses(ctx context.Context) ([]developerProcess, evidence.State, string) {
	switch runtime.GOOS {
	case "linux":
		return collectDeveloperProcessesLinux(ctx)
	case "darwin":
		return collectDeveloperProcessesDarwin(ctx)
	case "windows":
		return collectDeveloperProcessesWindows(ctx)
	default:
		return nil, evidence.StateUnsupported, "developer process metadata provider is unsupported on this platform"
	}
}

func collectDeveloperProcessesLinux(ctx context.Context) ([]developerProcess, evidence.State, string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, evidence.StateUnavailable, "cannot enumerate /proc: " + shortErr(err)
	}
	out := make([]developerProcess, 0, 256)
	for _, ent := range entries {
		select {
		case <-ctx.Done():
			return out, evidence.StateUnavailable, "process enumeration deadline reached"
		default:
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join("/proc", ent.Name())
		comm, _ := os.ReadFile(filepath.Join(base, "comm"))
		exe, _ := os.Readlink(filepath.Join(base, "exe"))
		cmd, err := readBoundedFile(filepath.Join(base, "cmdline"), maxDeveloperCmdBytes)
		if err != nil && len(comm) == 0 && exe == "" {
			continue
		}
		command := strings.ReplaceAll(string(cmd), "\x00", " ")
		out = append(out, developerProcess{PID: pid, Name: strings.TrimSpace(string(comm)), Executable: strings.TrimSpace(exe), Command: command})
		if len(out) >= maxDeveloperProcesses {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, evidence.StateObserved, ""
}

func collectDeveloperProcessesDarwin(ctx context.Context) ([]developerProcess, evidence.State, string) {
	out, err := localCommand(ctx, 1800*time.Millisecond, "ps", "-axo", "pid=,comm=,args=")
	if err != nil {
		return nil, evidence.StateUnavailable, "ps process metadata unavailable: " + shortErr(err)
	}
	result := make([]developerProcess, 0, 256)
	s := bufio.NewScanner(strings.NewReader(out))
	s.Buffer(make([]byte, 0, 64*1024), maxDeveloperCmdBytes)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		name := parts[1]
		command := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		result = append(result, developerProcess{PID: pid, Name: name, Executable: name, Command: command})
		if len(result) >= maxDeveloperProcesses {
			break
		}
	}
	return result, evidence.StateObserved, ""
}

type windowsDeveloperProcess struct {
	ProcessID      int    `json:"ProcessId"`
	Name           string `json:"Name"`
	ExecutablePath string `json:"ExecutablePath"`
	CommandLine    string `json:"CommandLine"`
}

func collectDeveloperProcessesWindows(ctx context.Context) ([]developerProcess, evidence.State, string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		return nil, evidence.StateUnavailable, "PowerShell process metadata provider unavailable"
	}
	script := "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
	out, err := localCommand(ctx, 3*time.Second, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, evidence.StateUnavailable, "Win32_Process metadata unavailable: " + shortErr(err)
	}
	var rows []windowsDeveloperProcess
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		var one windowsDeveloperProcess
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil, evidence.StateUnavailable, "Win32_Process metadata was not valid JSON"
		}
		rows = []windowsDeveloperProcess{one}
	}
	result := make([]developerProcess, 0, len(rows))
	for _, r := range rows {
		if r.ProcessID <= 0 {
			continue
		}
		result = append(result, developerProcess{PID: r.ProcessID, Name: r.Name, Executable: r.ExecutablePath, Command: r.CommandLine})
		if len(result) >= maxDeveloperProcesses {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, evidence.StateObserved, ""
}

func readBoundedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, max+1)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	if int64(n) > max {
		n = int(max)
	}
	return buf[:n], nil
}

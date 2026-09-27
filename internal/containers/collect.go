package containers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type runtimeSpec struct {
	Name        string
	Binary      string
	VersionArgs []string
}

type endpointCandidate struct {
	Runtime  string
	Endpoint string
	Kind     string
}

type configCandidate struct{ Runtime, Path string }

func collectPlatform(ctx context.Context, inv *Inventory) {
	specs := []runtimeSpec{
		{Name: "docker", Binary: "docker", VersionArgs: []string{"--version"}},
		{Name: "containerd", Binary: "containerd", VersionArgs: []string{"--version"}},
		{Name: "podman", Binary: "podman", VersionArgs: []string{"--version"}},
	}
	endpoints := platformEndpoints()
	configs := platformConfigCandidates()

	endpointByRuntime := map[string]endpointCandidate{}
	for _, ep := range endpoints {
		if endpointObserved(ep) {
			if _, exists := endpointByRuntime[ep.Runtime]; !exists {
				endpointByRuntime[ep.Runtime] = ep
			}
		}
	}
	configSeen := map[string]bool{}
	for _, c := range configs {
		cf, ok := statConfig(c)
		if !ok {
			continue
		}
		inv.ConfigFiles = append(inv.ConfigFiles, cf)
		configSeen[c.Runtime] = true
	}

	collectRuntimeEndpointPosture(inv, endpoints)

	for _, spec := range specs {
		r := Runtime{ID: spec.Name, Name: spec.Name, InstallationState: "NOT_OBSERVED", RuntimeState: "UNKNOWN", Accessibility: "UNKNOWN", RootlessState: "UNKNOWN", CollectionSource: "PATH + local runtime endpoint/configuration metadata", Confidence: evidence.ConfidenceMedium}
		path, err := exec.LookPath(spec.Binary)
		if err == nil {
			r.BinaryPath = path
			r.InstallationState = "PRESENT"
			if out, err := localCommand(ctx, 1500*time.Millisecond, spec.Binary, spec.VersionArgs...); err == nil {
				r.Version = trimVersion(out)
			} else {
				r.Reason = appendReason(r.Reason, "version metadata unavailable: "+shortErr(err))
			}
		}
		if ep, ok := endpointByRuntime[spec.Name]; ok {
			r.Endpoint, r.EndpointKind = ep.Endpoint, ep.Kind
			r.InstallationState = "PRESENT"
		}
		if configSeen[spec.Name] {
			r.InstallationState = "PRESENT"
		}

		if r.InstallationState == "PRESENT" {
			if applicable, reason := localInstanceCollectionApplicable(spec.Name); !applicable {
				r.RuntimeState = "NOT_APPLICABLE"
				r.Accessibility = "NOT_APPLICABLE"
				r.RootlessState = "NOT_APPLICABLE"
				r.Reason = appendReason(r.Reason, reason)
				addSource(inv, spec.Name+"-instances", evidence.StateNotApplicable, localSource(spec.Name, r.Endpoint), 0, reason)
				addSource(inv, spec.Name+"-security", evidence.StateNotApplicable, localSource(spec.Name, r.Endpoint)+" security inspection", 0, reason)
				inv.Runtimes = append(inv.Runtimes, r)
				continue
			}
		}

		var instances []Container
		var queryErr error
		switch spec.Name {
		case "docker":
			instances, queryErr = collectDocker(ctx, r)
		case "podman":
			instances, queryErr = collectPodman(ctx, r)
		case "containerd":
			instances, queryErr = collectContainerd(ctx, r)
		}
		if queryErr == nil && r.InstallationState == "PRESENT" {
			r.RuntimeState = "RUNNING"
			r.Accessibility = "ACCESSIBLE"
			if runtime.GOOS == "linux" {
				r.RootlessState = runtimeRootlessState(ctx, r)
			}
			inv.Containers = append(inv.Containers, instances...)
			addSource(inv, spec.Name+"-instances", evidence.StateObserved, localSource(spec.Name, r.Endpoint), len(instances), "")

			security, securityState, securityReason := collectSecurityPosture(ctx, r, instances)
			inv.Security = append(inv.Security, security...)
			addSource(inv, spec.Name+"-security", securityState, localSource(spec.Name, r.Endpoint)+" security inspection", len(security), securityReason)
		} else if queryErr != nil && r.InstallationState == "PRESENT" {
			r.Accessibility = classifyAccess(queryErr)
			r.Reason = appendReason(r.Reason, shortErr(queryErr))
			state := evidence.StateUnavailable
			if r.Accessibility == "DENIED" {
				state = evidence.StateDenied
			}
			addSource(inv, spec.Name+"-instances", state, localSource(spec.Name, r.Endpoint), 0, shortErr(queryErr))
			addSource(inv, spec.Name+"-security", state, localSource(spec.Name, r.Endpoint)+" security inspection", 0, "container security posture cannot be assessed because local instance inventory is unavailable: "+shortErr(queryErr))
		} else {
			addSource(inv, spec.Name+"-instances", evidence.StateNotApplicable, localSource(spec.Name, r.Endpoint), 0, spec.Name+" runtime was not observed locally")
			addSource(inv, spec.Name+"-security", evidence.StateNotApplicable, localSource(spec.Name, r.Endpoint)+" security inspection", 0, spec.Name+" runtime was not observed locally")
		}
		inv.Runtimes = append(inv.Runtimes, r)
	}
	if runtime.GOOS == "linux" {
		detectRootlessLinux(inv)
	}
}

func localInstanceCollectionApplicable(name string) (bool, string) {
	switch name {
	case "containerd":
		if runtime.GOOS != "linux" {
			return false, "local containerd instance enumeration is not applicable on this platform; the implemented provider uses the Linux local socket/ctr contract"
		}
	case "podman":
		if runtime.GOOS != "linux" {
			return false, "local Podman instance enumeration is not applicable on this platform; configured VM/remote connections are intentionally not followed by ordinary scans"
		}
	}
	return true, ""
}

func collectDocker(ctx context.Context, r Runtime) ([]Container, error) {
	if r.BinaryPath == "" {
		return nil, fmt.Errorf("docker CLI is unavailable")
	}
	if r.Endpoint == "" {
		return nil, fmt.Errorf("no local Docker socket/pipe endpoint was observed; remote endpoints are intentionally not used")
	}
	args := []string{"-H", dockerEndpoint(r.Endpoint, r.EndpointKind), "ps", "-a", "--no-trunc", "--format", "{{json .}}"}
	out, err := localCommand(ctx, 2500*time.Millisecond, r.BinaryPath, args...)
	if err != nil {
		return nil, err
	}
	return parseDockerPS(out)
}

func parseDockerPS(out string) ([]Container, error) {
	var items []Container
	s := bufio.NewScanner(strings.NewReader(out))
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, fmt.Errorf("parse docker ps output: %w", err)
		}
		id := firstString(m, "ID", "Id")
		if id == "" {
			continue
		}
		items = append(items, Container{Runtime: "docker", RuntimeContainerID: id, Name: firstString(m, "Names", "Name"), Image: firstString(m, "Image"), State: firstString(m, "State"), Status: firstString(m, "Status"), CollectionSource: "docker CLI over explicit local engine endpoint", Confidence: evidence.ConfidenceHigh})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func collectPodman(ctx context.Context, r Runtime) ([]Container, error) {
	if r.BinaryPath == "" {
		return nil, fmt.Errorf("podman CLI is unavailable")
	}
	// On Linux Podman can inventory the local libpod store without a remote
	// connection. On macOS/Windows it is VM/connection based; does
	// not follow configured SSH/TCP connections because ordinary scans must not
	// create unexpected network activity.
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Podman instance enumeration is not followed through configured remote/VM connections on %s", runtime.GOOS)
	}
	out, err := localCommandEnv(ctx, 3000*time.Millisecond, sanitizedContainerEnv(), r.BinaryPath, "--remote=false", "ps", "-a", "--no-trunc", "--format", "json")
	if err != nil {
		return nil, err
	}
	return parsePodmanPS(out)
}

func parsePodmanPS(out string) ([]Container, error) {
	raw := strings.TrimSpace(out)
	if raw == "" {
		return nil, nil
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return nil, fmt.Errorf("parse podman ps output: %w", err)
	}
	items := make([]Container, 0, len(arr))
	for _, m := range arr {
		id := firstString(m, "Id", "ID", "id")
		if id == "" {
			continue
		}
		name := firstString(m, "Names", "Name", "names")
		if name == "" {
			if v, ok := m["Names"].([]any); ok && len(v) > 0 {
				name = fmt.Sprint(v[0])
			}
		}
		pid := firstInt(m, "Pid", "PID", "pid")
		items = append(items, Container{Runtime: "podman", RuntimeContainerID: id, Name: name, Image: firstString(m, "Image", "ImageName", "image"), State: firstString(m, "State", "state"), Status: firstString(m, "Status", "status"), PID: pid, CollectionSource: "podman local libpod inventory", Confidence: evidence.ConfidenceHigh})
	}
	return items, nil
}

func collectContainerd(ctx context.Context, r Runtime) ([]Container, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("containerd local instance enumeration is not applicable on %s", runtime.GOOS)
	}
	ctr, err := exec.LookPath("ctr")
	if err != nil {
		return nil, fmt.Errorf("ctr CLI is unavailable")
	}
	if r.Endpoint == "" {
		return nil, fmt.Errorf("no local containerd socket endpoint was observed")
	}
	nsOut, err := localCommand(ctx, 2000*time.Millisecond, ctr, "--address", r.Endpoint, "namespaces", "list", "-q")
	if err != nil {
		return nil, err
	}
	namespaces := boundedLines(nsOut, 64)
	if len(namespaces) == 0 {
		namespaces = []string{"default"}
	}
	var items []Container
	for _, ns := range namespaces {
		if len(items) >= maxContainers {
			break
		}
		out, err := localCommand(ctx, 2000*time.Millisecond, ctr, "--address", r.Endpoint, "--namespace", ns, "containers", "list", "-q")
		if err != nil {
			return nil, fmt.Errorf("containerd namespace %s: %w", ns, err)
		}
		for _, id := range boundedLines(out, maxContainers-len(items)) {
			items = append(items, Container{Runtime: "containerd", RuntimeContainerID: id, Namespace: ns, State: "UNKNOWN", CollectionSource: "ctr over explicit local containerd socket", Confidence: evidence.ConfidenceHigh})
		}
	}
	return items, nil
}

func statConfig(c configCandidate) (ConfigFile, bool) {
	if strings.TrimSpace(c.Path) == "" {
		return ConfigFile{}, false
	}
	info, err := os.Stat(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return ConfigFile{}, false
		}
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		return ConfigFile{Runtime: c.Runtime, Path: c.Path, Exists: false, ReadableMetadata: false, State: state, CollectionSource: "os.Stat metadata only", Confidence: evidence.ConfidenceMedium, Reason: err.Error()}, true
	}
	t := info.ModTime().UTC()
	return ConfigFile{Runtime: c.Runtime, Path: c.Path, Exists: true, ReadableMetadata: true, SizeBytes: info.Size(), Mode: info.Mode().String(), ModifiedAt: &t, State: evidence.StateObserved, CollectionSource: "os.Stat metadata only", Confidence: evidence.ConfidenceExact}, true
}

func collectRuntimeEndpointPosture(inv *Inventory, endpoints []endpointCandidate) {
	observed := 0
	unknown := 0
	for _, ep := range endpoints {
		if !endpointObserved(ep) {
			continue
		}
		rec := inspectRuntimeEndpoint(ep)
		inv.RuntimeEndpoints = append(inv.RuntimeEndpoints, rec)
		if rec.State == evidence.StateObserved {
			observed++
		} else {
			unknown++
		}
	}
	if observed > 0 {
		addSource(inv, "runtime-endpoint-permissions", evidence.StateObserved, "local runtime socket/pipe metadata", observed, "")
		return
	}
	if unknown > 0 {
		addSource(inv, "runtime-endpoint-permissions", evidence.StateUnavailable, "local runtime socket/pipe metadata", unknown, "one or more local runtime control endpoints were identified but permission metadata was unavailable")
		return
	}
	addSource(inv, "runtime-endpoint-permissions", evidence.StateNotApplicable, "local runtime socket/pipe metadata", 0, "no local container-runtime control endpoint was observed")
}

func inspectRuntimeEndpoint(ep endpointCandidate) RuntimeEndpointPosture {
	rec := RuntimeEndpointPosture{
		Runtime: ep.Runtime, Endpoint: ep.Endpoint, EndpointKind: ep.Kind,
		State: evidence.StateObserved, PermissionAssessmentState: "UNKNOWN", OwnerAssessmentState: "UNKNOWN",
		WorldWritableState: "UNKNOWN", GroupWritableState: "UNKNOWN", LocalTransportState: "LOCAL_ONLY",
		CollectionSource: "local runtime endpoint metadata", Confidence: evidence.ConfidenceHigh,
	}
	if ep.Kind == "NPIPE" {
		// The local named-pipe endpoint itself is observed. ACL/owner semantics
		// are a provider capability gap, not a failed Linux socket check.
		rec.State = evidence.StateObserved
		rec.PermissionAssessmentState = "NOT_APPLICABLE"
		rec.OwnerAssessmentState = "NOT_APPLICABLE"
		rec.Confidence = evidence.ConfidenceHigh
		rec.Reason = "Windows named-pipe ACL/owner enrichment is not provided by this local endpoint metadata collector"
		return rec
	}
	info, err := os.Lstat(ep.Endpoint)
	if err != nil {
		rec.State = evidence.StateUnavailable
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		}
		rec.Confidence = evidence.ConfidenceLow
		rec.Reason = shortErr(err)
		return rec
	}
	mode := info.Mode().Perm()
	rec.Mode = fmt.Sprintf("%04o", mode)
	rec.PermissionAssessmentState = "OBSERVED"
	if mode&0002 != 0 {
		rec.WorldWritableState = "TRUE"
	} else {
		rec.WorldWritableState = "FALSE"
	}
	if mode&0020 != 0 {
		rec.GroupWritableState = "TRUE"
	} else {
		rec.GroupWritableState = "FALSE"
	}
	if uid, gid, ok := endpointOwnerMetadata(info); ok {
		rec.OwnerUID, rec.OwnerGID = uid, gid
		rec.OwnerAssessmentState = "OBSERVED"
	}
	return rec
}

func endpointObserved(ep endpointCandidate) bool {
	if ep.Kind == "NPIPE" {
		return runtime.GOOS == "windows"
	}
	if ep.Endpoint == "" {
		return false
	}
	info, err := os.Stat(ep.Endpoint)
	return err == nil && (info.Mode()&os.ModeSocket != 0 || !info.IsDir())
}

func platformEndpoints() []endpointCandidate {
	home, _ := os.UserHomeDir()
	uid := os.Getuid()
	switch runtime.GOOS {
	case "linux":
		return []endpointCandidate{
			{"docker", "/var/run/docker.sock", "UNIX_SOCKET"}, {"docker", "/run/docker.sock", "UNIX_SOCKET"},
			{"containerd", "/run/containerd/containerd.sock", "UNIX_SOCKET"}, {"containerd", "/var/run/containerd/containerd.sock", "UNIX_SOCKET"},
			{"podman", fmt.Sprintf("/run/user/%d/podman/podman.sock", uid), "UNIX_SOCKET"}, {"podman", "/run/podman/podman.sock", "UNIX_SOCKET"},
		}
	case "darwin":
		return []endpointCandidate{{"docker", "/var/run/docker.sock", "UNIX_SOCKET"}, {"docker", filepath.Join(home, ".docker", "run", "docker.sock"), "UNIX_SOCKET"}, {"podman", filepath.Join(home, ".local", "share", "containers", "podman", "machine", "podman.sock"), "UNIX_SOCKET"}}
	case "windows":
		return []endpointCandidate{{"docker", `\\.\pipe\docker_engine`, "NPIPE"}, {"containerd", `\\.\pipe\containerd-containerd`, "NPIPE"}, {"podman", `\\.\pipe\podman-machine-default`, "NPIPE"}}
	default:
		return nil
	}
}

func firstRootlessDockerSocket() string {
	matches, _ := filepath.Glob("/run/user/*/docker.sock")
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func firstRootlessPodmanSocket() string {
	matches, _ := filepath.Glob("/run/user/*/podman/podman.sock")
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func platformConfigCandidates() []configCandidate {
	home, _ := os.UserHomeDir()
	var out []configCandidate
	add := func(runtimeName string, paths ...string) {
		for _, p := range paths {
			if strings.TrimSpace(p) != "" {
				out = append(out, configCandidate{runtimeName, p})
			}
		}
	}
	switch runtime.GOOS {
	case "linux":
		add("docker", "/etc/docker/daemon.json", filepath.Join(home, ".config", "docker", "daemon.json"), filepath.Join(home, ".docker", "config.json"))
		add("containerd", "/etc/containerd/config.toml")
		add("podman", "/etc/containers/containers.conf", "/usr/share/containers/containers.conf", "/etc/containers/storage.conf", filepath.Join(home, ".config", "containers", "containers.conf"), filepath.Join(home, ".config", "containers", "storage.conf"), filepath.Join(home, ".config", "containers", "registries.conf"))
	case "darwin":
		add("docker", filepath.Join(home, ".docker", "config.json"), filepath.Join(home, "Library", "Group Containers", "group.com.docker", "settings-store.json"))
		add("podman", filepath.Join(home, ".config", "containers", "containers.conf"), filepath.Join(home, ".config", "containers", "storage.conf"))
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		add("docker", filepath.Join(programData, "docker", "config", "daemon.json"), filepath.Join(home, ".docker", "config.json"))
		add("containerd", filepath.Join(programData, "containerd", "config.toml"))
		add("podman", filepath.Join(home, ".config", "containers", "containers.conf"), filepath.Join(home, ".config", "containers", "storage.conf"))
	}
	return out
}

func detectRootlessLinux(inv *Inventory) {
	uid := os.Getuid()
	userSock := fmt.Sprintf("/run/user/%d", uid)
	for i := range inv.Runtimes {
		r := &inv.Runtimes[i]
		switch r.Name {
		case "podman":
			if strings.HasPrefix(r.Endpoint, userSock) {
				r.RootlessState = "TRUE"
			} else if r.InstallationState == "PRESENT" {
				r.RootlessState = "UNKNOWN"
			}
		case "docker":
			if strings.HasPrefix(r.Endpoint, userSock) {
				r.RootlessState = "TRUE"
			} else if r.Endpoint != "" {
				r.RootlessState = "FALSE"
			}
		case "containerd":
			r.RootlessState = "UNKNOWN"
		}
	}
}

func dockerEndpoint(endpoint, kind string) string {
	if kind == "NPIPE" {
		return "npipe:////./pipe/docker_engine"
	}
	return "unix://" + endpoint
}

func localCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return localCommandEnv(ctx, timeout, sanitizedContainerEnv(), name, args...)
}
func localCommandEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, error) {
	sub, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(sub, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if sub.Err() != nil {
		return stdout.String(), fmt.Errorf("command timed out: %w", sub.Err())
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s", truncateText(detail, 240))
	}
	return stdout.String(), nil
}
func sanitizedContainerEnv() []string {
	deny := map[string]bool{"DOCKER_HOST": true, "DOCKER_CONTEXT": true, "CONTAINER_HOST": true, "CONTAINER_CONNECTION": true}
	out := make([]string, 0, len(os.Environ()))
	for _, v := range os.Environ() {
		k := v
		if i := strings.IndexByte(v, '='); i >= 0 {
			k = v[:i]
		}
		if !deny[strings.ToUpper(k)] {
			out = append(out, v)
		}
	}
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch x := v.(type) {
			case string:
				if strings.TrimSpace(x) != "" {
					return strings.TrimSpace(x)
				}
			case []any:
				if len(x) > 0 {
					return strings.TrimSpace(fmt.Sprint(x[0]))
				}
			}
		}
	}
	return ""
}
func firstInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case float64:
				return int(x)
			case int:
				return x
			case string:
				n, _ := strconv.Atoi(strings.TrimSpace(x))
				return n
			}
		}
	}
	return 0
}
func boundedLines(v string, limit int) []string {
	s := bufio.NewScanner(strings.NewReader(v))
	s.Buffer(make([]byte, 0, 4096), 1024*1024)
	out := []string{}
	for s.Scan() && len(out) < limit {
		if x := strings.TrimSpace(s.Text()); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func trimVersion(v string) string {
	return truncateText(strings.TrimSpace(strings.ReplaceAll(v, "\n", " ")), 200)
}
func shortErr(err error) string {
	if err == nil {
		return ""
	}
	return truncateText(strings.TrimSpace(err.Error()), 240)
}
func truncateText(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
func appendReason(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}
func classifyAccess(err error) string {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		return "DENIED"
	}
	return "UNAVAILABLE"
}
func localSource(name, endpoint string) string {
	if endpoint != "" {
		return name + " local endpoint " + endpoint
	}
	return name + " local runtime metadata"
}

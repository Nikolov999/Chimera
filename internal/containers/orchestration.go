package containers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxKubeconfigs                 = 64
	maxCredentialPaths             = 256
	maxKubeconfigBytes       int64 = 2 * 1024 * 1024
	maxKubeconfigServers           = 64
	maxCredentialRefsPerFile       = 64
)

// KubernetesPosture summarizes Kubernetes/orchestration presence and role
// applicability on the live host. It does not contact a cluster or execute
// kubectl against configured contexts.
type KubernetesPosture struct {
	ID                    string              `json:"id"`
	State                 evidence.State      `json:"state"`
	InstallationState     string              `json:"installation_state"`
	Applicability         string              `json:"applicability"`
	ClientTools           []string            `json:"client_tools,omitempty"`
	ServerComponents      []string            `json:"server_components,omitempty"`
	WorkstationIndicators []string            `json:"workstation_indicators,omitempty"`
	ServerIndicators      []string            `json:"server_indicators,omitempty"`
	CollectionSource      string              `json:"collection_source"`
	Confidence            evidence.Confidence `json:"confidence"`
	Reason                string              `json:"reason,omitempty"`
}

// KubeconfigPosture contains permission metadata plus a redacted structural
// summary. Credential values are never retained. Server values are reduced to
// scheme+host and credential-bearing scalar values are represented only by
// indicator names.
type KubeconfigPosture struct {
	ID                        string              `json:"id"`
	Path                      string              `json:"path"`
	Scope                     string              `json:"scope"`
	State                     evidence.State      `json:"state"`
	Exists                    bool                `json:"exists"`
	PermissionAssessmentState string              `json:"permission_assessment_state"`
	Mode                      string              `json:"mode,omitempty"`
	OwnerUID                  string              `json:"owner_uid,omitempty"`
	OwnerGID                  string              `json:"owner_gid,omitempty"`
	OwnerAssessmentState      string              `json:"owner_assessment_state"`
	WorldReadableState        string              `json:"world_readable_state"`
	WorldWritableState        string              `json:"world_writable_state"`
	GroupReadableState        string              `json:"group_readable_state"`
	GroupWritableState        string              `json:"group_writable_state"`
	StructureAssessmentState  string              `json:"structure_assessment_state"`
	EmbeddedCredentialState   string              `json:"embedded_credential_state"`
	EmbeddedCredentialKinds   []string            `json:"embedded_credential_kinds,omitempty"`
	CredentialReferenceCount  int                 `json:"credential_reference_count"`
	ServerEndpointCount       int                 `json:"server_endpoint_count"`
	LocalServerEndpointCount  int                 `json:"local_server_endpoint_count"`
	ServerEndpoints           []string            `json:"server_endpoints,omitempty"`
	CollectionSource          string              `json:"collection_source"`
	Confidence                evidence.Confidence `json:"confidence"`
	Reason                    string              `json:"reason,omitempty"`
}

// KubernetesCredentialPathPosture is metadata-only posture for a local file
// referenced by kubeconfig as credential material. File contents are never read.
type KubernetesCredentialPathPosture struct {
	ID                        string              `json:"id"`
	KubeconfigID              string              `json:"kubeconfig_id"`
	Kind                      string              `json:"kind"`
	Path                      string              `json:"path"`
	State                     evidence.State      `json:"state"`
	Exists                    bool                `json:"exists"`
	PermissionAssessmentState string              `json:"permission_assessment_state"`
	Mode                      string              `json:"mode,omitempty"`
	OwnerUID                  string              `json:"owner_uid,omitempty"`
	OwnerGID                  string              `json:"owner_gid,omitempty"`
	OwnerAssessmentState      string              `json:"owner_assessment_state"`
	WorldReadableState        string              `json:"world_readable_state"`
	WorldWritableState        string              `json:"world_writable_state"`
	GroupReadableState        string              `json:"group_readable_state"`
	GroupWritableState        string              `json:"group_writable_state"`
	CollectionSource          string              `json:"collection_source"`
	Confidence                evidence.Confidence `json:"confidence"`
	Reason                    string              `json:"reason,omitempty"`
}

type kubeconfigCandidate struct {
	Path  string
	Scope string
}

type credentialReference struct {
	Kind string
	Path string
}

type kubeconfigStructure struct {
	Servers                 []string
	LocalServerCount        int
	EmbeddedCredentialKinds []string
	CredentialReferences    []credentialReference
}

func collectKubernetesPosture(ctx context.Context, inv *Inventory) {
	_ = ctx // Reserved for future bounded local providers; performs no cluster calls.

	candidates := kubernetesConfigCandidates()
	observedConfigs := 0
	deniedConfigs := 0
	unavailableConfigs := 0
	for _, candidate := range candidates {
		if len(inv.Kubeconfigs) >= maxKubeconfigs {
			break
		}
		cfg, refs, ok := inspectKubeconfig(candidate)
		if !ok {
			continue
		}
		inv.Kubeconfigs = append(inv.Kubeconfigs, cfg)
		switch cfg.State {
		case evidence.StateObserved:
			observedConfigs++
		case evidence.StateDenied:
			deniedConfigs++
		default:
			unavailableConfigs++
		}
		for _, ref := range refs {
			if len(inv.KubernetesCredentialPaths) >= maxCredentialPaths {
				break
			}
			inv.KubernetesCredentialPaths = append(inv.KubernetesCredentialPaths, inspectCredentialPath(cfg.ID, ref))
		}
	}

	posture := detectKubernetesApplicability(inv.Kubeconfigs)
	inv.Kubernetes = posture

	switch {
	case observedConfigs > 0:
		addSource(inv, "kubernetes-kubeconfig", evidence.StateObserved, "local kubeconfig metadata + redacted structure", observedConfigs, "")
	case deniedConfigs > 0:
		addSource(inv, "kubernetes-kubeconfig", evidence.StateDenied, "local kubeconfig metadata + redacted structure", deniedConfigs, "one or more Kubernetes configuration files were observed but could not be read for redacted structural assessment")
	case unavailableConfigs > 0:
		addSource(inv, "kubernetes-kubeconfig", evidence.StateUnavailable, "local kubeconfig metadata + redacted structure", unavailableConfigs, "one or more Kubernetes configuration files could not be fully assessed")
	case posture.State == evidence.StateObserved:
		addSource(inv, "kubernetes-kubeconfig", evidence.StateObserved, "local kubeconfig metadata + redacted structure", 0, "")
	default:
		addSource(inv, "kubernetes-kubeconfig", evidence.StateNotApplicable, "local kubeconfig metadata + redacted structure", 0, "no local Kubernetes configuration file was observed")
	}

	if len(inv.KubernetesCredentialPaths) > 0 {
		state := evidence.StateObserved
		reason := ""
		for _, p := range inv.KubernetesCredentialPaths {
			if p.State == evidence.StateDenied {
				state = evidence.StateDenied
				reason = "one or more referenced Kubernetes credential paths could not be inspected due to permissions"
				break
			}
			if p.State != evidence.StateObserved && state == evidence.StateObserved {
				state = evidence.StateUnavailable
				reason = "one or more referenced Kubernetes credential paths could not be fully inspected"
			}
		}
		addSource(inv, "kubernetes-credential-paths", state, "local referenced Kubernetes credential path metadata", len(inv.KubernetesCredentialPaths), reason)
	} else if posture.State == evidence.StateObserved {
		addSource(inv, "kubernetes-credential-paths", evidence.StateObserved, "local referenced Kubernetes credential path metadata", 0, "")
	} else {
		addSource(inv, "kubernetes-credential-paths", evidence.StateNotApplicable, "local referenced Kubernetes credential path metadata", 0, "no local Kubernetes credential-file references were observed")
	}

	if posture.State == evidence.StateObserved {
		addSource(inv, "kubernetes-applicability", evidence.StateObserved, posture.CollectionSource, 1, "")
	} else {
		addSource(inv, "kubernetes-applicability", evidence.StateNotApplicable, posture.CollectionSource, 0, fallback(posture.Reason, "Kubernetes was not observed locally"))
	}
}

func kubernetesConfigCandidates() []kubeconfigCandidate {
	home, _ := os.UserHomeDir()
	seen := map[string]struct{}{}
	out := make([]kubeconfigCandidate, 0, 20)
	add := func(scope string, paths ...string) {
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			p = expandUserPath(p, home)
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			key := pathIdentityKey(p)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, kubeconfigCandidate{Path: filepath.Clean(p), Scope: scope})
		}
	}

	if raw := strings.TrimSpace(os.Getenv("KUBECONFIG")); raw != "" {
		for _, p := range filepath.SplitList(raw) {
			add("ENVIRONMENT", p)
		}
	}
	if home != "" {
		add("USER", filepath.Join(home, ".kube", "config"))
	}
	switch runtime.GOOS {
	case "linux":
		add("CONTROL_PLANE", "/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf", "/etc/kubernetes/controller-manager.conf", "/etc/kubernetes/scheduler.conf")
		add("NODE", "/etc/kubernetes/kubelet.conf", "/var/lib/kubelet/kubeconfig", "/var/lib/kubelet/config.yaml")
		add("DISTRIBUTION", "/etc/rancher/k3s/k3s.yaml", "/etc/rancher/rke2/rke2.yaml", "/var/snap/microk8s/current/credentials/client.config")
	case "darwin":
		add("SYSTEM", "/etc/kubernetes/admin.conf", "/etc/kubernetes/kubelet.conf")
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = `C:`
		}
		add("SYSTEM", filepath.Join(programData, "kubernetes", "config"), filepath.Join(systemDrive+`\`, "etc", "kubernetes", "admin.conf"), filepath.Join(systemDrive+`\`, "var", "lib", "kubelet", "config.yaml"))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path)
	})
	return out
}

func inspectKubeconfig(candidate kubeconfigCandidate) (KubeconfigPosture, []credentialReference, bool) {
	path := candidate.Path
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return KubeconfigPosture{}, nil, false
		}
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		rec := baseKubeconfigPosture(path, candidate.Scope)
		rec.State = state
		rec.Reason = shortErr(err)
		return rec, nil, true
	}
	if !info.Mode().IsRegular() {
		rec := baseKubeconfigPosture(path, candidate.Scope)
		rec.State = evidence.StateUnavailable
		rec.Exists = true
		rec.Reason = "kubeconfig candidate is not a regular file"
		return rec, nil, true
	}

	rec := baseKubeconfigPosture(path, candidate.Scope)
	rec.State = evidence.StateObserved
	rec.Exists = true
	applyPermissionMetadata(&rec.PermissionAssessmentState, &rec.Mode, &rec.OwnerUID, &rec.OwnerGID, &rec.OwnerAssessmentState, &rec.WorldReadableState, &rec.WorldWritableState, &rec.GroupReadableState, &rec.GroupWritableState, info)

	if info.Size() > maxKubeconfigBytes {
		rec.StructureAssessmentState = "UNKNOWN"
		rec.Reason = fmt.Sprintf("kubeconfig exceeds bounded structural-read limit (%d bytes)", maxKubeconfigBytes)
		rec.Confidence = evidence.ConfidenceHigh
		return rec, nil, true
	}
	f, err := os.Open(path)
	if err != nil {
		rec.StructureAssessmentState = "UNKNOWN"
		rec.Reason = appendReason(rec.Reason, "redacted structure unavailable: "+shortErr(err))
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		}
		rec.Confidence = evidence.ConfidenceHigh
		return rec, nil, true
	}
	defer f.Close()
	openedInfo, statErr := f.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		rec.StructureAssessmentState = "UNKNOWN"
		rec.Reason = appendReason(rec.Reason, "kubeconfig changed identity during bounded structural assessment")
		return rec, nil, true
	}
	if openedInfo.Size() > maxKubeconfigBytes {
		rec.StructureAssessmentState = "UNKNOWN"
		rec.Reason = appendReason(rec.Reason, fmt.Sprintf("kubeconfig exceeds bounded structural-read limit (%d bytes)", maxKubeconfigBytes))
		return rec, nil, true
	}

	structure, err := parseKubeconfigStructure(path, f)
	if err != nil {
		rec.StructureAssessmentState = "UNKNOWN"
		rec.Reason = appendReason(rec.Reason, "redacted structure unavailable: "+shortErr(err))
		return rec, nil, true
	}
	rec.StructureAssessmentState = "OBSERVED"
	if len(structure.EmbeddedCredentialKinds) > 0 {
		rec.EmbeddedCredentialState = "TRUE"
	} else {
		rec.EmbeddedCredentialState = "FALSE"
	}
	rec.EmbeddedCredentialKinds = structure.EmbeddedCredentialKinds
	rec.CredentialReferenceCount = len(structure.CredentialReferences)
	rec.ServerEndpointCount = len(structure.Servers)
	rec.LocalServerEndpointCount = structure.LocalServerCount
	rec.ServerEndpoints = structure.Servers
	return rec, structure.CredentialReferences, true
}

func baseKubeconfigPosture(path, scope string) KubeconfigPosture {
	return KubeconfigPosture{
		ID: stableID("kubeconfig", pathIdentityKey(path)), Path: filepath.Clean(path), Scope: normalizeWord(fallback(scope, "UNKNOWN")),
		State: evidence.StateUnavailable, PermissionAssessmentState: "UNKNOWN", OwnerAssessmentState: "UNKNOWN",
		WorldReadableState: "UNKNOWN", WorldWritableState: "UNKNOWN", GroupReadableState: "UNKNOWN", GroupWritableState: "UNKNOWN",
		StructureAssessmentState: "UNKNOWN", EmbeddedCredentialState: "UNKNOWN",
		CollectionSource: "local kubeconfig metadata + bounded redacted structure", Confidence: evidence.ConfidenceHigh,
	}
}

func inspectCredentialPath(kubeconfigID string, ref credentialReference) KubernetesCredentialPathPosture {
	rec := KubernetesCredentialPathPosture{
		ID: stableID("kube-credential", kubeconfigID, ref.Kind, pathIdentityKey(ref.Path)), KubeconfigID: kubeconfigID,
		Kind: normalizeWord(ref.Kind), Path: filepath.Clean(ref.Path), State: evidence.StateUnavailable,
		PermissionAssessmentState: "UNKNOWN", OwnerAssessmentState: "UNKNOWN", WorldReadableState: "UNKNOWN", WorldWritableState: "UNKNOWN", GroupReadableState: "UNKNOWN", GroupWritableState: "UNKNOWN",
		CollectionSource: "os.Lstat metadata for kubeconfig credential reference", Confidence: evidence.ConfidenceHigh,
	}
	info, err := os.Lstat(ref.Path)
	if err != nil {
		if os.IsNotExist(err) {
			rec.State = evidence.StateUnavailable
			rec.Reason = "referenced Kubernetes credential path does not exist"
		} else if os.IsPermission(err) {
			rec.State = evidence.StateDenied
			rec.Reason = shortErr(err)
		} else {
			rec.State = evidence.StateUnavailable
			rec.Reason = shortErr(err)
		}
		return rec
	}
	rec.Exists = true
	rec.State = evidence.StateObserved
	if !info.Mode().IsRegular() {
		rec.State = evidence.StateUnavailable
		rec.Reason = "referenced Kubernetes credential path is not a regular file"
		return rec
	}
	applyPermissionMetadata(&rec.PermissionAssessmentState, &rec.Mode, &rec.OwnerUID, &rec.OwnerGID, &rec.OwnerAssessmentState, &rec.WorldReadableState, &rec.WorldWritableState, &rec.GroupReadableState, &rec.GroupWritableState, info)
	return rec
}

func applyPermissionMetadata(assessment, mode, ownerUID, ownerGID, ownerAssessment, worldRead, worldWrite, groupRead, groupWrite *string, info os.FileInfo) {
	if runtime.GOOS == "windows" {
		*assessment = "UNKNOWN"
		*ownerAssessment = "UNKNOWN"
		*worldRead, *worldWrite, *groupRead, *groupWrite = "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"
		return
	}
	perm := info.Mode().Perm()
	*assessment = "OBSERVED"
	*mode = fmt.Sprintf("%04o", perm)
	*worldRead = boolWordLocal(perm&0004 != 0)
	*worldWrite = boolWordLocal(perm&0002 != 0)
	*groupRead = boolWordLocal(perm&0040 != 0)
	*groupWrite = boolWordLocal(perm&0020 != 0)
	if uid, gid, ok := endpointOwnerMetadata(info); ok {
		*ownerUID, *ownerGID, *ownerAssessment = uid, gid, "OBSERVED"
	}
}

func parseKubeconfigStructure(configPath string, r io.Reader) (kubeconfigStructure, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), int(maxKubeconfigBytes))
	structure := kubeconfigStructure{}
	serverSeen := map[string]struct{}{}
	embeddedSeen := map[string]struct{}{}
	referenceSeen := map[string]struct{}{}

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitYAMLKeyValue(line)
		if !ok {
			continue
		}
		normalizedKey := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", "-"))
		switch normalizedKey {
		case "server":
			if endpoint := sanitizeKubernetesServer(value); endpoint != "" {
				if _, ok := serverSeen[endpoint]; !ok && len(structure.Servers) < maxKubeconfigServers {
					serverSeen[endpoint] = struct{}{}
					structure.Servers = append(structure.Servers, endpoint)
					if kubernetesServerIsLocal(endpoint) {
						structure.LocalServerCount++
					}
				}
			}
		case "client-key", "tokenfile", "token-file":
			kind := "CLIENT_KEY"
			if normalizedKey != "client-key" {
				kind = "TOKEN_FILE"
			}
			if len(structure.CredentialReferences) < maxCredentialRefsPerFile {
				if path := resolveKubeconfigReference(configPath, value); path != "" {
					k := kind + "\x00" + pathIdentityKey(path)
					if _, ok := referenceSeen[k]; !ok {
						referenceSeen[k] = struct{}{}
						structure.CredentialReferences = append(structure.CredentialReferences, credentialReference{Kind: kind, Path: path})
					}
				}
			}
		case "client-key-data", "token", "password":
			kind := strings.ToUpper(strings.ReplaceAll(normalizedKey, "-", "_"))
			if _, ok := embeddedSeen[kind]; !ok {
				embeddedSeen[kind] = struct{}{}
				structure.EmbeddedCredentialKinds = append(structure.EmbeddedCredentialKinds, kind)
			}
		}
	}
	if err := s.Err(); err != nil {
		return kubeconfigStructure{}, err
	}
	sort.Strings(structure.Servers)
	sort.Strings(structure.EmbeddedCredentialKinds)
	sort.Slice(structure.CredentialReferences, func(i, j int) bool {
		if structure.CredentialReferences[i].Kind != structure.CredentialReferences[j].Kind {
			return structure.CredentialReferences[i].Kind < structure.CredentialReferences[j].Kind
		}
		return strings.ToLower(structure.CredentialReferences[i].Path) < strings.ToLower(structure.CredentialReferences[j].Path)
	})
	return structure, nil
}

func splitYAMLKeyValue(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(strings.TrimPrefix(line[:idx], "-"))
	value := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, trimYAMLScalar(value), true
}

func trimYAMLScalar(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
	}
	return strings.TrimSpace(v)
}

func resolveKubeconfigReference(configPath, raw string) string {
	raw = trimYAMLScalar(raw)
	if raw == "" || strings.HasPrefix(raw, "data:") {
		return ""
	}
	home, _ := os.UserHomeDir()
	raw = expandUserPath(raw, home)
	if !filepath.IsAbs(raw) {
		raw = filepath.Join(filepath.Dir(configPath), raw)
	}
	return filepath.Clean(raw)
}

func expandUserPath(path, home string) string {
	if path == "~" && home != "" {
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home != "" {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func sanitizeKubernetesServer(raw string) string {
	raw = trimYAMLScalar(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	host := strings.ToLower(u.Host)
	if h, p, err := net.SplitHostPort(u.Host); err == nil {
		host = net.JoinHostPort(strings.ToLower(h), p)
	}
	return scheme + "://" + host
}

func kubernetesServerIsLocal(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := strings.TrimSpace(strings.ToLower(u.Hostname()))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func detectKubernetesApplicability(configs []KubeconfigPosture) KubernetesPosture {
	posture := KubernetesPosture{
		ID: "kubernetes", State: evidence.StateNotApplicable, InstallationState: "NOT_OBSERVED", Applicability: "NOT_APPLICABLE",
		CollectionSource: "PATH + local Kubernetes configuration/component metadata", Confidence: evidence.ConfidenceHigh,
		Reason: "Kubernetes client, node, control-plane, or local configuration indicators were not observed",
	}
	clientTools := detectTools([]string{"kubectl", "helm"})
	serverComponents := detectTools([]string{"kubelet", "kube-apiserver", "kube-controller-manager", "kube-scheduler", "k3s", "rke2", "microk8s"})
	workstation := []string{}
	server := []string{}
	if containsTool(clientTools, "kubectl") {
		workstation = append(workstation, "kubectl client available")
	}
	for _, cfg := range configs {
		switch cfg.Scope {
		case "USER", "ENVIRONMENT":
			workstation = append(workstation, "kubeconfig:"+cfg.Scope)
		case "CONTROL_PLANE", "NODE", "DISTRIBUTION", "SYSTEM":
			server = append(server, "kubernetes-config:"+cfg.Scope)
		}
	}
	if len(serverComponents) > 0 {
		server = append(server, "server component binary observed")
	}
	posture.ClientTools = uniqueSorted(clientTools)
	posture.ServerComponents = uniqueSorted(serverComponents)
	posture.WorkstationIndicators = uniqueSorted(workstation)
	posture.ServerIndicators = uniqueSorted(server)
	if len(posture.ClientTools) == 0 && len(posture.ServerComponents) == 0 && len(configs) == 0 {
		return posture
	}
	posture.State = evidence.StateObserved
	posture.InstallationState = "PRESENT"
	posture.Reason = ""
	switch {
	case len(posture.WorkstationIndicators) > 0 && len(posture.ServerIndicators) > 0:
		posture.Applicability = "MIXED"
	case len(posture.ServerIndicators) > 0:
		posture.Applicability = "SERVER"
	case len(posture.WorkstationIndicators) > 0 || len(posture.ClientTools) > 0:
		posture.Applicability = "WORKSTATION"
	default:
		posture.Applicability = "UNKNOWN"
	}
	return posture
}

func detectTools(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil && strings.TrimSpace(p) != "" {
			out = append(out, name+"="+filepath.Clean(p))
		}
	}
	return out
}

func containsTool(tools []string, name string) bool {
	prefix := strings.ToLower(name) + "="
	for _, item := range tools {
		if strings.HasPrefix(strings.ToLower(item), prefix) {
			return true
		}
	}
	return false
}

func pathIdentityKey(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func boolWordLocal(v bool) string {
	if v {
		return "TRUE"
	}
	return "FALSE"
}

func normalizeKubernetesPosture(in KubernetesPosture) KubernetesPosture {
	in.ID = slug(fallback(in.ID, "kubernetes"))
	if in.State == "" {
		in.State = evidence.StateNotApplicable
	}
	in.InstallationState = normalizeWord(fallback(in.InstallationState, "NOT_OBSERVED"))
	in.Applicability = normalizeKubernetesApplicability(in.Applicability)
	in.ClientTools = uniqueSorted(in.ClientTools)
	in.ServerComponents = uniqueSorted(in.ServerComponents)
	in.WorkstationIndicators = uniqueSorted(in.WorkstationIndicators)
	in.ServerIndicators = uniqueSorted(in.ServerIndicators)
	in.CollectionSource = fallback(in.CollectionSource, "local Kubernetes metadata")
	if in.Confidence == "" {
		in.Confidence = evidence.ConfidenceMedium
	}
	in.Reason = strings.TrimSpace(in.Reason)
	return in
}

func normalizeKubeconfigs(in []KubeconfigPosture) []KubeconfigPosture {
	byID := map[string]KubeconfigPosture{}
	for _, c := range in {
		c.Path = filepath.Clean(strings.TrimSpace(c.Path))
		if c.Path == "" || c.Path == "." {
			continue
		}
		c.ID = stableID("kubeconfig", pathIdentityKey(c.Path))
		c.Scope = normalizeWord(fallback(c.Scope, "UNKNOWN"))
		if c.State == "" {
			c.State = evidence.StateUnavailable
		}
		c.PermissionAssessmentState = normalizeObservedState(c.PermissionAssessmentState)
		c.OwnerAssessmentState = normalizeObservedState(c.OwnerAssessmentState)
		c.WorldReadableState = normalizeTriState(c.WorldReadableState)
		c.WorldWritableState = normalizeTriState(c.WorldWritableState)
		c.GroupReadableState = normalizeTriState(c.GroupReadableState)
		c.GroupWritableState = normalizeTriState(c.GroupWritableState)
		c.StructureAssessmentState = normalizeObservedState(c.StructureAssessmentState)
		c.EmbeddedCredentialState = normalizeTriState(c.EmbeddedCredentialState)
		c.EmbeddedCredentialKinds = uniqueSortedUpper(c.EmbeddedCredentialKinds)
		c.ServerEndpoints = uniqueSorted(c.ServerEndpoints)
		c.CollectionSource = fallback(c.CollectionSource, "local kubeconfig metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		c.Reason = strings.TrimSpace(c.Reason)
		byID[c.ID] = c
	}
	out := make([]KubeconfigPosture, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path) })
	if len(out) > maxKubeconfigs {
		out = out[:maxKubeconfigs]
	}
	return out
}

func normalizeKubernetesCredentialPaths(in []KubernetesCredentialPathPosture) []KubernetesCredentialPathPosture {
	byID := map[string]KubernetesCredentialPathPosture{}
	for _, p := range in {
		p.KubeconfigID = strings.TrimSpace(p.KubeconfigID)
		p.Kind = normalizeWord(p.Kind)
		p.Path = filepath.Clean(strings.TrimSpace(p.Path))
		if p.KubeconfigID == "" || p.Kind == "" || p.Path == "" || p.Path == "." {
			continue
		}
		p.ID = stableID("kube-credential", p.KubeconfigID, p.Kind, pathIdentityKey(p.Path))
		if p.State == "" {
			p.State = evidence.StateUnavailable
		}
		p.PermissionAssessmentState = normalizeObservedState(p.PermissionAssessmentState)
		p.OwnerAssessmentState = normalizeObservedState(p.OwnerAssessmentState)
		p.WorldReadableState = normalizeTriState(p.WorldReadableState)
		p.WorldWritableState = normalizeTriState(p.WorldWritableState)
		p.GroupReadableState = normalizeTriState(p.GroupReadableState)
		p.GroupWritableState = normalizeTriState(p.GroupWritableState)
		p.CollectionSource = fallback(p.CollectionSource, "local Kubernetes credential path metadata")
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceHigh
		}
		p.Reason = strings.TrimSpace(p.Reason)
		byID[p.ID] = p
	}
	out := make([]KubernetesCredentialPathPosture, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path)
	})
	if len(out) > maxCredentialPaths {
		out = out[:maxCredentialPaths]
	}
	return out
}

func normalizeKubernetesApplicability(v string) string {
	v = normalizeWord(v)
	switch v {
	case "WORKSTATION", "SERVER", "MIXED", "NOT_APPLICABLE", "UNKNOWN":
		return v
	default:
		return "UNKNOWN"
	}
}

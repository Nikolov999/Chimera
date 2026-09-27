package containers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeAndValidateInventory(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Runtimes:    []Runtime{{ID: "docker", Name: "docker", InstallationState: "PRESENT", RuntimeState: "RUNNING", Accessibility: "ACCESSIBLE", RootlessState: "FALSE", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}},
		Containers:  []Container{{Runtime: "docker", RuntimeContainerID: "abc123", Name: "web", Image: "nginx:stable", State: "running", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}},
		ConfigFiles: []ConfigFile{{Runtime: "docker", Path: "/etc/docker/daemon.json", Exists: true, ReadableMetadata: true, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}},
		Sources:     []SourceStatus{{ID: "docker-instances", State: evidence.StateObserved, Source: "test", ItemCount: 1}},
	}
	inv.Runtimes = normalizeRuntimes(inv.Runtimes)
	inv.Containers = normalizeContainers(inv.Containers)
	inv.ConfigFiles = normalizeConfigs(inv.ConfigFiles)
	inv.Kubernetes = normalizeKubernetesPosture(inv.Kubernetes)
	inv.Kubeconfigs = normalizeKubeconfigs(inv.Kubeconfigs)
	inv.KubernetesCredentialPaths = normalizeKubernetesCredentialPaths(inv.KubernetesCredentialPaths)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Summary = summarize(inv)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Summary.RunningContainers != 1 || inv.Summary.AccessibleRuntimes != 1 {
		t.Fatalf("bad summary: %#v", inv.Summary)
	}
}

func TestParseDockerPS(t *testing.T) {
	got, err := parseDockerPS(`{"ID":"abcdef","Image":"nginx:stable","Names":"web","State":"running","Status":"Up 2 hours"}` + "\n")
	if err != nil {
		t.Fatal(err)
	}
	got = normalizeContainers(got)
	if len(got) != 1 || got[0].Runtime != "docker" || got[0].State != "RUNNING" || got[0].Name != "web" {
		t.Fatalf("unexpected docker parse: %#v", got)
	}
}

func TestParsePodmanPS(t *testing.T) {
	got, err := parsePodmanPS(`[{"Id":"012345","Names":["db"],"Image":"postgres:16","State":"exited","Status":"Exited (0)","Pid":0}]`)
	if err != nil {
		t.Fatal(err)
	}
	got = normalizeContainers(got)
	if len(got) != 1 || got[0].Runtime != "podman" || got[0].State != "STOPPED" || got[0].Name != "db" {
		t.Fatalf("unexpected podman parse: %#v", got)
	}
}

func TestSanitizedEnvironmentRemovesRemoteSelectors(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://198.51.100.10:2375")
	t.Setenv("CONTAINER_HOST", "ssh://example.invalid/run/podman.sock")
	for _, v := range sanitizedContainerEnv() {
		if strings.HasPrefix(strings.ToUpper(v), "DOCKER_HOST=") || strings.HasPrefix(strings.ToUpper(v), "CONTAINER_HOST=") {
			t.Fatalf("remote selector leaked: %q", v)
		}
	}
}

func TestCollectProducesValidContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inv := Collect(ctx)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(inv.Runtimes) != 3 {
		t.Fatalf("expected docker/containerd/podman status records, got %d", len(inv.Runtimes))
	}
}

func TestNormalizeRuntimeEndpointPosture(t *testing.T) {
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: time.Now().UTC(),
		RuntimeEndpoints: []RuntimeEndpointPosture{{
			Runtime: "docker", Endpoint: "/var/run/docker.sock", EndpointKind: "unix_socket", State: evidence.StateObserved,
			PermissionAssessmentState: "observed", Mode: "0660", OwnerUID: "0", OwnerGID: "999", OwnerAssessmentState: "observed",
			WorldWritableState: "false", GroupWritableState: "true", LocalTransportState: "local_only", CollectionSource: "test", Confidence: evidence.ConfidenceExact,
		}},
		Sources: []SourceStatus{{ID: "runtime-endpoint-permissions", State: evidence.StateObserved, Source: "test", ItemCount: 1}},
	}
	inv.Runtimes = normalizeRuntimes(inv.Runtimes)
	inv.Containers = normalizeContainers(inv.Containers)
	inv.Security = normalizeSecurity(inv.Security)
	inv.RuntimeEndpoints = normalizeRuntimeEndpoints(inv.RuntimeEndpoints)
	inv.ConfigFiles = normalizeConfigs(inv.ConfigFiles)
	inv.Kubernetes = normalizeKubernetesPosture(inv.Kubernetes)
	inv.Kubeconfigs = normalizeKubeconfigs(inv.Kubeconfigs)
	inv.KubernetesCredentialPaths = normalizeKubernetesCredentialPaths(inv.KubernetesCredentialPaths)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Summary = summarize(inv)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Summary.RuntimeEndpoints != 1 || inv.Summary.EndpointPermissions != 1 || inv.Summary.GroupWritableSockets != 1 || inv.Summary.WorldWritableSockets != 0 {
		t.Fatalf("unexpected endpoint summary: %#v", inv.Summary)
	}
	found := false
	for _, o := range inv.Evidence {
		if strings.HasPrefix(o.Key, "container.runtime_endpoint.") {
			found = true
		}
	}
	if !found {
		t.Fatal("runtime endpoint evidence missing")
	}
}

func TestNormalizeWindowsNamedPipeEndpointCapabilityState(t *testing.T) {
	ep := RuntimeEndpointPosture{Runtime: "docker", Endpoint: `\\.\pipe\docker_engine`, EndpointKind: "NPIPE", State: evidence.StateObserved, PermissionAssessmentState: "NOT_APPLICABLE", OwnerAssessmentState: "NOT_APPLICABLE", WorldWritableState: "UNKNOWN", GroupWritableState: "UNKNOWN", LocalTransportState: "LOCAL_ONLY", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Reason: "Windows named-pipe ACL enrichment unavailable in this provider"}
	got := normalizeRuntimeEndpoints([]RuntimeEndpointPosture{ep})
	if len(got) != 1 || got[0].State != evidence.StateObserved || got[0].PermissionAssessmentState != "NOT_APPLICABLE" || got[0].OwnerAssessmentState != "NOT_APPLICABLE" {
		t.Fatalf("endpoint=%#v", got)
	}
}

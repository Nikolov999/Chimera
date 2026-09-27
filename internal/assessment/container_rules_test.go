package assessment

import (
	"testing"
	"time"

	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
)

func TestPhase088ContainerRulesDetectPrivilegedBoundaryWeaknesses(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.SecurityPosture{
		ID: "x", Runtime: "docker", RuntimeContainerID: "abcdef", Name: "web", State: evidence.StateObserved,
		PrivilegedState: "TRUE", RootExecutionState: "TRUE", PIDNamespace: "HOST", NetworkNamespace: "HOST", UserNamespace: "HOST",
		CapabilityAssessmentState: "OBSERVED", AddedCapabilities: []string{"SYS_ADMIN"}, DangerousCapabilities: []string{"SYS_ADMIN"}, CapabilityBoundingState: "UNBOUNDED",
		SeccompState: "UNCONFINED", MandatoryAccessControlState: "UNCONFINED", ReadOnlyRootFSState: "FALSE", NoNewPrivilegesState: "FALSE",
		UnrestrictedDeviceAccessState: "TRUE", MountAssessmentState: "OBSERVED", HostRootMountState: "FALSE", RuntimeSocketMountState: "FALSE", CredentialMountState: "FALSE", DeviceMountState: "FALSE", SensitiveHostPathMountState: "FALSE", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.summary", containerinv.Summary{Containers: 1, SecurityPostures: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.source.docker-security", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewState("container.source.runtime-endpoint-permissions", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local runtime endpoint"),
		evidence.NewState("container.orchestration.kubernetes", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "Kubernetes not observed"),
		evidence.NewState("container.source.kubernetes-kubeconfig", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local kubeconfig"),
		evidence.NewState("container.source.kubernetes-credential-paths", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local credential paths"),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 0}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.inventory.count", 0, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.security.abc", rec, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"CHM-CTR-001": StatusFail,
		"CHM-CTR-002": StatusFail,
		"CHM-CTR-003": StatusFail,
		"CHM-CTR-004": StatusWarn,
		"CHM-CTR-005": StatusFail,
		"CHM-CTR-006": StatusWarn,
		"CHM-CTR-007": StatusFail,
		"CHM-CTR-008": StatusPass,
		"CHM-CTR-009": StatusPass,
		"CHM-CTR-010": StatusPass,
		"CHM-CTR-011": StatusPass,
		"CHM-CTR-012": StatusPass,
		"CHM-CTR-013": StatusFail,
		"CHM-CTR-014": StatusWarn,
		"CHM-CTR-015": StatusFail,
		"CHM-CTR-016": StatusWarn,
		"CHM-CTR-017": StatusWarn,
		"CHM-CTR-018": StatusPass,
		"CHM-CTR-019": StatusPass,
		"CHM-CTR-020": StatusPass,
		"CHM-CTR-021": StatusPass,
		"CHM-CTR-022": StatusPass,
		"CHM-CTR-023": StatusPass,
		"CHM-CTR-024": StatusPass,
		"CHM-CTR-025": StatusPass,
	}
	for _, f := range findings {
		if f.Status != want[f.RuleID] {
			t.Fatalf("%s status=%s want=%s", f.RuleID, f.Status, want[f.RuleID])
		}
	}
}

func TestPhase088ContainerRulesPassIsolatedNonRootContainer(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.SecurityPosture{
		Runtime: "docker", RuntimeContainerID: "abcdef", Name: "worker", State: evidence.StateObserved,
		PrivilegedState: "FALSE", RootExecutionState: "FALSE", PIDNamespace: "PRIVATE", NetworkNamespace: "PRIVATE", UserNamespace: "REMAPPED",
		CapabilityAssessmentState: "OBSERVED", CapabilityBoundingState: "BOUNDED", SeccompState: "DEFAULT", MandatoryAccessControlState: "ENFORCED", ReadOnlyRootFSState: "TRUE", NoNewPrivilegesState: "TRUE",
		UnrestrictedDeviceAccessState: "FALSE", MountAssessmentState: "OBSERVED", HostRootMountState: "FALSE", RuntimeSocketMountState: "FALSE", CredentialMountState: "FALSE", DeviceMountState: "FALSE", SensitiveHostPathMountState: "FALSE", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.summary", containerinv.Summary{Containers: 1, SecurityPostures: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.source.docker-security", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewState("container.source.runtime-endpoint-permissions", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local runtime endpoint"),
		evidence.NewState("container.orchestration.kubernetes", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "Kubernetes not observed"),
		evidence.NewState("container.source.kubernetes-kubeconfig", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local kubeconfig"),
		evidence.NewState("container.source.kubernetes-credential-paths", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local credential paths"),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 0}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.inventory.count", 0, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.security.abc", rec, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Status != StatusPass {
			t.Fatalf("%s status=%s observed=%s", f.RuleID, f.Status, f.ObservedState)
		}
	}
}

func TestPhase088ContainerRulesStayUnknownWhenSecurityProviderDenied(t *testing.T) {
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("container.summary", containerinv.Summary{}, "test", at, evidence.ConfidenceHigh),
		evidence.NewState("container.source.docker-security", evidence.StateDenied, "test", at, evidence.ConfidenceLow, "permission denied"),
		evidence.NewState("container.source.developer-surfaces", evidence.StateDenied, "test", at, evidence.ConfidenceLow, "permission denied"),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Status != StatusUnknown {
			t.Fatalf("%s status=%s", f.RuleID, f.Status)
		}
	}
}

func TestImplementedRulesIncludesPhase092ContainerRulesExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		counts[r.ID]++
	}
	for _, id := range []string{"CHM-CTR-001", "CHM-CTR-002", "CHM-CTR-003", "CHM-CTR-004", "CHM-CTR-005", "CHM-CTR-006", "CHM-CTR-007", "CHM-CTR-008", "CHM-CTR-009", "CHM-CTR-010", "CHM-CTR-011", "CHM-CTR-012", "CHM-CTR-013", "CHM-CTR-014", "CHM-CTR-015", "CHM-CTR-016", "CHM-CTR-017", "CHM-CTR-018", "CHM-CTR-019", "CHM-CTR-020", "CHM-CTR-021", "CHM-CTR-022", "CHM-CTR-023", "CHM-CTR-024", "CHM-CTR-025"} {
		if counts[id] != 1 {
			t.Fatalf("%s count=%d", id, counts[id])
		}
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("rule set version=%q", RuleSetVersion)
	}
}

func TestPhase089ContainerRulesDetectDangerousHostMounts(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.SecurityPosture{
		ID: "mounts", Runtime: "docker", RuntimeContainerID: "abcdef", Name: "builder", State: evidence.StateObserved,
		PrivilegedState: "FALSE", RootExecutionState: "FALSE", PIDNamespace: "PRIVATE", NetworkNamespace: "PRIVATE", UserNamespace: "REMAPPED",
		CapabilityAssessmentState: "OBSERVED", CapabilityBoundingState: "BOUNDED", SeccompState: "DEFAULT", MandatoryAccessControlState: "ENFORCED", ReadOnlyRootFSState: "TRUE", NoNewPrivilegesState: "TRUE", UnrestrictedDeviceAccessState: "FALSE", MountAssessmentState: "OBSERVED",
		HostRootMountState: "TRUE", RuntimeSocketMountState: "TRUE", CredentialMountState: "TRUE", DeviceMountState: "TRUE", SensitiveHostPathMountState: "TRUE",
		Mounts: []containerinv.MountPosture{
			{Type: "bind", Source: "/", Destination: "/host", Access: "READ_ONLY", RiskTags: []string{"HOST_ROOT"}},
			{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", Access: "READ_ONLY", RiskTags: []string{"RUNTIME_SOCKET"}},
			{Type: "bind", Source: "/home/alice/.ssh", Destination: "/keys", Access: "READ_ONLY", RiskTags: []string{"CREDENTIAL_PATH"}},
			{Type: "bind", Source: "/dev/kvm", Destination: "/dev/kvm", Access: "READ_WRITE", RiskTags: []string{"DEVICE_PATH"}},
			{Type: "bind", Source: "/etc/kubernetes", Destination: "/host-kube", Access: "READ_ONLY", RiskTags: []string{"SENSITIVE_HOST_PATH"}},
		},
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.summary", containerinv.Summary{Containers: 1, SecurityPostures: 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.source.docker-security", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.security.mounts", rec, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	wantFail := map[string]bool{"CHM-CTR-008": true, "CHM-CTR-009": true, "CHM-CTR-010": true, "CHM-CTR-011": true, "CHM-CTR-012": true}
	for _, f := range findings {
		if wantFail[f.RuleID] && f.Status != StatusFail {
			t.Fatalf("%s status=%s observed=%s", f.RuleID, f.Status, f.ObservedState)
		}
	}
}

func TestPhase091RuntimeEndpointPermissionsDetectWorldWritableSocket(t *testing.T) {
	at := time.Now().UTC()
	ep := containerinv.RuntimeEndpointPosture{
		Runtime: "docker", Endpoint: "/var/run/docker.sock", EndpointKind: "UNIX_SOCKET", State: evidence.StateObserved,
		PermissionAssessmentState: "OBSERVED", Mode: "0666", OwnerAssessmentState: "OBSERVED", OwnerUID: "0", OwnerGID: "999",
		WorldWritableState: "TRUE", GroupWritableState: "TRUE", LocalTransportState: "LOCAL_ONLY", CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.runtime_endpoint.test", ep, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.source.runtime-endpoint-permissions", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 0}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.inventory.count", 0, "test", at, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-CTR-018" && f.Status != StatusFail {
			t.Fatalf("CHM-CTR-018 status=%s observed=%s", f.Status, f.ObservedState)
		}
	}
}

func TestPhase091RuntimeNetworkExposureDetectsNonLoopbackDockerAPI(t *testing.T) {
	at := time.Now().UTC()
	ep := netinv.Endpoint{
		ID: "docker-api", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 2375,
		InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{ProcessName: "dockerd", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewState("container.source.runtime-endpoint-permissions", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "no local runtime endpoint"),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.endpoint.docker-api", ep, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-CTR-019" && f.Status != StatusFail {
			t.Fatalf("CHM-CTR-019 status=%s observed=%s", f.Status, f.ObservedState)
		}
	}
}

func TestPhase092KubeconfigPermissionsDetectBroadAccess(t *testing.T) {
	at := time.Now().UTC()
	cfg := containerinv.KubeconfigPosture{
		ID: "cfg", Path: "/home/alice/.kube/config", Scope: "USER", State: evidence.StateObserved,
		PermissionAssessmentState: "OBSERVED", Mode: "0644", OwnerAssessmentState: "OBSERVED", OwnerUID: "1000", OwnerGID: "1000",
		WorldReadableState: "TRUE", WorldWritableState: "FALSE", GroupReadableState: "TRUE", GroupWritableState: "FALSE",
		StructureAssessmentState: "OBSERVED", EmbeddedCredentialState: "TRUE", EmbeddedCredentialKinds: []string{"TOKEN"},
		CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.orchestration.kubernetes", containerinv.KubernetesPosture{ID: "kubernetes", State: evidence.StateObserved, InstallationState: "PRESENT", Applicability: "WORKSTATION", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.source.kubernetes-kubeconfig", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.orchestration.kubeconfig.cfg", cfg, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("container.source.kubernetes-credential-paths", map[string]any{"state": "OBSERVED", "item_count": 0}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 0}, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-CTR-020" && f.Status != StatusFail {
			t.Fatalf("CHM-CTR-020 status=%s observed=%s", f.Status, f.ObservedState)
		}
	}
}

func TestPhase092CredentialPathPermissionsDetectBroadAccess(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.KubernetesCredentialPathPosture{
		ID: "cred", KubeconfigID: "cfg", Kind: "CLIENT_KEY", Path: "/home/alice/.kube/client.key", State: evidence.StateObserved,
		PermissionAssessmentState: "OBSERVED", Mode: "0640", OwnerAssessmentState: "OBSERVED", OwnerUID: "1000", OwnerGID: "1000",
		WorldReadableState: "FALSE", WorldWritableState: "FALSE", GroupReadableState: "TRUE", GroupWritableState: "FALSE",
		CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.orchestration.kubernetes", containerinv.KubernetesPosture{ID: "kubernetes", State: evidence.StateObserved, InstallationState: "PRESENT", Applicability: "WORKSTATION", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.source.kubernetes-credential-paths", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.orchestration.credential_path.cred", rec, "test", at, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-CTR-021" && f.Status != StatusWarn {
			t.Fatalf("CHM-CTR-021 status=%s observed=%s", f.Status, f.ObservedState)
		}
	}
}

func TestPhase092KubernetesAPIExposureFailsOnWorkstationOwnerProvenListener(t *testing.T) {
	at := time.Now().UTC()
	ep := netinv.Endpoint{
		ID: "kube-api", Protocol: "TCP", TransportState: "LISTEN", AddressFamily: "IPV4", LocalAddress: "0.0.0.0", LocalPort: 6443,
		InterfaceBinding: netinv.Binding{Class: "ALL_INTERFACES", IsWildcard: true}, Owner: netinv.Owner{ProcessName: "kube-apiserver", State: "OBSERVED"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("container.orchestration.kubernetes", containerinv.KubernetesPosture{ID: "kubernetes", State: evidence.StateObserved, InstallationState: "PRESENT", Applicability: "WORKSTATION", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.source.test", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("network.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.endpoint.kube-api", ep, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ContainerSecurityRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-CTR-022" && f.Status != StatusFail {
			t.Fatalf("CHM-CTR-022 status=%s observed=%s", f.Status, f.ObservedState)
		}
	}
}

func TestPhase095DeveloperSurfaceExposureIsProfileAware(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.DeveloperSurface{
		ID: "dev", Kind: "LANGUAGE_DEBUGGER", Product: "debugpy", PID: 4242,
		State: evidence.StateObserved, ActivationState: "ENABLED", ListenerState: "LISTENING",
		BindingState: "ALL_INTERFACES", LocalAddress: "0.0.0.0", LocalPort: 5678,
		Transport: "TCP", ExposureState: "NETWORK_REACHABLE", CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("container.source.developer-surfaces", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.developer.surface.dev", rec, "test", at, evidence.ConfidenceExact),
	})
	r := phase095Rule(t, "CHM-CTR-023")
	if got := r.EvaluateProfile("developer", idx); got.Status != StatusWarn {
		t.Fatalf("developer profile status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.EvaluateProfile("workstation", idx); got.Status != StatusFail {
		t.Fatalf("workstation profile status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.EvaluateProfile("server", idx); got.Status != StatusFail {
		t.Fatalf("server profile status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestPhase095DeveloperSurfaceRoleDistinguishesDeveloperAndHardenedHosts(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.DeveloperSurface{
		ID: "dev", Kind: "BROWSER_REMOTE_DEBUG", Product: "Chrome DevTools", PID: 77,
		State: evidence.StateObserved, ActivationState: "ENABLED", ListenerState: "LISTENING",
		BindingState: "LOOPBACK", LocalAddress: "127.0.0.1", LocalPort: 9222,
		Transport: "TCP", ExposureState: "LOCAL_ONLY", CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("container.source.developer-surfaces", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("container.developer.surface.dev", rec, "test", at, evidence.ConfidenceExact),
	})
	r := phase095Rule(t, "CHM-CTR-024")
	if got := r.EvaluateProfile("developer", idx); got.Status != StatusPass {
		t.Fatalf("developer profile status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.EvaluateProfile("server", idx); got.Status != StatusWarn {
		t.Fatalf("server profile status=%s observed=%s", got.Status, got.ObservedState)
	}
	if got := r.EvaluateProfile("high-security", idx); got.Status != StatusFail {
		t.Fatalf("high-security profile status=%s observed=%s", got.Status, got.ObservedState)
	}
}

func TestPhase095DeveloperSurfaceUnknownExposureStaysUnknown(t *testing.T) {
	at := time.Now().UTC()
	rec := containerinv.DeveloperSurface{
		ID: "dev", Kind: "IDE_REMOTE", Product: "code-server", PID: 5150,
		State: evidence.StateObserved, ActivationState: "ENABLED", ListenerState: "NOT_OBSERVED",
		BindingState: "ALL_INTERFACES", LocalAddress: "0.0.0.0", LocalPort: 8080,
		ExposureState: "UNKNOWN", CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("container.source.developer-surfaces", map[string]any{"state": "OBSERVED", "item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewState("container.source.developer-listener-correlation", evidence.StateUnavailable, "test", at, evidence.ConfidenceLow, "listener provider unavailable"),
		evidence.NewObserved("container.developer.surface.dev", rec, "test", at, evidence.ConfidenceHigh),
	})
	for _, id := range []string{"CHM-CTR-023", "CHM-CTR-025"} {
		got := phase095Rule(t, id).EvaluateProfile("developer", idx)
		if got.Status != StatusUnknown {
			t.Fatalf("%s status=%s observed=%s", id, got.Status, got.ObservedState)
		}
	}
}

func phase095Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range DeveloperSurfaceRules() {
		if r.ID == id {
			if r.EvaluateProfile == nil {
				t.Fatalf("%s missing profile evaluator", id)
			}
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

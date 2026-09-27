package containers

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	networkinv "github.com/Nikolov999/chimera/internal/network"
)

func TestClassifyDeveloperProcessRedactsAndClassifies(t *testing.T) {
	tests := []struct {
		name string
		p    developerProcess
		kind string
		port uint16
		host string
	}{
		{"chrome", developerProcess{PID: 1, Name: "chrome", Command: `chrome --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0 --user-data-dir=/secret/path`}, "BROWSER_REMOTE_DEBUG", 9222, "0.0.0.0"},
		{"jupyter", developerProcess{PID: 2, Name: "jupyter-lab", Command: `jupyter lab --ServerApp.ip=127.0.0.1 --ServerApp.port=8899 --ServerApp.token=secret`}, "JUPYTER", 8899, "127.0.0.1"},
		{"debugpy", developerProcess{PID: 3, Name: "python", Command: `python -m debugpy --listen 0.0.0.0:5678 app.py --api-key secret`}, "LANGUAGE_DEBUGGER", 5678, "0.0.0.0"},
		{"node", developerProcess{PID: 4, Name: "node", Command: `node --inspect=127.0.0.1:9230 app.js`}, "LANGUAGE_DEBUGGER", 9230, "127.0.0.1"},
		{"delve", developerProcess{PID: 5, Name: "dlv", Command: `dlv debug --headless --listen=:2345`}, "LANGUAGE_DEBUGGER", 2345, "0.0.0.0"},
		{"code-server", developerProcess{PID: 6, Name: "code-server", Command: `code-server --bind-addr 0.0.0.0:8081 --auth password`}, "IDE_REMOTE", 8081, "0.0.0.0"},
		{"adb", developerProcess{PID: 7, Name: "adb", Command: `adb -a -P 5038 fork-server server --reply-fd 9`}, "ADB", 5038, "0.0.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDeveloperProcess(tt.p)
			if len(got) != 1 {
				t.Fatalf("expected one candidate, got %#v", got)
			}
			if got[0].Kind != tt.kind || got[0].RequestedPort != tt.port || got[0].RequestedHost != tt.host {
				t.Fatalf("unexpected classification: %#v", got[0])
			}
			for _, b := range got[0].DetectionBasis {
				if b == "secret" || b == "/secret/path" {
					t.Fatalf("secret argument value leaked into detection basis: %#v", got[0].DetectionBasis)
				}
			}
		})
	}
}

func TestBuildDeveloperSurfaceUsesOwnedListenerBinding(t *testing.T) {
	p := developerProcess{PID: 44, Name: "node", Executable: "/usr/bin/node"}
	c := developerCandidate{Kind: "LANGUAGE_DEBUGGER", Product: "Node.js inspector", RequestedHost: "127.0.0.1", RequestedPort: 9229, DetectionBasis: []string{"flag:--inspect"}, Confidence: evidence.ConfidenceExact}
	ep := networkinv.Endpoint{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 9229, InterfaceBinding: networkinv.Binding{Class: "ALL_INTERFACES"}}
	got := buildDeveloperSurface(p, c, []networkinv.Endpoint{ep}, evidence.StateObserved)
	if got.ListenerState != "LISTENING" || got.BindingState != "ALL_INTERFACES" || got.ExposureState != "NETWORK_REACHABLE" || got.LocalPort != 9229 {
		t.Fatalf("unexpected surface: %#v", got)
	}
}

func TestNormalizeDeveloperSurfacesDeterministic(t *testing.T) {
	in := []DeveloperSurface{
		{PID: 2, Kind: "jupyter", Product: "Jupyter", State: evidence.StateObserved, ActivationState: "enabled", ListenerState: "unknown", BindingState: "unknown", ExposureState: "unknown", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
		{PID: 1, Kind: "adb", Product: "ADB", State: evidence.StateObserved, ActivationState: "enabled", ListenerState: "unknown", BindingState: "unknown", ExposureState: "unknown", CollectionSource: "test", Confidence: evidence.ConfidenceHigh},
	}
	got := normalizeDeveloperSurfaces(in)
	if len(got) != 2 || got[0].PID != 1 || got[1].PID != 2 || got[0].ID == "" || got[1].ID == "" {
		t.Fatalf("unexpected normalized order: %#v", got)
	}
}

func TestFix59DeveloperNetworkStatePreservesDegradedSharedEvidence(t *testing.T) {
	base := networkinv.Inventory{
		Schema: networkinv.SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: networkinv.CollectorName, CollectorVersion: networkinv.CollectorVersion,
		Platform: "windows", Architecture: "amd64", CollectedAt: time.Now().UTC(),
	}

	observed := base
	observed.Sources = []networkinv.SourceStatus{{ID: "get-net-endpoints", State: evidence.StateObserved, Source: "test"}}
	if state, reason := developerNetworkState(observed); state != evidence.StateObserved || reason != "" {
		t.Fatalf("observed network state mismatch: state=%s reason=%q", state, reason)
	}

	degraded := base
	degraded.Sources = []networkinv.SourceStatus{{ID: "get-net-endpoints", State: evidence.StateDegraded, Source: "test", Reason: "safe collection boundary"}}
	if state, reason := developerNetworkState(degraded); state != evidence.StateDegraded || !strings.Contains(reason, "safe collection boundary") {
		t.Fatalf("degraded network state mismatch: state=%s reason=%q", state, reason)
	}

	unavailable := base
	unavailable.Sources = []networkinv.SourceStatus{{ID: "get-net-endpoints", State: evidence.StateUnavailable, Source: "test", Reason: "provider unavailable"}}
	if state, reason := developerNetworkState(unavailable); state != evidence.StateUnavailable || !strings.Contains(reason, "provider unavailable") {
		t.Fatalf("unavailable network state mismatch: state=%s reason=%q", state, reason)
	}
}

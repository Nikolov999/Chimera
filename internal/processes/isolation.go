package processes

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// IsolationContext is additive evidence describing process isolation
// and containment metadata only. It never changes process state or host policy.
type IsolationContext struct {
	ProcessID          string              `json:"process_id"`
	PID                int                 `json:"pid"`
	Platform           string              `json:"platform"`
	State              string              `json:"state"`
	IsolationState     string              `json:"isolation_state"`
	PIDNamespace       bool                `json:"pid_namespace"`
	MountNamespace     bool                `json:"mount_namespace"`
	NetworkNamespace   bool                `json:"network_namespace"`
	UserNamespace      bool                `json:"user_namespace"`
	UTSNamespace       bool                `json:"uts_namespace"`
	IPCNamespace       bool                `json:"ipc_namespace"`
	CgroupNamespace    bool                `json:"cgroup_namespace"`
	TimeNamespace      bool                `json:"time_namespace"`
	NamespaceCount     int                 `json:"namespace_count"`
	NestedPIDNamespace bool                `json:"nested_pid_namespace"`
	Seccomp            string              `json:"seccomp,omitempty"`
	NoNewPrivileges    bool                `json:"no_new_privileges"`
	Cgroup             string              `json:"cgroup,omitempty"`
	CgroupScoped       bool                `json:"cgroup_scoped"`
	ContainerHint      bool                `json:"container_hint"`
	ContainerRuntime   string              `json:"container_runtime,omitempty"`
	AppContainer       string              `json:"app_container,omitempty"`
	JobObject          string              `json:"job_object,omitempty"`
	Sandbox            string              `json:"sandbox,omitempty"`
	SandboxBasis       string              `json:"sandbox_basis,omitempty"`
	LSMProfile         string              `json:"lsm_profile,omitempty"`
	Signals            []string            `json:"signals,omitempty"`
	Source             string              `json:"source"`
	Confidence         evidence.Confidence `json:"confidence"`
	Reason             string              `json:"reason,omitempty"`
}

type isolationProviderStats struct {
	ID      string
	State   evidence.State
	Source  string
	Count   int
	Denied  int
	Missing int
	Reason  string
}

func collectIsolationPosture(ctx context.Context, items []Process, platform string) ([]IsolationContext, SourceStatus) {
	raw, stats := collectIsolationPlatform(ctx, items)
	byPID := make(map[int]IsolationContext, len(raw))
	for _, c := range raw {
		if c.PID <= 0 {
			continue
		}
		c.Platform = fallback(strings.ToLower(strings.TrimSpace(c.Platform)), strings.ToLower(strings.TrimSpace(platform)))
		c.State = strings.ToUpper(fallback(strings.TrimSpace(c.State), "UNKNOWN"))
		c.IsolationState = strings.ToUpper(fallback(strings.TrimSpace(c.IsolationState), "UNKNOWN"))
		c.Seccomp = strings.ToUpper(strings.TrimSpace(c.Seccomp))
		c.AppContainer = strings.ToUpper(strings.TrimSpace(c.AppContainer))
		c.JobObject = strings.ToUpper(strings.TrimSpace(c.JobObject))
		c.Sandbox = strings.ToUpper(strings.TrimSpace(c.Sandbox))
		c.ContainerRuntime = strings.ToLower(strings.TrimSpace(c.ContainerRuntime))
		c.Cgroup = strings.TrimSpace(c.Cgroup)
		c.LSMProfile = strings.TrimSpace(c.LSMProfile)
		c.SandboxBasis = strings.TrimSpace(c.SandboxBasis)
		c.Source = fallback(strings.TrimSpace(c.Source), "platform process-isolation metadata")
		c.Reason = strings.TrimSpace(c.Reason)
		c.Signals = normalizedList(c.Signals)
		c.NamespaceCount = countIsolationNamespaces(c)
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceLow
		}
		if old, ok := byPID[c.PID]; !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) {
			byPID[c.PID] = c
		}
	}

	out := make([]IsolationContext, 0, len(items))
	for _, p := range items {
		c, ok := byPID[p.PID]
		if !ok {
			c = IsolationContext{
				PID: p.PID, Platform: strings.ToLower(strings.TrimSpace(platform)), State: "UNKNOWN", IsolationState: "UNKNOWN",
				AppContainer: "UNKNOWN", JobObject: "UNKNOWN", Sandbox: "UNKNOWN",
				Source: "platform process-isolation metadata", Confidence: evidence.ConfidenceLow,
				Reason: "process-isolation metadata unavailable for observed process",
			}
		}
		c.ProcessID = p.ID
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ProcessID < out[j].ProcessID
	})

	state := stats.State
	if state == "" {
		state = evidence.StateUnavailable
	}
	reason := strings.TrimSpace(stats.Reason)
	if reason == "" && (stats.Denied > 0 || stats.Missing > 0) {
		parts := []string{}
		if stats.Denied > 0 {
			parts = append(parts, itoa(stats.Denied)+" process isolation record(s) permission-restricted")
		}
		if stats.Missing > 0 {
			parts = append(parts, itoa(stats.Missing)+" process isolation record(s) unavailable or exited during collection")
		}
		reason = strings.Join(parts, "; ")
		if stats.Count > 0 {
			state = evidence.StateDegraded
		} else if stats.Denied > 0 {
			state = evidence.StateDenied
		}
	}
	return out, SourceStatus{ID: stats.ID, State: state, Source: fallback(stats.Source, "platform process-isolation metadata"), ItemCount: stats.Count, Reason: reason}
}

func countIsolationNamespaces(c IsolationContext) int {
	n := 0
	for _, v := range []bool{c.PIDNamespace, c.MountNamespace, c.NetworkNamespace, c.UserNamespace, c.UTSNamespace, c.IPCNamespace, c.CgroupNamespace, c.TimeNamespace} {
		if v {
			n++
		}
	}
	return n
}

func applyIsolationSummaries(items []Process, contexts []IsolationContext) {
	byID := make(map[string]IsolationContext, len(contexts))
	for _, c := range contexts {
		byID[c.ProcessID] = c
	}
	for i := range items {
		c, ok := byID[items[i].ID]
		if !ok {
			continue
		}
		items[i].Isolation.State = c.IsolationState
		items[i].Isolation.PIDNamespace = c.PIDNamespace
		items[i].Isolation.MountNamespace = c.MountNamespace
		items[i].Isolation.NetworkNamespace = c.NetworkNamespace
		items[i].Isolation.UserNamespace = c.UserNamespace
		items[i].Isolation.Seccomp = c.Seccomp
		items[i].Isolation.NoNewPrivileges = c.NoNewPrivileges
		items[i].Isolation.Cgroup = c.Cgroup
		items[i].Isolation.AppContainer = c.AppContainer
		items[i].Isolation.JobObject = c.JobObject
		items[i].Isolation.Sandbox = c.Sandbox
		items[i].Isolation.Reason = c.Reason
	}
}

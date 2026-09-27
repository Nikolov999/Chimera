//go:build darwin

package processes

import (
	"context"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	raw, extended, err := darwinProcessTable(ctx)
	if err != nil {
		addSource(inv, "darwin-ps", stateForDarwinErr(ctx, err), "ps process metadata", 0, err.Error())
		addSource(inv, "darwin-runtime-privilege", stateForDarwinErr(ctx, err), "ps real/effective credential metadata", 0, err.Error())
		return
	}
	cmdMeta := darwinCommandMetadata(ctx)
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if extended {
			if len(f) < 9 {
				continue
			}
		} else if len(f) < 7 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		if e1 != nil || e2 != nil || pid <= 0 {
			continue
		}
		var ruid, euid, rgid, egid, session, state, path string
		if extended {
			ruid, euid, rgid, egid = f[2], f[3], f[4], f[5]
			session, state = f[6], f[7]
			path = strings.Join(f[8:], " ")
		} else {
			ruid, euid, rgid, egid = f[2], f[2], f[3], f[3]
			session, state = f[4], f[5]
			path = strings.Join(f[6:], " ")
		}
		name := filepath.Base(path)
		if name == "." || name == "" {
			name = path
		}
		uname := euid
		if u, e := user.LookupId(euid); e == nil && u.Username != "" {
			uname = u.Username
		}
		gname := egid
		if g, e := user.LookupGroupId(egid); e == nil && g.Name != "" {
			gname = g.Name
		}
		elevated := euid == "0"
		pctx := "STANDARD"
		desc := "standard user"
		if elevated {
			pctx = "ROOT"
			desc = "root-equivalent effective UID"
		}
		trust := TrustContext{State: "UNCLASSIFIED_PATH", Basis: "path classification only; code-signing trust evaluation is deferred to "}
		if strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/sbin/") {
			trust.State = "SYSTEM_OR_MANAGED_PATH"
			trust.Basis = "executable resides in a conventional macOS system path"
		} else if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/private/tmp/") {
			trust.State = "TEMPORARY_PATH"
			trust.Basis = "executable resides in a temporary path"
		}
		meta := cmdMeta[pid]
		if meta.Source == "" {
			meta = CommandLineMetadata{Redacted: true, Source: "ps command metadata", Reason: "command-line metadata unavailable"}
		}
		inv.Processes = append(inv.Processes, Process{PID: pid, PPID: ppid, Name: name, Executable: name, ExecutablePath: path, Principal: Principal{User: uname, UserID: euid, Group: gname, GroupID: egid, Elevated: elevated, Context: desc}, SessionID: session, PrivilegeContext: pctx, RuntimeState: state, CommandLine: meta, Trust: trust, Isolation: IsolationSummary{State: "UNKNOWN", Sandbox: "UNKNOWN", Reason: "ps does not expose definitive sandbox/container membership"}, CollectionSource: "macOS ps", Confidence: evidence.ConfidenceHigh})
		inv.RuntimePrivileges = append(inv.RuntimePrivileges, darwinRuntimePrivilege(pid, ruid, euid, rgid, egid, extended))
		count++
		if count >= maxProcesses {
			break
		}
	}
	addSource(inv, "darwin-ps", evidence.StateObserved, "ps process metadata", count, "")
	privState := evidence.StateObserved
	privReason := ""
	if !extended {
		privState = evidence.StateDegraded
		privReason = "ps real/effective credential columns were unavailable; effective identity remains observable but transitions cannot be distinguished"
	}
	addSource(inv, "darwin-runtime-privilege", privState, "ps real/effective credential metadata", len(inv.RuntimePrivileges), privReason)
}

func darwinProcessTable(ctx context.Context) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,ruid=,euid=,rgid=,egid=,sess=,state=,comm=")
	raw, err := cmd.Output()
	if err == nil {
		return raw, true, nil
	}
	cmd = exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,uid=,gid=,sess=,state=,comm=")
	raw, fallbackErr := cmd.Output()
	if fallbackErr != nil {
		return nil, false, err
	}
	return raw, false, nil
}

func darwinRuntimePrivilege(pid int, ruid, euid, rgid, egid string, extended bool) RuntimePrivilegeContext {
	accountClass := "USER"
	if euid == "0" {
		accountClass = "ROOT"
	} else if euid == "" {
		accountClass = "UNKNOWN"
	}
	transition := extended && ((ruid != "" && euid != "" && ruid != euid) || (rgid != "" && egid != "" && rgid != egid))
	signals := []string{}
	if extended && ruid != "" && euid != "" && ruid != euid {
		signals = append(signals, "effective-user-id-differs-from-real-user-id")
		if euid == "0" && ruid != "0" {
			signals = append(signals, "effective-root-identity-transition")
		}
	}
	if extended && rgid != "" && egid != "" && rgid != egid {
		signals = append(signals, "effective-group-id-differs-from-real-group-id")
	}
	state := "STANDARD"
	confidence := evidence.ConfidenceHigh
	reason := "macOS ps does not expose a generic per-process privilege-set equivalent; credential identity is assessed separately"
	if euid == "" {
		state = "UNKNOWN"
		confidence = evidence.ConfidenceLow
	} else if len(signals) > 0 {
		state = "EXCESS"
	} else if euid == "0" {
		state = "ELEVATED"
	}
	if !extended {
		confidence = evidence.ConfidenceMedium
		reason = "real/effective credential distinction unavailable from ps fallback; privilege-set metadata is not exposed by this provider"
	}
	return RuntimePrivilegeContext{
		PID: pid, Platform: "darwin", State: state, AccountClass: accountClass,
		RealUserID: ruid, EffectiveUserID: euid, RealGroupID: rgid, EffectiveGroupID: egid,
		IdentityTransition: transition, PrivilegeSetState: "NOT_APPLICABLE", ExcessSignals: signals,
		Source: "macOS ps credential metadata", Confidence: confidence, Reason: reason,
	}
}

func darwinCommandMetadata(ctx context.Context) map[int]CommandLineMetadata {
	out := map[int]CommandLineMetadata{}
	cmd := exec.CommandContext(ctx, "ps", "-ww", "-axo", "pid=,command=")
	b, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line[:i]))
		if err != nil {
			continue
		}
		command := strings.TrimSpace(line[i:])
		argc := len(strings.Fields(command))
		out[pid] = CommandLineMetadata{Available: true, ArgumentCount: argc, ByteCount: len(command), Redacted: true, Source: "ps -ww command metadata"}
	}
	return out
}
func stateForDarwinErr(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil {
		return evidence.StateDegraded
	}
	if strings.Contains(strings.ToLower(err.Error()), "permission") {
		return evidence.StateDenied
	}
	return evidence.StateUnavailable
}

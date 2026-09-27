//go:build linux

package processes

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type linuxStatus struct {
	name, state                            string
	ppid                                   int
	uid, euid, suid, fsuid                 string
	gid, egid, sgid, fsgid                 string
	nspid                                  []string
	seccomp                                string
	noNewPrivs                             bool
	capInh, capPrm, capEff, capBnd, capAmb string
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		addSource(inv, "linux-proc", stateForErr(err), "/proc process metadata", 0, err.Error())
		return
	}
	selfNS := namespaceLinks("/proc/self/ns")
	userCache := map[string]string{}
	groupCache := map[string]string{}
	count := 0
	denied := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			addSource(inv, "linux-proc-deadline", evidence.StateDegraded, "/proc process metadata", count, ctx.Err().Error())
			break
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		st, err := readLinuxStatus(filepath.Join(base, "status"))
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		exePath, deleted := readExe(filepath.Join(base, "exe"))
		cmd := readCmdline(filepath.Join(base, "cmdline"))
		session := readSessionID(filepath.Join(base, "stat"))
		principal := linuxPrincipal(st, userCache, groupCache)
		trust := linuxTrust(exePath, deleted)
		isolation := linuxIsolation(base, selfNS, st)
		executable := filepath.Base(strings.TrimSuffix(exePath, " (deleted)"))
		if executable == "." || executable == "" {
			executable = st.name
		}
		inv.Processes = append(inv.Processes, Process{
			PID: pid, PPID: st.ppid, Name: st.name, Executable: executable, ExecutablePath: strings.TrimSuffix(exePath, " (deleted)"),
			Principal: principal, SessionID: session, PrivilegeContext: linuxPrivilege(st), RuntimeState: st.state,
			CommandLine: cmd, Trust: trust, Isolation: isolation, CollectionSource: "Linux procfs", Confidence: evidence.ConfidenceHigh,
		})
		inv.RuntimePrivileges = append(inv.RuntimePrivileges, linuxRuntimePrivilege(pid, st))
		count++
		if count >= maxProcesses {
			inv.Degraded = append(inv.Degraded, fmt.Sprintf("process inventory truncated at %d records", maxProcesses))
			break
		}
	}
	addSource(inv, "linux-proc", evidence.StateObserved, "/proc process metadata", count, "")
	addSource(inv, "linux-runtime-privilege", evidence.StateObserved, "/proc/<pid>/status UID/GID/Cap* metadata", len(inv.RuntimePrivileges), "")
	if denied > 0 {
		addSource(inv, "linux-proc-restricted", evidence.StateDenied, "/proc restricted process metadata", 0, fmt.Sprintf("%d process status records were permission-restricted or vanished during collection", denied))
	}
}

func readLinuxStatus(path string) (linuxStatus, error) {
	f, err := os.Open(path)
	if err != nil {
		return linuxStatus{}, err
	}
	defer f.Close()
	var st linuxStatus
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		fields := strings.Fields(v)
		switch k {
		case "Name":
			st.name = v
		case "State":
			st.state = v
		case "PPid":
			st.ppid, _ = strconv.Atoi(v)
		case "Uid":
			if len(fields) >= 2 {
				st.uid = fields[0]
				st.euid = fields[1]
			}
			if len(fields) >= 4 {
				st.suid = fields[2]
				st.fsuid = fields[3]
			}
		case "Gid":
			if len(fields) >= 2 {
				st.gid = fields[0]
				st.egid = fields[1]
			}
			if len(fields) >= 4 {
				st.sgid = fields[2]
				st.fsgid = fields[3]
			}
		case "NSpid":
			st.nspid = fields
		case "Seccomp":
			st.seccomp = v
		case "NoNewPrivs":
			st.noNewPrivs = v == "1"
		case "CapInh":
			st.capInh = v
		case "CapPrm":
			st.capPrm = v
		case "CapEff":
			st.capEff = v
		case "CapBnd":
			st.capBnd = v
		case "CapAmb":
			st.capAmb = v
		}
	}
	if err := s.Err(); err != nil {
		return st, err
	}
	if st.name == "" {
		return st, fmt.Errorf("missing process name")
	}
	return st, nil
}

func readExe(path string) (string, bool) {
	p, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	return p, strings.HasSuffix(p, " (deleted)")
}
func readCmdline(path string) CommandLineMetadata {
	b, err := os.ReadFile(path)
	if err != nil {
		return CommandLineMetadata{Redacted: true, Source: "/proc/<pid>/cmdline", Reason: err.Error()}
	}
	if len(b) == 0 {
		return CommandLineMetadata{Available: true, Redacted: true, Source: "/proc/<pid>/cmdline"}
	}
	argc := 0
	for _, x := range b {
		if x == 0 {
			argc++
		}
	}
	if b[len(b)-1] != 0 {
		argc++
	}
	return CommandLineMetadata{Available: true, ArgumentCount: argc, ByteCount: len(b), Redacted: true, Source: "/proc/<pid>/cmdline"}
}
func readSessionID(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "UNKNOWN"
	}
	text := string(b)
	end := strings.LastIndex(text, ")")
	if end < 0 {
		return "UNKNOWN"
	}
	f := strings.Fields(text[end+1:])
	if len(f) < 4 {
		return "UNKNOWN"
	}
	return f[3]
}

func linuxPrincipal(st linuxStatus, users, groups map[string]string) Principal {
	uid := st.euid
	if uid == "" {
		uid = st.uid
	}
	gid := st.egid
	if gid == "" {
		gid = st.gid
	}
	name := lookupUser(uid, users)
	group := lookupGroup(gid, groups)
	elevated := uid == "0"
	ctx := "standard user"
	if elevated {
		ctx = "root-equivalent effective UID"
	}
	return Principal{User: name, UserID: uid, Group: group, GroupID: gid, Elevated: elevated, Context: ctx}
}
func lookupUser(id string, cache map[string]string) string {
	if id == "" {
		return "UNKNOWN"
	}
	if v, ok := cache[id]; ok {
		return v
	}
	v := id
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		v = u.Username
	}
	cache[id] = v
	return v
}
func lookupGroup(id string, cache map[string]string) string {
	if id == "" {
		return "UNKNOWN"
	}
	if v, ok := cache[id]; ok {
		return v
	}
	v := id
	if g, err := user.LookupGroupId(id); err == nil && g.Name != "" {
		v = g.Name
	}
	cache[id] = v
	return v
}
func linuxPrivilege(st linuxStatus) string {
	if st.euid == "0" {
		return "ROOT"
	}
	if st.capEff != "" && st.capEff != "0000000000000000" {
		return "CAPABILITIES_PRESENT"
	}
	return "STANDARD"
}

func linuxRuntimePrivilege(pid int, st linuxStatus) RuntimePrivilegeContext {
	effective := linuxCapabilityNames(st.capEff)
	permitted := linuxCapabilityNames(st.capPrm)
	ambient := linuxCapabilityNames(st.capAmb)
	high := highImpactCapabilitySet(effective, permitted, ambient)
	accountClass := "USER"
	if st.euid == "0" {
		accountClass = "ROOT"
	} else if st.euid == "" {
		accountClass = "UNKNOWN"
	}
	transition := (st.uid != "" && st.euid != "" && st.uid != st.euid) || (st.gid != "" && st.egid != "" && st.gid != st.egid)
	signals := []string{}
	if st.uid != "" && st.euid != "" && st.uid != st.euid {
		signals = append(signals, "effective-user-id-differs-from-real-user-id")
		if st.euid == "0" && st.uid != "0" {
			signals = append(signals, "effective-root-identity-transition")
		}
	}
	if st.gid != "" && st.egid != "" && st.gid != st.egid {
		signals = append(signals, "effective-group-id-differs-from-real-group-id")
	}
	if st.euid != "" && st.euid != "0" && len(highImpactCapabilitySet(effective)) > 0 {
		signals = append(signals, "non-root-high-impact-effective-capabilities")
	}
	if st.euid != "" && st.euid != "0" && len(highImpactCapabilitySet(permitted)) > 0 {
		signals = append(signals, "non-root-high-impact-permitted-capabilities")
	}
	if len(highImpactCapabilitySet(ambient)) > 0 {
		signals = append(signals, "high-impact-ambient-capabilities")
	}
	state := "STANDARD"
	if st.euid == "" && st.uid == "" {
		state = "UNKNOWN"
	} else if len(signals) > 0 {
		state = "EXCESS"
	} else if st.euid == "0" || len(effective) > 0 {
		state = "ELEVATED"
	}
	return RuntimePrivilegeContext{
		PID: pid, Platform: "linux", State: state, AccountClass: accountClass,
		RealUserID: st.uid, EffectiveUserID: st.euid, SavedUserID: st.suid, FileSystemUserID: st.fsuid,
		RealGroupID: st.gid, EffectiveGroupID: st.egid, SavedGroupID: st.sgid, FileSystemGroupID: st.fsgid,
		IdentityTransition: transition, PrivilegeSetState: "OBSERVED",
		EffectiveCapabilities: effective, PermittedCapabilities: permitted, AmbientCapabilities: ambient,
		HighImpactPrivileges: high, ExcessSignals: signals,
		Source: "/proc/<pid>/status UID/GID/Cap* metadata", Confidence: evidence.ConfidenceExact,
	}
}

func linuxCapabilityNames(hexMask string) []string {
	hexMask = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(hexMask), "0x"))
	if hexMask == "" {
		return nil
	}
	mask, err := strconv.ParseUint(hexMask, 16, 64)
	if err != nil || mask == 0 {
		return nil
	}
	names := []string{
		"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
		"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
		"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
		"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
	}
	out := make([]string, 0)
	for bit, name := range names {
		if mask&(uint64(1)<<uint(bit)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func linuxTrust(path string, deleted bool) TrustContext {
	t := TrustContext{State: "UNKNOWN", Basis: "executable path metadata only; signing/package trust evaluation is deferred to ", DeletedBacking: deleted}
	if path == "" {
		t.Reason = "executable path unavailable"
		return t
	}
	clean := strings.TrimSuffix(path, " (deleted)")
	info, err := os.Stat(clean)
	if err != nil {
		t.Reason = err.Error()
		if deleted {
			t.State = "DELETED_BACKING"
		}
		return t
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		t.Owner = strconv.FormatUint(uint64(st.Uid), 10)
	}
	t.Mode = info.Mode().Perm().String()
	if deleted {
		t.State = "DELETED_BACKING"
		t.Basis = "procfs executable symlink marks deleted backing"
		return t
	}
	switch {
	case strings.HasPrefix(clean, "/usr/") || strings.HasPrefix(clean, "/bin/") || strings.HasPrefix(clean, "/sbin/") || strings.HasPrefix(clean, "/lib/") || strings.HasPrefix(clean, "/opt/"):
		t.State = "SYSTEM_OR_MANAGED_PATH"
		t.Basis = "executable resides in a conventional system/managed path"
	case strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/var/tmp/") || strings.HasPrefix(clean, "/dev/shm/"):
		t.State = "TEMPORARY_PATH"
		t.Basis = "executable resides in a temporary or shared-memory path"
	default:
		t.State = "UNCLASSIFIED_PATH"
		t.Basis = "path is outside conventional system and temporary roots"
	}
	return t
}

func namespaceLinks(dir string) map[string]string {
	out := map[string]string{}
	for _, n := range []string{"pid", "mnt", "net", "user"} {
		if p, err := os.Readlink(filepath.Join(dir, n)); err == nil {
			out[n] = p
		}
	}
	return out
}
func linuxIsolation(base string, self map[string]string, st linuxStatus) IsolationSummary {
	cur := namespaceLinks(filepath.Join(base, "ns"))
	iso := IsolationSummary{State: "HOST", Seccomp: seccompName(st.seccomp), NoNewPrivileges: st.noNewPrivs}
	iso.PIDNamespace = cur["pid"] != "" && self["pid"] != "" && cur["pid"] != self["pid"]
	iso.MountNamespace = cur["mnt"] != "" && self["mnt"] != "" && cur["mnt"] != self["mnt"]
	iso.NetworkNamespace = cur["net"] != "" && self["net"] != "" && cur["net"] != self["net"]
	iso.UserNamespace = cur["user"] != "" && self["user"] != "" && cur["user"] != self["user"]
	if len(st.nspid) > 1 || iso.PIDNamespace || iso.MountNamespace || iso.NetworkNamespace || iso.UserNamespace {
		iso.State = "ISOLATED"
	}
	if b, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		lines := strings.Fields(string(b))
		if len(lines) > 0 {
			iso.Cgroup = strings.Join(lines, ";")
		}
	} else {
		iso.Reason = "cgroup metadata unavailable: " + err.Error()
	}
	return iso
}
func seccompName(v string) string {
	switch v {
	case "0":
		return "DISABLED"
	case "1":
		return "STRICT"
	case "2":
		return "FILTER"
	}
	if v == "" {
		return "UNKNOWN"
	}
	return v
}
func stateForErr(err error) evidence.State {
	if os.IsPermission(err) {
		return evidence.StateDenied
	}
	return evidence.StateUnavailable
}

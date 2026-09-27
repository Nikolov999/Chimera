//go:build windows

package processes

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

type winProc struct {
	PID               int      `json:"pid"`
	PPID              int      `json:"ppid"`
	Name              string   `json:"name"`
	Path              string   `json:"path"`
	StartTime         string   `json:"start_time"`
	SessionID         int      `json:"session_id"`
	State             string   `json:"state"`
	User              string   `json:"user"`
	Domain            string   `json:"domain"`
	SID               string   `json:"sid"`
	CmdBytes          int      `json:"cmd_bytes"`
	ArgCount          int      `json:"arg_count"`
	Signature         string   `json:"signature"`
	TokenAvailable    bool     `json:"token_available"`
	TokenElevated     bool     `json:"token_elevated"`
	ElevationType     string   `json:"elevation_type"`
	Integrity         string   `json:"integrity"`
	EnabledPrivileges []string `json:"enabled_privileges"`
	TokenReason       string   `json:"token_reason"`
	AppContainerKnown bool     `json:"app_container_known"`
	AppContainer      bool     `json:"app_container"`
	JobKnown          bool     `json:"job_known"`
	InJob             bool     `json:"in_job"`
}

type winTokenProc struct {
	PID               int      `json:"pid"`
	User              string   `json:"user"`
	Domain            string   `json:"domain"`
	SID               string   `json:"sid"`
	TokenAvailable    bool     `json:"token_available"`
	TokenElevated     bool     `json:"token_elevated"`
	ElevationType     string   `json:"elevation_type"`
	Integrity         string   `json:"integrity"`
	EnabledPrivileges []string `json:"enabled_privileges"`
	TokenReason       string   `json:"token_reason"`
	AppContainerKnown bool     `json:"app_container_known"`
	AppContainer      bool     `json:"app_container"`
	JobKnown          bool     `json:"job_known"`
	InJob             bool     `json:"in_job"`
}

const windowsProcessCIMScript = `$ErrorActionPreference='Stop'
try { $procs=@(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { Write-Error ('[chimera-stage:windows-cim-enumeration] ' + $_.Exception.Message); exit 20 }
$ErrorActionPreference='SilentlyContinue'
$o=@()
foreach($p in $procs){
    $cmd=[string]$p.CommandLine
    $argc=0
    if($cmd){$argc=([regex]::Matches($cmd,'(?:[^\s"]+|"[^"]*")+')).Count}
    $start=''; try{if($null -ne $p.CreationDate){$start=([datetime]$p.CreationDate).ToUniversalTime().ToString('o')}}catch{}
    $o += [pscustomobject]@{pid=[int]$p.ProcessId;ppid=[int]$p.ParentProcessId;name=[string]$p.Name;path=[string]$p.ExecutablePath;start_time=$start;session_id=[int]$p.SessionId;state='RUNNING';user='';domain='';sid='';cmd_bytes=$cmd.Length;arg_count=$argc;signature='UNKNOWN'}
}
ConvertTo-Json -InputObject @($o) -Compress -Depth 5`

const windowsTokenPrivilegeScript = `$ErrorActionPreference='Stop'
try {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public sealed class ChimeraTokenInfo {
    public string User { get; set; }
    public string Domain { get; set; }
    public string Sid { get; set; }
    public bool Available { get; set; }
    public bool Elevated { get; set; }
    public string ElevationType { get; set; }
    public string Integrity { get; set; }
    public string[] EnabledPrivileges { get; set; }
    public bool AppContainerKnown { get; set; }
    public bool AppContainer { get; set; }
    public bool JobKnown { get; set; }
    public bool InJob { get; set; }
    public string Reason { get; set; }
}

public static class ChimeraTokenInspector {
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x0008;
    const int TokenUser = 1;
    const int TokenPrivileges = 3;
    const int TokenElevationType = 18;
    const int TokenElevation = 20;
    const int TokenIntegrityLevel = 25;
    const int TokenIsAppContainer = 29;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr processHandle, IntPtr jobHandle, out bool result);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeName(string systemName, ref LUID luid, StringBuilder name, ref int nameLength);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);

    static IntPtr Query(IntPtr token, int cls, out int len) {
        len = 0;
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out len);
        if (len <= 0) return IntPtr.Zero;
        IntPtr p = Marshal.AllocHGlobal(len);
        if (!GetTokenInformation(token, cls, p, len, out len)) { Marshal.FreeHGlobal(p); return IntPtr.Zero; }
        return p;
    }

    static string IntegrityName(IntPtr token) {
        int len; IntPtr p = Query(token, TokenIntegrityLevel, out len);
        if (p == IntPtr.Zero) return "UNKNOWN";
        try {
            TOKEN_MANDATORY_LABEL t = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(p, typeof(TOKEN_MANDATORY_LABEL));
            if (t.Label.Sid == IntPtr.Zero) return "UNKNOWN";
            byte count = Marshal.ReadByte(GetSidSubAuthorityCount(t.Label.Sid));
            if (count == 0) return "UNKNOWN";
            uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(t.Label.Sid, (uint)(count - 1)));
            if (rid >= 0x5000) return "PROTECTED";
            if (rid >= 0x4000) return "SYSTEM";
            if (rid >= 0x3000) return "HIGH";
            if (rid >= 0x2100) return "MEDIUM_PLUS";
            if (rid >= 0x2000) return "MEDIUM";
            if (rid >= 0x1000) return "LOW";
            return "UNTRUSTED";
        } finally { Marshal.FreeHGlobal(p); }
    }

    static string[] EnabledPrivilegeNames(IntPtr token) {
        int len; IntPtr p = Query(token, TokenPrivileges, out len);
        if (p == IntPtr.Zero) return new string[0];
        try {
            int count = Marshal.ReadInt32(p);
            int offset = sizeof(uint);
            int stride = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            List<string> names = new List<string>();
            for (int i=0; i<count; i++) {
                IntPtr item = IntPtr.Add(p, offset + i * stride);
                LUID_AND_ATTRIBUTES la = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(item, typeof(LUID_AND_ATTRIBUTES));
                if ((la.Attributes & SE_PRIVILEGE_ENABLED) == 0) continue;
                int n = 0; LUID luid = la.Luid;
                LookupPrivilegeName(null, ref luid, null, ref n);
                if (n <= 0) continue;
                StringBuilder sb = new StringBuilder(n + 1);
                if (LookupPrivilegeName(null, ref luid, sb, ref n)) names.Add(sb.ToString());
            }
            names.Sort(StringComparer.Ordinal);
            return names.ToArray();
        } finally { Marshal.FreeHGlobal(p); }
    }

    static void ReadIdentity(IntPtr token, ChimeraTokenInfo info) {
        int len; IntPtr p = Query(token, TokenUser, out len);
        if (p == IntPtr.Zero) return;
        try {
            TOKEN_MANDATORY_LABEL u = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(p, typeof(TOKEN_MANDATORY_LABEL));
            if (u.Label.Sid == IntPtr.Zero) return;
            SecurityIdentifier sid = new SecurityIdentifier(u.Label.Sid);
            info.Sid = sid.Value;
            try {
                NTAccount account = (NTAccount)sid.Translate(typeof(NTAccount));
                string value = account.Value ?? "";
                int slash = value.IndexOf('\\');
                if (slash >= 0) { info.Domain = value.Substring(0, slash); info.User = value.Substring(slash + 1); }
                else { info.User = value; }
            } catch {}
        } finally { Marshal.FreeHGlobal(p); }
    }

    public static ChimeraTokenInfo Inspect(int pid) {
        ChimeraTokenInfo info = new ChimeraTokenInfo { User="", Domain="", Sid="", Available=false, Elevated=false, ElevationType="UNKNOWN", Integrity="UNKNOWN", EnabledPrivileges=new string[0], AppContainerKnown=false, AppContainer=false, JobKnown=false, InJob=false, Reason="" };
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) { info.Reason = "OpenProcess failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message; return info; }
        try {
            bool inJob;
            if (IsProcessInJob(process, IntPtr.Zero, out inJob)) { info.JobKnown = true; info.InJob = inJob; }
            IntPtr token;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) { info.Reason = "OpenProcessToken failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message; return info; }
            try {
                ReadIdentity(token, info);
                int len; IntPtr elev = Query(token, TokenElevation, out len);
                if (elev != IntPtr.Zero) { try { info.Elevated = Marshal.ReadInt32(elev) != 0; } finally { Marshal.FreeHGlobal(elev); } }
                IntPtr typ = Query(token, TokenElevationType, out len);
                if (typ != IntPtr.Zero) {
                    try {
                        int v = Marshal.ReadInt32(typ);
                        info.ElevationType = v == 1 ? "DEFAULT" : (v == 2 ? "FULL" : (v == 3 ? "LIMITED" : "UNKNOWN"));
                    } finally { Marshal.FreeHGlobal(typ); }
                }
                info.Integrity = IntegrityName(token);
                info.EnabledPrivileges = EnabledPrivilegeNames(token);
                IntPtr ac = Query(token, TokenIsAppContainer, out len);
                if (ac != IntPtr.Zero) {
                    try { info.AppContainerKnown = true; info.AppContainer = Marshal.ReadInt32(ac) != 0; } finally { Marshal.FreeHGlobal(ac); }
                }
                info.Available = true;
                return info;
            } finally { CloseHandle(token); }
        } finally { CloseHandle(process); }
    }
}
'@
} catch { Write-Error ('[chimera-stage:windows-token-helper-init] ' + $_.Exception.Message); exit 30 }
try { $procs=@(Get-Process -ErrorAction Stop) } catch { Write-Error ('[chimera-stage:windows-token-process-list] ' + $_.Exception.Message); exit 31 }
$o=@()
foreach($p in $procs){
    $ti=[ChimeraTokenInspector]::Inspect([int]$p.Id)
    if(-not $ti){continue}
    $o += [pscustomobject]@{pid=[int]$p.Id;user=[string]$ti.User;domain=[string]$ti.Domain;sid=[string]$ti.Sid;token_available=[bool]$ti.Available;token_elevated=[bool]$ti.Elevated;elevation_type=[string]$ti.ElevationType;integrity=[string]$ti.Integrity;enabled_privileges=@($ti.EnabledPrivileges);token_reason=[string]$ti.Reason;app_container_known=[bool]$ti.AppContainerKnown;app_container=[bool]$ti.AppContainer;job_known=[bool]$ti.JobKnown;in_job=[bool]$ti.InJob}
}
ConvertTo-Json -InputObject @($o) -Compress -Depth 5`

func collectPlatform(ctx context.Context, inv *Inventory) {
	ps, err := windowsPowerShellPath()
	if err != nil {
		reason := "PowerShell executable was not found"
		addSource(inv, "windows-cim", evidence.StateUnavailable, "PowerShell/CIM process metadata", 0, reason)
		addSource(inv, "windows-token-privilege", evidence.StateUnavailable, "Windows process token metadata", 0, reason)
		return
	}

	baseRaw, baseReason, baseErr := runWindowsProcessPowerShell(ctx, ps, "windows-cim-enumeration", windowsProcessCIMScript)
	if baseErr != nil {
		state := stateForWindowsErr(ctx, baseErr)
		addSource(inv, "windows-cim", state, "Win32_Process CIM", 0, baseReason)
		addSource(inv, "windows-token-privilege", evidence.StateUnavailable, "OpenProcessToken/GetTokenInformation metadata", 0, "token enrichment not attempted because Windows process enumeration failed: "+baseReason)
		return
	}
	rows, err := decodeWindowsProcessRows(baseRaw)
	if err != nil {
		reason := "decode Windows CIM process inventory: " + err.Error()
		addSource(inv, "windows-cim", evidence.StateDegraded, "Win32_Process CIM", 0, reason)
		addSource(inv, "windows-token-privilege", evidence.StateUnavailable, "OpenProcessToken/GetTokenInformation metadata", 0, "token enrichment not attempted because process inventory could not be decoded")
		return
	}

	tokenCtx, tokenCancel, _ := reliability.StageContext(ctx, 7*time.Second, 750*time.Millisecond, reliability.ProviderBudgetMedium)
	tokenRaw, tokenReason, tokenErr := runWindowsProcessPowerShell(tokenCtx, ps, "windows-token-privilege", windowsTokenPrivilegeScript)
	tokenErrState := evidence.StateObserved
	if tokenErr != nil {
		tokenErrState = stateForWindowsErr(tokenCtx, tokenErr)
	}
	tokenCancel()
	tokenRows := []winTokenProc(nil)
	if tokenErr == nil {
		tokenRows, err = decodeWindowsTokenRows(tokenRaw)
		if err != nil {
			tokenErr = err
			tokenReason = "decode Windows process token inventory: " + err.Error()
		}
	}
	mergeWindowsTokenRows(rows, tokenRows, tokenReason)

	tokenObserved := 0
	tokenUnavailable := 0
	for _, r := range rows {
		if r.PID <= 0 {
			continue
		}
		user := r.User
		if r.Domain != "" && user != "" {
			user = r.Domain + `\` + user
		}
		priv := windowsRuntimePrivilege(r)
		elevated := isWindowsPrivileged(r.SID, r.User) || priv.State == "ELEVATED" || priv.State == "EXCESS"
		pctx := "STANDARD"
		desc := "standard process principal"
		if elevated {
			pctx = "PRIVILEGED"
			desc = "elevated token, high-integrity context, or well-known privileged service principal"
		}
		name := r.Name
		if name == "" {
			name = filepath.Base(r.Path)
		}
		trust := TrustContext{State: "UNKNOWN", Basis: "Windows Authenticode status", Signature: fallback(r.Signature, "UNKNOWN")}
		switch strings.ToLower(r.Signature) {
		case "valid":
			trust.State = "SIGNED_VALID"
		case "notsigned":
			trust.State = "UNSIGNED"
		case "hashmismatch", "nottrusted", "unknownerror":
			trust.State = "SIGNATURE_UNTRUSTED"
		}
		path := strings.TrimSpace(r.Path)
		if path == "" {
			trust.Reason = "executable path unavailable from Win32_Process"
		}
		iso := windowsIsolationSummary(r)
		inv.Processes = append(inv.Processes, Process{PID: r.PID, PPID: r.PPID, Name: name, Executable: name, ExecutablePath: path, StartTime: strings.TrimSpace(r.StartTime), Principal: Principal{User: fallback(user, "UNKNOWN"), UserID: fallback(r.SID, "UNKNOWN"), Elevated: elevated, Context: desc}, SessionID: strconv.Itoa(r.SessionID), PrivilegeContext: pctx, RuntimeState: fallback(r.State, "RUNNING"), CommandLine: CommandLineMetadata{Available: r.CmdBytes > 0, ArgumentCount: r.ArgCount, ByteCount: r.CmdBytes, Redacted: true, Source: "Win32_Process CommandLine metadata", Reason: func() string {
			if r.CmdBytes == 0 {
				return "command line unavailable or empty"
			}
			return ""
		}()}, Trust: trust, Isolation: iso, CollectionSource: "Windows CIM Win32_Process", Confidence: evidence.ConfidenceHigh})
		inv.RuntimePrivileges = append(inv.RuntimePrivileges, priv)
		if r.TokenAvailable {
			tokenObserved++
		} else {
			tokenUnavailable++
		}
		if len(inv.Processes) >= maxProcesses {
			break
		}
	}
	addSource(inv, "windows-cim", evidence.StateObserved, "Win32_Process CIM", len(inv.Processes), "")

	tokenState := evidence.StateObserved
	tokenSourceReason := ""
	if tokenErr != nil {
		tokenState = tokenErrState
		tokenSourceReason = tokenReason
	} else if tokenObserved == 0 && len(inv.Processes) > 0 {
		tokenState = evidence.StateUnavailable
		tokenSourceReason = "token metadata was unavailable for all observed processes"
	} else if tokenUnavailable > 0 {
		tokenState = evidence.StateDegraded
		tokenSourceReason = strconv.Itoa(tokenUnavailable) + " process token(s) were access-restricted, exited during collection, or otherwise unavailable"
	}
	addSource(inv, "windows-token-privilege", tokenState, "OpenProcessToken/GetTokenInformation metadata", tokenObserved, tokenSourceReason)
}

func windowsPowerShellPath() (string, error) {
	for _, name := range []string{"powershell.exe", "powershell", "pwsh.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("PowerShell executable was not found")
}

func runWindowsProcessPowerShell(ctx context.Context, ps, stage, script string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err == nil {
		return out, "", nil
	}
	return out, windowsProcessProviderReason(ctx, stage, err), err
}

func windowsProcessProviderReason(ctx context.Context, stage string, err error) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		stage = "windows-process-provider"
	}
	if ctx != nil && ctx.Err() != nil {
		return stage + ": " + ctx.Err().Error()
	}
	reason := stage + " failed"
	if ee, ok := err.(*exec.ExitError); ok {
		reason += fmt.Sprintf(" (exit code %d)", ee.ExitCode())
		if detail := boundedWindowsProviderDetail(string(ee.Stderr)); detail != "" {
			reason += ": " + detail
		}
		return reason
	}
	if err != nil {
		reason += ": " + boundedWindowsProviderDetail(err.Error())
	}
	return reason
}

func boundedWindowsProviderDetail(s string) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	const max = 2048
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func decodeWindowsProcessRows(raw []byte) ([]winProc, error) {
	rows := []winProc{}
	if err := json.Unmarshal(raw, &rows); err == nil {
		return rows, nil
	}
	var one winProc
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []winProc{one}, nil
}

func decodeWindowsTokenRows(raw []byte) ([]winTokenProc, error) {
	rows := []winTokenProc{}
	if err := json.Unmarshal(raw, &rows); err == nil {
		return rows, nil
	}
	var one winTokenProc
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []winTokenProc{one}, nil
}

func mergeWindowsTokenRows(rows []winProc, tokens []winTokenProc, stageReason string) {
	byPID := make(map[int]winTokenProc, len(tokens))
	for _, t := range tokens {
		if t.PID > 0 {
			byPID[t.PID] = t
		}
	}
	for i := range rows {
		t, ok := byPID[rows[i].PID]
		if !ok {
			if strings.TrimSpace(stageReason) != "" {
				rows[i].TokenReason = boundedWindowsProviderDetail(stageReason)
			} else {
				rows[i].TokenReason = "token record unavailable; process may have exited during token enrichment"
			}
			continue
		}
		if strings.TrimSpace(t.User) != "" {
			rows[i].User = strings.TrimSpace(t.User)
		}
		if strings.TrimSpace(t.Domain) != "" {
			rows[i].Domain = strings.TrimSpace(t.Domain)
		}
		if strings.TrimSpace(t.SID) != "" {
			rows[i].SID = strings.TrimSpace(t.SID)
		}
		rows[i].TokenAvailable = t.TokenAvailable
		rows[i].TokenElevated = t.TokenElevated
		rows[i].ElevationType = t.ElevationType
		rows[i].Integrity = t.Integrity
		rows[i].EnabledPrivileges = append([]string(nil), t.EnabledPrivileges...)
		rows[i].TokenReason = boundedWindowsProviderDetail(t.TokenReason)
		rows[i].AppContainerKnown = t.AppContainerKnown
		rows[i].AppContainer = t.AppContainer
		rows[i].JobKnown = t.JobKnown
		rows[i].InJob = t.InJob
	}
}

func windowsRuntimePrivilege(r winProc) RuntimePrivilegeContext {
	accountClass := windowsAccountClass(r.SID)
	tokenElevation := "UNKNOWN"
	if r.TokenAvailable {
		if r.TokenElevated {
			tokenElevation = "ELEVATED"
		} else {
			tokenElevation = "NOT_ELEVATED"
		}
	}
	high := highImpactWindowsPrivileges(r.EnabledPrivileges)
	signals := []string{}
	integrity := strings.ToUpper(strings.TrimSpace(r.Integrity))
	userContext := false
	if r.TokenAvailable && (integrity == "HIGH" || integrity == "SYSTEM" || integrity == "PROTECTED") && accountClass == "USER" && r.SessionID != 0 {
		userContext = true
		signals = append(signals, "elevated-user-context")
	}
	if integrity == "SYSTEM" && accountClass != "SYSTEM" {
		signals = append(signals, "system-integrity-non-system-account")
	}
	if len(high) > 0 && accountClass != "SYSTEM" && accountClass != "BUILTIN_SERVICE" {
		signals = append(signals, "user-or-unknown-account-high-impact-token-privileges")
	}
	state := "STANDARD"
	confidence := evidence.ConfidenceHigh
	privilegeSetState := "OBSERVED"
	reason := strings.TrimSpace(r.TokenReason)
	if !r.TokenAvailable {
		state = "UNKNOWN"
		privilegeSetState = "UNAVAILABLE"
		confidence = evidence.ConfidenceLow
		if reason == "" {
			reason = "process token metadata unavailable"
		}
	} else if len(signals) > 0 {
		state = "EXCESS"
	} else if r.TokenElevated || integrity == "HIGH" || integrity == "SYSTEM" || integrity == "PROTECTED" || accountClass == "SYSTEM" {
		state = "ELEVATED"
	}
	return RuntimePrivilegeContext{
		PID: r.PID, Platform: "windows", State: state, AccountClass: accountClass,
		IntegrityLevel: integrity, TokenElevation: tokenElevation, ElevationType: strings.ToUpper(strings.TrimSpace(r.ElevationType)),
		PrivilegeSetState: privilegeSetState, EnabledPrivileges: r.EnabledPrivileges, HighImpactPrivileges: high,
		ExcessSignals: signals, ElevatedUserContext: userContext,
		Source: "Windows process token metadata", Confidence: confidence, Reason: reason,
	}
}

func windowsAccountClass(sid string) string {
	switch strings.ToUpper(strings.TrimSpace(sid)) {
	case "S-1-5-18":
		return "SYSTEM"
	case "S-1-5-19", "S-1-5-20":
		return "BUILTIN_SERVICE"
	case "":
		return "UNKNOWN"
	default:
		return "USER"
	}
}

func isWindowsPrivileged(sid, user string) bool {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	u := strings.ToUpper(strings.TrimSpace(user))
	return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || u == "SYSTEM"
}
func stateForWindowsErr(ctx context.Context, err error) evidence.State {
	if ctx != nil && ctx.Err() != nil {
		return evidence.StateDegraded
	}
	s := ""
	if err != nil {
		s = strings.ToLower(err.Error())
		if ee, ok := err.(*exec.ExitError); ok {
			s += " " + strings.ToLower(string(ee.Stderr))
		}
	}
	if strings.Contains(s, "access") || strings.Contains(s, "denied") || strings.Contains(s, "unauthorized") {
		return evidence.StateDenied
	}
	return evidence.StateUnavailable
}

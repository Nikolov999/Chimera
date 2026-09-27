//go:build windows

package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsAccountRecord struct {
	Name               string   `json:"name"`
	SID                string   `json:"sid"`
	Disabled           bool     `json:"disabled"`
	Description        string   `json:"description"`
	PasswordRequired   bool     `json:"password_required"`
	PasswordExpires    bool     `json:"password_expires"`
	PasswordChangeable bool     `json:"password_changeable"`
	Groups             []string `json:"groups"`
	ServiceNames       []string `json:"service_names"`
	LastLogon          string   `json:"last_logon"`
	Home               string   `json:"home"`
}
type windowsGroupRecord struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members"`
}
type windowsPayload struct {
	Accounts []windowsAccountRecord `json:"accounts"`
	Groups   []windowsGroupRecord   `json:"groups"`
	Degraded []string               `json:"degraded"`
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		addSource(inv, "windows-local-accounts", evidence.StateUnavailable, "PowerShell/CIM local account provider", 0, "PowerShell not found")
		return
	}
	script := `$ErrorActionPreference='SilentlyContinue'
$deg=New-Object System.Collections.Generic.List[string]
$users=@(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Sort-Object Name)
$services=@(Get-CimInstance Win32_Service)
$profiles=@{}
foreach($pr in @(Get-CimInstance Win32_UserProfile)){if($pr.SID -and $pr.LocalPath){$profiles[[string]$pr.SID]=[string]$pr.LocalPath}}
$groupRows=@()
$memberMap=@{}
if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
  foreach($g in @(Get-LocalGroup | Sort-Object Name)) {
    $members=@()
    try { $members=@(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { $deg.Add('group membership unavailable: '+$g.Name) }
    $groupRows += [pscustomobject]@{name=[string]$g.Name;sid=[string]$g.SID;members=$members}
    foreach($m in $members){$short=([string]$m).Split('\\')[-1].ToLowerInvariant();if(-not $memberMap.ContainsKey($short)){$memberMap[$short]=New-Object System.Collections.Generic.List[string]};$memberMap[$short].Add([string]$g.Name)}
  }
} else { $deg.Add('LocalAccounts group cmdlets unavailable') }
$rows=@()
foreach($u in $users){
  $n=[string]$u.Name;$key=$n.ToLowerInvariant();$gs=@();if($memberMap.ContainsKey($key)){$gs=@($memberMap[$key])}
  $svc=@($services | Where-Object { $s=([string]$_.StartName).ToLowerInvariant(); $s -eq ('.\\'+$key) -or $s -eq (($env:COMPUTERNAME+'\\'+$n).ToLowerInvariant()) -or $s -eq $key } | ForEach-Object {[string]$_.Name})
  $home='';if($profiles.ContainsKey([string]$u.SID)){$home=$profiles[[string]$u.SID]}
  $rows += [pscustomobject]@{name=$n;sid=[string]$u.SID;disabled=[bool]$u.Disabled;description=[string]$u.Description;password_required=[bool]$u.PasswordRequired;password_expires=[bool]$u.PasswordExpires;password_changeable=[bool]$u.PasswordChangeable;groups=$gs;service_names=$svc;last_logon=if($u.LastLogon){([datetime]$u.LastLogon).ToUniversalTime().ToString('o')}else{''};home=$home}
}
[pscustomobject]@{accounts=$rows;groups=$groupRows;degraded=@($deg)} | ConvertTo-Json -Depth 6 -Compress`
	raw, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		reason := err.Error()
		if ctx.Err() != nil {
			reason = ctx.Err().Error()
		}
		addSource(inv, "windows-local-accounts", evidence.StateUnavailable, "PowerShell/CIM local account provider", 0, reason)
		return
	}
	var p windowsPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		addSource(inv, "windows-local-accounts", evidence.StateDegraded, "PowerShell/CIM local account provider", 0, "invalid local account provider JSON: "+err.Error())
		return
	}
	sort.Slice(p.Groups, func(i, j int) bool { return strings.ToLower(p.Groups[i].Name) < strings.ToLower(p.Groups[j].Name) })
	for _, g := range p.Groups {
		inv.Groups = append(inv.Groups, Group{Name: g.Name, SID: g.SID, Privileged: windowsPrivilegedGroup(g.Name), Members: g.Members, CollectionSource: "Windows LocalAccounts/CIM metadata", Confidence: evidence.ConfidenceHigh})
	}
	for _, u := range p.Accounts {
		groups := uniqueSorted(u.Groups)
		priv := strings.EqualFold(u.SID, "S-1-5-500")
		basis := []string{}
		if priv {
			basis = append(basis, "built-in Administrator SID")
		}
		for _, g := range groups {
			if windowsPrivilegedGroup(g) {
				priv = true
				basis = append(basis, "member of privileged group "+g)
			}
		}
		service := len(u.ServiceNames) > 0
		serviceBasis := []string{}
		if service {
			serviceBasis = append(serviceBasis, fmt.Sprintf("used by %d Windows service(s)", len(u.ServiceNames)))
		}
		kind := "HUMAN"
		if service {
			kind = "SERVICE"
		}
		enabled := "ENABLED"
		login := "LOGIN_CAPABLE"
		if u.Disabled {
			enabled = "DISABLED"
			login = "LOGIN_DISABLED"
		}
		principal := u.Name
		if strings.TrimSpace(principal) != "" && strings.TrimSpace(getComputerName()) != "" {
			principal = getComputerName() + "\\" + u.Name
		}
		inv.Accounts = append(inv.Accounts, Account{Name: u.Name, Principal: principal, SID: u.SID, Home: u.Home, Description: u.Description, AccountType: kind, EnabledState: enabled, LoginCapability: login, Privileged: priv, PrivilegeBasis: basis, ServiceAccount: service, ServiceBasis: serviceBasis, Groups: groups, Authentication: AuthenticationMetadata{State: "OBSERVED", PasswordState: "UNKNOWN", PasswordRequired: boolState(u.PasswordRequired), PasswordExpires: boolState(u.PasswordExpires), PasswordChangeable: boolState(u.PasswordChangeable), LastLogin: u.LastLogon, Source: "Win32_UserAccount metadata; no credential material collected", Reason: "password value/state is intentionally not retrieved in "}, CollectionSource: "Windows CIM + LocalAccounts metadata", Confidence: evidence.ConfidenceHigh})
	}
	state := evidence.StateObserved
	reason := ""
	if len(p.Degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(p.Degraded), "; ")
		inv.Degraded = append(inv.Degraded, p.Degraded...)
	}
	addSource(inv, "windows-local-accounts", state, "PowerShell/CIM local account provider", len(inv.Accounts), reason)
	addSource(inv, "windows-local-groups", state, "PowerShell LocalAccounts group provider", len(inv.Groups), reason)
}
func windowsPrivilegedGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "administrators", "remote desktop users", "backup operators", "account operators", "server operators", "print operators", "hyper-v administrators":
		return true
	}
	return false
}
func boolState(v bool) string {
	if v {
		return "YES"
	}
	return "NO"
}

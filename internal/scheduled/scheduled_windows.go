//go:build windows

package scheduled

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

type winTask struct {
	Name                       string      `json:"name"`
	Path                       string      `json:"path"`
	State                      string      `json:"state"`
	Enabled                    bool        `json:"enabled"`
	Hidden                     bool        `json:"hidden"`
	User                       string      `json:"user"`
	RunLevel                   string      `json:"run_level"`
	LogonType                  string      `json:"logon_type"`
	Executable                 string      `json:"executable"`
	ArgumentsPresent           bool        `json:"arguments_present"`
	ReferencedScriptPath       string      `json:"referenced_script_path"`
	WorkingDirectory           string      `json:"working_directory"`
	TriggerSummary             string      `json:"trigger_summary"`
	ActionPath                 PathPosture `json:"action_path"`
	ActionDirectoryPosture     PathPosture `json:"action_directory_posture"`
	ScriptPathPosture          PathPosture `json:"script_path_posture"`
	WorkingDirectoryPosture    PathPosture `json:"working_directory_posture"`
	DefinitionPathPosture      PathPosture `json:"definition_path_posture"`
	DefinitionDirectoryPosture PathPosture `json:"definition_directory_posture"`
}

const winTaskScript = `$ErrorActionPreference='Stop'
$lowTrustSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$trustedOwnerSids=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$writeMask=` + windowsacl.PowerShellMutatingMaskExpression + `
function New-NAPath([string]$p) {
 [pscustomobject]@{path=$p;state='NOT_APPLICABLE';exists=$false;is_directory=$false;mode='';owner='';owner_sid='';owner_trust='NOT_APPLICABLE';group='';group_writable=$false;other_writable=$false;broadly_writable=$false;untrusted_writable=$false;inherited_untrusted_write=$false;write_principals=@();dacl_state='NOT_APPLICABLE';permission_basis='Windows NTFS DACL lower-trust write grants';reason=''}
}
function New-UnavailablePath([string]$p,[string]$state,[string]$reason) {
 [pscustomobject]@{path=$p;state=$state;exists=$false;is_directory=$false;mode='';owner='';owner_sid='';owner_trust='UNKNOWN';group='';group_writable=$false;other_writable=$false;broadly_writable=$false;untrusted_writable=$false;inherited_untrusted_write=$false;write_principals=@();dacl_state=$state;permission_basis='Windows NTFS DACL lower-trust write grants';reason=$reason}
}
function Resolve-LocalPath([string]$p,[switch]$Executable) {
 if([string]::IsNullOrWhiteSpace($p)){ return '' }
 $v=[Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"').Trim("'"))
 if($Executable -and -not [IO.Path]::IsPathRooted($v)) {
   try { $c=Get-Command -Name $v -CommandType Application -ErrorAction Stop | Select-Object -First 1; if($c){$v=[string]$c.Source} } catch {}
 }
 return $v
}
function Get-PathPosture([string]$p,[switch]$Executable) {
 if([string]::IsNullOrWhiteSpace($p)){ return (New-NAPath '') }
 $v=Resolve-LocalPath $p -Executable:$Executable
 if(-not $Executable -and -not [IO.Path]::IsPathRooted($v)){ return (New-UnavailablePath $v 'UNAVAILABLE' 'relative path has no explicit resolution directory') }
 try {
  if(-not (Test-Path -LiteralPath $v)){ return (New-UnavailablePath $v 'UNAVAILABLE' 'path not found') }
  $item=Get-Item -LiteralPath $v -Force -ErrorAction Stop
  $acl=Get-Acl -LiteralPath $v -ErrorAction Stop
  $ownerSid='';try{$ownerSid=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value}catch{}
  $ownerTrust=if([string]::IsNullOrWhiteSpace($ownerSid)){'UNKNOWN'}elseif($trustedOwnerSids -contains $ownerSid){'TRUSTED'}else{'UNTRUSTED'}
  $allow=@{};$deny=@{};$inheritedAllow=@{}
  foreach($ace in @($acl.Access)) {
   $sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}
   if($lowTrustSids -notcontains $sid){continue}
   if(([int64]$ace.FileSystemRights -band [int64]$writeMask) -eq 0){continue}
   if([string]$ace.AccessControlType -eq 'Deny'){$deny[$sid]=$true}else{$allow[$sid]=$true;if([bool]$ace.IsInherited){$inheritedAllow[$sid]=$true}}
  }
  $writers=@();$inherited=$false
  foreach($sid in $allow.Keys){if(-not $deny.ContainsKey($sid)){$writers+=$sid;if($inheritedAllow.ContainsKey($sid)){$inherited=$true}}}
  $writers=@($writers | Sort-Object -Unique)
  $weak=($writers.Count -gt 0)
  $why=if($weak){'lower-trust DACL write grant: '+($writers -join ', ')}else{''}
  return [pscustomobject]@{path=$v;state='OBSERVED';exists=$true;is_directory=([bool]$item.PSIsContainer);mode='';owner=[string]$acl.Owner;owner_sid=$ownerSid;owner_trust=$ownerTrust;group='';group_writable=$false;other_writable=$false;broadly_writable=$weak;untrusted_writable=$weak;inherited_untrusted_write=$inherited;write_principals=$writers;dacl_state='OBSERVED';permission_basis='Windows NTFS DACL lower-trust write grants';reason=$why}
 } catch {
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  return (New-UnavailablePath $v $st ([string]$_.Exception.Message))
 }
}
function Get-ParentPosture([string]$p,[switch]$Executable) {
 $v=Resolve-LocalPath $p -Executable:$Executable
 if([string]::IsNullOrWhiteSpace($v)){return (New-NAPath '')}
 try {$parent=[IO.Path]::GetDirectoryName($v)} catch {$parent=''}
 if([string]::IsNullOrWhiteSpace($parent)){return (New-UnavailablePath '' 'UNAVAILABLE' 'containing directory unresolved')}
 return Get-PathPosture $parent
}
function Get-ReferencedPathPosture([string]$p,[string]$wd) {
 if([string]::IsNullOrWhiteSpace($p)){return (New-NAPath '')}
 $v=[Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"').Trim("'"))
 if([IO.Path]::IsPathRooted($v)){return Get-PathPosture $v}
 $w=Resolve-LocalPath $wd
 if(-not [string]::IsNullOrWhiteSpace($w) -and [IO.Path]::IsPathRooted($w)){return Get-PathPosture (Join-Path $w $v)}
 return (New-UnavailablePath $v 'UNAVAILABLE' 'relative referenced script path has no explicit absolute working directory')
}
function Get-ScriptPath([string]$exe,[string]$args) {
 if([string]::IsNullOrWhiteSpace($exe) -or [string]::IsNullOrWhiteSpace($args)){return ''}
 $leaf=[IO.Path]::GetFileName($exe).ToLowerInvariant()
 if($leaf -in @('powershell.exe','powershell','pwsh.exe','pwsh')) {
  $m=[regex]::Match($args,'(?i)(?:^|\s)-File\s+(?:"([^"]+)"|''([^'']+)''|(\S+))')
  if($m.Success){foreach($i in 1..3){if(-not [string]::IsNullOrWhiteSpace($m.Groups[$i].Value)){return $m.Groups[$i].Value}}}
 }
 $rest=$args
 if($leaf -in @('cmd.exe','cmd')) {$rest=[regex]::Replace($rest,'(?i)^\s*/[ck]\s+','')}
 if($leaf -in @('wscript.exe','wscript','cscript.exe','cscript','python.exe','python','python3.exe','python3','node.exe','node','perl.exe','perl','ruby.exe','ruby','bash.exe','bash','sh.exe','sh','cmd.exe','cmd')) {
  $m=[regex]::Match($rest,'^\s*(?:"([^"]+)"|''([^'']+)''|(\S+))')
  if($m.Success){foreach($i in 1..3){if(-not [string]::IsNullOrWhiteSpace($m.Groups[$i].Value)){return $m.Groups[$i].Value}}}
 }
 return ''
}
$o=@(Get-ScheduledTask | ForEach-Object {
 $t=$_; $a=@($t.Actions | Select-Object -First 1); $tr=@($t.Triggers)
 $exe=if($a.Count){[string]$a[0].Execute}else{''}; $args=if($a.Count){[string]$a[0].Arguments}else{''}; $wd=if($a.Count){[string]$a[0].WorkingDirectory}else{''}
 $script=Get-ScriptPath $exe $args
 $taskRel=if([string]::IsNullOrWhiteSpace([string]$t.TaskPath) -or [string]$t.TaskPath -eq '\'){$t.TaskName}else{([string]$t.TaskPath).Trim('\')+'\'+$t.TaskName}
 $defFile=Join-Path (Join-Path $env:windir 'System32\Tasks') $taskRel
 [pscustomobject]@{
  name=[string]$t.TaskName;path=[string]$t.TaskPath;state=[string]$t.State;enabled=([bool]$t.Settings.Enabled);hidden=([bool]$t.Settings.Hidden);
  user=[string]$t.Principal.UserId;run_level=[string]$t.Principal.RunLevel;logon_type=[string]$t.Principal.LogonType;
  executable=$exe;arguments_present=(-not [string]::IsNullOrWhiteSpace($args));referenced_script_path=$script;working_directory=$wd;
  trigger_summary=if($tr.Count -eq 0){'NONE'}else{(($tr | ForEach-Object {$_.CimClass.CimClassName}) -join ',')};
  action_path=(Get-PathPosture $exe -Executable);action_directory_posture=(Get-ParentPosture $exe -Executable);script_path_posture=(Get-ReferencedPathPosture $script $wd);
  working_directory_posture=(Get-PathPosture $wd);definition_path_posture=(Get-PathPosture $defFile);definition_directory_posture=(Get-ParentPosture $defFile)
 }
});$o|ConvertTo-Json -Depth 7 -Compress`

func collectPlatform(ctx context.Context, inv *Inventory) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		addSource(inv, "windows-task-scheduler", evidence.StateUnavailable, "Get-ScheduledTask", 0, "PowerShell not found")
		return
	}
	raw, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", winTaskScript).Output()
	if err != nil {
		r := err.Error()
		if ctx.Err() != nil {
			r = ctx.Err().Error()
		}
		addSource(inv, "windows-task-scheduler", evidence.StateUnavailable, "Get-ScheduledTask", 0, r)
		return
	}
	var rows []winTask
	if len(strings.TrimSpace(string(raw))) > 0 {
		if raw[0] == '{' {
			var one winTask
			if json.Unmarshal(raw, &one) == nil {
				rows = []winTask{one}
			}
		} else if err := json.Unmarshal(raw, &rows); err != nil {
			addSource(inv, "windows-task-scheduler", evidence.StateUnavailable, "Get-ScheduledTask", 0, err.Error())
			return
		}
	}
	for _, r := range rows {
		acct := fallback(r.User, "UNKNOWN")
		priv := "USER"
		low := strings.ToLower(acct)
		if strings.Contains(low, "system") {
			priv = "SYSTEM"
		} else if strings.EqualFold(r.RunLevel, "Highest") {
			priv = "ADMINISTRATOR"
		}
		name := strings.TrimSpace(r.Path) + strings.TrimSpace(r.Name)
		enabled := "DISABLED"
		if r.Enabled {
			enabled = "ENABLED"
		}
		hidden := "NO"
		if r.Hidden {
			hidden = "YES"
		}
		inv.Entries = append(inv.Entries, Entry{
			Name:                        fallback(name, r.Name),
			Manager:                     "windows-task-scheduler",
			Kind:                        "scheduled-task",
			EnabledState:                enabled,
			RuntimeState:                fallback(r.State, "UNKNOWN"),
			Account:                     acct,
			PrivilegeContext:            priv,
			Schedule:                    fallback(r.TriggerSummary, "UNKNOWN"),
			ActionExecutable:            r.Executable,
			ArgumentsPresent:            r.ArgumentsPresent,
			ReferencedScriptPath:        r.ReferencedScriptPath,
			WorkingDirectory:            r.WorkingDirectory,
			DefinitionPath:              "TaskScheduler:" + name,
			RunLevel:                    fallback(r.RunLevel, "UNKNOWN"),
			LogonType:                   fallback(r.LogonType, "UNKNOWN"),
			HiddenState:                 hidden,
			ConfigurationSource:         "Windows Task Scheduler",
			CollectionSource:            "Get-ScheduledTask local metadata plus read-only filesystem ACL posture",
			Confidence:                  evidence.ConfidenceHigh,
			ActionPath:                  r.ActionPath,
			ActionDirectoryPosture:      r.ActionDirectoryPosture,
			ReferencedScriptPathPosture: r.ScriptPathPosture,
			WorkingDirectoryPosture:     r.WorkingDirectoryPosture,
			DefinitionPathPosture:       r.DefinitionPathPosture,
			DefinitionDirectoryPosture:  r.DefinitionDirectoryPosture,
		})
	}
	addSource(inv, "windows-task-scheduler", evidence.StateObserved, "Get-ScheduledTask plus local DACL metadata", len(rows), "")
}

//go:build windows

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const windowsFirewallRuleCap = 4096

// Post-117 Fix45 acquisition model:
//
//	A. profiles / service state
//	B. enabled inbound rule identities
//	C. bulk associated-filter acquisition keyed by rule identity
//	D. Go-side normalization/correlation
//
// Stage C deliberately uses one query per filter *class* rather than five
// associated-filter cmdlets per firewall rule. Microsoft NetSecurity filter
// objects expose InstanceID and have a one-to-one relationship with rules, so
// the provider can correlate them in memory without thousands of CIM round trips.
const windowsFirewallBaseScript = `$ErrorActionPreference='Stop'
$stageErrors=New-Object System.Collections.ArrayList
function Clean-Reason([string]$s){ if($null -eq $s){return ''}; return (($s -replace '[\r\n]+',' ') -replace '\s+',' ').Trim() }
function Add-StageError([string]$stage,[string]$command,$err){
 $typ=''; $msg=''
 if($null -ne $err){
  try{$typ=[string]$err.Exception.GetType().FullName}catch{}
  try{$msg=Clean-Reason ([string]$err.Exception.Message)}catch{$msg=Clean-Reason ([string]$err)}
 }
 [void]$stageErrors.Add([pscustomobject]@{Stage=$stage;Command=$command;Type=$typ;Message=$msg})
}
$activeKnown=$true; $active=@{}
try {
 $conns=@(Get-NetConnectionProfile -ErrorAction Stop)
 foreach($c in $conns){
  if(([string]$c.IPv4Connectivity -eq 'Disconnected') -and ([string]$c.IPv6Connectivity -eq 'Disconnected')){continue}
  $cat=[string]$c.NetworkCategory; $pn=''
  if($cat -eq 'DomainAuthenticated'){$pn='Domain'} elseif($cat -eq 'Private'){$pn='Private'} elseif($cat -eq 'Public'){$pn='Public'}
  if($pn -ne ''){ if(-not $active.ContainsKey($pn)){$active[$pn]=@()}; $active[$pn]+=[string]$c.InterfaceAlias }
 }
} catch { $activeKnown=$false; Add-StageError 'PROFILE_ACTIVITY' 'Get-NetConnectionProfile' $_ }
$profiles=@(); $profilesObserved=$false
try {
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
  $n=[string]$_.Name
  $as=if(-not $activeKnown){'UNKNOWN'} elseif($active.ContainsKey($n)){'ACTIVE'} else {'INACTIVE'}
  $ai=if($active.ContainsKey($n)){(@($active[$n] | Sort-Object -Unique) -join ',')}else{''}
  [pscustomobject]@{
   Name=$n; Enabled=[bool]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction;
   AllowInboundRules=[string]$_.AllowInboundRules; AllowLocalFirewallRules=[string]$_.AllowLocalFirewallRules; AllowLocalIPsecRules=[string]$_.AllowLocalIPsecRules;
   NotifyOnListen=[bool]$_.NotifyOnListen; LogAllowed=[bool]$_.LogAllowed; LogBlocked=[bool]$_.LogBlocked; LogFileName=[string]$_.LogFileName;
   LogMaxSizeKilobytes=[int]$_.LogMaxSizeKilobytes; ActiveState=$as; ActiveInterfaces=$ai
  }
 })
 $profilesObserved=$true
} catch { Add-StageError 'PROFILES' 'Get-NetFirewallProfile' $_ }
$rules=@(); $ruleCount=0; $inboundCount=0; $rulesTruncated=$false; $rulesObserved=$false
try {
 $all=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
 $ruleCount=[int]$all.Count
 $inbound=@($all | Where-Object {([string]$_.Enabled -eq 'True') -and ([string]$_.Direction -eq 'Inbound'})
 $inboundCount=[int]$inbound.Count; $rulesTruncated=($inboundCount -gt 4096)
 $rules=@($inbound | Select-Object -First 4096 | ForEach-Object {
  $name=[string]$_.Name; $instance=[string]$_.InstanceID; $cid=$name
  if([string]::IsNullOrWhiteSpace($cid)){$cid=$instance}
  [pscustomobject]@{CorrelationID=$cid;InstanceID=$instance;Name=$name;DisplayName=[string]$_.DisplayName;Action=[string]$_.Action;Direction=[string]$_.Direction;Profile=[string]$_.Profile}
 })
 $rulesObserved=$true
} catch { Add-StageError 'RULES' 'Get-NetFirewallRule' $_ }
$serviceStatus='UNKNOWN'; $serviceObserved=$false
try { $serviceStatus=(Get-Service -Name MpsSvc -ErrorAction Stop).Status.ToString(); $serviceObserved=$true } catch { Add-StageError 'SERVICE_STATE' 'Get-Service MpsSvc' $_ }
[pscustomobject]@{
 Profiles=@($profiles); Rules=@($rules); RuleCount=$ruleCount; InboundEnabledRuleCount=$inboundCount; RulesTruncated=$rulesTruncated; ServiceStatus=$serviceStatus;
 ProfilesObserved=$profilesObserved; RulesObserved=$rulesObserved; ServiceObserved=$serviceObserved; StageErrors=@($stageErrors)
} | ConvertTo-Json -Depth 7 -Compress`

// windowsFirewallCompatibilityBaseScript intentionally mirrors the base
// acquisition shape that was proven on the live Windows 11 host before Fix45,
// while omitting the old per-rule associated-filter calls. It is used only when
// the richer staged base wrapper cannot produce either profile or rule evidence.
// This gives Windows PowerShell 5.1 a conservative compatibility path without
// weakening the evidence contract or reverting the Fix45 bulk filter design.
const windowsFirewallCompatibilityBaseScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$activeKnown=$true; $active=@{}
try {
 $conns=@(Get-NetConnectionProfile -ErrorAction Stop)
 foreach($c in $conns){
  if(([string]$c.IPv4Connectivity -eq 'Disconnected') -and ([string]$c.IPv6Connectivity -eq 'Disconnected')){continue}
  $cat=[string]$c.NetworkCategory; $pn=''
  if($cat -eq 'DomainAuthenticated'){$pn='Domain'} elseif($cat -eq 'Private'){$pn='Private'} elseif($cat -eq 'Public'){$pn='Public'}
  if($pn -ne ''){ if(-not $active.ContainsKey($pn)){$active[$pn]=@()}; $active[$pn]+=[string]$c.InterfaceAlias }
 }
} catch { $activeKnown=$false }
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
 $n=$_.Name.ToString()
 $as=if(-not $activeKnown){'UNKNOWN'} elseif($active.ContainsKey($n)){'ACTIVE'} else {'INACTIVE'}
 $ai=if($active.ContainsKey($n)){(@($active[$n] | Sort-Object -Unique) -join ',')} else {''}
 [pscustomobject]@{
  Name=$n; Enabled=[bool]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction;
  AllowInboundRules=[string]$_.AllowInboundRules; AllowLocalFirewallRules=[string]$_.AllowLocalFirewallRules; AllowLocalIPsecRules=[string]$_.AllowLocalIPsecRules;
  NotifyOnListen=[bool]$_.NotifyOnListen; LogAllowed=[bool]$_.LogAllowed; LogBlocked=[bool]$_.LogBlocked; LogFileName=[string]$_.LogFileName;
  LogMaxSizeKilobytes=[int]$_.LogMaxSizeKilobytes; ActiveState=$as; ActiveInterfaces=$ai
 }
})
$all=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
$inbound=@($all | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'})
$rules=@($inbound | Select-Object -First 4096 | ForEach-Object {
 $name=[string]$_.Name; $instance=[string]$_.InstanceID; $cid=$name
 if([string]::IsNullOrWhiteSpace($cid)){$cid=$instance}
 [pscustomobject]@{CorrelationID=$cid;InstanceID=$instance;Name=$name;DisplayName=[string]$_.DisplayName;Action=[string]$_.Action;Direction=[string]$_.Direction;Profile=[string]$_.Profile}
})
$serviceStatus='UNKNOWN'; $serviceObserved=$false
try { $serviceStatus=(Get-Service -Name MpsSvc -ErrorAction Stop).Status.ToString(); $serviceObserved=$true } catch {}
[pscustomobject]@{
 Profiles=@($profiles); Rules=@($rules); RuleCount=[int]$all.Count; InboundEnabledRuleCount=[int]$inbound.Count; RulesTruncated=([int]$inbound.Count -gt 4096); ServiceStatus=$serviceStatus;
 ProfilesObserved=$true; RulesObserved=$true; ServiceObserved=$serviceObserved; StageErrors=@()
} | ConvertTo-Json -Depth 7 -Compress`

const windowsFirewallFilterScript = `$ErrorActionPreference='Stop'
$stageErrors=New-Object System.Collections.ArrayList
function Clean-Reason([string]$s){ if($null -eq $s){return ''}; return (($s -replace '[\r\n]+',' ') -replace '\s+',' ').Trim() }
function Add-StageError([string]$stage,[string]$command,$err){
 $typ=''; $msg=''
 if($null -ne $err){ try{$typ=[string]$err.Exception.GetType().FullName}catch{}; try{$msg=Clean-Reason ([string]$err.Exception.Message)}catch{$msg=Clean-Reason ([string]$err)} }
 [void]$stageErrors.Add([pscustomobject]@{Stage=$stage;Command=$command;Type=$typ;Message=$msg})
}
function Join-Values($v){ return (@($v | ForEach-Object {[string]$_} | Where-Object {-not [string]::IsNullOrWhiteSpace($_)} | Sort-Object -Unique) -join ',') }
$candidates=@()
try { $candidates=@(ConvertFrom-Json $env:CHIMERA_FIREWALL_RULE_IDS_JSON -ErrorAction Stop) } catch { Add-StageError 'FILTER_INPUT' 'ConvertFrom-Json CHIMERA_FIREWALL_RULE_IDS_JSON' $_ }
$aliases=@{}; $rows=@{}
foreach($c in $candidates){
 $rid=[string]$c.rule_id
 if([string]::IsNullOrWhiteSpace($rid)){continue}
 if(-not $rows.ContainsKey($rid)){$rows[$rid]=[ordered]@{RuleID=$rid;Protocol='';LocalPort='';LocalAddress='';RemoteAddress='';Interface='';Program='';Service=''}}
 foreach($a in @($c.aliases)){
  $alias=[string]$a
  if(-not [string]::IsNullOrWhiteSpace($alias)){$aliases[$alias]=$rid}
 }
}
function Resolve-RuleID([string]$instanceID){ if($aliases.ContainsKey($instanceID)){return [string]$aliases[$instanceID]}; return '' }
$portComplete=$false
try {
 foreach($f in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop)){
  $rid=Resolve-RuleID ([string]$f.InstanceID); if($rid -eq ''){continue}; $row=$rows[$rid]
  $row.Protocol=Join-Values @($f.Protocol); $row.LocalPort=Join-Values @($f.LocalPort)
 }
 $portComplete=$true
} catch { Add-StageError 'FILTER_PORT' 'Get-NetFirewallPortFilter -PolicyStore ActiveStore' $_ }
$addressComplete=$false
try {
 foreach($f in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -ErrorAction Stop)){
  $rid=Resolve-RuleID ([string]$f.InstanceID); if($rid -eq ''){continue}; $row=$rows[$rid]
  $row.LocalAddress=Join-Values @($f.LocalAddress); $row.RemoteAddress=Join-Values @($f.RemoteAddress)
 }
 $addressComplete=$true
} catch { Add-StageError 'FILTER_ADDRESS' 'Get-NetFirewallAddressFilter -PolicyStore ActiveStore' $_ }
$interfaceComplete=$false
try {
 foreach($f in @(Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore -ErrorAction Stop)){
  $rid=Resolve-RuleID ([string]$f.InstanceID); if($rid -eq ''){continue}; $row=$rows[$rid]
  $row.Interface=Join-Values @($f.InterfaceAlias)
 }
 $interfaceComplete=$true
} catch { Add-StageError 'FILTER_INTERFACE' 'Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore' $_ }
$applicationComplete=$false
try {
 foreach($f in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop)){
  $rid=Resolve-RuleID ([string]$f.InstanceID); if($rid -eq ''){continue}; $row=$rows[$rid]
  $row.Program=Join-Values @($f.Program)
 }
 $applicationComplete=$true
} catch { Add-StageError 'FILTER_APPLICATION' 'Get-NetFirewallApplicationFilter -PolicyStore ActiveStore' $_ }
$serviceComplete=$false
try {
 foreach($f in @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore -ErrorAction Stop)){
  $rid=Resolve-RuleID ([string]$f.InstanceID); if($rid -eq ''){continue}; $row=$rows[$rid]
  $row.Service=Join-Values @($f.Service)
 }
 $serviceComplete=$true
} catch { Add-StageError 'FILTER_SERVICE' 'Get-NetFirewallServiceFilter -PolicyStore ActiveStore' $_ }
$records=@(); foreach($rid in @($rows.Keys | Sort-Object)){ $r=$rows[$rid]; $records += [pscustomobject]$r }
[pscustomobject]@{
 Records=@($records); PortComplete=$portComplete; AddressComplete=$addressComplete; InterfaceComplete=$interfaceComplete;
 ApplicationComplete=$applicationComplete; ServiceComplete=$serviceComplete; StageErrors=@($stageErrors)
} | ConvertTo-Json -Depth 6 -Compress`

type winFirewallFilterCandidate struct {
	RuleID  string   `json:"rule_id"`
	Aliases []string `json:"aliases"`
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	path, err := exec.LookPath("powershell.exe")
	if err != nil {
		addProvider(inv, ProviderStatus{ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: evidence.StateUnavailable, Enabled: "UNKNOWN", Source: "powershell.exe", Reason: "PowerShell provider unavailable: " + err.Error()})
		return
	}

	baseStarted := time.Now()
	base, baseMode, baseFailure, err := collectWindowsFirewallBase(ctx, path)
	baseElapsed := time.Since(baseStarted)
	if err != nil {
		reason := baseFailure
		if strings.TrimSpace(reason) == "" {
			reason = windowsFirewallCommandFailure("BASE", "Get-NetFirewallProfile/Get-NetFirewallRule", "", err)
		}
		addProvider(inv, ProviderStatus{ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: windowsFirewallFailureState(reason, err), Enabled: "UNKNOWN", Source: "Windows NetSecurity ActiveStore staged provider", Reason: reason})
		return
	}
	stageErrors := append([]winFirewallStageError(nil), base.StageErrors...)
	if base.MalformedRecords > 0 {
		stageErrors = append(stageErrors, winFirewallStageError{Stage: "BASE_NORMALIZATION", Command: "Go record decoder", Type: "SCHEMA", Message: fmt.Sprintf("isolated %d malformed base firewall record(s)", base.MalformedRecords)})
	}

	// Stage C receives only stable rule aliases. Both Name and InstanceID are
	// retained because Windows filter objects expose InstanceID while rule objects
	// are commonly correlated by Name. No per-rule NetSecurity cmdlets are used.
	filters := winFirewallFilterPayload{}
	filterElapsed := time.Duration(0)
	if base.RulesObserved && len(base.Rules) > 0 && ctx.Err() == nil {
		candidates := make([]winFirewallFilterCandidate, 0, len(base.Rules))
		for _, r := range base.Rules {
			aliases := uniqueNonBlankStrings(r.CorrelationID, r.Name, r.InstanceID)
			candidates = append(candidates, winFirewallFilterCandidate{RuleID: r.CorrelationID, Aliases: aliases})
		}
		rawCandidates, marshalErr := json.Marshal(candidates)
		if marshalErr != nil {
			stageErrors = append(stageErrors, winFirewallStageError{Stage: "FILTER_INPUT", Command: "json.Marshal", Type: "GO", Message: marshalErr.Error()})
		} else {
			filterStarted := time.Now()
			filterOut, filterStderr, filterErr := runWindowsFirewallPowerShell(ctx, path, windowsFirewallFilterScript, []string{"CHIMERA_FIREWALL_RULE_IDS_JSON=" + string(rawCandidates)})
			filterElapsed = time.Since(filterStarted)
			if filterErr != nil {
				stageErrors = append(stageErrors, winFirewallStageError{Stage: "FILTERS", Command: "bulk NetSecurity filters", Type: "PROVIDER", Message: windowsFirewallCommandFailure("FILTERS", "bulk NetSecurity filters", filterStderr, filterErr)})
			} else if decoded, decodeErr := decodeWindowsFirewallFilterPayload(filterOut); decodeErr != nil {
				stageErrors = append(stageErrors, winFirewallStageError{Stage: "FILTER_DECODE", Command: "json.Unmarshal", Type: "JSON", Message: decodeErr.Error()})
			} else {
				filters = decoded
				stageErrors = append(stageErrors, decoded.StageErrors...)
				if decoded.MalformedRecords > 0 {
					stageErrors = append(stageErrors, winFirewallStageError{Stage: "FILTER_NORMALIZATION", Command: "Go record decoder", Type: "SCHEMA", Message: fmt.Sprintf("isolated %d malformed filter record(s)", decoded.MalformedRecords)})
				}
			}
		}
	}

	enabled := "UNKNOWN"
	if base.ProfilesObserved {
		enabled = windowsOverallEnabled(base.Profiles)
	}
	providerState := evidence.StateObserved
	if !base.ProfilesObserved && !base.RulesObserved {
		providerState = evidence.StateUnavailable
	}
	if windowsFirewallErrorsContainAccessDenied(stageErrors) && !base.ProfilesObserved && !base.RulesObserved {
		providerState = evidence.StateDenied
	}

	filterByRule := make(map[string]winRuleFilter, len(filters.Records))
	for _, f := range filters.Records {
		filterByRule[strings.ToLower(f.RuleID)] = f
	}
	completeRestrictions := base.RulesObserved && !base.RulesTruncated && filters.complete() && len(filters.Records) == len(base.Rules)
	if filters.complete() && len(filters.Records) != len(base.Rules) {
		stageErrors = append(stageErrors, winFirewallStageError{Stage: "FILTER_CORRELATION", Command: "Go in-memory correlation", Type: "SCHEMA", Message: fmt.Sprintf("filter rows=%d base rules=%d", len(filters.Records), len(base.Rules))})
		completeRestrictions = false
	}

	reason := windowsFirewallStageReason(stageErrors)
	provider := ProviderStatus{
		ID: "windows-defender-firewall", Name: "Windows Defender Firewall", State: providerState, Enabled: enabled,
		Source:    "Get-NetFirewallProfile/Get-NetFirewallRule ActiveStore (" + baseMode + ") + bulk NetSecurity filters + MpsSvc",
		RuleCount: base.RuleCount, RuleCountKnown: base.RulesObserved,
		RestrictionCount: base.InboundEnabledRuleCount, RestrictionCountKnown: base.RulesObserved,
		RestrictionSetComplete: completeRestrictions, Reason: reason,
	}
	addProvider(inv, provider)
	if reason != "" {
		// An observed provider can still have incomplete secondary enrichment. Keep
		// the base firewall evidence usable while making the missing stage explicit.
		inv.Degraded = append(inv.Degraded, "windows-defender-firewall: "+reason)
	}

	for _, p := range base.Profiles {
		e := "DISABLED"
		if p.Enabled {
			e = "ENABLED"
		}
		rawIn, rawOut := p.DefaultInboundAction, p.DefaultOutboundAction
		inb, inSource := windowsEffectiveFirewallAction(rawIn, true)
		outb, outSource := windowsEffectiveFirewallAction(rawOut, false)
		conf := evidence.ConfidenceExact
		if inSource != "ActiveStore" || outSource != "ActiveStore" {
			conf = evidence.ConfidenceHigh
		}
		logging := "allowed=" + boolString(p.LogAllowed) + ",blocked=" + boolString(p.LogBlocked)
		addPolicy(inv, Policy{
			Provider: "windows-defender-firewall", Scope: p.Name, Enabled: e,
			DefaultInbound: inb, DefaultOutbound: outb, RuleCount: base.RuleCount, RuleCountKnown: base.RulesObserved,
			Logging: logging, Source: "Get-NetFirewallProfile -PolicyStore ActiveStore", Confidence: conf,
			Attributes: attrs(
				"active_state", p.ActiveState, "active_interfaces", p.ActiveInterfaces,
				"raw_default_inbound", fallback(rawIn, "UNKNOWN"), "raw_default_outbound", fallback(rawOut, "UNKNOWN"),
				"default_inbound_source", inSource, "default_outbound_source", outSource,
				"allow_inbound_rules", p.AllowInboundRules, "allow_local_firewall_rules", p.AllowLocalFirewallRules,
				"allow_local_ipsec_rules", p.AllowLocalIPsecRules, "notify_on_listen", boolString(p.NotifyOnListen),
				"log_file", p.LogFileName, "log_max_kb", fmt.Sprint(p.LogMaxSizeKilobytes), "service_status", base.ServiceStatus,
				"fix45_base_stage_ms", fmt.Sprint(baseElapsed.Milliseconds()), "fix45_filter_stage_ms", fmt.Sprint(filterElapsed.Milliseconds()),
				"fix48_hotfix_base_mode", baseMode,
				"filter_enrichment_complete", boolString(completeRestrictions),
			),
		})
	}

	// Do not turn missing filter dimensions into artificially broad rules. A
	// complete bulk filter stage is required before restrictions are eligible for
	// listener correlation. Base rule counts remain available even when filters are
	// partial, so a late enrichment failure cannot erase firewall posture.
	if filters.complete() {
		for _, r := range base.Rules {
			f, ok := filterByRule[strings.ToLower(r.CorrelationID)]
			if !ok {
				continue
			}
			addRestriction(inv, RestrictionRule{
				Provider: "windows-defender-firewall", Scope: r.Profile, Direction: r.Direction, Action: r.Action, Protocol: f.Protocol,
				LocalPorts: parsePortSpec(f.LocalPort), LocalAddresses: selectorField(f.LocalAddress), RemoteAddresses: selectorField(f.RemoteAddress), Interfaces: selectorField(f.Interface),
				Application: firstSelector(f.Program), Service: firstSelector(f.Service), Enabled: "ENABLED", Order: 0,
				Source: "Get-NetFirewallRule ActiveStore + bulk associated NetSecurity filters", Confidence: evidence.ConfidenceHigh,
			})
		}
	}
}

// collectWindowsFirewallBase prefers the staged diagnostic wrapper. If that
// wrapper itself is incompatible with the local Windows PowerShell 5.1 runtime
// or yields no authoritative profile/rule evidence, retry the previously
// live-proven direct ActiveStore acquisition shape. A successful compatibility
// retry is authoritative evidence, not a release-blocking degradation.
func collectWindowsFirewallBase(ctx context.Context, path string) (winFirewallBasePayload, string, string, error) {
	primaryOut, primaryStderr, primaryErr := runWindowsFirewallPowerShell(ctx, path, windowsFirewallBaseScript, nil)
	primaryFailure := ""
	if primaryErr == nil {
		if base, decodeErr := decodeWindowsFirewallBasePayload(primaryOut); decodeErr == nil {
			if base.ProfilesObserved || base.RulesObserved {
				return base, "staged", "", nil
			}
			primaryFailure = "stage=BASE_PRIMARY reason=no profile or rule evidence returned"
			if detail := windowsFirewallStageReason(base.StageErrors); detail != "" {
				primaryFailure += " detail=" + detail
			}
		} else {
			primaryFailure = "stage=BASE_PRIMARY_DECODE reason=" + strings.Join(strings.Fields(decodeErr.Error()), " ")
		}
	} else {
		primaryFailure = windowsFirewallCommandFailure("BASE_PRIMARY", "staged Get-NetFirewallProfile/Get-NetFirewallRule", primaryStderr, primaryErr)
	}

	if ctx.Err() != nil {
		return winFirewallBasePayload{}, "", primaryFailure, ctx.Err()
	}

	compatOut, compatStderr, compatErr := runWindowsFirewallPowerShell(ctx, path, windowsFirewallCompatibilityBaseScript, nil)
	if compatErr != nil {
		compatFailure := windowsFirewallCommandFailure("BASE_COMPAT", "direct Get-NetFirewallProfile/Get-NetFirewallRule", compatStderr, compatErr)
		return winFirewallBasePayload{}, "", joinWindowsFirewallFailures(primaryFailure, compatFailure), compatErr
	}
	base, decodeErr := decodeWindowsFirewallBasePayload(compatOut)
	if decodeErr != nil {
		compatFailure := "stage=BASE_COMPAT_DECODE reason=" + strings.Join(strings.Fields(decodeErr.Error()), " ")
		return winFirewallBasePayload{}, "", joinWindowsFirewallFailures(primaryFailure, compatFailure), decodeErr
	}
	if !base.ProfilesObserved && !base.RulesObserved {
		compatFailure := "stage=BASE_COMPAT reason=no profile or rule evidence returned"
		return winFirewallBasePayload{}, "", joinWindowsFirewallFailures(primaryFailure, compatFailure), errors.New("Windows firewall base acquisition returned no authoritative evidence")
	}
	return base, "powershell51-compat", "", nil
}

func joinWindowsFirewallFailures(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, " | ")
}

func runWindowsFirewallPowerShell(ctx context.Context, path, script string, extraEnv []string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func windowsFirewallCommandFailure(stage, command, stderr string, err error) string {
	parts := []string{"stage=" + strings.ToUpper(strings.TrimSpace(stage)), "command=" + strings.TrimSpace(command)}
	if stderr = strings.TrimSpace(stderr); stderr != "" {
		parts = append(parts, "stderr="+strings.Join(strings.Fields(stderr), " "))
	}
	if err != nil {
		parts = append(parts, "error="+err.Error())
	}
	return strings.Join(parts, " ")
}

func windowsFirewallFailureState(reason string, err error) evidence.State {
	low := strings.ToLower(reason)
	if strings.Contains(low, "access is denied") || strings.Contains(low, "unauthorized") || strings.Contains(low, "permission") {
		return evidence.StateDenied
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(low, "deadline") || strings.Contains(low, "timed out") {
		return evidence.StateDegraded
	}
	return evidence.StateUnavailable
}

func windowsFirewallErrorsContainAccessDenied(errors []winFirewallStageError) bool {
	for _, e := range errors {
		low := strings.ToLower(e.Message)
		if strings.Contains(low, "access is denied") || strings.Contains(low, "unauthorized") || strings.Contains(low, "permission") {
			return true
		}
	}
	return false
}

func uniqueNonBlankStrings(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func selectorField(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return []string{v}
}

func windowsEffectiveFirewallAction(raw string, inbound bool) (string, string) {
	n := normalizeAction(raw)
	if n != "" && n != "NOT_CONFIGURED" && n != "UNKNOWN" {
		return n, "ActiveStore"
	}
	// Windows Defender Firewall's platform defaults are block inbound and
	// allow outbound when a profile does not explicitly configure those
	// actions. This fallback is used only for an observed enabled Windows
	// firewall profile; collection failures are never converted into defaults.
	if inbound {
		return "BLOCK", "Windows platform default (ActiveStore not configured)"
	}
	return "ALLOW", "Windows platform default (ActiveStore not configured)"
}

func windowsOverallEnabled(p []winProfile) string {
	if len(p) == 0 {
		return "UNKNOWN"
	}
	on := 0
	for _, x := range p {
		if x.Enabled {
			on++
		}
	}
	if on == 0 {
		return "DISABLED"
	}
	if on == len(p) {
		return "ENABLED"
	}
	return "MIXED"
}

func firstSelector(v string) string {
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" && !strings.EqualFold(p, "Any") {
			return p
		}
	}
	return ""
}

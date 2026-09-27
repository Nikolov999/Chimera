//go:build windows

package accounts

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsCredentialProtectionRaw struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Value  *int64 `json:"value"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type windowsCredentialProtectionPayload struct {
	Controls []windowsCredentialProtectionRaw `json:"controls"`
}

func collectCredentialProtection(ctx context.Context, inv *Inventory) {
	const provider = "Windows credential-protection registry and Device Guard metadata"
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		inv.CredentialProtection = CredentialProtection{State: evidence.StateUnavailable, Source: provider, Reason: "PowerShell not found"}
		inv.Degraded = append(inv.Degraded, "windows-credential-protection: PowerShell not found")
		return
	}

	script := `$ErrorActionPreference='Stop'
function Control([string]$id,[string]$name,[string]$state,$value,[string]$source,[string]$reason) {
  return [pscustomobject]@{id=$id;name=$name;state=$state;value=$value;source=$source;reason=$reason}
}
function Read-Dword([string]$path,[string]$name,[string]$id,[string]$label) {
  $source=$path+'\\'+$name
  try {
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return (Control $id $label 'ABSENT' $null $source 'registry key/value is absent') }
    $item=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $prop=$item.PSObject.Properties[$name]
    if ($null -eq $prop) { return (Control $id $label 'ABSENT' $null $source 'registry value is absent') }
    return (Control $id $label 'PRESENT' ([int64]$prop.Value) $source '')
  } catch [System.UnauthorizedAccessException] {
    return (Control $id $label 'DENIED' $null $source 'registry value access denied')
  } catch [System.Security.SecurityException] {
    return (Control $id $label 'DENIED' $null $source 'registry value access denied')
  } catch {
    return (Control $id $label 'ERROR' $null $source ('registry read failed: '+$_.Exception.Message))
  }
}
function Read-IntegerString([string]$path,[string]$name,[string]$id,[string]$label) {
  $source=$path+'\\'+$name
  try {
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return (Control $id $label 'ABSENT' $null $source 'registry key/value is absent') }
    $item=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $prop=$item.PSObject.Properties[$name]
    if ($null -eq $prop) { return (Control $id $label 'ABSENT' $null $source 'registry value is absent') }
    $parsed=[int64]0
    if (-not [int64]::TryParse(([string]$prop.Value), [ref]$parsed)) { return (Control $id $label 'DEGRADED' $null $source 'registry value is present but is not an integer') }
    return (Control $id $label 'PRESENT' $parsed $source '')
  } catch [System.UnauthorizedAccessException] {
    return (Control $id $label 'DENIED' $null $source 'registry value access denied')
  } catch [System.Security.SecurityException] {
    return (Control $id $label 'DENIED' $null $source 'registry value access denied')
  } catch {
    return (Control $id $label 'ERROR' $null $source ('registry read failed: '+$_.Exception.Message))
  }
}
$lsa='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$wdigest='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$winlogon='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$controls=@(
  (Read-Dword $lsa 'RunAsPPL' 'lsa-protection-config' 'LSA protected-process configuration'),
  (Read-Dword $lsa 'LsaCfgFlags' 'credential-guard-lsa-config' 'Credential Guard LSA configuration'),
  (Read-Dword $wdigest 'UseLogonCredential' 'wdigest-credential-caching' 'WDigest plaintext credential caching'),
  (Read-IntegerString $winlogon 'CachedLogonsCount' 'cached-logons-count' 'Cached domain logon count'),
  (Read-Dword $lsa 'NoLMHash' 'lm-hash-storage' 'Legacy LAN Manager password hash storage')
)
try {
  $dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
  $running=if (@($dg.SecurityServicesRunning) -contains 1) { 1 } else { 0 }
  $configured=if (@($dg.SecurityServicesConfigured) -contains 1) { 1 } else { 0 }
  $vbs=[int64]$dg.VirtualizationBasedSecurityStatus
  $controls += (Control 'credential-guard-runtime' 'Credential Guard runtime' 'PRESENT' ([int64]$running) 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesRunning' '')
  $controls += (Control 'credential-guard-configured' 'Credential Guard configured state' 'PRESENT' ([int64]$configured) 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesConfigured' '')
  $controls += (Control 'virtualization-based-security' 'Virtualization-based security runtime' 'PRESENT' $vbs 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.VirtualizationBasedSecurityStatus' '')
} catch [System.UnauthorizedAccessException] {
  $controls += (Control 'credential-guard-runtime' 'Credential Guard runtime' 'DENIED' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesRunning' 'Device Guard CIM access denied')
  $controls += (Control 'credential-guard-configured' 'Credential Guard configured state' 'DENIED' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesConfigured' 'Device Guard CIM access denied')
  $controls += (Control 'virtualization-based-security' 'Virtualization-based security runtime' 'DENIED' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.VirtualizationBasedSecurityStatus' 'Device Guard CIM access denied')
} catch {
  $reason='Device Guard CIM metadata is unavailable'
  $controls += (Control 'credential-guard-runtime' 'Credential Guard runtime' 'ERROR' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesRunning' $reason)
  $controls += (Control 'credential-guard-configured' 'Credential Guard configured state' 'ERROR' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.SecurityServicesConfigured' $reason)
  $controls += (Control 'virtualization-based-security' 'Virtualization-based security runtime' 'ERROR' $null 'CIM root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard.VirtualizationBasedSecurityStatus' $reason)
}
try {
  $cs=Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop
  $domain=if ([bool]$cs.PartOfDomain) { 1 } else { 0 }
  $controls += (Control 'domain-membership' 'Windows domain membership' 'PRESENT' ([int64]$domain) 'CIM Win32_ComputerSystem.PartOfDomain' '')
} catch [System.UnauthorizedAccessException] {
  $controls += (Control 'domain-membership' 'Windows domain membership' 'DENIED' $null 'CIM Win32_ComputerSystem.PartOfDomain' 'computer-system CIM access denied')
} catch {
  $controls += (Control 'domain-membership' 'Windows domain membership' 'ERROR' $null 'CIM Win32_ComputerSystem.PartOfDomain' 'computer-system CIM metadata is unavailable')
}
[pscustomobject]@{controls=$controls} | ConvertTo-Json -Depth 5 -Compress`

	raw, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		reason := err.Error()
		if ctx.Err() != nil {
			reason = ctx.Err().Error()
		}
		inv.CredentialProtection = CredentialProtection{State: evidence.StateUnavailable, Source: provider, Reason: reason}
		inv.Degraded = append(inv.Degraded, "windows-credential-protection: "+reason)
		return
	}
	var payload windowsCredentialProtectionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		reason := "invalid Windows credential-protection provider JSON: " + err.Error()
		inv.CredentialProtection = CredentialProtection{State: evidence.StateDegraded, Source: provider, Reason: reason}
		inv.Degraded = append(inv.Degraded, "windows-credential-protection: "+reason)
		return
	}

	posture := CredentialProtection{State: evidence.StateObserved, Source: provider}
	degraded := make([]string, 0)
	for _, r := range payload.Controls {
		rawState := strings.ToUpper(strings.TrimSpace(r.State))
		if (rawState == "PRESENT" || rawState == string(evidence.StateObserved)) && r.Value != nil {
			posture.Controls = append(posture.Controls, makeObservedCredentialControl(r.ID, r.Name, r.Source, *r.Value))
			continue
		}
		if rawState == "ABSENT" {
			if def, ok := windowsCredentialProtectionDefault(r.ID); ok {
				posture.Controls = append(posture.Controls, makeDefaultCredentialControl(r.ID, r.Name, r.Source, def))
				continue
			}
			r.Reason = "registry value is absent; no deterministic Windows default is inferred"
		}
		state := evidence.StateUnavailable
		if rawState == "DENIED" {
			state = evidence.StateDenied
		}
		if rawState == string(evidence.StateUnsupported) {
			state = evidence.StateUnsupported
		}
		if rawState == string(evidence.StateDegraded) {
			state = evidence.StateDegraded
		}
		reason := strings.TrimSpace(r.Reason)
		if reason == "" {
			reason = "credential-protection value was not observable"
		}
		posture.Controls = append(posture.Controls, makeUnavailableCredentialControl(r.ID, r.Name, r.Source, reason, state))
		degraded = append(degraded, r.ID+": "+reason)
	}
	if len(posture.Controls) == 0 {
		posture.State = evidence.StateUnavailable
		posture.Reason = "Windows credential-protection provider returned no controls"
		inv.Degraded = append(inv.Degraded, "windows-credential-protection: "+posture.Reason)
	} else if len(degraded) > 0 {
		posture.State = evidence.StateDegraded
		posture.Reason = strings.Join(uniqueSorted(degraded), "; ")
		inv.Degraded = append(inv.Degraded, "windows-credential-protection: "+posture.Reason)
	}
	inv.CredentialProtection = posture
}

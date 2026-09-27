//go:build windows

package accounts

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsPolicyRaw struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Value  *int64 `json:"value"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type windowsPolicyPayload struct {
	Controls []windowsPolicyRaw `json:"controls"`
}

func collectSecurityPolicy(ctx context.Context, inv *Inventory) {
	const provider = "Windows registry local security/UAC policy metadata"
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		inv.SecurityPolicy = SecurityPolicy{State: evidence.StateUnavailable, Source: provider, Reason: "PowerShell not found"}
		inv.Degraded = append(inv.Degraded, "windows-security-policy: PowerShell not found")
		return
	}

	script := `$ErrorActionPreference='Stop'
function Read-Dword([string]$path,[string]$name,[string]$id,[string]$label) {
  $source=$path+'\\'+$name
  try {
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
      return [pscustomobject]@{id=$id;name=$label;state='ABSENT';value=$null;source=$source;reason='registry key/value is absent'}
    }
    $item=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $prop=$item.PSObject.Properties[$name]
    if ($null -eq $prop) {
      return [pscustomobject]@{id=$id;name=$label;state='ABSENT';value=$null;source=$source;reason='registry value is absent'}
    }
    return [pscustomobject]@{id=$id;name=$label;state='PRESENT';value=[int64]$prop.Value;source=$source;reason=''}
  } catch [System.UnauthorizedAccessException] {
    return [pscustomobject]@{id=$id;name=$label;state='DENIED';value=$null;source=$source;reason='registry value access denied'}
  } catch [System.Security.SecurityException] {
    return [pscustomobject]@{id=$id;name=$label;state='DENIED';value=$null;source=$source;reason='registry value access denied'}
  } catch {
    return [pscustomobject]@{id=$id;name=$label;state='ERROR';value=$null;source=$source;reason=('registry read failed: '+$_.Exception.Message)}
  }
}
$uac='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$controls=@(
  (Read-Dword $uac 'EnableLUA' 'uac-enabled' 'User Account Control'),
  (Read-Dword $uac 'ConsentPromptBehaviorAdmin' 'admin-consent-prompt' 'Administrator elevation prompt behavior'),
  (Read-Dword $uac 'PromptOnSecureDesktop' 'secure-desktop-prompt' 'UAC secure desktop prompt'),
  (Read-Dword $uac 'FilterAdministratorToken' 'builtin-admin-approval-mode' 'Built-in Administrator Admin Approval Mode'),
  (Read-Dword $uac 'LocalAccountTokenFilterPolicy' 'remote-uac-filtering' 'Remote UAC token filtering'),
  (Read-Dword $lsa 'LimitBlankPasswordUse' 'limit-blank-password-use' 'Blank password remote-use restriction'),
  (Read-Dword $lsa 'EveryoneIncludesAnonymous' 'everyone-includes-anonymous' 'Everyone permissions include anonymous users'),
  (Read-Dword $lsa 'RestrictAnonymous' 'restrict-anonymous' 'Anonymous access restriction'),
  (Read-Dword $lsa 'RestrictAnonymousSAM' 'restrict-anonymous-sam' 'Anonymous SAM enumeration restriction'),
  (Read-Dword $lsa 'ForceGuest' 'force-guest' 'Network access sharing/security model ForceGuest')
)
[pscustomobject]@{controls=$controls} | ConvertTo-Json -Depth 5 -Compress`

	raw, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		reason := err.Error()
		if ctx.Err() != nil {
			reason = ctx.Err().Error()
		}
		inv.SecurityPolicy = SecurityPolicy{State: evidence.StateUnavailable, Source: provider, Reason: reason}
		inv.Degraded = append(inv.Degraded, "windows-security-policy: "+reason)
		return
	}
	var payload windowsPolicyPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		reason := "invalid Windows security-policy provider JSON: " + err.Error()
		inv.SecurityPolicy = SecurityPolicy{State: evidence.StateDegraded, Source: provider, Reason: reason}
		inv.Degraded = append(inv.Degraded, "windows-security-policy: "+reason)
		return
	}

	policy := SecurityPolicy{State: evidence.StateObserved, Source: provider}
	degraded := make([]string, 0)
	for _, r := range payload.Controls {
		rawState := strings.ToUpper(strings.TrimSpace(r.State))
		if (rawState == "PRESENT" || rawState == string(evidence.StateObserved)) && r.Value != nil {
			policy.Controls = append(policy.Controls, makeObservedSecurityControl(r.ID, r.Name, r.Source, *r.Value))
			continue
		}
		if rawState == "ABSENT" {
			if def, ok := windowsSecurityPolicyDefault(r.ID); ok {
				policy.Controls = append(policy.Controls, makeDefaultSecurityControl(r.ID, r.Name, r.Source, def))
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
			reason = "policy value was not observable"
		}
		policy.Controls = append(policy.Controls, makeUnavailableSecurityControl(r.ID, r.Name, r.Source, reason, state))
		degraded = append(degraded, r.ID+": "+reason)
	}
	if len(policy.Controls) == 0 {
		policy.State = evidence.StateUnavailable
		policy.Reason = "Windows security-policy provider returned no controls"
		inv.Degraded = append(inv.Degraded, "windows-security-policy: "+policy.Reason)
	} else if len(degraded) > 0 {
		policy.State = evidence.StateDegraded
		policy.Reason = strings.Join(uniqueSorted(degraded), "; ")
		inv.Degraded = append(inv.Degraded, "windows-security-policy: "+policy.Reason)
	}
	inv.SecurityPolicy = policy
}

//go:build windows

package processes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

const (
	// Authenticode is useful process evidence, but it is secondary enrichment.
	// Keep the stage bounded well inside the HEAVY process-provider ceiling and
	// preserve every completed row when the boundary is reached.
	windowsTrustPreferredBudget = 8 * time.Second
	windowsTrustCleanupReserve  = 1250 * time.Millisecond
	windowsTrustMinimumStart    = 1500 * time.Millisecond
)

const windowsTrustNDJSONScript = `$ErrorActionPreference='Stop'
function CleanReason([object]$v){
  $s=[string]$v
  if([string]::IsNullOrWhiteSpace($s)){return ''}
  $s=($s -replace '[\r\n\t]+',' ' -replace '\s+',' ').Trim()
  if($s.Length -gt 768){$s=$s.Substring(0,768)+'...'}
  return $s
}
try {
  $raw=[Console]::In.ReadToEnd()
  $root=ConvertFrom-Json -InputObject $raw -ErrorAction Stop
  if($null -eq $root){throw 'Authenticode candidate envelope decoded to null'}
  $sp=$root.PSObject.Properties['schema_version']
  if($null -eq $sp -or [int]$sp.Value -ne 1){throw 'Authenticode candidate envelope has invalid schema_version'}
  $ip=$root.PSObject.Properties['items']
  if($null -eq $ip){throw 'Authenticode candidate envelope missing items'}
  $items=@($ip.Value)
  foreach($entry in $items){
    $p=[string]$entry.path
    if([string]::IsNullOrWhiteSpace($p)){continue}
    $status='UNKNOWN'; $reason=''
    try {
      if(Test-Path -LiteralPath $p -PathType Leaf){
        $sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $status=[string]$sig.Status
        $reason=CleanReason $sig.StatusMessage
      } else {
        $reason='executable path not found or not accessible during Authenticode enrichment'
      }
    } catch {
      $reason=CleanReason $_.Exception.Message
    }
    $row=[pscustomobject]@{path=$p;status=$status;reason=$reason}
    # One compact object per line is intentional: Go can retain completed rows
    # even when the bounded stage terminates before the full candidate set.
    Write-Output ($row | ConvertTo-Json -Compress -Depth 3)
  }
} catch {
  Write-Error ('[chimera-stage:windows-process-authenticode] '+(CleanReason $_.Exception.Message))
  exit 42
}`

// enrichTrust is deliberately independent from Win32_Process enumeration.
// Fix58 makes Windows Authenticode enrichment streaming and partial-result safe:
// one slow tail cannot turn all executable-trust evidence into a provider-defect
// UNKNOWN. Completed rows remain usable and candidates not reached by the
// bounded secondary stage are explicitly marked as a safe collection boundary.
func enrichTrust(ctx context.Context, inv *Inventory) {
	if inv == nil || len(inv.Processes) == 0 {
		return
	}
	ps, err := windowsPowerShellPath()
	if err != nil {
		reason := "Authenticode enrichment unavailable: PowerShell executable was not found"
		for i := range inv.Processes {
			if strings.TrimSpace(inv.Processes[i].ExecutablePath) != "" {
				inv.Processes[i].Trust.Reason = reason
			}
		}
		addSource(inv, "windows-process-authenticode", evidence.StateUnavailable, "Get-AuthenticodeSignature", 0, reason)
		return
	}

	candidates := makeWindowsTrustCandidates(inv.Processes)
	if len(candidates) == 0 {
		addSource(inv, "windows-process-authenticode", evidence.StateObserved, "Get-AuthenticodeSignature", 0, "")
		return
	}
	payload, err := json.Marshal(windowsTrustEnvelope{SchemaVersion: windowsTrustSchemaVersion, Items: candidates})
	if err != nil {
		reason := "windows-process-authenticode candidate envelope encode failed: " + boundedWindowsProviderDetail(err.Error())
		markWindowsTrustUnresolved(inv, nil, reason)
		addSource(inv, "windows-process-authenticode", evidence.StateDegraded, "Get-AuthenticodeSignature", 0, reason)
		return
	}

	trustCtx, cancel, decision := reliability.StageContext(ctx, windowsTrustPreferredBudget, windowsTrustCleanupReserve, reliability.ProviderBudgetHeavy)
	defer cancel()
	if decision.Applied < windowsTrustMinimumStart {
		reason := "safe collection boundary: Authenticode enrichment was not started because insufficient process-provider budget remained"
		markWindowsTrustUnresolved(inv, nil, reason)
		addSource(inv, "windows-process-authenticode", evidence.StateDegraded, "Get-AuthenticodeSignature streaming NDJSON", 0, reason)
		return
	}

	cmd := exec.CommandContext(trustCtx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsTrustNDJSONScript)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(started)

	rows, decodeFailures := decodeWindowsTrustNDJSON(stdout.Bytes())
	byPath := make(map[string]windowsTrustRow, len(rows))
	for _, row := range rows {
		path := strings.TrimSpace(row.Path)
		if path == "" {
			continue
		}
		byPath[strings.ToLower(path)] = row
	}

	for i := range inv.Processes {
		path := strings.TrimSpace(inv.Processes[i].ExecutablePath)
		if path == "" {
			continue
		}
		row, ok := byPath[strings.ToLower(path)]
		if !ok {
			continue
		}
		applyWindowsTrustRow(&inv.Processes[i], row)
	}

	stageTimedOut := trustCtx.Err() != nil
	providerFailure := runErr != nil && !stageTimedOut
	boundaryReason := "safe collection boundary: Authenticode enrichment ended before this executable candidate was reached"
	if stageTimedOut {
		markWindowsTrustUnresolved(inv, byPath, boundaryReason)
	} else if providerFailure {
		reason := "windows-process-authenticode class=provider_failure: " + windowsProcessProviderReason(trustCtx, "windows-process-authenticode", runErr)
		if detail := boundedWindowsProviderDetail(stderr.String()); detail != "" && !strings.Contains(reason, detail) {
			reason = appendReason(reason, detail)
		}
		markWindowsTrustUnresolved(inv, byPath, reason)
	} else {
		markWindowsTrustUnresolved(inv, byPath, "Authenticode enrichment did not return a record for this executable candidate")
	}

	state := evidence.StateObserved
	reasons := []string{}
	if stageTimedOut {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("safe collection boundary: Authenticode enrichment preserved %d of %d unique executable result(s) before its bounded stage ended", len(byPath), len(candidates)))
	}
	if providerFailure {
		state = evidence.StateDegraded
		reason := "windows-process-authenticode class=provider_failure: " + windowsProcessProviderReason(trustCtx, "windows-process-authenticode", runErr)
		if detail := boundedWindowsProviderDetail(stderr.String()); detail != "" && !strings.Contains(reason, detail) {
			reason = appendReason(reason, detail)
		}
		reasons = append(reasons, reason)
	}
	if decodeFailures > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("windows-process-authenticode quarantined %d malformed NDJSON result line(s); valid completed rows were preserved", decodeFailures))
	}
	if len(byPath) < len(candidates) && !stageTimedOut && !providerFailure {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("Authenticode provider returned %d of %d unique executable result(s)", len(byPath), len(candidates)))
	}
	if runErr == nil && trustCtx.Err() == nil && len(byPath) == 0 && len(candidates) > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, "windows-process-authenticode unexpected zero-result contract: executable candidates were submitted but no result rows were returned")
	}
	if elapsed > 0 && state != evidence.StateObserved {
		reasons = append(reasons, fmt.Sprintf("Authenticode stage telemetry: candidates=%d completed=%d elapsed=%s", len(candidates), len(byPath), elapsed.Round(time.Millisecond)))
	}
	addSource(inv, "windows-process-authenticode", state, "Get-AuthenticodeSignature streaming NDJSON", len(byPath), strings.Join(uniqueNonEmptyStrings(reasons), "; "))
}

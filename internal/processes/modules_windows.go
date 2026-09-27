//go:build windows

package processes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

const windowsLoadedModuleSource = "Windows Process.Modules enumeration + bounded Authenticode/NTFS ACL enrichment"

func collectLoadedModulesPlatform(ctx context.Context, items []Process) ([]LoadedModuleContext, moduleProviderStats) {
	ps, err := windowsPowerShellPath()
	if err != nil {
		reason := "PowerShell executable was not found"
		return windowsModuleFailureContexts(items, "PROVIDER_UNAVAILABLE", reason), moduleProviderStats{
			ID: "windows-loaded-modules", State: evidence.StateUnavailable,
			Source: windowsLoadedModuleSource, Reason: reason,
		}
	}

	candidates, err := makeWindowsModuleCandidates(items)
	if err != nil {
		reason := "windows-loaded-modules candidate contract failed: " + boundedWindowsProviderDetail(err.Error())
		return windowsModuleFailureContexts(items, "PROVIDER_UNAVAILABLE", reason), moduleProviderStats{
			ID: "windows-loaded-modules", State: evidence.StateDegraded,
			Source: windowsLoadedModuleSource, Reason: reason,
		}
	}
	if len(candidates) == 0 {
		return []LoadedModuleContext{}, moduleProviderStats{ID: "windows-loaded-modules", State: evidence.StateObserved, Source: windowsLoadedModuleSource}
	}

	candidateByPID := make(map[int]windowsModuleCandidate, len(candidates))
	processByCandidate := make(map[string]Process, len(candidates))
	for _, c := range candidates {
		candidateByPID[c.PID] = c
	}
	for _, p := range items {
		if c, ok := candidateByPID[p.PID]; ok {
			processByCandidate[c.CandidateID] = p
		}
	}

	rows, statusByCandidate, enumTelemetry, enumReasons, enumProductDefect, enumTruncated := collectWindowsModuleEnumeration(ctx, ps, candidates)

	allPaths := make([]string, 0, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.Path) != "" {
			allPaths = append(allPaths, r.Path)
		}
	}
	enrichment, enrichTelemetry, enrichReasons, enrichProductDefect, enrichmentCapped := collectWindowsModuleEnrichment(ctx, ps, allPaths)

	modulesByCandidate := make(map[string][]LoadedModule, len(candidates))
	unenrichedByCandidate := make(map[string]int, len(candidates))
	for _, r := range rows {
		p, ok := processByCandidate[r.CandidateID]
		if !ok || strings.TrimSpace(r.Path) == "" {
			continue
		}
		path := strings.TrimSpace(r.Path)
		m := LoadedModule{
			Path:           path,
			Name:           fallback(strings.TrimSpace(r.Name), filepath.Base(path)),
			BaseAddress:    strings.TrimSpace(r.BaseAddress),
			TrustState:     "UNKNOWN",
			TrustBasis:     "Windows Process.Modules enumeration; Authenticode enrichment not completed",
			DirectoryState: "UNKNOWN",
			Source:         "Windows Process.Modules enumeration",
			Confidence:     evidence.ConfidenceMedium,
			Reason:         "module trust/ACL enrichment was not completed within the bounded secondary stage",
		}
		if e, ok := enrichment[strings.ToLower(path)]; ok {
			m.DeletedBacking = e.Deleted
			m.TrustState = strings.ToUpper(fallback(strings.TrimSpace(e.SignatureState), "UNKNOWN"))
			m.TrustBasis = "Windows Authenticode verification"
			m.Signature = strings.TrimSpace(e.Signature)
			m.DirectoryState = strings.ToUpper(fallback(strings.TrimSpace(e.DirectoryState), "UNKNOWN"))
			m.DirectoryWritable = e.DirectoryWeak
			m.BroadDirectoryWrite = e.DirectoryBroad
			m.Source = windowsLoadedModuleSource
			m.Reason = strings.Trim(strings.TrimSpace(e.Reason), "; ")
			m.Confidence = evidence.ConfidenceHigh
			if m.TrustState == "UNKNOWN" || m.DirectoryState != "OBSERVED" {
				m.Confidence = evidence.ConfidenceMedium
			}
		} else {
			unenrichedByCandidate[r.CandidateID]++
		}
		m.TrustMismatch = moduleTrustMismatch(p.Trust.State, m.TrustState, m.DeletedBacking)
		modulesByCandidate[r.CandidateID] = append(modulesByCandidate[r.CandidateID], m)
	}

	out := make([]LoadedModuleContext, 0, len(items))
	observed, degraded, denied, exited, wow64, failed, unavailable := 0, 0, 0, 0, 0, 0, 0
	for _, p := range items {
		candidate, ok := candidateByPID[p.PID]
		if !ok {
			continue
		}
		mods := normalizeLoadedModules(modulesByCandidate[candidate.CandidateID], "windows")
		status, ok := statusByCandidate[candidate.CandidateID]
		state := "PROVIDER_UNAVAILABLE"
		reason := "loaded-module provider returned no process status"
		conf := evidence.ConfidenceLow
		if ok {
			state = normalizeWindowsModuleProcessState(status.State)
			reason = boundedWindowsProviderDetail(status.Reason)
		}
		if state == "OBSERVED" {
			conf = evidence.ConfidenceHigh
			if n := unenrichedByCandidate[candidate.CandidateID]; n > 0 {
				state = "DEGRADED"
				conf = evidence.ConfidenceMedium
				reason = appendReason(reason, fmt.Sprintf("%d of %d module trust/ACL enrichment record(s) were unavailable or bounded", n, len(mods)))
			}
		} else if state == "DEGRADED" {
			conf = evidence.ConfidenceMedium
		}
		if state == "OBSERVED" && len(mods) == 0 && reason == "" {
			reason = "module table enumerated; no distinct loaded modules were returned"
		}

		switch state {
		case "OBSERVED":
			observed++
		case "DEGRADED":
			degraded++
		case "ACCESS_DENIED", "PROTECTED_PROCESS":
			denied++
		case "PROCESS_EXITED":
			exited++
		case "WOW64_ARCH_MISMATCH":
			wow64++
		case "ENUMERATION_FAILED":
			failed++
		default:
			unavailable++
		}

		c := LoadedModuleContext{
			PID: p.PID, Platform: "windows", State: state, Modules: mods,
			Source: windowsLoadedModuleSource, Confidence: conf, Reason: reason,
		}
		c.ModuleCount = len(c.Modules)
		summarizeLoadedModules(&c)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })

	state := evidence.StateObserved
	parts := make([]string, 0, 16)
	if degraded+denied+exited+wow64+failed+unavailable > 0 || len(enumReasons) > 0 || len(enrichReasons) > 0 || enumTruncated || enrichmentCapped {
		state = evidence.StateDegraded
	}
	if denied > 0 {
		parts = append(parts, fmt.Sprintf("%d process module table(s) were access-restricted/protected", denied))
	}
	if exited > 0 {
		parts = append(parts, fmt.Sprintf("%d process(es) exited before module enumeration", exited))
	}
	if wow64 > 0 {
		parts = append(parts, fmt.Sprintf("%d process module table(s) had architecture/WOW64 restrictions", wow64))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d process module table(s) failed enumeration", failed))
	}
	if unavailable > 0 {
		parts = append(parts, fmt.Sprintf("%d process module table(s) were not reached by a completed provider batch", unavailable))
	}
	if degraded > 0 {
		parts = append(parts, fmt.Sprintf("%d process module context(s) retained enumeration evidence with partial trust/ACL enrichment", degraded))
	}
	if enumTruncated {
		parts = append(parts, fmt.Sprintf("loaded-module enumeration bounded at %d total module records", maxLoadedModulesTotal))
	}
	if enrichmentCapped {
		parts = append(parts, fmt.Sprintf("module trust/ACL enrichment bounded to %d highest-coverage unique module paths", windowsLoadedModuleEnrichmentLimit))
	}
	parts = append(parts, enumReasons...)
	parts = append(parts, enrichReasons...)
	if tel := formatWindowsModuleBatchTelemetry(enumTelemetry); tel != "" && state != evidence.StateObserved {
		parts = append(parts, "enumeration telemetry: "+tel)
	}
	if tel := formatWindowsModuleBatchTelemetry(enrichTelemetry); tel != "" && state != evidence.StateObserved {
		parts = append(parts, "enrichment telemetry: "+tel)
	}
	if enumProductDefect || enrichProductDefect {
		state = evidence.StateDegraded
	}
	if observed == 0 && degraded == 0 && len(items) > 0 {
		if denied > 0 && denied+exited+wow64+failed+unavailable == len(items) && exited+wow64+failed+unavailable == 0 {
			state = evidence.StateDenied
		} else {
			state = evidence.StateDegraded
		}
	}

	return out, moduleProviderStats{
		ID: "windows-loaded-modules", State: state, Source: windowsLoadedModuleSource,
		Count: len(rows), Denied: denied, Missing: exited,
		Reason: strings.Join(uniqueNonEmptyStrings(parts), "; "),
	}
}

func collectWindowsModuleEnumeration(ctx context.Context, ps string, candidates []windowsModuleCandidate) ([]windowsModuleRow, map[string]windowsModuleProcessRow, []windowsModuleBatchTelemetry, []string, bool, bool) {
	status := make(map[string]windowsModuleProcessRow, len(candidates))
	rows := make([]windowsModuleRow, 0, 4096)
	telemetry := make([]windowsModuleBatchTelemetry, 0)
	reasons := make([]string, 0)
	productDefect := false
	truncated := false

	enumCtx, cancel := windowsModuleEnumerationStageContext(ctx)
	defer cancel()
	batches := chunkWindowsModuleCandidates(candidates, defaultWindowsModuleBatchSize)
	fatal := false
	for i, batch := range batches {
		if fatal || enumCtx.Err() != nil || len(rows) >= maxLoadedModulesTotal {
			break
		}
		remainingRows := maxLoadedModulesTotal - len(rows)
		batchCtx, batchCancel := windowsModuleBatchContext(enumCtx, 900*time.Millisecond)
		started := time.Now()
		payload, stageReason, runErr, decodeErr := runWindowsModuleEnumerationBatch(batchCtx, ps, batch, remainingRows)
		elapsed := time.Since(started)
		batchErr := batchCtx.Err()
		t := windowsModuleBatchTelemetry{Stage: "enumeration", Index: i + 1, Candidates: len(batch), Elapsed: elapsed}
		batchCancel()

		if runErr != nil {
			if batchErr != nil || strings.Contains(strings.ToLower(stageReason), "deadline exceeded") {
				t.TimedOut = true
				t.Failed = len(batch)
				t.Reason = "bounded enumeration batch deadline reached"
				telemetry = append(telemetry, t)
				reasons = append(reasons, fmt.Sprintf("loaded-module enumeration batch %d/%d reached its bounded deadline; completed batches were preserved", i+1, len(batches)))
				for _, c := range batch {
					status[c.CandidateID] = windowsModuleProcessRow{CandidateID: c.CandidateID, PID: c.PID, State: "PROVIDER_UNAVAILABLE", Reason: fmt.Sprintf("enumeration batch %d reached its bounded deadline; evidence from other batches was preserved", i+1)}
				}
				continue
			}
			t.Failed = len(batch)
			t.Reason = stageReason
			telemetry = append(telemetry, t)
			productDefect = true
			fatal = true
			reasons = append(reasons, "loaded-module provider product defect: "+boundedWindowsProviderDetail(stageReason))
			for _, c := range batch {
				status[c.CandidateID] = windowsModuleProcessRow{CandidateID: c.CandidateID, PID: c.PID, State: "PROVIDER_UNAVAILABLE", Reason: boundedWindowsProviderDetail(stageReason)}
			}
			continue
		}
		if decodeErr != nil {
			t.Failed = len(batch)
			t.Reason = decodeErr.Error()
			telemetry = append(telemetry, t)
			productDefect = true
			fatal = true
			reason := "loaded-module provider product defect: " + boundedWindowsProviderDetail(decodeErr.Error())
			reasons = append(reasons, reason)
			for _, c := range batch {
				status[c.CandidateID] = windowsModuleProcessRow{CandidateID: c.CandidateID, PID: c.PID, State: "PROVIDER_UNAVAILABLE", Reason: reason}
			}
			continue
		}

		rows = append(rows, payload.Rows...)
		truncated = truncated || payload.Truncated
		for _, p := range payload.Processes {
			p.State = normalizeWindowsModuleProcessState(p.State)
			p.Reason = boundedWindowsProviderDetail(p.Reason)
			status[p.CandidateID] = p
			switch p.State {
			case "OBSERVED", "DEGRADED":
				t.Completed++
			case "ACCESS_DENIED", "PROTECTED_PROCESS":
				t.Denied++
			case "PROCESS_EXITED":
				t.Exited++
			default:
				t.Failed++
			}
		}
		telemetry = append(telemetry, t)
		if payload.Truncated || len(rows) >= maxLoadedModulesTotal {
			break
		}
	}

	for _, c := range candidates {
		if _, ok := status[c.CandidateID]; ok {
			continue
		}
		reason := "bounded loaded-module enumeration stage ended before this candidate was attempted; completed batch evidence was preserved"
		if fatal {
			reason = "loaded-module enumeration stopped after a provider product defect; completed batch evidence was preserved"
		} else if len(rows) >= maxLoadedModulesTotal || truncated {
			reason = fmt.Sprintf("loaded-module inventory reached the %d-record safety cap before this candidate was attempted", maxLoadedModulesTotal)
		}
		status[c.CandidateID] = windowsModuleProcessRow{CandidateID: c.CandidateID, PID: c.PID, State: "PROVIDER_UNAVAILABLE", Reason: reason}
	}
	return rows, status, telemetry, uniqueNonEmptyStrings(reasons), productDefect, truncated
}

func runWindowsModuleEnumerationBatch(ctx context.Context, ps string, batch []windowsModuleCandidate, maxRows int) (windowsModuleEnumerationPayload, string, error, error) {
	var payload windowsModuleEnumerationPayload
	rawEnvelope, err := marshalWindowsModuleCandidates(batch)
	if err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules candidate envelope encode failed: %w", err)
	}
	script := windowsModuleEnumerationScript(base64.StdEncoding.EncodeToString(rawEnvelope), maxRows)
	raw, stageReason, runErr := runWindowsProcessPowerShell(ctx, ps, "windows-loaded-modules-enumeration", script)
	if runErr != nil {
		return payload, stageReason, runErr, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules enumeration JSON decode failed: %w", err)
	}
	if err := validateWindowsModuleEnumerationPayload(payload, batch); err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules enumeration structural validation failed: %w", err)
	}
	return payload, "", nil, nil
}

func collectWindowsModuleEnrichment(ctx context.Context, ps string, paths []string) (map[string]windowsModuleEnrichmentRow, []windowsModuleBatchTelemetry, []string, bool, bool) {
	out := make(map[string]windowsModuleEnrichmentRow)
	telemetry := make([]windowsModuleBatchTelemetry, 0)
	reasons := make([]string, 0)
	if len(paths) == 0 || ctx.Err() != nil {
		return out, telemetry, reasons, false, false
	}
	allUnique := makeWindowsModuleEnrichmentCandidates(paths, len(paths))
	capped := len(allUnique) > windowsLoadedModuleEnrichmentLimit
	candidates := allUnique
	if len(candidates) > windowsLoadedModuleEnrichmentLimit {
		candidates = candidates[:windowsLoadedModuleEnrichmentLimit]
	}
	batches := chunkWindowsModuleEnrichmentCandidates(candidates, defaultWindowsModuleEnrichmentBatch)
	productDefect := false
	for i, batch := range batches {
		if ctx.Err() != nil {
			break
		}
		batchCtx, batchCancel := windowsModuleBatchContext(ctx, 800*time.Millisecond)
		started := time.Now()
		payload, stageReason, runErr, decodeErr := runWindowsModuleEnrichmentBatch(batchCtx, ps, batch)
		elapsed := time.Since(started)
		batchErr := batchCtx.Err()
		t := windowsModuleBatchTelemetry{Stage: "enrichment", Index: i + 1, Candidates: len(batch), Elapsed: elapsed}
		batchCancel()
		if runErr != nil {
			if batchErr != nil || strings.Contains(strings.ToLower(stageReason), "deadline exceeded") {
				t.TimedOut = true
				t.Failed = len(batch)
				t.Reason = "bounded enrichment batch deadline reached"
				telemetry = append(telemetry, t)
				reasons = append(reasons, fmt.Sprintf("module trust/ACL enrichment batch %d/%d reached its bounded deadline; enumerated module paths were preserved", i+1, len(batches)))
				continue
			}
			t.Failed = len(batch)
			t.Reason = stageReason
			telemetry = append(telemetry, t)
			productDefect = true
			reasons = append(reasons, "loaded-module enrichment provider product defect: "+boundedWindowsProviderDetail(stageReason))
			break
		}
		if decodeErr != nil {
			t.Failed = len(batch)
			t.Reason = decodeErr.Error()
			telemetry = append(telemetry, t)
			productDefect = true
			reasons = append(reasons, "loaded-module enrichment provider product defect: "+boundedWindowsProviderDetail(decodeErr.Error()))
			break
		}
		for _, r := range payload.Rows {
			out[strings.ToLower(strings.TrimSpace(r.Path))] = r
			if strings.EqualFold(strings.TrimSpace(r.SignatureState), "UNKNOWN") || !strings.EqualFold(strings.TrimSpace(r.DirectoryState), "OBSERVED") {
				t.Failed++
			} else {
				t.Completed++
			}
		}
		telemetry = append(telemetry, t)
	}
	if ctx.Err() != nil && len(out) < len(candidates) {
		reasons = append(reasons, fmt.Sprintf("bounded module enrichment stage ended after %d/%d selected unique paths; enumerated module paths were preserved", len(out), len(candidates)))
	}
	return out, telemetry, uniqueNonEmptyStrings(reasons), productDefect, capped
}

func runWindowsModuleEnrichmentBatch(ctx context.Context, ps string, batch []windowsModuleEnrichmentCandidate) (windowsModuleEnrichmentPayload, string, error, error) {
	var payload windowsModuleEnrichmentPayload
	rawEnvelope, err := marshalWindowsModuleEnrichmentCandidates(batch)
	if err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules enrichment envelope encode failed: %w", err)
	}
	script := windowsModuleEnrichmentScript(base64.StdEncoding.EncodeToString(rawEnvelope))
	raw, stageReason, runErr := runWindowsProcessPowerShell(ctx, ps, "windows-loaded-modules-enrichment", script)
	if runErr != nil {
		return payload, stageReason, runErr, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules enrichment JSON decode failed: %w", err)
	}
	if err := validateWindowsModuleEnrichmentPayload(payload, batch); err != nil {
		return payload, "", nil, fmt.Errorf("windows-loaded-modules enrichment structural validation failed: %w", err)
	}
	return payload, "", nil, nil
}

func windowsModuleEnumerationStageContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel, _ := reliability.StageContext(parent, 4300*time.Millisecond, 1200*time.Millisecond, reliability.ProviderBudgetHeavy)
	return ctx, cancel
}

func windowsModuleBatchContext(parent context.Context, preferred time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel, _ := reliability.StageContext(parent, preferred, 75*time.Millisecond, reliability.ProviderBudgetMedium)
	return ctx, cancel
}

func windowsModuleFailureContexts(items []Process, state, reason string) []LoadedModuleContext {
	out := make([]LoadedModuleContext, 0, len(items))
	for _, p := range items {
		out = append(out, LoadedModuleContext{
			PID: p.PID, Platform: "windows", State: state,
			Source:     windowsLoadedModuleSource,
			Confidence: evidence.ConfidenceLow, Reason: boundedWindowsProviderDetail(reason),
		})
	}
	return out
}

func windowsModuleEnumerationScript(envelopeB64 string, maxRows int) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
function CleanReason([object]$v){ $s=[string]$v; if([string]::IsNullOrWhiteSpace($s)){return ''}; $s=($s -replace '[\r\n\t]+',' ' -replace '\s+',' ').Trim(); if($s.Length -gt 768){$s=$s.Substring(0,768)+'...'}; return $s }
function FailureState([System.Exception]$e){
 $m=(CleanReason $e.Message).ToLowerInvariant()
 if($m.Contains('has exited') -or $m.Contains('no process') -or $m.Contains('cannot find a process') -or $m.Contains('process is not running') -or $m.Contains('process identifier')){ return 'PROCESS_EXITED' }
 if($m.Contains('only part of a readprocessmemory') -or $m.Contains('wow64') -or $m.Contains('32-bit') -or $m.Contains('64-bit')){ return 'WOW64_ARCH_MISMATCH' }
 if($m.Contains('protected process') -or $m.Contains('protected light') -or $m.Contains('ppl')){ return 'PROTECTED_PROCESS' }
 if($m.Contains('access is denied') -or $m.Contains('access denied') -or $m.Contains('unauthorized')){ return 'ACCESS_DENIED' }
 return 'ENUMERATION_FAILED'
}
function ReadEnvelope([string]$b64){
 if([string]::IsNullOrWhiteSpace($b64)){throw 'module candidate envelope is empty'}
 $json=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
 $root=ConvertFrom-Json -InputObject $json -ErrorAction Stop
 if($null -eq $root){throw 'module candidate envelope decoded to null'}
 $sp=$root.PSObject.Properties['schema_version']; if($null -eq $sp){throw 'module candidate envelope missing schema_version'}
 if([int]$sp.Value -ne 1){throw ('module candidate envelope unsupported schema_version '+[string]$sp.Value)}
 $ip=$root.PSObject.Properties['items']; if($null -eq $ip){throw 'module candidate envelope missing items'}
 $items=$ip.Value; if($null -eq $items -or -not ($items -is [System.Array])){throw 'module candidate envelope items must be a JSON array'}
 return $items
}
try {
 $items=@(ReadEnvelope '%s')
 $rows=[System.Collections.Generic.List[object]]::new(); $states=[System.Collections.Generic.List[object]]::new()
 $maxRows=%d; $visited=0; $truncated=$false
 foreach($entry in $items){
  $idp=$entry.PSObject.Properties['candidate_id']; $pidp=$entry.PSObject.Properties['pid']
  if($null -eq $idp -or [string]::IsNullOrWhiteSpace([string]$idp.Value)){throw 'module candidate missing candidate_id'}
  if($null -eq $pidp){throw ('module candidate '+[string]$idp.Value+' missing pid')}
  $id=[string]$idp.Value; $pidv=[int]$pidp.Value; $exe=''; $expectedStart=''
  $ep=$entry.PSObject.Properties['executable_path']; if($null -ne $ep){$exe=[string]$ep.Value}
  $stp=$entry.PSObject.Properties['start_time']; if($null -ne $stp){$expectedStart=[string]$stp.Value}
  if($rows.Count -ge $maxRows){
   $truncated=$true
   [void]$states.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;state='PROVIDER_UNAVAILABLE';reason='global loaded-module record cap reached before this candidate was enumerated';module_count=0})
   continue
  }
  $visited++
  try{$proc=Get-Process -Id $pidv -ErrorAction Stop}catch{
   $st=FailureState $_.Exception
   [void]$states.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;state=$st;reason=(CleanReason $_.Exception.Message);module_count=0}); continue
  }
  if(-not [string]::IsNullOrWhiteSpace($expectedStart)){
   try{
    $expected=[datetime]::Parse($expectedStart,[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $actual=$proc.StartTime.ToUniversalTime()
    if([math]::Abs(($actual-$expected).TotalSeconds) -gt 1){
     [void]$states.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;state='PROCESS_EXITED';reason='process identity changed after base inventory; PID was reused before module enumeration';module_count=0}); continue
    }
   }catch{}
  }
  try{$mods=@($proc.Modules)}catch{
   $st=FailureState $_.Exception
   [void]$states.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;state=$st;reason=(CleanReason $_.Exception.Message);module_count=0}); continue
  }
  $count=0; $procState='OBSERVED'; $reason=''
  foreach($m in $mods){
   if($rows.Count -ge $maxRows){$truncated=$true; $procState='DEGRADED'; $reason='global loaded-module record cap reached during this process module table'; break}
   $path=''; try{$path=[string]$m.FileName}catch{}
   if([string]::IsNullOrWhiteSpace($path)){continue}
   if(-not [string]::IsNullOrWhiteSpace($exe) -and $path.Equals($exe,[System.StringComparison]::OrdinalIgnoreCase)){continue}
   $name=''; try{$name=[string]$m.ModuleName}catch{}
   $base=''; try{$base='0x'+$m.BaseAddress.ToInt64().ToString('x')}catch{}
   [void]$rows.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;path=$path;name=$name;base_address=$base})
   $count++
  }
  if($count -eq 0 -and $procState -eq 'OBSERVED'){$reason='module table enumerated; no distinct loaded modules were returned'}
  [void]$states.Add([pscustomobject]@{candidate_id=$id;pid=$pidv;state=$procState;reason=$reason;module_count=$count})
 }
 [pscustomobject]@{rows=$rows.ToArray();processes=$states.ToArray();visited=$visited;truncated=$truncated} | ConvertTo-Json -Compress -Depth 6
} catch { Write-Error ('[chimera-stage:windows-loaded-modules-enumeration] '+(CleanReason $_.Exception.Message)); exit 40 }`, envelopeB64, maxRows)
}

func windowsModuleEnrichmentScript(envelopeB64 string) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
function CleanReason([object]$v){ $s=[string]$v; if([string]::IsNullOrWhiteSpace($s)){return ''}; $s=($s -replace '[\r\n\t]+',' ' -replace '\s+',' ').Trim(); if($s.Length -gt 768){$s=$s.Substring(0,768)+'...'}; return $s }
function ReadEnvelope([string]$b64){
 $json=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64)); $root=ConvertFrom-Json -InputObject $json -ErrorAction Stop
 if($null -eq $root){throw 'module enrichment envelope decoded to null'}
 $sp=$root.PSObject.Properties['schema_version']; if($null -eq $sp -or [int]$sp.Value -ne 1){throw 'module enrichment envelope has invalid schema_version'}
 $ip=$root.PSObject.Properties['items']; if($null -eq $ip){throw 'module enrichment envelope missing items'}
 $items=$ip.Value; if($null -eq $items -or -not ($items -is [System.Array])){throw 'module enrichment envelope items must be a JSON array'}
 return $items
}
function IsTrustedSid([string]$sid){ $s=$sid.ToUpperInvariant(); return $s -eq 'S-1-5-18' -or $s -eq 'S-1-5-32-544' -or $s -eq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
function IsBroadSid([string]$sid){ $s=$sid.ToUpperInvariant(); return $s -eq 'S-1-1-0' -or $s -eq 'S-1-5-11' -or $s -eq 'S-1-5-32-545' -or $s -eq 'S-1-5-4' }
try {
 $items=@(ReadEnvelope '%s'); $rows=[System.Collections.Generic.List[object]]::new(); $visited=0; $degraded=0; $mutatingMask=%s
 $aclCache=@{}
 foreach($entry in $items){
  $id=[string]$entry.candidate_id; $path=[string]$entry.path; $visited++
  $sigState='UNKNOWN'; $signature='UNKNOWN'; $deleted=$false; $reasons=[System.Collections.Generic.List[string]]::new()
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){$sigState='DELETED_BACKING';$signature='MISSING';$deleted=$true;[void]$reasons.Add('loaded module backing path no longer exists')}
  else{
   try{$s=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop; $signature=[string]$s.Status; switch($signature){'Valid'{$sigState='SIGNED_VALID'}'NotSigned'{$sigState='UNSIGNED'}'HashMismatch'{$sigState='HASH_MISMATCH'}'NotTrusted'{$sigState='SIGNATURE_UNTRUSTED'}default{$sigState='UNKNOWN'}}; if($s.StatusMessage){[void]$reasons.Add((CleanReason $s.StatusMessage))}}
   catch{[void]$reasons.Add(('signature: '+(CleanReason $_.Exception.Message)))}
  }
  $dirState='UNKNOWN'; $weak=$false; $broad=$false; $dir=[System.IO.Path]::GetDirectoryName($path)
  if(-not [string]::IsNullOrWhiteSpace($dir)){
   $key=$dir.ToLowerInvariant()
   if($aclCache.ContainsKey($key)){$di=$aclCache[$key]}
   else{
    try{$acl=Get-Acl -LiteralPath $dir -ErrorAction Stop; $w=$false; $b=$false; foreach($r in @($acl.Access)){if([string]$r.AccessControlType -ne 'Allow'){continue}; $bits=[int64]$r.FileSystemRights; if(($bits -band $mutatingMask) -eq 0){continue}; $sid=''; try{$sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}; if(IsBroadSid $sid){$b=$true}; if(-not (IsTrustedSid $sid)){$w=$true}}; $di=[pscustomobject]@{state='OBSERVED';weak=$w;broad=$b;reason=''}}
    catch{$di=[pscustomobject]@{state='UNKNOWN';weak=$false;broad=$false;reason=(CleanReason $_.Exception.Message)}}
    $aclCache[$key]=$di
   }
   $dirState=[string]$di.state; $weak=[bool]$di.weak; $broad=[bool]$di.broad; if($di.reason){[void]$reasons.Add(('directory ACL: '+[string]$di.reason))}
  }else{[void]$reasons.Add('module directory path is unavailable')}
  if($sigState -eq 'UNKNOWN' -or $dirState -ne 'OBSERVED'){$degraded++}
  [void]$rows.Add([pscustomobject]@{candidate_id=$id;path=$path;signature=$signature;signature_state=$sigState;directory_state=$dirState;directory_weak=$weak;directory_broad=$broad;deleted=$deleted;reason=(CleanReason ($reasons -join '; '))})
 }
 [pscustomobject]@{rows=$rows.ToArray();visited=$visited;degraded=$degraded;truncated=$false} | ConvertTo-Json -Compress -Depth 5
} catch { Write-Error ('[chimera-stage:windows-loaded-modules-enrichment] '+(CleanReason $_.Exception.Message)); exit 41 }`, envelopeB64, windowsacl.PowerShellMutatingMaskExpression)
}

func uniqueNonEmptyStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

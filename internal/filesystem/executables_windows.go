//go:build windows

package filesystem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

type windowsExecutableWire struct {
	Kind            string   `json:"kind"`
	CandidateID     string   `json:"candidate_id"`
	Path            string   `json:"path"`
	State           string   `json:"state"`
	Exists          bool     `json:"exists"`
	Regular         bool     `json:"regular"`
	Owner           string   `json:"owner"`
	BroadlyWritable bool     `json:"broadly_writable"`
	WritePrincipals []string `json:"write_principals"`
	Reason          string   `json:"reason"`
}

// Fix55 deliberately separates the executable-DACL stage's hard Go deadline
// from its normal PowerShell work boundary. PowerShell exits itself before the
// hard stage deadline, leaving enough time to emit terminal candidate states,
// flush JSON, decode results, and let the filesystem collector continue into
// the later search-path/sensitive/TEMP/ACL-boundary stages.
const (
	windowsExecutableWorkBudgetMilliseconds = 5200
	windowsExecutablePerDirectoryLimit      = 128
)

const windowsExecutableScript = `$ErrorActionPreference='Stop'
` + windowsCandidateEnvelopePowerShell + `
$dirs=@()
try{$dirs=@(Read-ChimeraCandidateEnvelope -Json $env:CHIMERA_EXEC_DIRS_JSON -Label 'executable-directory')}catch{
 [pscustomobject]@{kind='provider_error';candidate_id='';path='';state='UNAVAILABLE';exists=$false;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason=('decode executable candidate envelope: '+[string]$_.Exception.Message)} | ConvertTo-Json -Compress
 exit 0
}
$exts=@('.exe','.com','.bat','.cmd','.ps1','.vbs','.js','.wsf','.msc')
$broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$mask=` + windowsacl.PowerShellMutatingMaskExpression + `
$limit=8192
try{if(-not [string]::IsNullOrWhiteSpace($env:CHIMERA_EXEC_RECORD_LIMIT)){$limit=[Math]::Max(1,[int]$env:CHIMERA_EXEC_RECORD_LIMIT)}}catch{$limit=8192}
$perDirLimit=128
try{if(-not [string]::IsNullOrWhiteSpace($env:CHIMERA_EXEC_PER_DIR_LIMIT)){$perDirLimit=[Math]::Max(1,[int]$env:CHIMERA_EXEC_PER_DIR_LIMIT)}}catch{$perDirLimit=128}
$workBudgetMs=5200
try{if(-not [string]::IsNullOrWhiteSpace($env:CHIMERA_EXEC_WORK_BUDGET_MS)){$workBudgetMs=[Math]::Max(250,[int]$env:CHIMERA_EXEC_WORK_BUDGET_MS)}}catch{$workBudgetMs=5200}
$sw=[System.Diagnostics.Stopwatch]::StartNew()
$sections=[System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
$useStaticAcl=$false
try{$useStaticAcl=(@([System.IO.File].GetMethods() | Where-Object {$_.Name -eq 'GetAccessControl' -and $_.GetParameters().Count -eq 2}).Count -gt 0)}catch{$useStaticAcl=$false}
$count=0
$workBoundary=$false
foreach($i in $dirs){
 $id=[string]$i.candidate_id
 $d=[string]$i.path
 if($workBoundary -or $sw.ElapsedMilliseconds -ge $workBudgetMs){
  $workBoundary=$true
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='DEGRADED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason='safe collection boundary: executable DACL work window completed before this candidate was enumerated'} | ConvertTo-Json -Compress
  continue
 }
 if($count -ge $limit){
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='DEGRADED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason='safe collection boundary: global executable record ceiling reached before this candidate was enumerated'} | ConvertTo-Json -Compress
  continue
 }
 try{
  if(-not (Test-Path -LiteralPath $d -PathType Container -ErrorAction Stop)){
   [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='OBSERVED';exists=$false;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason='candidate directory does not exist on this host'} | ConvertTo-Json -Compress
   continue
  }
 }catch{
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state=$st;exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress
  continue
 }

 # Enumerate lazily so a large directory cannot first materialize thousands of
 # unrelated files and consume the entire bounded work window. The per-directory
 # ceiling spreads useful coverage across PATH/system directories deterministically.
 $files=New-Object 'System.Collections.Generic.List[string]'
 $enumerationBoundary=$false
 try{
  $enum=[System.IO.Directory]::EnumerateFiles($d,'*',[System.IO.SearchOption]::TopDirectoryOnly).GetEnumerator()
  try{
   while($files.Count -lt $perDirLimit -and $enum.MoveNext()){
    if($sw.ElapsedMilliseconds -ge $workBudgetMs){$enumerationBoundary=$true;$workBoundary=$true;break}
    $fp=[string]$enum.Current
    $e=[System.IO.Path]::GetExtension($fp)
    if((-not [string]::IsNullOrWhiteSpace($e)) -and ($exts -contains $e.ToLowerInvariant())){[void]$files.Add($fp)}
   }
  }finally{if($null -ne $enum -and $enum -is [System.IDisposable]){$enum.Dispose()}}
 }catch{
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state=$st;exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress
  continue
 }

 $aclBoundary=$false
 foreach($fp in $files){
  if($count -ge $limit){$aclBoundary=$true;break}
  if($sw.ElapsedMilliseconds -ge $workBudgetMs){$aclBoundary=$true;$workBoundary=$true;break}
  try{
   if($useStaticAcl){
    $acl=[System.IO.File]::GetAccessControl($fp,$sections)
   }else{
    $acl=Get-Acl -LiteralPath $fp -ErrorAction Stop
   }
   $allow=@{};$deny=@{};$names=@{}
   $rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
   foreach($ace in $rules){
    $sid=[string]$ace.IdentityReference.Value
    if($broadSids -notcontains $sid){continue}
    if(([int64]$ace.FileSystemRights -band [int64]$mask) -eq 0){continue}
    $display=$sid;try{$display=$ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value}catch{}
    if([string]$ace.AccessControlType -eq 'Deny'){$deny[$sid]=$true}else{$allow[$sid]=$true;$names[$sid]=$display}
   }
   $writers=@();foreach($sid in $allow.Keys){if(-not $deny.ContainsKey($sid)){$writers+=$names[$sid]}}
   $owner='';try{$owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value}catch{$owner=[string]$acl.Owner}
   [pscustomobject]@{kind='executable';candidate_id=$id;path=$fp;state='OBSERVED';exists=$true;regular=$true;owner=$owner;broadly_writable=($writers.Count -gt 0);write_principals=@($writers|Sort-Object -Unique);reason=''} | ConvertTo-Json -Compress
  }catch{
   $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
   [pscustomobject]@{kind='executable';candidate_id=$id;path=$fp;state=$st;exists=$true;regular=$true;owner='';broadly_writable=$false;write_principals=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress
  }
  $count++
 }
 if($workBoundary -or $enumerationBoundary -or ($aclBoundary -and $sw.ElapsedMilliseconds -ge $workBudgetMs)){
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='DEGRADED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason='safe collection boundary: executable DACL work window completed while this candidate was being enumerated'} | ConvertTo-Json -Compress
 }elseif($count -ge $limit){
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='DEGRADED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason='safe collection boundary: global executable record ceiling reached while this candidate was being enumerated'} | ConvertTo-Json -Compress
 }elseif($files.Count -ge $perDirLimit){
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='DEGRADED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason=('safe collection boundary: per-directory executable record ceiling '+[string]$perDirLimit+' reached')} | ConvertTo-Json -Compress
 }else{
  [pscustomobject]@{kind='candidate_status';candidate_id=$id;path=$d;state='OBSERVED';exists=$true;regular=$false;owner='';broadly_writable=$false;write_principals=@();reason=''} | ConvertTo-Json -Compress
 }
}`

func collectPlatformExecutables(ctx context.Context, dirs []string, capability PermissionCapability) ([]ExecutableRecord, SourceStatus, []string) {
	const source = "Windows PowerShell bounded single-session executable permission inventory"
	if len(dirs) == 0 {
		return nil, SourceStatus{ID: "executable-permissions", State: evidence.StateObserved, Source: source, ItemCount: 0}, nil
	}
	ps, err := windowsFilesystemPowerShellPath()
	if err != nil {
		return nil, SourceStatus{ID: "executable-permissions", State: evidence.StateUnavailable, Source: source, Reason: "PowerShell not found"}, []string{"executable DACL inventory unavailable: PowerShell not found"}
	}

	wire := make([]windowsCandidateEnvelopeItem, 0, len(dirs))
	byID := make(map[string]string, len(dirs))
	for i, dir := range dirs {
		id := fmt.Sprintf("exec-dir-%03d", i)
		wire = append(wire, windowsCandidateEnvelopeItem{CandidateID: id, Path: dir})
		byID[id] = dir
	}
	rawDirs, marshalErr := marshalWindowsCandidateEnvelope(wire)
	if marshalErr != nil {
		reason := "executable candidate input contract: " + marshalErr.Error()
		return nil, SourceStatus{ID: "executable-permissions", State: evidence.StateUnavailable, Source: source, Reason: reason}, []string{"executable DACL inventory unavailable: " + reason}
	}

	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsExecutableScript)
	cmd.Env = append(os.Environ(),
		"CHIMERA_EXEC_DIRS_JSON="+string(rawDirs),
		"CHIMERA_EXEC_RECORD_LIMIT="+strconv.Itoa(maxExecutables),
		"CHIMERA_EXEC_PER_DIR_LIMIT="+strconv.Itoa(windowsExecutablePerDirectoryLimit),
		"CHIMERA_EXEC_WORK_BUDGET_MS="+strconv.Itoa(windowsExecutableWorkBudgetMilliseconds),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	var contextErr error
	if ctx != nil {
		contextErr = ctx.Err()
	}

	out := []ExecutableRecord{}
	unresolved := 0
	malformed := 0
	diagnostics := []string{}
	providerFaults := []string{}
	providerRunReasons := []string{}
	boundaryReasons := []string{}
	seenCandidateStatus := make(map[string]struct{}, len(byID))
	candidateDegraded := 0
	boundarySkipped := 0

	markBoundaryCandidates := func(items []windowsCandidateEnvelopeItem, reason string) {
		marked := 0
		for _, item := range items {
			if _, seen := seenCandidateStatus[item.CandidateID]; seen {
				continue
			}
			seenCandidateStatus[item.CandidateID] = struct{}{}
			candidateDegraded++
			boundarySkipped++
			marked++
		}
		if marked > 0 {
			diagnostics = append(diagnostics, fmt.Sprintf("DEGRADED: %d executable search directory candidate(s) not completed: %s", marked, reason))
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var w windowsExecutableWire
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			malformed++
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(w.Kind))
		if kind == "provider_error" {
			providerFaults = append(providerFaults, fallback(strings.TrimSpace(w.Reason), "executable provider input contract failed"))
			continue
		}
		if kind == "candidate_status" || kind == "directory_error" {
			candidateID := strings.TrimSpace(w.CandidateID)
			expectedPath, correlated := byID[candidateID]
			if !correlated || strings.TrimSpace(w.Path) == "" || platformPathKey(w.Path) != platformPathKey(expectedPath) {
				malformed++
				continue
			}
			if _, duplicate := seenCandidateStatus[candidateID]; duplicate {
				malformed++
				continue
			}
			seenCandidateStatus[candidateID] = struct{}{}
			candidateState := evidence.State(strings.ToUpper(strings.TrimSpace(w.State)))
			if !validWindowsCandidateEvidenceState(candidateState) {
				candidateState = evidence.StateDegraded
				w.Reason = appendFilesystemReason(w.Reason, "candidate status contained an invalid state")
			}
			if candidateState != evidence.StateObserved {
				candidateDegraded++
				detail := fmt.Sprintf("candidate %s (%s): %s", candidateID, expectedPath, fallback(strings.TrimSpace(w.Reason), "candidate enumeration degraded"))
				diagnostics = append(diagnostics, string(candidateState)+": "+detail)
			}
			continue
		}
		if kind != "" && kind != "executable" {
			malformed++
			continue
		}
		candidateID := strings.TrimSpace(w.CandidateID)
		candidateDir, correlated := byID[candidateID]
		if !correlated {
			malformed++
			continue
		}
		path := strings.TrimSpace(w.Path)
		if path == "" {
			malformed++
			continue
		}
		path = filepath.Clean(path)
		if platformPathKey(filepath.Dir(path)) != platformPathKey(candidateDir) {
			malformed++
			continue
		}
		state := evidence.State(strings.ToUpper(strings.TrimSpace(w.State)))
		reason := strings.TrimSpace(w.Reason)
		if !validWindowsCandidateEvidenceState(state) {
			state = evidence.StateDegraded
			reason = appendFilesystemReason(reason, "provider record did not include a valid state")
		}
		exists := w.Exists
		regular := w.Regular
		if state == evidence.StateObserved {
			exists = true
			regular = true
		}
		if len(out) >= maxExecutables {
			continue
		}
		rec := ExecutableRecord{
			ID: stableExecutableID(path), Path: path, Directory: filepath.Dir(path), State: state,
			Exists: exists, Regular: regular, Executable: true,
			OwnerID: strings.TrimSpace(w.Owner), PermissionModel: capability.Model,
			BroadlyWritable: w.BroadlyWritable, UntrustedWrite: w.BroadlyWritable,
			WritePrincipals:  append([]string(nil), w.WritePrincipals...),
			DiscoverySource:  "bounded executable search directory enumeration (" + candidateID + ")",
			CollectionSource: source,
			Confidence:       evidence.ConfidenceHigh, Reason: reason,
		}
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		malformed++
		diagnostics = append(diagnostics, "stdout scanner: "+boundedFilesystemProviderDetail(err.Error()))
	}

	if runErr != nil {
		if contextErr != nil {
			missing := make([]windowsCandidateEnvelopeItem, 0, len(wire))
			for _, item := range wire {
				if _, seen := seenCandidateStatus[item.CandidateID]; !seen {
					missing = append(missing, item)
				}
			}
			reason := fmt.Sprintf("safe collection boundary: hard executable DACL stage boundary reached after preserving %d decoded executable record(s)", len(out))
			markBoundaryCandidates(missing, reason)
			boundaryReasons = append(boundaryReasons, reason)
		} else {
			reason := windowsFilesystemProviderReasonWithDetail(nil, "windows-executable-dacl-inventory", runErr, stderr.String())
			if len(out) == 0 && stdout.Len() > 0 {
				reason = appendFilesystemReason(reason, fmt.Sprintf("provider stdout contained %d undecoded byte(s)", stdout.Len()))
			}
			providerRunReasons = append(providerRunReasons, reason)
		}
	}

	missingCandidateStatus := len(byID) - len(seenCandidateStatus)
	state := evidence.StateObserved
	reasons := []string{}
	limitations := []string{}
	if unresolved > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("permission metadata unresolved for %d executable(s)", unresolved))
	}
	if candidateDegraded > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("candidate enumeration degraded for %d executable search directory candidate(s)", candidateDegraded))
	}
	if malformed > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("quarantined %d malformed or uncorrelated executable provider record(s)", malformed))
		limitations = append(limitations, fmt.Sprintf("executable DACL provider degraded: quarantined %d malformed or uncorrelated provider record(s)", malformed))
	}
	if missingCandidateStatus > 0 {
		if len(out) == 0 && len(seenCandidateStatus) == 0 {
			state = evidence.StateUnavailable
		} else {
			state = evidence.StateDegraded
		}
		contractReason := fmt.Sprintf("provider contract violation: submitted=%d terminal_candidate_records=%d missing=%d", len(byID), len(seenCandidateStatus), missingCandidateStatus)
		reasons = append(reasons, contractReason)
		limitations = append(limitations, "executable DACL inventory degraded: "+contractReason)
	}
	if len(diagnostics) > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("%d executable candidate/provider stage(s) degraded", len(diagnostics)))
		for _, d := range diagnostics {
			if len(limitations) >= 16 {
				break
			}
			limitations = append(limitations, "executable DACL provider degraded: "+d)
		}
	}
	for _, fault := range providerFaults {
		if len(out) == 0 {
			state = evidence.StateUnavailable
		} else {
			state = evidence.StateDegraded
		}
		reasons = append(reasons, "provider input contract failed: "+fault)
		limitations = append(limitations, "executable DACL inventory unavailable: "+fault)
	}
	for _, reason := range providerRunReasons {
		if len(out) == 0 {
			state = evidence.StateUnavailable
		} else {
			state = evidence.StateDegraded
		}
		reasons = append(reasons, reason)
		limitations = append(limitations, "executable DACL inventory degraded: "+reason)
	}
	if len(boundaryReasons) > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("safe collection boundary left %d executable search directory candidate(s) incomplete", boundarySkipped))
		for _, reason := range uniqueSorted(boundaryReasons) {
			limitations = append(limitations, "executable DACL inventory bounded: "+reason)
		}
	}
	if len(out) == 0 && len(byID) > 0 && len(seenCandidateStatus) == len(byID) && len(providerFaults) == 0 && len(providerRunReasons) == 0 && len(boundaryReasons) == 0 && malformed == 0 && candidateDegraded == 0 {
		state = evidence.StateObserved
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	return out, SourceStatus{ID: "executable-permissions", State: state, Source: source, ItemCount: len(out), Reason: reason}, uniqueSorted(limitations)
}

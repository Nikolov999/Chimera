//go:build windows

package remotemgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	windowsSMBStageServerConfiguration = "SERVER_CONFIGURATION"
	windowsSMBStageShareInventory      = "SHARE_INVENTORY"
	windowsSMBStageShareAccess         = "SHARE_ACCESS"
	windowsSMBStageRegistryPolicy      = "REGISTRY_POLICY"
)

// Post-117 Fix46: each Windows SMB evidence family executes in its own
// PowerShell stage. A failed Get-SmbShare must never erase successfully
// collected Get-SmbServerConfiguration evidence (and vice versa).
const windowsSMBServerConfigurationScript = `$ErrorActionPreference='Stop'
$stage='SERVER_CONFIGURATION'
$commandName='Get-SmbServerConfiguration'
function Fail-ChimeraSMBStage([string]$class,[string]$type,[string]$message,[int]$code) {
  $d=[ordered]@{Stage=$stage;Command=$commandName;Class=$class;ExceptionType=$type;Message=$message}
  [Console]::Error.WriteLine(($d | ConvertTo-Json -Compress))
  exit $code
}
if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {
  Fail-ChimeraSMBStage 'MODULE_UNAVAILABLE' 'System.Management.Automation.CommandNotFoundException' 'Get-SmbServerConfiguration is unavailable' 3
}
try {
  $c=Get-SmbServerConfiguration -ErrorAction Stop
  [ordered]@{
    Server=[ordered]@{
      EnableSMB1Protocol=[bool]$c.EnableSMB1Protocol
      EnableSMB2Protocol=[bool]$c.EnableSMB2Protocol
      EnableSecuritySignature=[bool]$c.EnableSecuritySignature
      RequireSecuritySignature=[bool]$c.RequireSecuritySignature
      EncryptData=[bool]$c.EncryptData
      RejectUnencryptedAccess=[bool]$c.RejectUnencryptedAccess
    }
    Shares=@();AccessErrors=@();Access=@()
  } | ConvertTo-Json -Depth 6 -Compress
} catch {
  $exceptionType=$_.Exception.GetType().FullName
  $exceptionMessage=$_.Exception.Message
  Fail-ChimeraSMBStage 'PROVIDER_FAILURE' $exceptionType $exceptionMessage 1
}`

const windowsSMBShareInventoryScript = `$ErrorActionPreference='Stop'
$stage='SHARE_INVENTORY'
$commandName='Get-SmbShare'
function Fail-ChimeraSMBStage([string]$class,[string]$type,[string]$message,[int]$code) {
  $d=[ordered]@{Stage=$stage;Command=$commandName;Class=$class;ExceptionType=$type;Message=$message}
  [Console]::Error.WriteLine(($d | ConvertTo-Json -Compress))
  exit $code
}
if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
  Fail-ChimeraSMBStage 'MODULE_UNAVAILABLE' 'System.Management.Automation.CommandNotFoundException' 'Get-SmbShare is unavailable' 3
}
try {
  $rawShares=@(Get-SmbShare -ErrorAction Stop)
  $shares=@()
  foreach ($s in $rawShares) {
    $shares += [pscustomobject]@{
      Name=[string]$s.Name
      Path=[string]$s.Path
      Description=[string]$s.Description
      EncryptData=[bool]$s.EncryptData
      FolderEnumerationMode=[string]$s.FolderEnumerationMode
      Special=[bool]$s.Special
      Temporary=[bool]$s.Temporary
    }
  }
  [ordered]@{Server=[ordered]@{};Shares=@($shares);AccessErrors=@();Access=@()} | ConvertTo-Json -Depth 6 -Compress
} catch {
  $exceptionType=$_.Exception.GetType().FullName
  $exceptionMessage=$_.Exception.Message
  Fail-ChimeraSMBStage 'PROVIDER_FAILURE' $exceptionType $exceptionMessage 1
}`

const windowsSMBShareAccessScript = `$ErrorActionPreference='Stop'
$stage='SHARE_ACCESS'
$commandName='Get-SmbShareAccess'
function Fail-ChimeraSMBStage([string]$class,[string]$type,[string]$message,[int]$code) {
  $d=[ordered]@{Stage=$stage;Command=$commandName;Class=$class;ExceptionType=$type;Message=$message}
  [Console]::Error.WriteLine(($d | ConvertTo-Json -Compress))
  exit $code
}
if (-not (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue)) {
  Fail-ChimeraSMBStage 'MODULE_UNAVAILABLE' 'System.Management.Automation.CommandNotFoundException' 'Get-SmbShareAccess is unavailable' 3
}
try {
  if ([string]::IsNullOrWhiteSpace($env:CHIMERA_SMB_SHARE_ACCESS_JSON)) {
    Fail-ChimeraSMBStage 'INPUT_CONTRACT' 'System.ArgumentException' 'CHIMERA_SMB_SHARE_ACCESS_JSON is empty' 4
  }
  $inputObj=ConvertFrom-Json -InputObject $env:CHIMERA_SMB_SHARE_ACCESS_JSON -ErrorAction Stop
  if ($null -eq $inputObj -or $null -eq $inputObj.Names) {
    Fail-ChimeraSMBStage 'INPUT_CONTRACT' 'System.ArgumentException' 'SMB share-access input is missing Names' 4
  }
  $names=@($inputObj.Names)
  $access=@()
  $accessErrors=@()
  $accessFailures=@()
  foreach ($nameValue in $names) {
    $name=[string]$nameValue
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    try {
      foreach ($a in @(Get-SmbShareAccess -Name $name -ErrorAction Stop)) {
        $access += [pscustomobject]@{
          Name=$name
          AccountName=[string]$a.AccountName
          AccessControlType=[string]$a.AccessControlType
          AccessRight=[string]$a.AccessRight
        }
      }
    } catch {
      $accessErrors += [string]$name
      $accessFailures += [pscustomobject]@{
        Name=$name
        ExceptionType=[string]$_.Exception.GetType().FullName
        Message=[string]$_.Exception.Message
      }
    }
  }
  [ordered]@{Server=[ordered]@{};Shares=@();AccessErrors=@($accessErrors);AccessFailures=@($accessFailures);Access=@($access)} | ConvertTo-Json -Depth 6 -Compress
} catch {
  $exceptionType=$_.Exception.GetType().FullName
  $exceptionMessage=$_.Exception.Message
  Fail-ChimeraSMBStage 'PROVIDER_FAILURE' $exceptionType $exceptionMessage 1
}`

const windowsSMBRegistryPolicyScript = `$ErrorActionPreference='Stop'
$stage='REGISTRY_POLICY'
$commandName='SMB registry policy'
function Fail-ChimeraSMBStage([string]$class,[string]$type,[string]$message,[int]$code) {
  $d=[ordered]@{Stage=$stage;Command=$commandName;Class=$class;ExceptionType=$type;Message=$message}
  [Console]::Error.WriteLine(($d | ConvertTo-Json -Compress))
  exit $code
}
try {
  $guest=$null
  $restrictNull=$null
  $nullShares=@()
  $workstationPath='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (Test-Path -LiteralPath $workstationPath) {
    $p=Get-ItemProperty -LiteralPath $workstationPath -ErrorAction Stop
    if ($null -ne $p.AllowInsecureGuestAuth) { $guest=[bool]$p.AllowInsecureGuestAuth }
  }
  $serverPath='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
  if (Test-Path -LiteralPath $serverPath) {
    $p=Get-ItemProperty -LiteralPath $serverPath -ErrorAction Stop
    if ($null -ne $p.RestrictNullSessAccess) { $restrictNull=[bool]$p.RestrictNullSessAccess }
    if ($null -ne $p.NullSessionShares) { $nullShares=@($p.NullSessionShares) }
  }
  [ordered]@{
    Server=[ordered]@{
      AllowInsecureGuestAuth=$guest
      RestrictNullSessAccess=$restrictNull
      NullSessionShares=@($nullShares)
    }
    Shares=@();AccessErrors=@();Access=@()
  } | ConvertTo-Json -Depth 6 -Compress
} catch {
  $exceptionType=$_.Exception.GetType().FullName
  $exceptionMessage=$_.Exception.Message
  Fail-ChimeraSMBStage 'PROVIDER_FAILURE' $exceptionType $exceptionMessage 1
}`

type windowsSMBStageDiagnostic struct {
	Stage         string `json:"Stage"`
	Command       string `json:"Command"`
	Class         string `json:"Class"`
	ExceptionType string `json:"ExceptionType"`
	Message       string `json:"Message"`
}

type windowsSMBStageFailure struct {
	Stage         string
	Command       string
	Class         string
	ExceptionType string
	Message       string
	Stderr        string
	ExitCode      int
	Elapsed       time.Duration
}

func (f *windowsSMBStageFailure) reason() string {
	if f == nil {
		return ""
	}
	parts := []string{
		"provider=windows-smb",
		"stage=" + strings.TrimSpace(f.Stage),
		"command=" + strings.TrimSpace(f.Command),
		"class=" + strings.TrimSpace(f.Class),
		"exit_code=" + strconv.Itoa(f.ExitCode),
		"elapsed_ms=" + strconv.FormatInt(f.Elapsed.Milliseconds(), 10),
	}
	if v := strings.TrimSpace(f.ExceptionType); v != "" {
		parts = append(parts, "exception="+v)
	}
	if v := strings.TrimSpace(f.Message); v != "" {
		parts = append(parts, "message="+boundedSMBText(v, 500))
	}
	if v := strings.TrimSpace(f.Stderr); v != "" && !strings.Contains(v, `"Stage"`) {
		parts = append(parts, "stderr="+boundedSMBText(v, 500))
	}
	return strings.Join(parts, " ")
}

func collectPlatformSMBSecurity(ctx context.Context) smbPlatformResult {
	result := smbPlatformResult{
		ShareInventoryState:  evidence.StateUnavailable,
		ShareInventorySource: "Windows SMB SHARE_INVENTORY stage",
	}
	ps := findWindowsSMBPowerShell()
	if ps == "" {
		reason := "provider=windows-smb stage=PRECHECK command=PowerShell class=MODULE_UNAVAILABLE exit_code=-1 message=PowerShell SMB provider unavailable"
		result.Settings = windowsSMBSettings(windowsSMBJSON{}, reason, reason, false, false)
		result.ShareInventoryReason = reason
		result.Degraded = append(result.Degraded, reason)
		return result
	}

	var raw windowsSMBJSON
	serverOK := false
	registryOK := false

	serverOut, serverElapsed, serverFailure := runWindowsSMBStage(ctx, ps, windowsSMBStageServerConfiguration, "Get-SmbServerConfiguration", windowsSMBServerConfigurationScript, nil)
	if serverFailure != nil {
		result.Degraded = append(result.Degraded, serverFailure.reason())
	} else {
		stage, err := decodeWindowsSMBJSON(serverOut)
		if err != nil {
			serverFailure = decodeWindowsSMBStageFailure(windowsSMBStageServerConfiguration, "Get-SmbServerConfiguration", serverElapsed, err)
			result.Degraded = append(result.Degraded, serverFailure.reason())
		} else {
			raw.Server = stage.Server
			serverOK = true
			result.Detected = true
		}
	}

	registryOut, registryElapsed, registryFailure := runWindowsSMBStage(ctx, ps, windowsSMBStageRegistryPolicy, "SMB registry policy", windowsSMBRegistryPolicyScript, nil)
	if registryFailure != nil {
		result.Degraded = append(result.Degraded, registryFailure.reason())
	} else {
		stage, err := decodeWindowsSMBJSON(registryOut)
		if err != nil {
			registryFailure = decodeWindowsSMBStageFailure(windowsSMBStageRegistryPolicy, "SMB registry policy", registryElapsed, err)
			result.Degraded = append(result.Degraded, registryFailure.reason())
		} else {
			mergeWindowsSMBRegistryPolicy(&raw.Server, stage.Server)
			registryOK = true
		}
	}

	sharesOut, sharesElapsed, sharesFailure := runWindowsSMBStage(ctx, ps, windowsSMBStageShareInventory, "Get-SmbShare", windowsSMBShareInventoryScript, nil)
	if sharesFailure != nil {
		result.ShareInventoryReason = sharesFailure.reason()
		result.Degraded = append(result.Degraded, result.ShareInventoryReason)
	} else {
		stage, err := decodeWindowsSMBJSON(sharesOut)
		if err != nil {
			sharesFailure = decodeWindowsSMBStageFailure(windowsSMBStageShareInventory, "Get-SmbShare", sharesElapsed, err)
			result.ShareInventoryReason = sharesFailure.reason()
			result.Degraded = append(result.Degraded, result.ShareInventoryReason)
		} else {
			raw.Shares = append(raw.Shares, stage.Shares...)
			raw.ShareDecodeErrors = append(raw.ShareDecodeErrors, stage.ShareDecodeErrors...)
			result.ShareInventoryState = evidence.StateObserved
			result.ShareInventorySource = "Get-SmbShare (SHARE_INVENTORY stage)"
			result.Detected = true
		}
	}

	// SHARE_ACCESS is deliberately downstream of successful share inventory.
	// Failure here only marks ACL knowledge unavailable; it never destroys the
	// shares returned by SHARE_INVENTORY.
	if sharesFailure == nil && len(raw.Shares) > 0 {
		names := make([]string, 0, len(raw.Shares))
		for _, share := range raw.Shares {
			if name := strings.TrimSpace(share.Name); name != "" {
				names = append(names, name)
			}
		}
		input, _ := json.Marshal(struct {
			Names []string `json:"Names"`
		}{Names: names})
		accessOut, accessElapsed, accessFailure := runWindowsSMBStage(ctx, ps, windowsSMBStageShareAccess, "Get-SmbShareAccess", windowsSMBShareAccessScript, []string{"CHIMERA_SMB_SHARE_ACCESS_JSON=" + string(input)})
		if accessFailure != nil {
			result.Degraded = append(result.Degraded, accessFailure.reason())
			for _, name := range names {
				raw.AccessErrors = append(raw.AccessErrors, name)
			}
		} else {
			stage, err := decodeWindowsSMBJSON(accessOut)
			if err != nil {
				accessFailure = decodeWindowsSMBStageFailure(windowsSMBStageShareAccess, "Get-SmbShareAccess", accessElapsed, err)
				result.Degraded = append(result.Degraded, accessFailure.reason())
				for _, name := range names {
					raw.AccessErrors = append(raw.AccessErrors, name)
				}
			} else {
				raw.Access = append(raw.Access, stage.Access...)
				raw.AccessErrors = append(raw.AccessErrors, stage.AccessErrors...)
				raw.AccessFailures = append(raw.AccessFailures, stage.AccessFailures...)
				raw.AccessDecodeErrors = append(raw.AccessDecodeErrors, stage.AccessDecodeErrors...)
			}
		}
	}

	serverReason := ""
	if serverFailure != nil {
		serverReason = serverFailure.reason()
	}
	registryReason := ""
	if registryFailure != nil {
		registryReason = registryFailure.reason()
	}
	result.Settings = windowsSMBSettings(raw, serverReason, registryReason, serverOK, registryOK)
	result.Shares = windowsSMBShares(raw)
	result.EvaluationSource = "SERVER_CONFIGURATION:Get-SmbServerConfiguration; SHARE_INVENTORY:Get-SmbShare; SHARE_ACCESS:Get-SmbShareAccess; REGISTRY_POLICY:registry"

	if len(raw.ShareDecodeErrors) > 0 && result.ShareInventoryState == evidence.StateObserved {
		result.ShareInventoryState = evidence.StateDegraded
		result.ShareInventoryReason = fmt.Sprintf("%d malformed Windows SMB share record(s) were skipped", len(raw.ShareDecodeErrors))
		result.Degraded = append(result.Degraded, result.ShareInventoryReason+": "+strings.Join(raw.ShareDecodeErrors, "; "))
	}
	if len(raw.AccessDecodeErrors) > 0 {
		result.Degraded = append(result.Degraded, fmt.Sprintf("%d malformed Windows SMB access record(s) were skipped: %s", len(raw.AccessDecodeErrors), strings.Join(raw.AccessDecodeErrors, "; ")))
	}
	if len(raw.AccessErrors) > 0 {
		result.Degraded = append(result.Degraded, fmt.Sprintf("share-level access metadata unavailable for %d Windows SMB share(s)", len(uniqueSMBStrings(raw.AccessErrors))))
	}
	return result
}

func findWindowsSMBPowerShell() string {
	for _, name := range []string{"powershell.exe", "pwsh.exe", "powershell", "pwsh"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func runWindowsSMBStage(ctx context.Context, ps, stage, command, script string, extraEnv []string) ([]byte, time.Duration, *windowsSMBStageFailure) {
	started := time.Now()
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	elapsed := time.Since(started)
	if err == nil {
		return stdout.Bytes(), elapsed, nil
	}

	failure := &windowsSMBStageFailure{
		Stage:    stage,
		Command:  command,
		Class:    "PROVIDER_FAILURE",
		Message:  err.Error(),
		Stderr:   boundedSMBText(stderr.String(), 1200),
		ExitCode: -1,
		Elapsed:  elapsed,
	}
	if ctx.Err() != nil {
		failure.Class = "DEADLINE"
		failure.Message = ctx.Err().Error()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		failure.ExitCode = exitErr.ExitCode()
	}
	if diag, ok := parseWindowsSMBStageDiagnostic(stderr.Bytes()); ok {
		if v := strings.TrimSpace(diag.Stage); v != "" {
			failure.Stage = v
		}
		if v := strings.TrimSpace(diag.Command); v != "" {
			failure.Command = v
		}
		if v := strings.TrimSpace(diag.Class); v != "" {
			failure.Class = v
		}
		failure.ExceptionType = strings.TrimSpace(diag.ExceptionType)
		if v := strings.TrimSpace(diag.Message); v != "" {
			failure.Message = v
		}
	}
	return nil, elapsed, failure
}

func parseWindowsSMBStageDiagnostic(stderr []byte) (windowsSMBStageDiagnostic, bool) {
	lines := strings.Split(strings.ReplaceAll(string(stderr), "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var d windowsSMBStageDiagnostic
		if err := json.Unmarshal([]byte(line), &d); err == nil && strings.TrimSpace(d.Stage) != "" {
			return d, true
		}
	}
	return windowsSMBStageDiagnostic{}, false
}

func decodeWindowsSMBStageFailure(stage, command string, elapsed time.Duration, err error) *windowsSMBStageFailure {
	return &windowsSMBStageFailure{
		Stage:    stage,
		Command:  command,
		Class:    "PROVIDER_DECODE",
		Message:  "invalid stage JSON: " + err.Error(),
		ExitCode: 0,
		Elapsed:  elapsed,
	}
}

func boundedSMBText(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if max > 0 && len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func mergeWindowsSMBRegistryPolicy(dst *windowsSMBServerJSON, src windowsSMBServerJSON) {
	if dst == nil {
		return
	}
	dst.AllowInsecureGuestAuth = src.AllowInsecureGuestAuth
	dst.RestrictNullSessAccess = src.RestrictNullSessAccess
	dst.NullSessionShares = append([]string(nil), src.NullSessionShares...)
}

func windowsSMBSettings(raw windowsSMBJSON, serverReason, registryReason string, serverOK, registryOK bool) []SMBSetting {
	serverSource := "Get-SmbServerConfiguration (SERVER_CONFIGURATION stage)"
	registryGuestSource := `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth`
	registryNullSource := `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RestrictNullSessAccess`
	registrySharesSource := `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionShares`
	out := []SMBSetting{}
	add := func(name string, v *bool, source, stageReason string, stageOK bool) {
		if !stageOK {
			reason := strings.TrimSpace(stageReason)
			if reason == "" {
				reason = "provider stage did not complete"
			}
			out = append(out, SMBSetting{Name: name, Scope: "server", State: evidence.StateUnavailable, Source: source, Confidence: evidence.ConfidenceLow, Reason: reason})
			return
		}
		if v == nil {
			out = append(out, SMBSetting{Name: name, Scope: "server", State: evidence.StateUnavailable, Source: source, Confidence: evidence.ConfidenceLow, Reason: "setting was not exposed by the local provider"})
			return
		}
		value := "false"
		if *v {
			value = "true"
		}
		out = append(out, SMBSetting{Name: name, Scope: "server", State: evidence.StateObserved, Value: value, Source: source, Confidence: evidence.ConfidenceExact, Explicit: true})
	}
	add("smb1_enabled", raw.Server.EnableSMB1Protocol, serverSource, serverReason, serverOK)
	add("smb2_enabled", raw.Server.EnableSMB2Protocol, serverSource, serverReason, serverOK)
	add("signing_enabled", raw.Server.EnableSecuritySignature, serverSource, serverReason, serverOK)
	add("signing_required", raw.Server.RequireSecuritySignature, serverSource, serverReason, serverOK)
	add("encryption_default", raw.Server.EncryptData, serverSource, serverReason, serverOK)
	add("reject_unencrypted_access", raw.Server.RejectUnencryptedAccess, serverSource, serverReason, serverOK)
	add("allow_insecure_guest_auth", raw.Server.AllowInsecureGuestAuth, registryGuestSource, registryReason, registryOK)
	add("restrict_null_session_access", raw.Server.RestrictNullSessAccess, registryNullSource, registryReason, registryOK)
	if !registryOK {
		reason := strings.TrimSpace(registryReason)
		if reason == "" {
			reason = "provider stage did not complete"
		}
		out = append(out, SMBSetting{Name: "null_session_shares", Scope: "server", State: evidence.StateUnavailable, Source: registrySharesSource, Confidence: evidence.ConfidenceLow, Reason: reason})
	} else if len(raw.Server.NullSessionShares) > 0 {
		out = append(out, SMBSetting{Name: "null_session_shares", Scope: "server", State: evidence.StateObserved, Value: fmt.Sprintf("%d", len(raw.Server.NullSessionShares)), Source: registrySharesSource, Confidence: evidence.ConfidenceExact, Explicit: true})
	} else {
		out = append(out, SMBSetting{Name: "null_session_shares", Scope: "server", State: evidence.StateObserved, Value: "0", Source: registrySharesSource, Confidence: evidence.ConfidenceHigh})
	}
	return out
}

func unavailableSMBSettingsWindows(reason string) []SMBSetting {
	return windowsSMBSettings(windowsSMBJSON{}, reason, reason, false, false)
}

func windowsSMBShares(raw windowsSMBJSON) []SMBShare {
	accessErrors := map[string]bool{}
	for _, name := range raw.AccessErrors {
		accessErrors[strings.ToLower(strings.TrimSpace(name))] = true
	}
	accessFailureReason := map[string]string{}
	for _, failure := range raw.AccessFailures {
		key := strings.ToLower(strings.TrimSpace(failure.Name))
		if key == "" {
			continue
		}
		reason := "SHARE_ACCESS"
		if v := strings.TrimSpace(failure.ExceptionType); v != "" {
			reason += " exception=" + v
		}
		if v := strings.TrimSpace(failure.Message); v != "" {
			reason += " message=" + boundedSMBText(v, 300)
		}
		accessFailureReason[key] = reason
	}
	grants := map[string][]SMBShareGrant{}
	broadRead := map[string]bool{}
	broadWrite := map[string]bool{}
	for _, a := range raw.Access {
		if !strings.EqualFold(strings.TrimSpace(a.AccessControlType), "Allow") {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(a.Name))
		g := SMBShareGrant{Principal: strings.TrimSpace(a.AccountName), Access: strings.TrimSpace(a.AccessRight), Type: strings.TrimSpace(a.AccessControlType)}
		grants[name] = append(grants[name], g)
		if windowsBroadPrincipal(g.Principal) {
			broadRead[name] = true
			if strings.EqualFold(g.Access, "Full") || strings.EqualFold(g.Access, "Change") {
				broadWrite[name] = true
			}
		}
	}
	out := make([]SMBShare, 0, len(raw.Shares))
	for _, s := range raw.Shares {
		name := strings.TrimSpace(s.Name)
		key := strings.ToLower(name)
		hidden := strings.HasSuffix(name, "$")
		sensitive := smbSensitivePath(s.Path)
		tags := []string{}
		if broadWrite[key] {
			tags = append(tags, "broad-write")
		}
		if sensitive && !s.Special {
			tags = append(tags, "sensitive-path")
		}
		sh := SMBShare{
			Name: name, Path: strings.TrimSpace(s.Path), State: evidence.StateObserved,
			Special: s.Special, Hidden: hidden, WritableKnown: true, Writable: true,
			EncryptionRequired: s.EncryptData, BroadRead: broadRead[key], BroadWrite: broadWrite[key], AccessKnown: !accessErrors[key],
			SensitivePath: sensitive, Grants: grants[key], RiskTags: tags,
			Source: "Get-SmbShare (SHARE_INVENTORY) / Get-SmbShareAccess (SHARE_ACCESS)", Confidence: evidence.ConfidenceHigh,
		}
		if !sh.AccessKnown {
			if reason := strings.TrimSpace(accessFailureReason[key]); reason != "" {
				sh.Reason = reason
			} else {
				sh.Reason = "SHARE_ACCESS metadata unavailable"
			}
		}
		sh.ID = smbShareID(sh.Name, sh.Path)
		out = append(out, sh)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func uniqueSMBStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, strings.TrimSpace(item))
	}
	return out
}

func windowsBroadPrincipal(principal string) bool {
	p := strings.ToLower(strings.TrimSpace(principal))
	return p == "everyone" || strings.HasSuffix(p, `\everyone`) || p == "authenticated users" || strings.HasSuffix(p, `\authenticated users`) || p == "users" || strings.HasSuffix(p, `\users`) || strings.Contains(p, "anonymous logon") || strings.Contains(p, "guests")
}

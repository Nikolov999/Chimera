//go:build windows

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

type windowsServiceRecord struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	State       string `json:"state"`
	StartMode   string `json:"start_mode"`
	ProcessID   int    `json:"process_id"`
	StartName   string `json:"start_name"`
	PathName    string `json:"path_name"`
	ServiceType string `json:"service_type"`
}

type windowsServiceSecurityEnvelope struct {
	Name     string                `json:"name"`
	Security windowsSecurityRecord `json:"security"`
}

// Keep SCM inventory independent from security enrichment. A failure in ACL,
// registry, service-object, or account inspection must never erase the base
// Win32_Service inventory.
const windowsServiceInventoryScript = `$ErrorActionPreference='Stop'
try { $rows=@(Get-CimInstance Win32_Service -ErrorAction Stop) }
catch { Write-Error ('[chimera-stage:windows-scm-enumeration] ' + $_.Exception.Message); exit 20 }
$o=@($rows | ForEach-Object {
    [pscustomobject]@{
        name=[string]$_.Name
        display_name=[string]$_.DisplayName
        description=[string]$_.Description
        state=[string]$_.State
        start_mode=[string]$_.StartMode
        process_id=[int]$_.ProcessId
        start_name=[string]$_.StartName
        path_name=[string]$_.PathName
        service_type=[string]$_.ServiceType
    }
})
ConvertTo-Json -InputObject @($o) -Depth 4 -Compress`

// The enrichment provider is read-only. Each security dimension is isolated
// so one inaccessible service/key/path produces a record-level state rather
// than aborting the entire service inventory.
const windowsServiceSecurityScriptTemplate = `$ErrorActionPreference='Stop'
$script:fileMutatingMask=__CHIMERA_FILE_MUTATING_MASK__
$script:registryMutatingMask=__CHIMERA_REGISTRY_MUTATING_MASK__
$script:aclCache=@{}
$script:adminMemberSids=@{}
$script:adminMemberNames=@{}
$script:adminLookupState='UNAVAILABLE'
$script:adminLookupReason='local Administrators membership provider unavailable'

function New-AclResult([string]$state,[bool]$broad,[object[]]$principals,[object[]]$rights,[string]$reason,[string]$ownerSid,[bool]$inheritedWrite) {
    return [pscustomobject]@{state=$state;broad_write_granted=$broad;principals=@($principals);rights=@($rights);reason=$reason;owner_sid=$ownerSid;inherited_write=$inheritedWrite}
}
function Failure-State($ex) {
    if ($null -ne $ex -and ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException] -or ([string]$ex.Message) -match '(?i)access.*denied|unauthorized|registry access is not allowed|requested registry access')) { return 'DENIED' }
    return 'UNAVAILABLE'
}
function Expand-ServicePath([string]$p) {
    $v=([string]$p).Trim().Trim('"')
    if(-not $v){return ''}
    if($v.StartsWith('\SystemRoot\',[System.StringComparison]::OrdinalIgnoreCase)){$v=(Join-Path $env:SystemRoot $v.Substring(12))}
    return [Environment]::ExpandEnvironmentVariables($v)
}
function Get-ServiceExecutable([string]$command) {
    $v=([string]$command).Trim(); if(-not $v){return ''}
    if($v.StartsWith('"')){$end=$v.IndexOf('"',1);if($end -gt 1){return (Expand-ServicePath $v.Substring(1,$end-1))}}
    $m=[regex]::Match($v,'^(.*?\.(?:exe|com|bat|cmd|sys))(?:\s|$)',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if($m.Success){return (Expand-ServicePath $m.Groups[1].Value)}
    $first=($v -split '\s+',2)[0]; return (Expand-ServicePath $first)
}
function Resolve-Sid([string]$account) {
    $a=([string]$account).Trim(); if(-not $a){return ''}
    try { return (([System.Security.Principal.NTAccount]::new($a)).Translate([System.Security.Principal.SecurityIdentifier]).Value) } catch { return '' }
}
function Normalize-Account([string]$account) {
    $a=([string]$account).Trim(); if($a.StartsWith('.\')){$a=$env:COMPUTERNAME+'\'+$a.Substring(2)}; return $a.ToLowerInvariant()
}
function Get-PathAclSummary([string]$path) {
    $p=Expand-ServicePath $path
    if(-not $p){return (New-AclResult 'NOT_APPLICABLE' $false @() @() '' '' $false)}
    $key='file|'+$p.ToLowerInvariant(); if($script:aclCache.ContainsKey($key)){return $script:aclCache[$key]}
    if(-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)){$r=New-AclResult 'UNAVAILABLE' $false @() @() 'path not found or not accessible' '' $false;$script:aclCache[$key]=$r;return $r}
    try {
        $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
        $principals=New-Object System.Collections.Generic.List[string];$rightsFound=New-Object System.Collections.Generic.List[string]
        $broad=$false;$inherited=$false;$ownerSid=''
        try{$ownerSid=Resolve-Sid ([string]$acl.Owner)}catch{}
        foreach($ace in @($acl.Access)){
            if([string]$ace.AccessControlType -ne 'Allow'){continue}
            $sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=[string]$ace.IdentityReference}
            if($sid -notin @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-7','S-1-5-4')){continue}
            $bits=[int64]$ace.FileSystemRights
            if(($bits -band $script:fileMutatingMask) -ne 0){
                $rights=[string]$ace.FileSystemRights
                $broad=$true;if([bool]$ace.IsInherited){$inherited=$true};if(-not $principals.Contains($sid)){$principals.Add($sid)};if(-not $rightsFound.Contains($rights)){$rightsFound.Add($rights)}
            }
        }
        $r=New-AclResult 'OBSERVED' $broad @($principals) @($rightsFound) '' $ownerSid $inherited;$script:aclCache[$key]=$r;return $r
    } catch {$state=Failure-State $_.Exception;$r=New-AclResult $state $false @() @() $_.Exception.Message '' $false;$script:aclCache[$key]=$r;return $r}
}
function Get-DirectoryAclSummary([string]$path) {
    $p=Expand-ServicePath $path;if(-not $p){return (New-AclResult 'NOT_APPLICABLE' $false @() @() '' '' $false)}
    try{$d=[System.IO.Path]::GetDirectoryName($p)}catch{$d=''};if(-not $d){return (New-AclResult 'UNAVAILABLE' $false @() @() 'parent directory could not be resolved' '' $false)}
    return (Get-PathAclSummary $d)
}
function New-RegistryAclFailure([string]$state,[string]$stage,[string]$reason,[string]$acquisitionMethod='') {
    $normalizedStage=([string]$stage).Trim().ToUpperInvariant()
    if(-not $normalizedStage){$normalizedStage='NORMALIZATION'}
    $message='stage='+$normalizedStage
    if(-not [string]::IsNullOrWhiteSpace($reason)){$message+='; '+$reason}
    $r=New-AclResult $state $false @() @() $message '' $false
    $r | Add-Member -NotePropertyName entries -NotePropertyValue @() -Force
    $r | Add-Member -NotePropertyName stage -NotePropertyValue $normalizedStage -Force
    $r | Add-Member -NotePropertyName acquisition_method -NotePropertyValue ([string]$acquisitionMethod) -Force
    return $r
}
function Add-RegistryAclMetadata($result,[string]$stage,[string]$acquisitionMethod) {
    if($null -eq $result){return $result}
    $result | Add-Member -NotePropertyName stage -NotePropertyValue (([string]$stage).Trim().ToUpperInvariant()) -Force
    $result | Add-Member -NotePropertyName acquisition_method -NotePropertyValue ([string]$acquisitionMethod) -Force
    return $result
}

# Windows PowerShell 5.1 runs on .NET Framework, where RegistryKey ACL method
# exposure differs from PowerShell 7/.NET. Keep the managed RegistryKey path as
# the preferred path, but compile one read-only advapi32 fallback so a missing
# GetAccessControl surface cannot collapse ACL coverage for every service.
$script:registryNativeAvailable=$false
$script:registryNativeReason=''
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ChimeraRegistrySecurityNative {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegGetKeySecurity(
        IntPtr hKey,
        UInt32 securityInformation,
        byte[] securityDescriptor,
        ref UInt32 securityDescriptorLength);
}
'@ -ErrorAction Stop
    $script:registryNativeAvailable=$true
} catch {
    $script:registryNativeReason=[string]$_.Exception.Message
}
function Get-RegistrySecurityDescriptorNative($registryKey) {
    if(-not $script:registryNativeAvailable){throw ('native RegGetKeySecurity fallback unavailable: '+$script:registryNativeReason)}
    $handle=[IntPtr]::Zero
    try {
        $safeProperty=$registryKey.PSObject.Properties['SafeRegistryHandle']
        if($null -ne $safeProperty -and $null -ne $registryKey.SafeRegistryHandle){
            $handle=$registryKey.SafeRegistryHandle.DangerousGetHandle()
        } else {
            $handle=[IntPtr]$registryKey.Handle
        }
    } catch {throw ('could not obtain native registry handle: '+[string]$_.Exception.Message)}
    if($handle -eq [IntPtr]::Zero){throw 'registry handle was zero'}

    # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION. We intentionally
    # do not request SACL data because Chimera is read-only and does not require
    # SeSecurityPrivilege for service configuration-integrity assessment.
    [uint32]$securityInformation=0x00000005
    [uint32]$required=0
    [byte[]]$probe=$null
    $rc=[ChimeraRegistrySecurityNative]::RegGetKeySecurity($handle,$securityInformation,$probe,[ref]$required)
    if($rc -ne 0 -and $rc -ne 122){throw ('RegGetKeySecurity size probe failed with Win32 error '+[string]$rc)}
    if($required -le 0){throw 'RegGetKeySecurity returned an empty security descriptor size'}
    [byte[]]$buffer=New-Object byte[] ([int]$required)
    $rc=[ChimeraRegistrySecurityNative]::RegGetKeySecurity($handle,$securityInformation,$buffer,[ref]$required)
    if($rc -ne 0){throw ('RegGetKeySecurity descriptor read failed with Win32 error '+[string]$rc)}
    try {
        $security=New-Object System.Security.AccessControl.RegistrySecurity
        $security.SetSecurityDescriptorBinaryForm($buffer)
        return $security
    } catch {throw ('could not materialize RegistrySecurity from native descriptor: '+[string]$_.Exception.Message)}
}
function Get-RegistrySecurityDescriptor($registryKey) {
    $sections=[System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
    # Windows PowerShell 5.1 can throw "Argument types do not match" when
    # generic List<T> instances are coerced through array-expression / binder
    # paths. Keep compatibility diagnostics in a native PowerShell array.
    $managedFailures=@()

    # Preferred .NET Framework path. Try both overload shapes because the method
    # surface exposed by Windows PowerShell 5.1 varies by installed framework.
    try {
        $acl=$registryKey.GetAccessControl($sections)
        if($null -ne $acl){return [pscustomobject]@{descriptor=$acl;acquisition_method='REGISTRYKEY_GETACCESSCONTROL';fallback_reason=''}}
        $managedFailures += 'GetAccessControl(sections) returned null'
    } catch {$managedFailures += ('GetAccessControl(sections): '+[string]$_.Exception.Message)}
    try {
        $acl=$registryKey.GetAccessControl()
        if($null -ne $acl){return [pscustomobject]@{descriptor=$acl;acquisition_method='REGISTRYKEY_GETACCESSCONTROL';fallback_reason=''}}
        $managedFailures += 'GetAccessControl() returned null'
    } catch {$managedFailures += ('GetAccessControl(): '+[string]$_.Exception.Message)}

    # Compatibility fallback for Windows PowerShell 5.1/.NET Framework hosts
    # where RegistryKey does not expose a callable ACL method to PowerShell.
    try {
        $acl=Get-RegistrySecurityDescriptorNative $registryKey
        $fallbackReason=if($managedFailures.Count -gt 0){[string]::Join(' | ',@($managedFailures))}else{''}
        return [pscustomobject]@{descriptor=$acl;acquisition_method='NATIVE_REGGETKEYSECURITY';fallback_reason=$fallbackReason}
    } catch {
        $managed=if($managedFailures.Count -gt 0){[string]::Join(' | ',@($managedFailures))}else{'managed ACL API unavailable'}
        throw ('managed registry ACL acquisition failed: '+$managed+'; native fallback failed: '+[string]$_.Exception.Message)
    }
}
function Get-ServiceRegistryAclSummary([string]$serviceName) {
    $name=([string]$serviceName).Trim()
    if(-not $name){return (New-RegistryAclFailure 'UNAVAILABLE' 'NORMALIZATION' 'service name is empty')}
    if($name -match '[\\\x00-\x1F]'){return (New-RegistryAclFailure 'UNAVAILABLE' 'NORMALIZATION' 'service name contains unsupported registry subkey characters')}
    $subKey='SYSTEM\CurrentControlSet\Services\'+$name
    $cacheKey='reg|hklm|'+$subKey.ToLowerInvariant()
    if($script:aclCache.ContainsKey($cacheKey)){return $script:aclCache[$cacheKey]}
    $baseKey=$null;$registryKey=$null;$acquisitionMethod=''
    try {
        try {
            $view=if([Environment]::Is64BitOperatingSystem){[Microsoft.Win32.RegistryView]::Registry64}else{[Microsoft.Win32.RegistryView]::Default}
            $baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        } catch {
            $r=New-RegistryAclFailure (Failure-State $_.Exception) 'OPEN_HIVE' $_.Exception.Message;$script:aclCache[$cacheKey]=$r;return $r
        }
        if($null -eq $baseKey){$r=New-RegistryAclFailure 'UNAVAILABLE' 'OPEN_HIVE' 'OpenBaseKey returned null';$script:aclCache[$cacheKey]=$r;return $r}

        # Prefer an explicit READ_CONTROL-capable RegistryRights open. If the
        # three-argument overload is not exposed by this .NET Framework build,
        # fall back to the read-only overload before declaring the key unusable.
        $primaryOpenReason=''
        try {
            $readRights=[System.Security.AccessControl.RegistryRights]::ReadKey
            $registryKey=$baseKey.OpenSubKey($subKey,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,$readRights)
        } catch {$primaryOpenReason=[string]$_.Exception.Message}
        if($null -eq $registryKey){
            try {$registryKey=$baseKey.OpenSubKey($subKey,$false)}
            catch {
                $detail=[string]$_.Exception.Message
                if($primaryOpenReason){$detail='explicit-rights open failed: '+$primaryOpenReason+'; read-only fallback failed: '+$detail}
                $r=New-RegistryAclFailure (Failure-State $_.Exception) 'OPEN_SUBKEY' $detail;$script:aclCache[$cacheKey]=$r;return $r
            }
        }
        if($null -eq $registryKey){
            $detail='service registry key was not found in HKLM: '+$subKey
            if($primaryOpenReason){$detail+='; explicit-rights open: '+$primaryOpenReason}
            $r=New-RegistryAclFailure 'UNAVAILABLE' 'OPEN_SUBKEY' $detail;$script:aclCache[$cacheKey]=$r;return $r
        }

        try {
            $descriptorResult=Get-RegistrySecurityDescriptor $registryKey
            $acl=$descriptorResult.descriptor
            $acquisitionMethod=[string]$descriptorResult.acquisition_method
        } catch {
            $r=New-RegistryAclFailure (Failure-State $_.Exception) 'READ_SECURITY_DESCRIPTOR' $_.Exception.Message $acquisitionMethod;$script:aclCache[$cacheKey]=$r;return $r
        }
        if($null -eq $acl){$r=New-RegistryAclFailure 'UNAVAILABLE' 'READ_SECURITY_DESCRIPTOR' 'registry security descriptor was null' $acquisitionMethod;$script:aclCache[$cacheKey]=$r;return $r}

        $ownerSid=''
        # Fix49: use plain PowerShell arrays throughout registry ACL
        # normalization. Windows PowerShell 5.1's binder can raise the generic
        # "Argument types do not match" exception when Generic.List<T> values
        # are embedded in PSCustomObject/NoteProperty array fields. That was
        # observed for every service on the live Windows 11 host.
        $normalizationErrors=@()
        try{$ownerSid=[string]$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value}
        catch{$normalizationErrors += ('stage=NORMALIZATION; owner SID: '+[string]$_.Exception.Message)}
        $entries=@()
        $principals=@()
        $rightsFound=@()
        $broad=$false;$inheritedWrite=$false
        try {$rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))}
        catch {$r=New-RegistryAclFailure (Failure-State $_.Exception) 'GET_ACCESS_RULES' $_.Exception.Message $acquisitionMethod;$script:aclCache[$cacheKey]=$r;return $r}
        foreach($ace in $rules){
            try {
                $sid='';$principal='';$translationState='OBSERVED';$translationReason=''
                try{$sid=[string]$ace.IdentityReference.Value}catch{$sid=[string]$ace.IdentityReference}
                if([string]::IsNullOrWhiteSpace($sid)){throw 'ACL entry has no SID identity'}
                try{$principal=[string]$ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value}
                catch{$translationState='UNAVAILABLE';$translationReason='stage=SID_TRANSLATION; '+[string]$_.Exception.Message}
                $accessType=[string]$ace.AccessControlType
                $bits=[int64]$ace.RegistryRights
                $atomic=@()
                foreach($definition in @(
                    [pscustomobject]@{name='SetValue';mask=[int64][System.Security.AccessControl.RegistryRights]::SetValue},
                    [pscustomobject]@{name='CreateSubKey';mask=[int64][System.Security.AccessControl.RegistryRights]::CreateSubKey},
                    [pscustomobject]@{name='CreateLink';mask=[int64][System.Security.AccessControl.RegistryRights]::CreateLink},
                    [pscustomobject]@{name='Delete';mask=[int64][System.Security.AccessControl.RegistryRights]::Delete},
                    [pscustomobject]@{name='ChangePermissions';mask=[int64][System.Security.AccessControl.RegistryRights]::ChangePermissions},
                    [pscustomobject]@{name='TakeOwnership';mask=[int64][System.Security.AccessControl.RegistryRights]::TakeOwnership}
                )){
                    if(($bits -band [int64]$definition.mask) -ne 0){$atomic += [string]$definition.name}
                }
                $entries += [pscustomobject]@{
                    sid=$sid
                    principal=$principal
                    principal_resolution=$translationState
                    principal_resolution_reason=$translationReason
                    access_type=$accessType
                    inherited=[bool]$ace.IsInherited
                    explicit=(-not [bool]$ace.IsInherited)
                    inheritance_flags=[string]$ace.InheritanceFlags
                    propagation_flags=[string]$ace.PropagationFlags
                    rights=[string]$ace.RegistryRights
                    rights_mask=$bits
                    atomic_mutating_rights=@($atomic)
                }
                if($accessType -ne 'Allow'){continue}
                if($sid -notin @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-7','S-1-5-4')){continue}
                if(($bits -band $script:registryMutatingMask) -eq 0){continue}
                $broad=$true
                if([bool]$ace.IsInherited){$inheritedWrite=$true}
                if($principals -notcontains $sid){$principals += $sid}
                foreach($right in @($atomic)){if($rightsFound -notcontains $right){$rightsFound += $right}}
            } catch {
                # Fix36 legacy stage=normalize_rule is now the canonical
                # Fix47 NORMALIZATION stage while preserving per-entry isolation.
                $normalizationErrors += ('stage=NORMALIZATION; '+[string]$_.Exception.Message)
            }
        }
        $state='OBSERVED';$reason=''
        if($normalizationErrors.Count -gt 0){
            $state='DEGRADED'
            $reason='registry ACL partially normalized; failed_components='+[string]$normalizationErrors.Count+'; '+[string]$normalizationErrors[0]
        }
        $r=New-AclResult $state $broad @($principals) @($rightsFound) $reason $ownerSid $inheritedWrite
        $r | Add-Member -NotePropertyName entries -NotePropertyValue @($entries) -Force
        $r=Add-RegistryAclMetadata $r 'OBSERVED' $acquisitionMethod
        $script:aclCache[$cacheKey]=$r
        return $r
    } catch {
        $r=New-RegistryAclFailure (Failure-State $_.Exception) 'NORMALIZATION' $_.Exception.Message $acquisitionMethod;$script:aclCache[$cacheKey]=$r;return $r
    } finally {
        if($null -ne $registryKey){try{$registryKey.Dispose()}catch{}}
        if($null -ne $baseKey){try{$baseKey.Dispose()}catch{}}
    }
}
function Test-UnquotedExecutable([string]$command,[string]$exe){$v=([string]$command).Trim();if(-not $v -or -not $exe -or $v.StartsWith('"')){return $false};return $exe.Contains(' ')}
function Get-ServiceObjectSDDL([string]$name,[string]$sc) {
    if(-not (Test-Path -LiteralPath $sc -ErrorAction SilentlyContinue)){return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason='sc.exe unavailable for service object ACL inspection'}}
    if(([string]$name) -match '["\r\n]'){return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason='service name contains unsupported characters for bounded sc.exe inspection'}}
    $proc=$null
    try {
        $psi=New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName=$sc
        $psi.Arguments='sdshow "'+$name+'"'
        $psi.UseShellExecute=$false
        $psi.CreateNoWindow=$true
        $psi.RedirectStandardOutput=$true
        $psi.RedirectStandardError=$true
        $proc=New-Object System.Diagnostics.Process
        $proc.StartInfo=$psi
        if(-not $proc.Start()){return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason='sc.exe sdshow failed to start'}}
        if(-not $proc.WaitForExit(2000)){
            try{$proc.Kill()}catch{}
            return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason='sc.exe sdshow exceeded 2 second per-service budget'}
        }
        $stdout=$proc.StandardOutput.ReadToEnd();$stderr=$proc.StandardError.ReadToEnd();$code=$proc.ExitCode
        if($code -ne 0){$detail=([string]$stderr).Trim();if(-not $detail){$detail='no stderr detail'};return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason=('sc.exe sdshow exit '+$code+': '+$detail)}}
        foreach($line in @([System.Text.RegularExpressions.Regex]::Split($stdout,'\r?\n'))){$candidate=([string]$line).Trim();if($candidate -match '^(O:|G:|D:|S:)'){return [pscustomobject]@{state='OBSERVED';sddl=$candidate;reason=''}}}
        return [pscustomobject]@{state='UNAVAILABLE';sddl='';reason='service object security descriptor missing from sc.exe output'}
    } catch {return [pscustomobject]@{state=(Failure-State $_.Exception);sddl='';reason=$_.Exception.Message}}
    finally {if($null -ne $proc){$proc.Dispose()}}
}
function Get-AccountAdminState([string]$account) {
    $n=Normalize-Account $account
    if($n -in @('localsystem','system','nt authority\system','localservice','nt authority\localservice','networkservice','nt authority\networkservice')){return [pscustomobject]@{state='NO';reason='built-in service identity'}}
    if($script:adminLookupState -ne 'OBSERVED'){return [pscustomobject]@{state='UNKNOWN';reason=$script:adminLookupReason}}
    $sid=Resolve-Sid $account
    if($sid -and $script:adminMemberSids.ContainsKey($sid)){return [pscustomobject]@{state='YES';reason='account SID is a direct local Administrators member'}}
    if($script:adminMemberNames.ContainsKey($n)){return [pscustomobject]@{state='YES';reason='account name is a direct local Administrators member'}}
    return [pscustomobject]@{state='NO';reason='not a direct local Administrators member'}
}

try {
    if(Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){
        foreach($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)){
            $sid=[string]$m.SID;if($sid){$script:adminMemberSids[$sid]=$true};$n=Normalize-Account ([string]$m.Name);if($n){$script:adminMemberNames[$n]=$true}
        }
        $script:adminLookupState='OBSERVED';$script:adminLookupReason=''
    }
} catch {$script:adminLookupState='UNAVAILABLE';$script:adminLookupReason=$_.Exception.Message}

try{$rows=@(Get-CimInstance Win32_Service -ErrorAction Stop)}catch{Write-Error ('[chimera-stage:windows-service-security-enumeration] '+$_.Exception.Message);exit 30}
$sc=Join-Path $env:SystemRoot 'System32\sc.exe'
$o=@()
foreach($svc in $rows){
    $name=[string]$svc.Name;$rawPath=[string]$svc.PathName;$exe=Get-ServiceExecutable $rawPath;$errors=New-Object System.Collections.Generic.List[string]
    try {
        $exeAcl=Get-PathAclSummary $exe;$exeDirAcl=Get-DirectoryAclSummary $exe
        $regPath='HKLM:\SYSTEM\CurrentControlSet\Services\'+$name
        $registryState='OBSERVED';$registryReason='';$failureCommand='';$failureCommandState='NOT_APPLICABLE';$failureCommandReason='';$serviceDll='';$serviceDllState='NOT_APPLICABLE';$serviceDllReason='';$typeValue=0
        try{
            $props=Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
            if($null -ne $props.FailureCommand -and -not [string]::IsNullOrWhiteSpace([string]$props.FailureCommand)){$failureCommand=[string]$props.FailureCommand;$failureCommandState='OBSERVED'}
            if($null -ne $props.Type){$typeValue=[int64]$props.Type}
        }
        catch{
            $registryState=Failure-State $_.Exception;$registryReason=$_.Exception.Message;$errors.Add('service registry metadata: '+$registryReason)
            $failureCommandState=$registryState;$failureCommandReason='recovery configuration unavailable because service registry metadata could not be read: '+$registryReason
        }
        $registryAcl=Get-ServiceRegistryAclSummary $name
        $paramsPath=$regPath+'\Parameters'
        try {
            if(Test-Path -LiteralPath $paramsPath -ErrorAction Stop){
                $params=Get-ItemProperty -LiteralPath $paramsPath -ErrorAction Stop
                if($null -ne $params.ServiceDll -and -not [string]::IsNullOrWhiteSpace([string]$params.ServiceDll)){
                    $serviceDll=Expand-ServicePath ([string]$params.ServiceDll)
                    if($serviceDll){$serviceDllState='OBSERVED'}else{$serviceDllState='UNAVAILABLE';$serviceDllReason='ServiceDll value exists but its path could not be resolved'}
                }
            }
        } catch {
            $serviceDllState=Failure-State $_.Exception;$serviceDllReason=$_.Exception.Message;$errors.Add('service parameters metadata: '+$serviceDllReason)
        }
        # Service-object SDDL is collected separately by the Go provider with
        # bounded concurrency. Keeping it out of this loop prevents hundreds of
        # sequential sc.exe invocations from starving registry/path/account ACLs.
        $sd=[pscustomobject]@{state='UNAVAILABLE';sddl='';reason='service object ACL collected by separate bounded provider'}
        $acct=Get-AccountAdminState ([string]$svc.StartName);if($acct.state -eq 'UNKNOWN'){$errors.Add('account classification: '+$acct.reason)}
        $failureExe=Get-ServiceExecutable $failureCommand;$failurePresent=-not [string]::IsNullOrWhiteSpace($failureCommand)
        $security=[pscustomobject]@{
            service_sddl=[string]$sd.sddl;service_acl_state=[string]$sd.state;service_acl_reason=[string]$sd.reason
            account_admin_state=[string]$acct.state;account_admin_reason=[string]$acct.reason
            registry_state=$registryState;registry_reason=$registryReason;registry_acl=$registryAcl
            interactive_process=(($typeValue -band 0x100) -ne 0)
            executable_acl=$exeAcl;executable_directory_acl=$exeDirAcl
            service_dll_path=$serviceDll;service_dll_state=$serviceDllState;service_dll_reason=$serviceDllReason;service_dll_acl=(Get-PathAclSummary $serviceDll);service_dll_directory_acl=(Get-DirectoryAclSummary $serviceDll)
            failure_command_present=$failurePresent;failure_command_state=$failureCommandState;failure_command_reason=$failureCommandReason;failure_executable_path=$failureExe;failure_executable_unquoted=(Test-UnquotedExecutable $failureCommand $failureExe)
            failure_executable_acl=(Get-PathAclSummary $failureExe);failure_executable_directory_acl=(Get-DirectoryAclSummary $failureExe)
            errors=@($errors)
        }
    } catch {
        $reason=$_.Exception.Message
        $na=New-AclResult 'UNAVAILABLE' $false @() @() $reason '' $false
        $security=[pscustomobject]@{service_sddl='';service_acl_state='UNAVAILABLE';service_acl_reason=$reason;account_admin_state='UNKNOWN';account_admin_reason=$reason;registry_state='UNAVAILABLE';registry_reason=$reason;registry_acl=$na;interactive_process=$false;executable_acl=$na;executable_directory_acl=$na;service_dll_path='';service_dll_state='UNAVAILABLE';service_dll_reason=$reason;service_dll_acl=$na;service_dll_directory_acl=$na;failure_command_present=$false;failure_command_state='UNAVAILABLE';failure_command_reason=$reason;failure_executable_path='';failure_executable_unquoted=$false;failure_executable_acl=$na;failure_executable_directory_acl=$na;errors=@('service enrichment failed: '+$reason)}
    }
    $o += [pscustomobject]@{name=$name;security=$security}
}
ConvertTo-Json -InputObject @($o) -Depth 8 -Compress`

var windowsServiceSecurityScript = strings.NewReplacer(
	"__CHIMERA_FILE_MUTATING_MASK__", windowsacl.PowerShellMutatingMaskExpression,
	"__CHIMERA_REGISTRY_MUTATING_MASK__", windowsacl.PowerShellRegistryMutatingMaskExpression,
).Replace(windowsServiceSecurityScriptTemplate)

func collectPlatform(ctx context.Context, inv *Inventory) {
	ps, err := windowsPowerShell()
	if err != nil {
		addSource(inv, "windows-scm", evidence.StateUnavailable, "Win32_Service CIM", 0, err.Error())
		addWindowsSecuritySources(inv, evidence.StateUnavailable, 0, err.Error())
		return
	}

	baseRaw, baseReason, baseErr := runWindowsServicePowerShell(ctx, ps, "windows-scm-enumeration", windowsServiceInventoryScript)
	if baseErr != nil {
		state := windowsServiceErrorState(ctx, baseErr)
		addSource(inv, "windows-scm", state, "Win32_Service CIM", 0, baseReason)
		addWindowsSecuritySources(inv, evidence.StateUnavailable, 0, "security enrichment not attempted because SCM inventory failed: "+baseReason)
		return
	}
	records, err := decodeWindowsServices(baseRaw)
	if err != nil {
		reason := "decode Windows SCM service inventory: " + err.Error()
		addSource(inv, "windows-scm", evidence.StateDegraded, "Win32_Service CIM", 0, reason)
		addWindowsSecuritySources(inv, evidence.StateUnavailable, 0, "security enrichment not attempted because SCM inventory could not be decoded")
		return
	}
	if len(records) > maxServices {
		records = records[:maxServices]
		inv.Degraded = append(inv.Degraded, fmt.Sprintf("Windows service inventory truncated at %d records", maxServices))
	}
	rawByName := make(map[string]windowsServiceRecord, len(records))
	for _, r := range records {
		path := windowsExecutablePath(r.PathName)
		account := fallback(r.StartName, "UNKNOWN")
		inv.Services = append(inv.Services, Service{
			Name: r.Name, DisplayName: r.DisplayName, Description: r.Description,
			Manager: "windows-service-control-manager", ServiceType: r.ServiceType,
			ExecutablePath: path, Account: account, StartMode: windowsStartMode(r.StartMode),
			RuntimePID: r.ProcessID, RuntimeState: windowsRuntimeState(r.State),
			PrivilegeContext: windowsServicePrivilege(account), DefinitionState: "REGISTERED",
			DefinitionPath:      `HKLM\SYSTEM\CurrentControlSet\Services\` + r.Name,
			ConfigurationSource: "Win32_Service CIM / Service Control Manager database",
			CollectionSource:    "Win32_Service CIM", Confidence: evidence.ConfidenceHigh,
		})
		rawByName[strings.ToLower(strings.TrimSpace(r.Name))] = r
	}
	addSource(inv, "windows-scm", evidence.StateObserved, "Win32_Service CIM", len(inv.Services), "")
	if len(inv.Services) == 0 {
		addWindowsSecuritySources(inv, evidence.StateNotApplicable, 0, "no Windows service records require security enrichment")
		return
	}

	// Keep expensive service security enrichment bounded independently from the
	// SCM inventory and run service-object SDDL collection in parallel with the
	// bulk registry/path/account pass. A slow enrichment stage must not consume
	// the provider's entire parent deadline or erase the already-observed SCM
	// inventory.
	// Fix38: service security is a heavy secondary stage, but it must not inherit
	// the exact same deadline as its parent collector. Reserve time for merging
	// already-observed SCM/object evidence even when the bulk stage is slow.
	enrichCtx, enrichCancel, _ := reliability.StageContext(ctx, 28*time.Second, 1500*time.Millisecond, reliability.ProviderBudgetHeavy)
	defer enrichCancel()
	objectSecurityCh := make(chan map[string]windowsServiceObjectSecurity, 1)
	go func() {
		objectSecurityCh <- collectWindowsServiceObjectSecurity(enrichCtx, records)
	}()

	securityRaw, securityReason, securityErr := runWindowsServicePowerShell(enrichCtx, ps, "windows-service-security-enrichment", windowsServiceSecurityScript)
	if securityErr != nil {
		_ = windowsServiceErrorState(enrichCtx, securityErr)
		objectSecurity := <-objectSecurityCh
		for i := range inv.Services {
			sec := unavailableWindowsSecurity("Windows service security enrichment failed: " + securityReason)
			base := rawByName[strings.ToLower(strings.TrimSpace(inv.Services[i].Name))]
			sec.UnquotedExecutablePath = windowsUnquotedExecutablePath(base.PathName, inv.Services[i].ExecutablePath)
			if obj, ok := objectSecurity[strings.ToLower(strings.TrimSpace(inv.Services[i].Name))]; ok {
				applyWindowsServiceObjectSecurity(sec, obj)
			}
			inv.Services[i].WindowsSecurity = sec
		}
		addWindowsSecurityCoverageSources(inv)
		return
	}
	envelopes, err := decodeWindowsServiceSecurity(securityRaw)
	if err != nil {
		reason := "decode Windows service security enrichment: " + err.Error()
		objectSecurity := <-objectSecurityCh
		for i := range inv.Services {
			sec := unavailableWindowsSecurity(reason)
			base := rawByName[strings.ToLower(strings.TrimSpace(inv.Services[i].Name))]
			sec.UnquotedExecutablePath = windowsUnquotedExecutablePath(base.PathName, inv.Services[i].ExecutablePath)
			if obj, ok := objectSecurity[strings.ToLower(strings.TrimSpace(inv.Services[i].Name))]; ok {
				applyWindowsServiceObjectSecurity(sec, obj)
			}
			inv.Services[i].WindowsSecurity = sec
		}
		addWindowsSecurityCoverageSources(inv)
		return
	}
	objectSecurity := <-objectSecurityCh
	securityByName := make(map[string]windowsSecurityRecord, len(envelopes))
	for _, e := range envelopes {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		if name != "" {
			sec := e.Security
			if obj, ok := objectSecurity[name]; ok {
				sec.ServiceSDDL = obj.SDDL
				sec.ServiceACLState = obj.State
				sec.ServiceACLReason = obj.Reason
			}
			securityByName[name] = sec
		}
	}
	for i := range inv.Services {
		key := strings.ToLower(strings.TrimSpace(inv.Services[i].Name))
		base := rawByName[key]
		rawSec, ok := securityByName[key]
		if !ok {
			sec := unavailableWindowsSecurity("security enrichment record missing for service")
			sec.UnquotedExecutablePath = windowsUnquotedExecutablePath(base.PathName, inv.Services[i].ExecutablePath)
			inv.Services[i].WindowsSecurity = sec
			continue
		}
		inv.Services[i].WindowsSecurity = normalizeWindowsSecurity(rawSec, base.PathName, inv.Services[i].ExecutablePath)
		inv.Services[i].CollectionSource = "Win32_Service CIM + read-only SCM/registry/NTFS security enrichment"
	}
	addWindowsSecurityCoverageSources(inv)
}

type windowsServiceObjectSecurity struct {
	State  string
	SDDL   string
	Reason string
}

func applyWindowsServiceObjectSecurity(sec *WindowsSecurity, obj windowsServiceObjectSecurity) {
	if sec == nil {
		return
	}
	if strings.TrimSpace(obj.SDDL) != "" {
		sec.ServiceACL = parseWindowsServiceSDDL(obj.SDDL)
	}
	if strings.TrimSpace(sec.ServiceACL.State) == "" || strings.TrimSpace(obj.SDDL) == "" {
		state := normalizeSecurityState(obj.State)
		if state == "" {
			state = "UNAVAILABLE"
		}
		sec.ServiceACL.State = state
	}
	if strings.TrimSpace(obj.Reason) != "" {
		sec.ServiceACL.Reason = strings.TrimSpace(obj.Reason)
	}
	sec.refreshComponents()
}

// collectWindowsServiceObjectSecurity keeps service-object security independent
// from the bulk registry/path/account enrichment. sc.exe is fast on healthy
// hosts, but running it sequentially for hundreds of services made the entire
// enrichment stage inherit the cost of the slowest records.
func collectWindowsServiceObjectSecurity(ctx context.Context, records []windowsServiceRecord) map[string]windowsServiceObjectSecurity {
	stageCtx, stageCancel, _ := reliability.StageContext(ctx, 20*time.Second, 500*time.Millisecond, reliability.ProviderBudgetHeavy)
	defer stageCancel()
	out := make(map[string]windowsServiceObjectSecurity, len(records))
	if len(records) == 0 {
		return out
	}
	sc, err := exec.LookPath("sc.exe")
	if err != nil {
		for _, r := range records {
			key := strings.ToLower(strings.TrimSpace(r.Name))
			if key != "" {
				out[key] = windowsServiceObjectSecurity{State: "UNAVAILABLE", Reason: "sc.exe unavailable for service object ACL inspection"}
			}
		}
		return out
	}
	type job struct{ name, key string }
	type result struct {
		key string
		sec windowsServiceObjectSecurity
	}
	jobs := make(chan job)
	results := make(chan result, len(records))
	workers := 16
	if len(records) < workers {
		workers = len(records)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if stageCtx.Err() != nil {
					results <- result{j.key, windowsServiceObjectSecurity{State: "UNAVAILABLE", Reason: "service object ACL collection stopped at bounded stage deadline: " + stageCtx.Err().Error()}}
					continue
				}
				callCtx, cancel, _ := reliability.StageContext(stageCtx, 1800*time.Millisecond, 100*time.Millisecond, reliability.ProviderBudgetFast)
				cmd := exec.CommandContext(callCtx, sc, "sdshow", j.name)
				raw, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					reason := "sc.exe sdshow failed"
					if callCtx.Err() != nil {
						reason = "sc.exe sdshow exceeded 1.8 second per-service budget"
					} else if detail := boundedServiceProviderText(string(raw), 384); detail != "" {
						reason += ": " + detail
					}
					results <- result{j.key, windowsServiceObjectSecurity{State: "UNAVAILABLE", Reason: reason}}
					continue
				}
				sddl := ""
				for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
					candidate := strings.TrimSpace(line)
					if strings.HasPrefix(candidate, "O:") || strings.HasPrefix(candidate, "G:") || strings.HasPrefix(candidate, "D:") || strings.HasPrefix(candidate, "S:") {
						sddl = candidate
						break
					}
				}
				if sddl == "" {
					results <- result{j.key, windowsServiceObjectSecurity{State: "UNAVAILABLE", Reason: "service object security descriptor missing from sc.exe output"}}
					continue
				}
				results <- result{j.key, windowsServiceObjectSecurity{State: "OBSERVED", SDDL: sddl}}
			}
		}()
	}
	go func() {
		for _, r := range records {
			name := strings.TrimSpace(r.Name)
			if name == "" {
				continue
			}
			jobs <- job{name: name, key: strings.ToLower(name)}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for r := range results {
		out[r.key] = r.sec
	}
	return out
}

func windowsPowerShell() (string, error) {
	for _, name := range []string{"powershell.exe", "pwsh.exe", "powershell", "pwsh"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("PowerShell was not found for read-only Win32_Service collection")
}

func runWindowsServicePowerShell(ctx context.Context, ps, stage, script string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	raw, err := cmd.Output()
	if err == nil {
		return raw, "", nil
	}
	if ctx.Err() != nil {
		return raw, stage + ": " + ctx.Err().Error(), err
	}
	reason := err.Error()
	if ee, ok := err.(*exec.ExitError); ok {
		stderr := boundedServiceProviderText(string(ee.Stderr), 768)
		if stderr != "" {
			reason += ": " + stderr
		}
	}
	return raw, stage + ": " + reason, err
}

func boundedServiceProviderText(v string, max int) string {
	v = strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
	if len(v) <= max {
		return v
	}
	return v[:max] + "..."
}

func windowsServiceErrorState(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil {
		return evidence.StateUnavailable
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "access") && strings.Contains(strings.ToLower(err.Error()), "denied") {
		return evidence.StateDenied
	}
	return evidence.StateUnavailable
}

func decodeWindowsServices(raw []byte) ([]windowsServiceRecord, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil, nil
	}
	var many []windowsServiceRecord
	if err := json.Unmarshal([]byte(text), &many); err == nil {
		return many, nil
	}
	var one windowsServiceRecord
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return nil, err
	}
	if strings.TrimSpace(one.Name) == "" {
		return nil, nil
	}
	return []windowsServiceRecord{one}, nil
}

func decodeWindowsServiceSecurity(raw []byte) ([]windowsServiceSecurityEnvelope, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil, nil
	}
	var many []windowsServiceSecurityEnvelope
	if err := json.Unmarshal([]byte(text), &many); err == nil {
		return many, nil
	}
	var one windowsServiceSecurityEnvelope
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return nil, err
	}
	if strings.TrimSpace(one.Name) == "" {
		return nil, nil
	}
	return []windowsServiceSecurityEnvelope{one}, nil
}

func addWindowsSecuritySources(inv *Inventory, state evidence.State, count int, reason string) {
	for _, src := range []struct{ id, source string }{
		{"windows-service-security", "SCM service security enrichment"},
		{"windows-service-object-security", "SCM service-object security descriptors"},
		{"windows-service-path-security", "NTFS service executable/DLL ACL metadata"},
		{"windows-service-registry-security", "service registry metadata and ACLs"},
		{"windows-service-account-security", "service-account privilege classification"},
		{"windows-service-recovery-security", "service recovery executable metadata and ACLs"},
	} {
		addSource(inv, src.id, state, src.source, count, reason)
	}
}

func addWindowsSecurityCoverageSources(inv *Inventory) {
	total := len(inv.Services)
	if total == 0 {
		addWindowsSecuritySources(inv, evidence.StateNotApplicable, 0, "no Windows service records require security enrichment")
		return
	}
	serviceObject, path, registry, account, recovery := securityCoverageCounter{}, securityCoverageCounter{}, securityCoverageCounter{}, securityCoverageCounter{}, securityCoverageCounter{}
	usableRecords := 0
	for _, svc := range inv.Services {
		sec := svc.WindowsSecurity
		if sec == nil {
			serviceObject.degraded++
			path.degraded++
			registry.degraded++
			account.degraded++
			recovery.degraded++
			continue
		}
		if sec.Components.ServiceObject == "OBSERVED" || sec.Components.ExecutableACL == "OBSERVED" || sec.Components.ExecutableDirectoryACL == "OBSERVED" || sec.Components.RegistryMetadata == "OBSERVED" || sec.Components.RegistryACL == "OBSERVED" || sec.Components.Account == "OBSERVED" {
			usableRecords++
		}
		countSecurityState(&serviceObject, sec.ServiceACL.State)
		countSecurityState(&path, combineSecurityComponentStates(sec.Components.ExecutableACL, sec.Components.ExecutableDirectoryACL, sec.Components.ServiceDLLMetadata, sec.Components.ServiceDLLACL, sec.Components.ServiceDLLDirectoryACL))
		countSecurityState(&registry, combineSecurityComponentStates(sec.Components.RegistryMetadata, sec.Components.RegistryACL))
		countSecurityState(&account, sec.Components.Account)
		countSecurityState(&recovery, combineSecurityComponentStates(sec.Components.RecoveryConfiguration, sec.Components.RecoveryExecutableACL, sec.Components.RecoveryExecutableDirACL))
	}
	addCoverageSource(inv, "windows-service-security", "SCM/registry/NTFS service security enrichment", total, securityCoverageCounter{observed: usableRecords, unavailable: total - usableRecords})
	addCoverageSource(inv, "windows-service-object-security", "SCM service-object security descriptors", total, serviceObject)
	addCoverageSource(inv, "windows-service-path-security", "NTFS service executable/DLL ACL metadata", total, path)
	addCoverageSource(inv, "windows-service-registry-security", "service registry metadata and ACLs", total, registry)
	addCoverageSource(inv, "windows-service-account-security", "service-account privilege classification", total, account)
	addCoverageSource(inv, "windows-service-recovery-security", "service recovery executable metadata and ACLs", total, recovery)
}

type securityCoverageCounter struct {
	observed      int
	degraded      int
	denied        int
	unavailable   int
	notApplicable int
}

func countSecurityState(c *securityCoverageCounter, state string) {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "OBSERVED":
		c.observed++
	case "DEGRADED":
		c.degraded++
	case "DENIED":
		c.denied++
	case "NOT_APPLICABLE":
		c.notApplicable++
	default:
		c.unavailable++
	}
}

func optionalSecurityState(path, state string) string {
	if strings.TrimSpace(path) == "" {
		return "NOT_APPLICABLE"
	}
	return state
}

func addCoverageSource(inv *Inventory, id, source string, total int, coverage securityCoverageCounter) {
	state := evidence.StateObserved
	reason := ""
	failures := coverage.degraded + coverage.denied + coverage.unavailable
	if failures > 0 {
		state = evidence.StateDegraded
		if coverage.observed == 0 && coverage.degraded == 0 && coverage.unavailable == 0 && coverage.denied > 0 {
			state = evidence.StateDenied
		}
		reason = fmt.Sprintf("component coverage: observed=%d degraded=%d denied=%d unavailable=%d not_applicable=%d total=%d", coverage.observed, coverage.degraded, coverage.denied, coverage.unavailable, coverage.notApplicable, total)
	} else if total > 0 && coverage.observed == 0 && coverage.notApplicable == total {
		state = evidence.StateNotApplicable
		reason = "component is not configured for any enumerated service"
	}
	addSource(inv, id, state, source, total, reason)
}

func windowsExecutablePath(command string) string {
	v := strings.TrimSpace(command)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, `"`) {
		if end := strings.Index(v[1:], `"`); end >= 0 {
			return strings.TrimSpace(v[1 : end+1])
		}
	}
	lower := strings.ToLower(v)
	for _, ext := range []string{".exe", ".com", ".bat", ".cmd", ".sys"} {
		if end := strings.Index(lower, ext); end >= 0 {
			return strings.Trim(strings.TrimSpace(v[:end+len(ext)]), `"`)
		}
	}
	if fields := strings.Fields(v); len(fields) > 0 {
		return strings.Trim(fields[0], `"`)
	}
	return ""
}

func windowsStartMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "auto", "automatic", "automatic delayed start":
		return "AUTOMATIC"
	case "manual":
		return "MANUAL"
	case "disabled":
		return "DISABLED"
	case "boot":
		return "BOOT"
	case "system":
		return "SYSTEM"
	case "":
		return "UNKNOWN"
	default:
		return v
	}
}

func windowsRuntimeState(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "running", "start pending", "continue pending":
		return "RUNNING"
	case "stopped", "stop pending", "pause pending", "paused":
		return "STOPPED"
	case "":
		return "UNKNOWN"
	default:
		return v
	}
}

func windowsServicePrivilege(account string) string {
	a := strings.ToLower(strings.TrimSpace(account))
	a = strings.ReplaceAll(a, "/", `\`)
	switch a {
	case "localsystem", `nt authority\system`, "system":
		return "SYSTEM"
	case `nt authority\localservice`, "localservice", `nt authority\networkservice`, "networkservice":
		return "SERVICE_BUILTIN"
	case "", "unknown":
		return "UNKNOWN"
	default:
		return "SERVICE_ACCOUNT"
	}
}

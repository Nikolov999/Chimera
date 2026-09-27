//go:build windows

package updateposture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	windowsUpdateStageMetadata = "DETECTION_INSTALL_METADATA"
	windowsUpdateStageReboot   = "REBOOT_STATE"
	windowsUpdateStagePackages = "CBS_PENDING_PACKAGES"

	windowsUpdateStageReserve = 1500 * time.Millisecond
)

type windowsStageEnvelope struct {
	OK               bool            `json:"ok"`
	Data             json.RawMessage `json:"data"`
	ExceptionType    string          `json:"exception_type"`
	ExceptionMessage string          `json:"exception_message"`
}

type windowsMetadataPayload struct {
	LastDetect  string `json:"LastDetect"`
	LastInstall string `json:"LastInstall"`
}

type windowsRebootPayload struct {
	RebootRequired bool `json:"RebootRequired"`
}

type windowsPackagesPayload struct {
	Packages []struct {
		PackageName  string `json:"PackageName"`
		PackageState string `json:"PackageState"`
		ReleaseType  string `json:"ReleaseType"`
		InstallTime  string `json:"InstallTime"`
	} `json:"Packages"`
}

type windowsStageSpec struct {
	ID      string
	Command string
	Budget  time.Duration
	Script  string
}

func collectPlatform(ctx context.Context, r *Result) {
	if !commandAvailable("powershell.exe") {
		addProvider(r, "windows-update", evidence.StateUnavailable, "Windows Update/CBS local metadata", 0, 0, time.Time{}, FreshnessUnknown, "powershell.exe is unavailable")
		return
	}

	stages := []ProviderStage{}
	partial := false
	observedStages := 0
	meta := time.Time{}
	start := len(r.Updates)
	security := 0

	metadataScript := `$ErrorActionPreference='Stop'; try { $d=''; $i=''; $dp='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'; $ip='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'; if(Test-Path -LiteralPath $dp){$v=Get-ItemProperty -LiteralPath $dp -ErrorAction Stop; $d=[string]$v.LastSuccessTime}; if(Test-Path -LiteralPath $ip){$v=Get-ItemProperty -LiteralPath $ip -ErrorAction Stop; $i=[string]$v.LastSuccessTime}; [pscustomobject]@{ok=$true;data=[pscustomobject]@{LastDetect=$d;LastInstall=$i};exception_type='';exception_message=''} | ConvertTo-Json -Compress -Depth 5 } catch { [pscustomobject]@{ok=$false;data=$null;exception_type=$_.Exception.GetType().FullName;exception_message=[string]$_.Exception.Message} | ConvertTo-Json -Compress -Depth 5 }`
	if raw, stage := runWindowsUpdateStage(ctx, windowsStageSpec{ID: windowsUpdateStageMetadata, Command: "Windows Update result registry metadata", Budget: 5 * time.Second, Script: metadataScript}); stage.State == evidence.StateObserved {
		var p windowsMetadataPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			stage.State = evidence.StateDegraded
			stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_decode: invalid metadata payload: %v", stage.ID, err)
			partial = true
			r.Limitations = append(r.Limitations, stage.Reason)
		} else {
			observedStages++
			detect := parseWindowsTime(p.LastDetect)
			install := parseWindowsTime(p.LastInstall)
			if install.After(detect) {
				meta = install
			} else {
				meta = detect
			}
		}
		stages = append(stages, stage)
	} else {
		partial = true
		stages = append(stages, stage)
		appendWindowsStageLimitation(r, stage)
	}

	rebootScript := `$ErrorActionPreference='Stop'; try { $rr=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'); [pscustomobject]@{ok=$true;data=[pscustomobject]@{RebootRequired=[bool]$rr};exception_type='';exception_message=''} | ConvertTo-Json -Compress -Depth 5 } catch { [pscustomobject]@{ok=$false;data=$null;exception_type=$_.Exception.GetType().FullName;exception_message=[string]$_.Exception.Message} | ConvertTo-Json -Compress -Depth 5 }`
	if raw, stage := runWindowsUpdateStage(ctx, windowsStageSpec{ID: windowsUpdateStageReboot, Command: "Windows Update/CBS reboot-pending registry state", Budget: 4 * time.Second, Script: rebootScript}); stage.State == evidence.StateObserved {
		var p windowsRebootPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			stage.State = evidence.StateDegraded
			stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_decode: invalid reboot payload: %v", stage.ID, err)
			partial = true
			r.Limitations = append(r.Limitations, stage.Reason)
		} else {
			observedStages++
			if p.RebootRequired {
				r.RebootRequired = true
			}
		}
		stages = append(stages, stage)
	} else {
		partial = true
		stages = append(stages, stage)
		appendWindowsStageLimitation(r, stage)
	}

	packagesScript := `$ErrorActionPreference='Stop'; try { $cmd=Get-Command Get-WindowsPackage -ErrorAction SilentlyContinue; if($null -eq $cmd){ [pscustomobject]@{ok=$false;data=$null;exception_type='COMMAND_UNAVAILABLE';exception_message='Get-WindowsPackage is unavailable in this PowerShell session'} | ConvertTo-Json -Compress -Depth 6 } else { $p=@(); foreach($x in @(Get-WindowsPackage -Online -ErrorAction Stop | Where-Object {$_.PackageState -eq 'InstallPending'})){ $p += [pscustomobject]@{PackageName=[string]$x.PackageName;PackageState=[string]$x.PackageState;ReleaseType=[string]$x.ReleaseType;InstallTime=[string]$x.InstallTime} }; [pscustomobject]@{ok=$true;data=[pscustomobject]@{Packages=@($p)};exception_type='';exception_message=''} | ConvertTo-Json -Compress -Depth 6 } } catch { [pscustomobject]@{ok=$false;data=$null;exception_type=$_.Exception.GetType().FullName;exception_message=[string]$_.Exception.Message} | ConvertTo-Json -Compress -Depth 6 }`
	if raw, stage := runWindowsUpdateStage(ctx, windowsStageSpec{ID: windowsUpdateStagePackages, Command: "Get-WindowsPackage -Online (InstallPending only)", Budget: 10 * time.Second, Script: packagesScript}); stage.State == evidence.StateObserved {
		var p windowsPackagesPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			stage.State = evidence.StateDegraded
			stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_decode: invalid CBS package payload: %v", stage.ID, err)
			partial = true
			r.Limitations = append(r.Limitations, stage.Reason)
		} else {
			observedStages++
			stage.ItemCount = len(p.Packages)
			for _, x := range p.Packages {
				name := strings.TrimSpace(x.PackageName)
				if name == "" {
					continue
				}
				cls := ClassificationUnknown
				reason := "CBS reports a package in InstallPending state"
				if strings.Contains(strings.ToLower(x.ReleaseType), "security") {
					cls = ClassificationSecurity
					security++
					reason = "CBS reports a pending package classified as a security update"
				}
				r.Updates = append(r.Updates, Update{Product: name, PackageID: name, CandidateVersion: name, Classification: cls, RebootRequired: r.RebootRequired, Source: "Windows CBS/Get-WindowsPackage local state", Confidence: evidence.ConfidenceHigh, Reason: reason})
			}
		}
		stages = append(stages, stage)
	} else {
		partial = true
		stages = append(stages, stage)
		appendWindowsStageLimitation(r, stage)
	}

	state := evidence.StateObserved
	if observedStages == 0 {
		state = evidence.StateDegraded
		for _, stage := range stages {
			if stage.State == evidence.StateDenied {
				state = evidence.StateDenied
				break
			}
			if stage.State == evidence.StateUnavailable {
				state = evidence.StateUnavailable
			}
		}
	}

	reason := "Windows Update posture is collected from independent bounded local stages; successful stages remain usable if a secondary stage fails"
	if partial {
		reason += "; one or more stages were partial or unavailable"
	}
	provider := Provider{
		ID:            "windows-update",
		State:         state,
		Source:        "Windows Update/CBS staged local metadata",
		ItemCount:     len(r.Updates) - start,
		SecurityCount: security,
		MetadataTime:  meta,
		Freshness:     freshness(meta, r.CollectedAt),
		Partial:       partial,
		Stages:        stages,
		Reason:        reason,
	}
	r.Providers = append(r.Providers, provider)
	r.Limitations = append(r.Limitations, "Windows missing-update enumeration is limited to local cached/servicing state; ordinary Chimera scans never contact Windows Update")
}

func runWindowsUpdateStage(parent context.Context, spec windowsStageSpec) (json.RawMessage, ProviderStage) {
	stage := ProviderStage{ID: spec.ID, State: evidence.StateDegraded, Command: spec.Command}
	ctx, cancel, ok := boundedWindowsUpdateStageContext(parent, spec.Budget)
	if !ok {
		stage.Reason = fmt.Sprintf("windows-update stage=%s skipped because insufficient parent collection time remained; successful update stages were preserved", spec.ID)
		return nil, stage
	}
	defer cancel()

	started := time.Now()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", spec.Script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	stage.ElapsedMS = time.Since(started).Milliseconds()
	stage.Stderr = boundedDiagnostic(stderr.String(), 2048)

	exitCode := 0
	if err != nil {
		exitCode = -1
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
	}
	stage.ExitCode = &exitCode

	if ctx.Err() != nil {
		if parent.Err() != nil {
			stage.Reason = fmt.Sprintf("windows-update stage=%s parent collection deadline reached; completed update stages were preserved", spec.ID)
		} else {
			stage.Reason = fmt.Sprintf("windows-update stage=%s exceeded its bounded optional stage window; completed update stages were preserved", spec.ID)
		}
		return nil, stage
	}
	if err != nil {
		stage.State = stateForError(parent, err)
		if stage.State == evidence.StateDenied {
			stage.Reason = fmt.Sprintf("windows-update stage=%s access restricted while running %s", spec.ID, spec.Command)
		} else {
			stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_failure command=%s exit_code=%d: PowerShell stage process failed", spec.ID, spec.Command, exitCode)
		}
		return nil, stage
	}

	var env windowsStageEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &env); err != nil {
		stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_decode: could not decode staged PowerShell JSON: %v", spec.ID, err)
		return nil, stage
	}
	stage.ExceptionType = strings.TrimSpace(env.ExceptionType)
	stage.ExceptionMessage = strings.TrimSpace(env.ExceptionMessage)
	if !env.OK {
		stage.State = windowsStageFailureState(stage.ExceptionType, stage.ExceptionMessage)
		stage.Reason = windowsStageFailureReason(spec.ID, spec.Command, stage.State, stage.ExceptionType, stage.ExceptionMessage)
		return nil, stage
	}
	if len(bytes.TrimSpace(env.Data)) == 0 || bytes.Equal(bytes.TrimSpace(env.Data), []byte("null")) {
		stage.Reason = fmt.Sprintf("windows-update stage=%s class=provider_decode: successful stage returned no data payload", spec.ID)
		return nil, stage
	}
	stage.State = evidence.StateObserved
	stage.Reason = "stage completed"
	return env.Data, stage
}

func boundedWindowsUpdateStageContext(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc, bool) {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return nil, nil, false
	}
	budget := requested
	if budget <= 0 {
		budget = 5 * time.Second
	}
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline) - windowsUpdateStageReserve
		if remaining < 750*time.Millisecond {
			return nil, nil, false
		}
		if remaining < budget {
			budget = remaining
		}
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	return ctx, cancel, true
}

func windowsStageFailureState(exceptionType, message string) evidence.State {
	s := strings.ToLower(strings.TrimSpace(exceptionType + " " + message))
	switch {
	case strings.Contains(s, "command_unavailable"), strings.Contains(s, "not recognized"), strings.Contains(s, "could not find") && strings.Contains(s, "command"):
		return evidence.StateUnavailable
	case strings.Contains(s, "access denied"), strings.Contains(s, "unauthorized"), strings.Contains(s, "permission"), strings.Contains(s, "requires elevation"):
		return evidence.StateDenied
	default:
		return evidence.StateDegraded
	}
}

func windowsStageFailureReason(stageID, command string, state evidence.State, exceptionType, message string) string {
	typeText := strings.TrimSpace(exceptionType)
	message = strings.TrimSpace(message)
	if typeText == "" {
		typeText = "UNKNOWN"
	}
	if message == "" {
		message = "PowerShell stage returned no exception message"
	}
	switch state {
	case evidence.StateUnavailable:
		return fmt.Sprintf("windows-update stage=%s unavailable command=%s exception_type=%s: %s", stageID, command, typeText, message)
	case evidence.StateDenied:
		return fmt.Sprintf("windows-update stage=%s access restricted command=%s exception_type=%s: %s", stageID, command, typeText, message)
	default:
		return fmt.Sprintf("windows-update stage=%s degraded command=%s exception_type=%s: %s", stageID, command, typeText, message)
	}
}

func appendWindowsStageLimitation(r *Result, stage ProviderStage) {
	if strings.TrimSpace(stage.Reason) != "" {
		r.Limitations = append(r.Limitations, stage.Reason)
	}
}

func boundedDiagnostic(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) <= max || max <= 0 {
		return v
	}
	return v[:max] + "..."
}

func parseWindowsTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "1/2/2006 3:04:05 PM", "1/2/2006 3:04:05 PM -07:00"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

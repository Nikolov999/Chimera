//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type winLoadedDriver struct {
	Name            string   `json:"Name"`
	DisplayName     string   `json:"DisplayName"`
	State           string   `json:"State"`
	ServiceType     string   `json:"ServiceType"`
	StartMode       string   `json:"StartMode"`
	Path            string   `json:"Path"`
	Version         string   `json:"Version"`
	SignatureStatus string   `json:"SignatureStatus"`
	Signer          string   `json:"Signer"`
	SignatureType   string   `json:"SignatureType"`
	IsOSBinary      bool     `json:"IsOSBinary"`
	BackingExists   *bool    `json:"BackingExists"`
	Errors          []string `json:"Errors"`
}

func collectLoadedModulesPlatform(ctx context.Context, _ Inventory) []ModuleAssessment {
	const provider = "Windows Win32_SystemDriver + Authenticode"
	if !commandAvailable("powershell.exe") {
		return []ModuleAssessment{{
			ID: "windows.loaded_drivers", Name: "Windows loaded kernel drivers", Kind: "kernel-driver-set",
			CollectionState: evidence.StateUnavailable, LoadState: "UNKNOWN", Provider: provider, Source: "PowerShell/CIM",
			SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceLow,
			Reason: "powershell.exe is unavailable; loaded-driver provenance cannot be collected",
		}}
	}

	ps := `$ErrorActionPreference='SilentlyContinue'; $rows=@(); Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | ForEach-Object { $d=$_; $p=[string]$d.PathName; if($p -match '^\\SystemRoot\\'){ $p=Join-Path $env:SystemRoot $p.Substring(12) }; if($p -match '^System32\\'){ $p=Join-Path $env:SystemRoot $p }; if($p -match '^"([^"]+)"'){ $p=$matches[1] } else { $p=($p -split '\\s+')[0] }; if($p -match '^\\\?\?\\'){ $p=$p.Substring(4) }; $exists=$null; $ver=''; $status=''; $signer=''; $stype=''; $os=$false; $errs=@(); if($p){ try{$exists=Test-Path -LiteralPath $p}catch{$errs+=$_.Exception.Message}; if($exists){ try{$ver=(Get-Item -LiteralPath $p).VersionInfo.FileVersion}catch{$errs+=$_.Exception.Message}; try{$sig=Get-AuthenticodeSignature -LiteralPath $p; $status=[string]$sig.Status; $stype=[string]$sig.SignatureType; if($sig.SignerCertificate){$signer=[string]$sig.SignerCertificate.Subject}; if($null -ne $sig.IsOSBinary){$os=[bool]$sig.IsOSBinary}}catch{$errs+=$_.Exception.Message} } }; $rows += [pscustomobject]@{Name=[string]$d.Name;DisplayName=[string]$d.DisplayName;State=[string]$d.State;ServiceType=[string]$d.ServiceType;StartMode=[string]$d.StartMode;Path=$p;Version=$ver;SignatureStatus=$status;Signer=$signer;SignatureType=$stype;IsOSBinary=$os;BackingExists=$exists;Errors=$errs} }; @($rows) | ConvertTo-Json -Compress -Depth 4`
	s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err != nil {
		return []ModuleAssessment{{
			ID: "windows.loaded_drivers", Name: "Windows loaded kernel drivers", Kind: "kernel-driver-set",
			CollectionState: evidence.StateUnavailable, LoadState: "UNKNOWN", Provider: provider, Source: "Win32_SystemDriver",
			SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceLow,
			Reason: "loaded-driver inventory failed: " + err.Error(),
		}}
	}
	var rows []winLoadedDriver
	if strings.TrimSpace(s) == "" || strings.TrimSpace(s) == "null" || strings.TrimSpace(s) == "[]" {
		return []ModuleAssessment{{
			ID: "windows.loaded_drivers", Name: "Windows loaded kernel drivers", Kind: "kernel-driver-set",
			CollectionState: evidence.StateObserved, LoadState: "EMPTY", Provider: provider, Source: "Win32_SystemDriver",
			SignatureState: "NOT_APPLICABLE", TrustState: "NOT_APPLICABLE", BackingState: "NOT_APPLICABLE", Confidence: evidence.ConfidenceHigh,
			Reason: "no running Win32_SystemDriver records were returned",
		}}
	}
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		var one winLoadedDriver
		if e := json.Unmarshal([]byte(s), &one); e != nil {
			return []ModuleAssessment{{ID: "windows.loaded_drivers", Name: "Windows loaded kernel drivers", Kind: "kernel-driver-set", CollectionState: evidence.StateDegraded, LoadState: "UNKNOWN", Provider: provider, Source: "Win32_SystemDriver", SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceLow, Reason: "driver JSON decode failed: " + e.Error()}}
		}
		rows = []winLoadedDriver{one}
	} else if e := json.Unmarshal([]byte(s), &rows); e != nil {
		return []ModuleAssessment{{ID: "windows.loaded_drivers", Name: "Windows loaded kernel drivers", Kind: "kernel-driver-set", CollectionState: evidence.StateDegraded, LoadState: "UNKNOWN", Provider: provider, Source: "Win32_SystemDriver", SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceLow, Reason: "driver JSON decode failed: " + e.Error()}}
	}

	out := make([]ModuleAssessment, 0, len(rows))
	for _, r := range rows {
		m := ModuleAssessment{
			ID: "windows.driver." + slug(r.Name), Name: r.Name, Kind: "windows-kernel-driver",
			CollectionState: evidence.StateObserved, LoadState: strings.ToUpper(r.State), Version: strings.TrimSpace(r.Version), Path: strings.TrimSpace(r.Path),
			Provider: provider, Source: "Win32_SystemDriver/Get-AuthenticodeSignature", SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceHigh,
		}
		if m.Name == "" {
			m.Name = strings.TrimSpace(r.DisplayName)
		}
		if r.BackingExists != nil {
			if *r.BackingExists {
				m.BackingState = "PRESENT"
			} else {
				m.BackingState = "DELETED_OR_MISSING"
				m.Flags = append(m.Flags, "DELETED_BACKING")
			}
		}
		m.Signer = strings.TrimSpace(r.Signer)
		status := strings.ToLower(strings.TrimSpace(r.SignatureStatus))
		switch status {
		case "valid":
			m.SignatureState = "SIGNED_VALID"
			if r.IsOSBinary || strings.Contains(strings.ToLower(m.Signer), "microsoft") {
				m.TrustState = "PLATFORM_SIGNED"
				m.Provenance = "Microsoft/OS-signed driver"
			} else {
				m.TrustState = "THIRD_PARTY_SIGNED"
				m.Provenance = "third-party signed driver"
			}
			if looksWindowsTestSigner(m.Signer) {
				m.TrustState = "TEST_SIGNED"
				m.Flags = append(m.Flags, "TEST_SIGNED")
			}
		case "notsigned":
			m.SignatureState = "UNSIGNED"
			m.TrustState = "UNSIGNED"
			m.Flags = append(m.Flags, "UNSIGNED")
		case "hashmismatch", "nottrusted", "unknownerror":
			m.SignatureState = strings.ToUpper(status)
			m.TrustState = "UNTRUSTED_OR_INVALID"
			m.Flags = append(m.Flags, "SIGNATURE_INVALID")
		default:
			if m.Path == "" {
				m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
			}
		}
		if m.Signer == "" && m.SignatureState == "UNKNOWN" {
			m.Flags = append(m.Flags, "UNKNOWN_SOURCE")
		}
		if len(r.Errors) > 0 {
			m.Reason = strings.Join(r.Errors, "; ")
			if m.CollectionState == evidence.StateObserved {
				m.CollectionState = evidence.StateDegraded
				m.Confidence = evidence.ConfidenceMedium
			}
		}
		if r.SignatureType != "" {
			if m.Provenance != "" {
				m.Provenance += "; "
			}
			m.Provenance += "signature_type=" + r.SignatureType
		}
		out = append(out, m)
	}
	return out
}

func looksWindowsTestSigner(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "test") || strings.Contains(s, "development") || strings.Contains(s, "debug")
}

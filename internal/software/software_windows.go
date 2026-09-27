//go:build windows

package software

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type winSoftwareRecord struct {
	Kind          string `json:"Kind"`
	Product       string `json:"Product"`
	PackageID     string `json:"PackageID"`
	Version       string `json:"Version"`
	Architecture  string `json:"Architecture"`
	Vendor        string `json:"Vendor"`
	PackageSource string `json:"PackageSource"`
	InstallPath   string `json:"InstallPath"`
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	if !commandAvailable("powershell.exe") {
		addSource(inv, "windows-software", evidence.StateUnavailable, "PowerShell registry/AppX providers", 0, "powershell.exe is unavailable")
		return
	}
	const script = `$r=@(); $paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'); foreach($p in $paths){Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | ForEach-Object {$a='UNKNOWN'; if($_.PSPath -like '*WOW6432Node*'){$a='x86'}; $r += [pscustomobject]@{Kind='application';Product=[string]$_.DisplayName;PackageID=[string]$_.PSChildName;Version=[string]$_.DisplayVersion;Architecture=$a;Vendor=[string]$_.Publisher;PackageSource='windows-uninstall-registry';InstallPath=[string]$_.InstallLocation}}}; Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {$r += [pscustomobject]@{Kind='application';Product=[string]$_.Name;PackageID=[string]$_.PackageFullName;Version=[string]$_.Version;Architecture=[string]$_.Architecture;Vendor=[string]$_.Publisher;PackageSource='windows-appx';InstallPath=[string]$_.InstallLocation}}; $r | ConvertTo-Json -Compress -Depth 4`
	text, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		addSource(inv, "windows-software", stateForWindowsError(ctx, err), "PowerShell registry/AppX providers", 0, err.Error())
		return
	}
	records, err := decodeWindowsRecords(text)
	if err != nil {
		addSource(inv, "windows-software", evidence.StateDegraded, "PowerShell registry/AppX providers", 0, "parse provider output: "+err.Error())
		return
	}
	start := len(inv.Items)
	for _, r := range records {
		if strings.TrimSpace(r.Product) == "" {
			continue
		}
		inv.Items = append(inv.Items, Item{Kind: r.Kind, Product: r.Product, PackageID: r.PackageID, Version: r.Version, Architecture: r.Architecture, Vendor: r.Vendor, PackageSource: r.PackageSource, InstallPath: r.InstallPath, SupportState: "UNKNOWN", SupportReason: "application lifecycle intelligence is introduced in ", CollectionSource: "Windows uninstall registry / AppX package metadata", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "windows-software", evidence.StateObserved, "PowerShell registry/AppX providers", len(inv.Items)-start, "")
}

func decodeWindowsRecords(text string) ([]winSoftwareRecord, error) {
	text = strings.TrimSpace(text)
	if text == "" || text == "null" {
		return []winSoftwareRecord{}, nil
	}
	var many []winSoftwareRecord
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal([]byte(text), &many); err != nil {
			return nil, err
		}
		return many, nil
	}
	var one winSoftwareRecord
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return nil, err
	}
	return []winSoftwareRecord{one}, nil
}

func stateForWindowsError(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil {
		return evidence.StateDegraded
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "access is denied") || strings.Contains(msg, "unauthorized") {
		return evidence.StateDenied
	}
	return evidence.StateDegraded
}

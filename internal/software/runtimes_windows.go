//go:build windows

package software

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type dotNetFrameworkRecord struct {
	Product     string `json:"Product"`
	Version     string `json:"Version"`
	InstallPath string `json:"InstallPath"`
	Arch        string `json:"Arch"`
}

func collectPlatformRuntimes(ctx context.Context, inv *Inventory) {
	if !commandAvailable("powershell.exe") {
		return
	}
	const script = `$r=@(); $roots=@(@{P='HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP';A='native'},@{P='HKLM:\SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP';A='x86'}); foreach($root in $roots){Get-ChildItem $root.P -Recurse -ErrorAction SilentlyContinue | ForEach-Object {$v=(Get-ItemProperty $_.PSPath -Name Version -ErrorAction SilentlyContinue).Version; if($v){$ip=(Get-ItemProperty $_.PSPath -Name InstallPath -ErrorAction SilentlyContinue).InstallPath; $r += [pscustomobject]@{Product=[string]$_.PSChildName;Version=[string]$v;InstallPath=[string]$ip;Arch=[string]$root.A}}}}; $r | ConvertTo-Json -Compress -Depth 4`
	text, err := runRuntimeProbe(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		addRuntimeSource(inv, "dotnet-framework-registry", runtimeStateForError(ctx, err), "Windows .NET Framework registry metadata", 0, err.Error())
		return
	}
	records, err := decodeDotNetFrameworkRecords(text)
	if err != nil {
		addRuntimeSource(inv, "dotnet-framework-registry", evidence.StateDegraded, "Windows .NET Framework registry metadata", 0, "parse provider output: "+err.Error())
		return
	}
	before := len(inv.Runtimes)
	for _, r := range records {
		if strings.TrimSpace(r.Version) == "" {
			continue
		}
		product := strings.TrimSpace(r.Product)
		if product == "" {
			product = ".NET Framework"
		} else {
			product = ".NET Framework " + product
		}
		arch := "UNKNOWN"
		switch strings.ToLower(strings.TrimSpace(r.Arch)) {
		case "x86":
			arch = "386"
		case "native":
			arch = defaultRuntimeArch()
		}
		inv.Runtimes = append(inv.Runtimes, RuntimeItem{Family: "dotnet-framework", Kind: "framework-runtime", Product: product, Version: r.Version, Architecture: arch, Executable: "N/A", ExecutablePath: "N/A", InstallPath: r.InstallPath, Distribution: "Microsoft .NET Framework", CollectionSource: "Windows .NET Framework registry metadata", Confidence: evidence.ConfidenceExact})
	}
	addRuntimeSource(inv, "dotnet-framework-registry", evidence.StateObserved, "Windows .NET Framework registry metadata", len(inv.Runtimes)-before, "")
}

func decodeDotNetFrameworkRecords(text string) ([]dotNetFrameworkRecord, error) {
	text = strings.TrimSpace(text)
	if text == "" || text == "null" {
		return []dotNetFrameworkRecord{}, nil
	}
	var many []dotNetFrameworkRecord
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal([]byte(text), &many); err != nil {
			return nil, err
		}
		return many, nil
	}
	var one dotNetFrameworkRecord
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return nil, err
	}
	return []dotNetFrameworkRecord{one}, nil
}

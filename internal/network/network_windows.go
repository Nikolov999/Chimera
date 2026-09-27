//go:build windows

package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

const (
	windowsEndpointPreferredBudget = 12 * time.Second
	windowsOwnerPreferredBudget    = 6 * time.Second
	windowsNetworkCleanupReserve   = 1500 * time.Millisecond
)

type winEndpointStreamRow struct {
	Kind          string `json:"kind"`
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	OwningProcess int    `json:"owning_process"`
	OK            bool   `json:"ok"`
	Reason        string `json:"reason"`
}

type winProtocolStatus struct {
	seen   bool
	ok     bool
	reason string
}

type winOwnerProcess struct {
	PID         int    `json:"PID"`
	ProcessName string `json:"ProcessName"`
	Executable  string `json:"Executable"`
}

type winOwnerService struct {
	PID         int    `json:"PID"`
	ServiceName string `json:"ServiceName"`
}

type winOwnerSnapshot struct {
	Processes []winOwnerProcess `json:"Processes"`
	Services  []winOwnerService `json:"Services"`
}

type winOwnerMetadata struct {
	ProcessName string
	Executable  string
	ServiceName string
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	rows, statuses, endpointReason := collectWindowsEndpointStream(ctx)
	endpointState := windowsEndpointSourceState(rows, statuses, endpointReason)
	addSource(inv, "get-net-endpoints", endpointState, "staged Get-NetTCPConnection/Get-NetUDPEndpoint", len(rows), endpointReason)

	owners := map[int]winOwnerMetadata{}
	ownerState := evidence.StateNotApplicable
	ownerReason := "no local TCP/UDP endpoints required owner enrichment"
	if len(rows) > 0 && ctx.Err() == nil {
		var err error
		owners, err = collectWindowsOwnerMetadata(ctx)
		if err != nil {
			ownerState = evidence.StateDegraded
			ownerReason = err.Error()
		} else {
			ownerState = evidence.StateObserved
			ownerReason = ""
		}
	}

	enriched := 0
	for _, r := range rows {
		if r.LocalPort <= 0 || r.LocalPort > 65535 {
			continue
		}
		meta := owners[r.OwningProcess]
		owner := Owner{
			PID:         r.OwningProcess,
			ProcessName: strings.TrimSpace(meta.ProcessName),
			Executable:  strings.TrimSpace(meta.Executable),
			ServiceName: strings.TrimSpace(meta.ServiceName),
			Source:      "Get-Net endpoint PID with batched local process/service enrichment",
		}
		if owner.PID > 0 {
			owner.State = "OBSERVED"
		} else {
			owner.State = "UNAVAILABLE"
		}
		if owner.ProcessName != "" || owner.Executable != "" || owner.ServiceName != "" {
			enriched++
		}
		state := "BOUND"
		if strings.EqualFold(r.Protocol, "TCP") {
			state = "LISTEN"
		}
		inv.Endpoints = append(inv.Endpoints, newEndpoint(r.Protocol, state, r.LocalAddress, uint16(r.LocalPort), owner, "pid:"+strconv.Itoa(r.OwningProcess), "Windows staged Get-NetTCPConnection/Get-NetUDPEndpoint"))
	}
	addSource(inv, "windows-owner-enrichment", ownerState, "single-pass Get-Process + Win32_Service metadata", enriched, ownerReason)
}

func collectWindowsEndpointStream(parent context.Context) ([]winEndpointStreamRow, map[string]winProtocolStatus, string) {
	stageCtx, cancel, _ := reliability.StageContext(parent, windowsEndpointPreferredBudget, windowsNetworkCleanupReserve, reliability.ProviderBudgetMedium)
	defer cancel()

	const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';function Emit-ChimeraJson($o){Write-Output ($o|ConvertTo-Json -Compress -Depth 3)};try{Get-NetTCPConnection -State Listen -ErrorAction Stop|ForEach-Object{Emit-ChimeraJson ([pscustomobject]@{kind='endpoint';protocol='TCP';local_address=[string]$_.LocalAddress;local_port=[int]$_.LocalPort;owning_process=[int]$_.OwningProcess;ok=$true;reason=''})};Emit-ChimeraJson ([pscustomobject]@{kind='status';protocol='TCP';local_address='';local_port=0;owning_process=0;ok=$true;reason=''})}catch{Emit-ChimeraJson ([pscustomobject]@{kind='status';protocol='TCP';local_address='';local_port=0;owning_process=0;ok=$false;reason=[string]$_.Exception.Message})};try{Get-NetUDPEndpoint -ErrorAction Stop|ForEach-Object{Emit-ChimeraJson ([pscustomobject]@{kind='endpoint';protocol='UDP';local_address=[string]$_.LocalAddress;local_port=[int]$_.LocalPort;owning_process=[int]$_.OwningProcess;ok=$true;reason=''})};Emit-ChimeraJson ([pscustomobject]@{kind='status';protocol='UDP';local_address='';local_port=0;owning_process=0;ok=$true;reason=''})}catch{Emit-ChimeraJson ([pscustomobject]@{kind='status';protocol='UDP';local_address='';local_port=0;owning_process=0;ok=$false;reason=[string]$_.Exception.Message})}`

	cmd := exec.CommandContext(stageCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, map[string]winProtocolStatus{}, "endpoint stream setup failed: " + err.Error()
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, map[string]winProtocolStatus{}, "endpoint provider start failed: " + err.Error()
	}

	rows := make([]winEndpointStreamRow, 0, 128)
	statuses := map[string]winProtocolStatus{}
	malformed := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row winEndpointStreamRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			malformed++
			continue
		}
		row.Kind = strings.ToLower(strings.TrimSpace(row.Kind))
		row.Protocol = strings.ToUpper(strings.TrimSpace(row.Protocol))
		switch row.Kind {
		case "endpoint":
			if (row.Protocol == "TCP" || row.Protocol == "UDP") && row.LocalPort > 0 && row.LocalPort <= 65535 {
				rows = append(rows, row)
			}
		case "status":
			if row.Protocol == "TCP" || row.Protocol == "UDP" {
				statuses[row.Protocol] = winProtocolStatus{seen: true, ok: row.OK, reason: strings.TrimSpace(row.Reason)}
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	reasons := make([]string, 0, 4)
	if malformed > 0 {
		reasons = append(reasons, fmt.Sprintf("%d malformed endpoint stream row(s) were quarantined", malformed))
	}
	if scanErr != nil {
		reasons = append(reasons, "endpoint stream read failed: "+scanErr.Error())
	}
	if stageCtx.Err() != nil && parent.Err() == nil {
		reasons = append(reasons, "safe collection boundary: staged Windows endpoint acquisition reached its bounded enrichment window")
	} else if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = waitErr.Error()
		}
		reasons = append(reasons, "endpoint provider failed: "+detail)
	}
	for _, proto := range []string{"TCP", "UDP"} {
		st, ok := statuses[proto]
		if !ok || !st.seen {
			reasons = append(reasons, proto+" endpoint stage did not emit a completion status")
			continue
		}
		if !st.ok {
			reasons = append(reasons, proto+" endpoint acquisition failed: "+fallback(st.reason, "provider returned an unspecified error"))
		}
	}
	return rows, statuses, strings.Join(uniqueSorted(reasons), "; ")
}

func windowsEndpointSourceState(rows []winEndpointStreamRow, statuses map[string]winProtocolStatus, reason string) evidence.State {
	success := 0
	for _, proto := range []string{"TCP", "UDP"} {
		if st, ok := statuses[proto]; ok && st.seen && st.ok {
			success++
		}
	}
	if success == 2 && strings.TrimSpace(reason) == "" {
		return evidence.StateObserved
	}
	if success > 0 || len(rows) > 0 {
		return evidence.StateDegraded
	}
	return evidence.StateUnavailable
}

func collectWindowsOwnerMetadata(parent context.Context) (map[int]winOwnerMetadata, error) {
	stageCtx, cancel, _ := reliability.StageContext(parent, windowsOwnerPreferredBudget, windowsNetworkCleanupReserve, reliability.ProviderBudgetMedium)
	defer cancel()

	const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$p=@(Get-Process -ErrorAction SilentlyContinue|ForEach-Object{$x='';try{$x=[string]$_.Path}catch{};[pscustomobject]@{PID=[int]$_.Id;ProcessName=[string]$_.ProcessName;Executable=$x}});$s=@(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue|Where-Object{$_.ProcessId -gt 0}|ForEach-Object{[pscustomobject]@{PID=[int]$_.ProcessId;ServiceName=[string]$_.Name}});[pscustomobject]@{Processes=$p;Services=$s}|ConvertTo-Json -Compress -Depth 4`
	cmd := exec.CommandContext(stageCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	b, err := cmd.Output()
	if err != nil {
		if stageCtx.Err() != nil && parent.Err() == nil {
			return map[int]winOwnerMetadata{}, fmt.Errorf("safe collection boundary: Windows endpoint owner enrichment reached its bounded stage")
		}
		return map[int]winOwnerMetadata{}, fmt.Errorf("Windows endpoint owner enrichment failed: %w", err)
	}
	var snap winOwnerSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return map[int]winOwnerMetadata{}, fmt.Errorf("decode Windows endpoint owner metadata: %w", err)
	}

	owners := make(map[int]winOwnerMetadata, len(snap.Processes))
	for _, p := range snap.Processes {
		if p.PID <= 0 {
			continue
		}
		m := owners[p.PID]
		m.ProcessName = strings.TrimSpace(p.ProcessName)
		m.Executable = strings.TrimSpace(p.Executable)
		owners[p.PID] = m
	}
	services := map[int][]string{}
	for _, svc := range snap.Services {
		name := strings.TrimSpace(svc.ServiceName)
		if svc.PID <= 0 || name == "" {
			continue
		}
		services[svc.PID] = append(services[svc.PID], name)
	}
	for pid, names := range services {
		sort.Strings(names)
		m := owners[pid]
		m.ServiceName = names[0]
		owners[pid] = m
	}
	return owners, nil
}

//go:build windows

package remotemgmt

import (
	"context"
	"fmt"
	"github.com/Nikolov999/chimera/internal/evidence"
	"os/exec"
	"strconv"
	"strings"
)

func collectPlatformControls(ctx context.Context) []Control {
	out := []Control{}
	addRegDWORD := func(family, name, key, value string, invert, affectsEnablement bool) {
		v, err := regDWORD(ctx, key, value)
		if err != nil {
			out = append(out, Control{Family: family, Name: name, State: evidence.StateUnavailable, Source: key + "\\" + value, Confidence: evidence.ConfidenceLow, Reason: err.Error()})
			return
		}
		enabled := v != 0
		if invert {
			enabled = v == 0
		}
		state := "DISABLED"
		if enabled {
			state = "ENABLED"
		}
		out = append(out, Control{Family: family, Name: name, State: evidence.StateObserved, Value: state, Source: key + "\\" + value, Confidence: evidence.ConfidenceExact, AffectsEnablement: affectsEnablement})
	}
	addRegDWORD("RDP", "Remote Desktop enabled", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections", true, true)
	addRegDWORD("RDP", "Network Level Authentication", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication", false, false)
	addRegDWORD("WINRM", "Allow unencrypted WinRM service transport", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`, "AllowUnencrypted", false, false)
	addRegDWORD("WINRM", "WinRM Basic authentication", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\Auth`, "Basic", false, false)
	return out
}

func regDWORD(ctx context.Context, key, value string) (uint64, error) {
	path, err := exec.LookPath("reg.exe")
	if err != nil {
		return 0, fmt.Errorf("reg.exe unavailable: %w", err)
	}
	b, err := exec.CommandContext(ctx, path, "query", key, "/v", value).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("registry value unavailable")
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.EqualFold(f[0], value) {
			continue
		}
		raw := f[len(f)-1]
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(raw), "0x"), 16, 64)
		if err == nil {
			return v, nil
		}
	}
	return 0, fmt.Errorf("registry value not found")
}

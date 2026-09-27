//go:build windows

package processes

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Nikolov999/chimera/internal/evidence"
)

var getDriveTypeW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW")

const (
	driveRemovable = 2
	driveRemote    = 4
)

func platformLocationHints(path string) locationHints {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), `\\`, `/`))
	h := locationHints{Confidence: evidence.ConfidenceHigh}
	if strings.HasPrefix(p, "//") {
		h.NetworkBacked = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Windows UNC/network-backed execution path")
	}
	if strings.Contains(p, "/temp/") || strings.Contains(p, "/tmp/") || strings.HasSuffix(p, "/temp") || strings.HasSuffix(p, "/tmp") {
		h.Temporary = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Windows temporary execution path")
	}
	if strings.Contains(p, "/users/") {
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Windows per-user profile execution path")
	}
	if strings.Contains(p, "/downloads/") || strings.HasSuffix(p, "/downloads") {
		h.Downloads = true
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Windows user Downloads execution path")
	}
	if strings.Contains(p, "/appdata/") {
		h.UserWritable = true
		h.WeakControl = true
		h.Reasons = append(h.Reasons, "Windows per-user AppData execution path")
	}
	if root := filepath.VolumeName(path); root != "" && !strings.HasPrefix(root, `\\`) {
		r := root + `\`
		if ptr, err := syscall.UTF16PtrFromString(r); err == nil {
			kind, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(ptr)))
			switch kind {
			case driveRemovable:
				h.Removable = true
				h.WeakControl = true
				h.Reasons = append(h.Reasons, "Windows removable-drive execution path")
			case driveRemote:
				h.NetworkBacked = true
				h.WeakControl = true
				h.Reasons = append(h.Reasons, "Windows remote-drive execution path")
			}
		}
	}
	return h
}

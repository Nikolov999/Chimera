//go:build windows

package processes

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	processQueryInformation = 0x0400
	memPrivate              = 0x00020000
	memMapped               = 0x00040000
	memImage                = 0x01000000
	pageExecute             = 0x10
	pageExecuteRead         = 0x20
	pageExecuteReadWrite    = 0x40
	pageExecuteWriteCopy    = 0x80
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var (
	kernel32Memory        = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcessMemory = kernel32Memory.NewProc("OpenProcess")
	procCloseHandleMemory = kernel32Memory.NewProc("CloseHandle")
	procVirtualQueryEx    = kernel32Memory.NewProc("VirtualQueryEx")
)

func collectExecutionMemoryPlatform(ctx context.Context, items []Process) ([]ExecutionMemoryContext, memoryProviderStats) {
	stats := memoryProviderStats{ID: "windows-virtualqueryex", State: evidence.StateObserved, Source: "OpenProcess(PROCESS_QUERY_INFORMATION)+VirtualQueryEx protection/type metadata"}
	out := make([]ExecutionMemoryContext, 0, len(items))
	for _, p := range items {
		if ctx.Err() != nil {
			stats.State = evidence.StateDegraded
			stats.Reason = ctx.Err().Error()
			break
		}
		c, err := readWindowsMemoryMap(ctx, p.PID)
		if err != nil {
			c = ExecutionMemoryContext{PID: p.PID, Platform: "windows", State: "DENIED", Source: "VirtualQueryEx", Confidence: evidence.ConfidenceLow, Reason: err.Error()}
			stats.Denied++
		} else {
			stats.Count++
		}
		out = append(out, c)
	}
	return out, stats
}

func readWindowsMemoryMap(ctx context.Context, pid int) (ExecutionMemoryContext, error) {
	h, _, callErr := procOpenProcessMemory.Call(uintptr(processQueryInformation), uintptr(0), uintptr(uint32(pid)))
	if h == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return ExecutionMemoryContext{}, callErr
		}
		return ExecutionMemoryContext{}, fmt.Errorf("OpenProcess denied")
	}
	defer procCloseHandleMemory.Call(h)

	c := ExecutionMemoryContext{PID: pid, Platform: "windows", State: "OBSERVED", Source: "VirtualQueryEx", Confidence: evidence.ConfidenceHigh}
	var address uintptr
	var mbi memoryBasicInformation
	for regions := 0; regions < maxMemoryRegionsPerProcess; regions++ {
		if ctx.Err() != nil {
			c.State = "DEGRADED"
			c.Confidence = evidence.ConfidenceMedium
			c.Reason = ctx.Err().Error()
			break
		}
		n, _, _ := procVirtualQueryEx.Call(h, address, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if n == 0 {
			break
		}
		c.RegionsObserved++
		baseProtect := mbi.Protect & 0xff
		if windowsExecutableProtection(baseProtect) {
			c.ExecutableRegions++
			if baseProtect == pageExecuteReadWrite || baseProtect == pageExecuteWriteCopy {
				c.WritableExecutableRegions++
			}
			switch mbi.Type {
			case memPrivate:
				c.AnonymousExecutableRegions++
			case memImage, memMapped:
				c.FileBackedExecutableRegions++
			}
		}
		if mbi.RegionSize == 0 || address > ^uintptr(0)-mbi.RegionSize {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= address {
			break
		}
		address = next
	}
	if c.RegionsObserved >= maxMemoryRegionsPerProcess {
		c.State = "DEGRADED"
		c.Confidence = evidence.ConfidenceMedium
		c.Reason = "memory region inventory truncated at safety bound"
		c.Signals = append(c.Signals, "memory-region-inventory-truncated")
	}
	return c, nil
}

func windowsExecutableProtection(p uint32) bool {
	switch p {
	case pageExecute, pageExecuteRead, pageExecuteReadWrite, pageExecuteWriteCopy:
		return true
	default:
		return false
	}
}

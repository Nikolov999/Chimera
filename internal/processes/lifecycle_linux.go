//go:build linux

package processes

import (
	"errors"
	"os"
	"syscall"
)

// linuxProcessLifecycleGone recognizes the two procfs error classes commonly
// returned when a PID disappears between the base process snapshot and a later
// enrichment read. ENOENT is surfaced through os.ErrNotExist on many procfs
// paths, while some live procfs opens return ESRCH ("no such process"). Both
// describe the same expected live-host lifecycle race rather than a provider
// acquisition failure.
func linuxProcessLifecycleGone(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}

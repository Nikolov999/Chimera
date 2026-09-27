//go:build linux

package processes

import (
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix62LinuxKernelThreadTreeClassification(t *testing.T) {
	items := []Process{
		{PID: 1, PPID: 0, Name: "systemd", ExecutablePath: "/usr/lib/systemd/systemd", CommandLine: CommandLineMetadata{Available: true, ArgumentCount: 2, ByteCount: 18, Redacted: true}},
		{PID: 2, PPID: 0, Name: "kthreadd", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
		{PID: 3, PPID: 2, Name: "pool_workqueue_release", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
		{PID: 4, PPID: 3, Name: "nested-kthread", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
		// An ordinary userspace process with temporarily missing executable metadata
		// must not be called a kernel thread just because argv is empty.
		{PID: 100, PPID: 1, Name: "userspace", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
	}
	got := linuxKernelThreadPIDs(items)
	for _, pid := range []int{2, 3, 4} {
		if _, ok := got[pid]; !ok {
			t.Fatalf("pid %d should be classified as a kthreadd descendant: %#v", pid, got)
		}
	}
	if _, ok := got[1]; ok {
		t.Fatal("pid 1 must not be classified as a kernel thread")
	}
	if _, ok := got[100]; ok {
		t.Fatal("userspace process outside the kthreadd tree must not be classified as a kernel thread")
	}
}

func TestFix62LinuxKernelThreadEnvironmentIsObservedEmpty(t *testing.T) {
	items := []Process{
		{PID: 2, PPID: 0, Name: "kthreadd", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
		{PID: 3, PPID: 2, Name: "kworker", CommandLine: CommandLineMetadata{Available: true, Redacted: true}},
	}
	got, stats := collectRuntimeEnvironmentPlatform(context.Background(), items)
	if len(got) != 2 || stats.Count != 2 || stats.Denied != 0 || stats.Missing != 0 {
		t.Fatalf("unexpected kernel-thread environment accounting: got=%#v stats=%#v", got, stats)
	}
	for _, c := range got {
		if c.State != "OBSERVED" || c.Posture != "NONE" || !c.ValuesRedacted || c.Reason != "kernel thread has no userspace process environment" {
			t.Fatalf("unexpected kernel-thread environment context: %#v", c)
		}
	}
}

func TestFix63ExitedUserspaceProcessDoesNotDegradeEnvironmentProvider(t *testing.T) {
	// Linux pid_max is far below this value, so the procfs path is guaranteed
	// to be absent on supported kernels. This models a userspace process that
	// exited after the base inventory snapshot but before environment enrichment.
	items := []Process{{
		PID: 999999999, PPID: 1, Name: "short-lived", ExecutablePath: "/usr/bin/short-lived",
		CommandLine: CommandLineMetadata{Available: true, ArgumentCount: 1, ByteCount: 11, Redacted: true},
	}}
	got, stats := collectRuntimeEnvironmentPlatform(context.Background(), items)
	if len(got) != 1 {
		t.Fatalf("unexpected transient environment record count: %#v", got)
	}
	if stats.State != evidence.StateObserved || stats.Count != 1 || stats.Missing != 0 || stats.Denied != 0 {
		t.Fatalf("transient process exit must not degrade provider health: %#v", stats)
	}
	if got[0].State != "UNKNOWN" || got[0].Posture != "UNKNOWN" || got[0].Reason != "process exited before environment enrichment completed" {
		t.Fatalf("unexpected transient process environment context: %#v", got[0])
	}
}

func TestFix64ESRCHIsHandledAsEnvironmentLifecycleRace(t *testing.T) {
	err := &os.PathError{Op: "open", Path: "/proc/123/environ", Err: syscall.ESRCH}
	if !linuxProcessLifecycleGone(err) {
		t.Fatalf("expected ESRCH procfs error to be treated as a lifecycle race: %v", err)
	}
}

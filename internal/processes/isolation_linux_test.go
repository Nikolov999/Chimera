//go:build linux

package processes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestLinuxCgroupIsolationDetectsContainerRuntime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(path, []byte("0::/kubepods.slice/kubepods-burstable.slice/docker-abc.scope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, scoped, runtimeName, container, err := linuxCgroupIsolation(path)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || !scoped || !container || runtimeName != "kubernetes" {
		t.Fatalf("unexpected cgroup classification: raw=%q scoped=%t runtime=%q container=%t", raw, scoped, runtimeName, container)
	}
}

func TestLinuxLSMIsolationClassification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current")
	if err := os.WriteFile(path, []byte("docker-default (enforce)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, sandbox, basis, err := linuxLSMIsolation(path)
	if err != nil {
		t.Fatal(err)
	}
	if profile != "docker-default (enforce)" || sandbox != "ENFORCED" || basis == "" {
		t.Fatalf("unexpected LSM classification: profile=%q sandbox=%q basis=%q", profile, sandbox, basis)
	}
}

func TestFix64ExitedProcessDoesNotDegradeIsolationProvider(t *testing.T) {
	items := []Process{{PID: 999999999, PPID: 1, Name: "short-lived", ExecutablePath: "/usr/bin/short-lived"}}
	got, stats := collectIsolationPlatform(context.Background(), items)
	if len(got) != 1 {
		t.Fatalf("unexpected transient isolation record count: %#v", got)
	}
	if stats.State != evidence.StateObserved || stats.Count != 1 || stats.Missing != 0 || stats.Denied != 0 {
		t.Fatalf("transient process exit must not degrade isolation provider health: %#v", stats)
	}
	if got[0].State != "UNKNOWN" || got[0].Reason != "process exited before isolation enrichment completed" {
		t.Fatalf("unexpected transient isolation context: %#v", got[0])
	}
}

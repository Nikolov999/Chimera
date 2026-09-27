//go:build linux

package scheduled

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShellExecutableRedactsArguments(t *testing.T) {
	exe, args := shellExecutable("/usr/local/bin/job --token secret")
	if exe != "/usr/local/bin/job" || !args {
		t.Fatalf("unexpected parse %q %t", exe, args)
	}
}

func TestFix65CronShellScaffoldingResolvesActualExecutable(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"run-parts", "debian-sa1"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	cron := filepath.Join(t.TempDir(), "fixture")
	content := "PATH=" + dir + "\n" +
		"17 * * * * root cd / && run-parts --report /etc/cron.hourly\n" +
		"5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1\n"
	if err := os.WriteFile(cron, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	entries, err := parseCronFile(cron, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected cron entry count: %#v", entries)
	}
	entries = normalizeEntries(entries)
	if entries[0].ActionPath.State != "OBSERVED" || entries[1].ActionPath.State != "OBSERVED" {
		t.Fatalf("cron shell scaffolding must resolve to observed executable paths: %#v", entries)
	}
	seen := map[string]Entry{}
	for _, e := range entries {
		seen[filepath.Base(e.ActionExecutable)] = e
	}
	if got := seen["run-parts"]; got.ActionExecutable != filepath.Join(dir, "run-parts") || got.WorkingDirectory != "/" || got.WorkingDirectoryPosture.State != "OBSERVED" {
		t.Fatalf("cd/run-parts cron semantics not normalized: %#v", got)
	}
	if got := seen["debian-sa1"]; got.ActionExecutable != filepath.Join(dir, "debian-sa1") || got.ActionPath.State != "OBSERVED" {
		t.Fatalf("command -v preflight must not become the scheduled executable: %#v", got)
	}
}

func TestFix66DebianCronFallbackSubshellResolvesRunParts(t *testing.T) {
	dir := t.TempDir()
	runParts := filepath.Join(dir, "run-parts")
	if err := os.WriteFile(runParts, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runParts, 0755); err != nil {
		t.Fatal(err)
	}

	cron := filepath.Join(t.TempDir(), "crontab")
	content := "PATH=" + dir + "\n" +
		"25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n" +
		"47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n" +
		"52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
	if err := os.WriteFile(cron, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseCronFile(cron, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("unexpected cron entry count: %#v", entries)
	}
	entries = normalizeEntries(entries)
	for _, got := range entries {
		if got.ActionExecutable != runParts {
			t.Fatalf("fallback subshell did not resolve run-parts: %#v", got)
		}
		if got.WorkingDirectory != "/" || got.WorkingDirectoryPosture.State != "OBSERVED" {
			t.Fatalf("fallback subshell did not preserve cd working directory: %#v", got)
		}
		if got.ActionPath.State != "OBSERVED" || got.ActionDirectoryPosture.State != "OBSERVED" {
			t.Fatalf("fallback subshell path posture remained unresolved: %#v", got)
		}
	}
}

func TestFix67KaliCronFallbackBraceGroupResolvesRunParts(t *testing.T) {
	dir := t.TempDir()
	runParts := filepath.Join(dir, "run-parts")
	if err := os.WriteFile(runParts, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runParts, 0755); err != nil {
		t.Fatal(err)
	}

	cron := filepath.Join(t.TempDir(), "crontab")
	content := "PATH=" + dir + "\n" +
		"25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\n" +
		"47 6 * * 7 root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }\n" +
		"52 6 1 * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }\n"
	if err := os.WriteFile(cron, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseCronFile(cron, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("unexpected cron entry count: %#v", entries)
	}
	entries = normalizeEntries(entries)
	for _, got := range entries {
		if got.ActionExecutable != runParts {
			t.Fatalf("brace-group fallback did not resolve run-parts: %#v", got)
		}
		if got.WorkingDirectory != "/" || got.WorkingDirectoryPosture.State != "OBSERVED" {
			t.Fatalf("brace-group fallback did not preserve cd working directory: %#v", got)
		}
		if got.ActionPath.State != "OBSERVED" || got.ActionDirectoryPosture.State != "OBSERVED" {
			t.Fatalf("brace-group fallback path posture remained unresolved: %#v", got)
		}
	}
}

func TestFix67StandaloneClosingBraceTerminatesCronCommandSegment(t *testing.T) {
	segment := cronCommandSegment([]string{"run-parts", "--report", "/etc/cron.daily", "}"})
	if len(segment) != 3 || segment[0] != "run-parts" || segment[2] != "/etc/cron.daily" {
		t.Fatalf("standalone closing brace must terminate command segment: %#v", segment)
	}
}

//go:build linux

package accounts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestPhase069SudoersParserDetectsBroadDelegationAndEnvironmentRisk(t *testing.T) {
	dir := t.TempDir()
	includeDir := filepath.Join(dir, "sudoers.d")
	if err := os.Mkdir(includeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "ops-script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o777); err != nil {
		t.Fatal(err)
	}
	included := filepath.Join(includeDir, "10-ops")
	includedText := "bob ALL=(root) SETENV: /usr/bin/id\ncarol ALL=(root) " + script + "\n"
	if err := os.WriteFile(included, []byte(includedText), 0o440); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "sudoers")
	mainText := "Defaults env_reset\nDefaults env_keep += \"LD_PRELOAD PATH\"\nalice ALL=(root) NOPASSWD: ALL\n#includedir " + includeDir + "\n"
	if err := os.WriteFile(main, []byte(mainText), 0o440); err != nil {
		t.Fatal(err)
	}

	posture := collectLinuxSudoPosture(context.Background(), main)
	if posture.State != evidence.StateObserved {
		t.Fatalf("expected observed posture, got %s reason=%s", posture.State, posture.Reason)
	}
	if posture.Summary.ParsedFiles != 2 {
		t.Fatalf("expected two parsed sudoers files, got %#v", posture.Summary)
	}
	if posture.Summary.BroadNOPASSWDCommands != 1 || posture.Summary.UnrestrictedCommands != 1 {
		t.Fatalf("expected broad NOPASSWD/ALL detection, got %#v", posture.Summary)
	}
	if posture.Summary.ExplicitSetEnvCommands != 1 || posture.Summary.UnsafeEnvironment != 1 {
		t.Fatalf("expected SETENV and env_keep risk, got %#v", posture.Summary)
	}
	if posture.Summary.WritableReferences == 0 {
		t.Fatalf("expected writable script reference issue, got %#v", posture.Summary)
	}
	if err := validateSudoPosture("linux", posture); err != nil {
		t.Fatal(err)
	}
}

func TestPhase069CommandAliasExpansion(t *testing.T) {
	lines := []sudoSourceLine{
		{Source: "/etc/sudoers", Line: 1, Text: "Cmnd_Alias OPS = /usr/bin/id, /usr/bin/whoami"},
		{Source: "/etc/sudoers", Line: 2, Text: "alice ALL=(root) NOPASSWD: OPS"},
	}
	aliases := parseSudoCommandAliases(lines)
	grants := parseSudoGrants(lines, aliases)
	if len(grants) != 1 || len(grants[0].Commands) != 2 {
		t.Fatalf("expected expanded command alias, got %#v", grants)
	}
	for _, cmd := range grants[0].Commands {
		if !cmd.NOPASSWD || cmd.Path == "" || cmd.Alias != "" {
			t.Fatalf("unexpected expanded command: %#v", cmd)
		}
	}
}

func TestPhase069SafeSudoersProducesNoRiskRecords(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(main, []byte("Defaults env_reset\nalice ALL=(root) /usr/bin/id\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	posture := collectLinuxSudoPosture(context.Background(), main)
	if posture.State != evidence.StateObserved {
		t.Fatalf("expected observed posture, got %s reason=%s", posture.State, posture.Reason)
	}
	if posture.Summary.BroadNOPASSWDCommands != 0 || posture.Summary.UnrestrictedCommands != 0 || posture.Summary.UnsafeEnvironment != 0 || posture.Summary.WritableReferences != 0 || posture.Summary.InsecureConfigPaths != 0 {
		t.Fatalf("unexpected risk summary: %#v", posture.Summary)
	}
}

func TestPhase069IncludedirSkipsDottedAndBackupNames(t *testing.T) {
	dir := t.TempDir()
	includeDir := filepath.Join(dir, "sudoers.d")
	if err := os.Mkdir(includeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"10-valid": "alice ALL=(root) /usr/bin/id\n",
		"20.skip":  "alice ALL=(root) NOPASSWD: ALL\n",
		"30-back~": "alice ALL=(root) NOPASSWD: ALL\n",
	} {
		if err := os.WriteFile(filepath.Join(includeDir, name), []byte(text), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	main := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(main, []byte("#includedir "+includeDir+"\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	posture := collectLinuxSudoPosture(context.Background(), main)
	if posture.Summary.ParsedFiles != 2 || posture.Summary.BroadNOPASSWDCommands != 0 {
		t.Fatalf("includedir filtering drift: %#v", posture.Summary)
	}
}

func TestPhase069CommandArgumentsAreRedacted(t *testing.T) {
	cmd := normalizeSudoCommand("/usr/local/bin/backup --token supersecret /srv/data", nil)
	if cmd.Path != "/usr/local/bin/backup" {
		t.Fatalf("unexpected command path: %#v", cmd)
	}
	if strings.Contains(cmd.Spec, "supersecret") || strings.Contains(cmd.Spec, "--token") {
		t.Fatalf("sudo command descriptor leaked arguments: %q", cmd.Spec)
	}
	if !strings.Contains(cmd.Spec, "arguments redacted") {
		t.Fatalf("expected redaction marker, got %q", cmd.Spec)
	}
}

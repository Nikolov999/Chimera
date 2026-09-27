package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/config"
)

func TestPulseStyleRootMenuIsCompact(t *testing.T) {
	var out bytes.Buffer
	if err := printLauncher(&out, config.Defaults(), commandRegistry()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Workflows", "Start", "chimera overview", "chimera scan", "chimera --help"} {
		if !strings.Contains(text, want) {
			t.Fatalf("root menu missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Global options") || strings.Contains(text, "CHIMERA HELP") {
		t.Fatalf("bare root should remain a compact launcher:\n%s", text)
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if len([]rune(line)) > 80 {
			t.Fatalf("root line exceeds 80 columns (%d): %q", len([]rune(line)), line)
		}
	}
}

func TestPulseStyleRootHelpCoversRegistryAndGlobals(t *testing.T) {
	var out bytes.Buffer
	registry := commandRegistry()
	if err := printRootHelp(&out, config.Defaults(), registry); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Contains(text, "______") {
		t.Fatalf("root help must be banner-free:\n%s", text)
	}
	for _, want := range []string{"CHIMERA HELP", "Navigation", "Commands", "Global options", "Help model"} {
		if !strings.Contains(text, want) {
			t.Fatalf("root help missing section %q", want)
		}
	}
	for name, cmd := range registry {
		usage := "Usage: " + cmd.Help.Usage
		if !strings.Contains(text, usage) {
			t.Fatalf("root help missing canonical usage for %s: %q", name, usage)
		}
	}
	for _, flag := range []string{
		"--json", "--plain", "--no-color", "--quiet", "--verbose", "--output <path>",
		"--profile <name>", "--severity <level>", "--category <name>", "--include <selector>", "--exclude <selector>",
		"--config <path>", "--offline", "--refresh-intelligence", "--timeout <duration>", "--max-workers <n>",
		"-h, --help", "-V, --version",
	} {
		if !strings.Contains(text, flag) {
			t.Fatalf("root help missing global option %q", flag)
		}
	}
}

func TestPulseStyleCommandHelpUsesSevenSectionsWithoutBanner(t *testing.T) {
	cmd := commandRegistry()["overview"]
	var out bytes.Buffer
	if err := printCommandHelp(&out, config.Defaults(), cmd); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Contains(text, "______") {
		t.Fatalf("command help must be banner-free:\n%s", text)
	}
	for _, section := range []string{"Purpose\n", "Usage\n", "Examples\n", "Output\n", "Safety\n", "Requirements\n", "Next steps\n"} {
		if !strings.Contains(text, section) {
			t.Fatalf("command help missing %q:\n%s", section, text)
		}
	}
}

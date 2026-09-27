package cli

import (
	"testing"
	"time"
)

func TestParseGlobalsBeforeAndAfterCommand(t *testing.T) {
	base := Options{Timeout: 30 * time.Second, MaxWorkers: 4, Profile: "default", Severity: "INFO"}
	got, err := Parse([]string{"--verbose", "overview", "--json", "--timeout=5s", "--max-workers", "2"}, base)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "overview" {
		t.Fatalf("command=%q", got.Command)
	}
	if !got.Options.JSON || !got.Options.Verbose {
		t.Fatalf("flags not applied: %+v", got.Options)
	}
	if !got.Options.Plain || !got.Options.NoColor {
		t.Fatalf("json must force plain/no-color: %+v", got.Options)
	}
	if got.Options.Timeout != 5*time.Second {
		t.Fatalf("timeout=%s", got.Options.Timeout)
	}
	if got.Options.MaxWorkers != 2 {
		t.Fatalf("max workers=%d", got.Options.MaxWorkers)
	}
}

func TestParseRejectsConflicts(t *testing.T) {
	base := Options{Timeout: 30 * time.Second, MaxWorkers: 1, Severity: "INFO"}
	if _, err := Parse([]string{"overview", "--quiet", "--verbose"}, base); err == nil {
		t.Fatal("expected quiet/verbose conflict")
	}
	if _, err := Parse([]string{"overview", "--offline", "--refresh-intelligence"}, base); err == nil {
		t.Fatal("expected offline/refresh conflict")
	}
}

func TestFindConfigPath(t *testing.T) {
	got, err := FindConfigPath([]string{"overview", "--config=custom.json"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "custom.json" {
		t.Fatalf("got %q", got)
	}
}

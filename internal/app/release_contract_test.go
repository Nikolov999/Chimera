package app

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/releasecontract"
	"github.com/Nikolov999/chimera/internal/version"
)

func TestV1PublicCommandRegistryIsFrozenAndComplete(t *testing.T) {
	if version.Version != releasecontract.ReleaseVersion {
		t.Fatalf("tool version=%q want %q", version.Version, releasecontract.ReleaseVersion)
	}
	registry := commandRegistry()
	if err := validateV1CommandRegistry(registry); err != nil {
		t.Fatal(err)
	}
	for _, name := range releasecontract.RequiredCommands() {
		if _, ok := registry[name]; !ok {
			t.Fatalf("required command %q missing", name)
		}
	}
}

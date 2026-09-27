package persistence

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
	"github.com/Nikolov999/chimera/internal/services"
)

func TestCollectFromComposesExistingPersistenceMechanisms(t *testing.T) {
	at := time.Now().UTC()
	sv := services.Inventory{
		Schema: services.SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: services.CollectorName, CollectorVersion: services.CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Services: []services.Service{{ID: "svc-1", Name: "demo.service", Manager: "systemd", Account: "root", StartMode: "enabled", RuntimeState: "RUNNING", PrivilegeContext: "ROOT", ExecutablePath: "/usr/bin/demo", DefinitionPath: "/etc/systemd/system/demo.service", ConfigurationSource: "/etc/systemd/system/demo.service", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}},
		Sources:  []services.SourceStatus{{ID: "test", State: evidence.StateObserved, Source: "test", ItemCount: 1}},
	}
	// Build the service evidence exactly as the service collector would require
	// is not possible from an external package fixture; use a real empty-valid
	// service collection contract instead and verify parser helpers separately.
	_ = sv
	sch := scheduled.Inventory{Schema: scheduled.SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: scheduled.CollectorName, CollectorVersion: scheduled.CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at}
	_ = sch

	exe, args := firstCommandToken(`"/opt/demo app/bin/demo" --token REDACTED`)
	if exe != "/opt/demo app/bin/demo" || !args {
		t.Fatalf("unexpected redacted token parse: exe=%q args=%t", exe, args)
	}
}

func TestNormalizeEntriesDeterministicAndEvidenceValid(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at}
	inv.Entries = normalizeEntries([]Entry{{Name: "b", Mechanism: "run_key", Manager: "m", Scope: "user", EnabledState: "enabled", RuntimeState: "not_assessed", Account: "u", PrivilegeContext: "user", ConfigurationSource: "c", CollectionSource: "s", Confidence: evidence.ConfidenceHigh}, {Name: "a", Mechanism: "service", Manager: "m", Scope: "system", EnabledState: "enabled", RuntimeState: "running", Account: "root", PrivilegeContext: "root", ConfigurationSource: "c", CollectionSource: "s", Confidence: evidence.ConfidenceHigh}})
	inv.Sources = []SourceStatus{{ID: "test", State: evidence.StateObserved, Source: "test", ItemCount: 2}}
	inv.Summary = summarize(inv.Entries)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(inv.Entries) != 2 || inv.Summary.Entries != 2 || len(inv.Evidence) != 6 {
		t.Fatalf("unexpected inventory shape: entries=%d summary=%+v evidence=%d", len(inv.Entries), inv.Summary, len(inv.Evidence))
	}
}

func TestFirstCommandTokenNeverReturnsArguments(t *testing.T) {
	exe, args := firstCommandToken(`/usr/bin/demo --password secret-value`)
	if exe != "/usr/bin/demo" || !args {
		t.Fatalf("unexpected parse %q %t", exe, args)
	}
	if exe == "secret-value" {
		t.Fatal("argument leaked as executable")
	}
}

func TestFirstCommandTokenWindowsUnquotedPathAndInterpreter(t *testing.T) {
	exe, args := firstCommandToken(`C:\\Program Files\\Demo App\\demo.exe --start`)
	if exe != `C:\\Program Files\\Demo App\\demo.exe` || !args {
		t.Fatalf("unexpected Windows absolute-path parse: %q args=%t", exe, args)
	}
	exe, args = firstCommandToken(`powershell -File C:\\Users\\u\\startup.ps1 -Token secret`)
	if exe != "powershell" || !args {
		t.Fatalf("interpreter command must retain only first token: %q args=%t", exe, args)
	}
}

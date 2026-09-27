package software

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestClassifyInfrastructureSeparatesInstalledAndRunning(t *testing.T) {
	items := []Item{{ID: "sw-test", Product: "nginx", PackageID: "nginx", Version: "1.26.0", InstallPath: "/usr/sbin/nginx", Confidence: evidence.ConfidenceExact}}
	activity := []infrastructureActivity{{Kind: "process", Name: "nginx", Path: "/usr/sbin/nginx"}, {Kind: "process", Name: "postgres", Path: "/usr/lib/postgresql/postgres"}}
	got := classifyInfrastructure(items, activity)
	var nginx, postgres *InfrastructureItem
	for i := range got {
		switch got[i].Family {
		case "nginx":
			nginx = &got[i]
		case "postgresql":
			postgres = &got[i]
		}
	}
	if nginx == nil || !nginx.Installed || !nginx.Running || nginx.Version != "1.26.0" || nginx.ID == "" {
		t.Fatalf("unexpected nginx record: %#v", nginx)
	}
	if postgres == nil || postgres.Installed || !postgres.Running || postgres.Confidence != evidence.ConfidenceMedium {
		t.Fatalf("unexpected postgres record: %#v", postgres)
	}
}

func TestInfrastructurePackageMatchingUsesTokenBoundaries(t *testing.T) {
	sig := infrastructureSignature{PackageAliases: []string{"nginx"}}
	if !matchesAnyPackage(Item{Product: "nginx", PackageID: "nginx"}, sig.PackageAliases) {
		t.Fatal("expected nginx match")
	}
	if matchesAnyPackage(Item{Product: "my-nginx-helper", PackageID: "my-nginx-helper"}, sig.PackageAliases) {
		t.Fatal("did not expect embedded alias match")
	}
}

func TestInfrastructureActivityUsesExactProcessNames(t *testing.T) {
	sig := infrastructureSignature{ProcessNames: []string{"sshd"}}
	if !activityMatches(infrastructureActivity{Kind: "process", Name: "/usr/sbin/sshd"}, sig) {
		t.Fatal("expected sshd match")
	}
	if activityMatches(infrastructureActivity{Kind: "process", Name: "sshd-helper"}, sig) {
		t.Fatal("did not expect sshd-helper match")
	}
}

func TestInfrastructureActivityHintsReuseDedicatedInventory(t *testing.T) {
	inv := Inventory{Items: []Item{}}
	hints := []HostActivityHint{
		{Kind: "process", Name: "nginx", Path: `C:\\nginx\\nginx.exe`},
		{Kind: "service", Name: "W3SVC", Path: `C:\\Windows\\System32\\svchost.exe`},
	}
	collectInfrastructureInventoryWithActivity(nil, &inv, hints)
	seenReuse := false
	for _, src := range inv.InfrastructureSources {
		if src.ID == "assessment-process-service-metadata-reuse" && src.State == evidence.StateObserved && src.ItemCount == len(hints) {
			seenReuse = true
		}
	}
	if !seenReuse {
		t.Fatalf("expected reused assessment process/service metadata source, got %#v", inv.InfrastructureSources)
	}
	foundNginx := false
	for _, item := range inv.Infrastructure {
		if item.Family == "nginx" && item.Running {
			foundNginx = true
		}
	}
	if !foundNginx {
		t.Fatalf("expected running nginx from host activity hint, got %#v", inv.Infrastructure)
	}
}

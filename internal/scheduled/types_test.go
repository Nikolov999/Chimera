package scheduled

import (
	"context"
	"testing"
)

func TestCollectContract(t *testing.T) {
	inv := Collect(context.Background())
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Schema != SchemaVersion || inv.CollectorVersion != CollectorVersion {
		t.Fatalf("unexpected contract: %#v", inv)
	}
}
func TestNormalizeStableOrderingAndIDs(t *testing.T) {
	in := []Entry{{Name: "B", Manager: "cron", Kind: "cron-entry", EnabledState: "enabled", RuntimeState: "on-demand", Account: "root", PrivilegeContext: "root", Schedule: "@daily", ConfigurationSource: "/b", CollectionSource: "test"}, {Name: "A", Manager: "cron", Kind: "cron-entry", EnabledState: "enabled", RuntimeState: "on-demand", Account: "root", PrivilegeContext: "root", Schedule: "@hourly", ConfigurationSource: "/a", CollectionSource: "test"}}
	out := normalizeEntries(in)
	if len(out) != 2 || out[0].ID == "" || out[1].ID == "" || entrySortKey(out[0]) > entrySortKey(out[1]) {
		t.Fatalf("bad normalization: %#v", out)
	}
}

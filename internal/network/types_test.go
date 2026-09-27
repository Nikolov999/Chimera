package network

import (
	"testing"
)

func TestBindingClassification(t *testing.T) {
	cases := []struct {
		addr, class string
		wild, loop  bool
	}{{"0.0.0.0", "ALL_INTERFACES", true, false}, {"::", "ALL_INTERFACES", true, false}, {"127.0.0.1", "LOOPBACK", false, true}, {"::1", "LOOPBACK", false, true}, {"192.0.2.10", "NON_LOOPBACK", false, false}}
	for _, tc := range cases {
		b := classifyBinding(tc.addr)
		if b.Class != tc.class || b.IsWildcard != tc.wild || b.IsLoopback != tc.loop {
			t.Fatalf("%s => %#v", tc.addr, b)
		}
	}
}
func TestInventoryValidateAndDeterminism(t *testing.T) {
	inv := Collect(testContext(t))
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(inv.Endpoints); i++ {
		if endpointSortKey(inv.Endpoints[i]) < endpointSortKey(inv.Endpoints[i-1]) {
			t.Fatal("endpoints unsorted")
		}
	}
}

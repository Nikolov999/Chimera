package kernel

import "testing"

func TestInterpretUnprivilegedBPF(t *testing.T) {
	tests := []struct {
		value   int
		state   string
		exposed bool
		ok      bool
	}{
		{0, "ENABLED", true, true},
		{1, "DISABLED", false, true},
		{2, "DISABLED", false, true},
		{9, "", false, false},
	}
	for _, tc := range tests {
		state, _, exposed, ok := interpretUnprivilegedBPF(tc.value)
		if ok != tc.ok || state != tc.state {
			t.Fatalf("value %d: state=%q ok=%v", tc.value, state, ok)
		}
		if tc.ok && (exposed == nil || *exposed != tc.exposed) {
			t.Fatalf("value %d: exposed=%v", tc.value, exposed)
		}
	}
}

func TestInterpretPerfEventParanoid(t *testing.T) {
	tests := []struct {
		value int
		state string
	}{
		{-1, "BROAD_UNPRIVILEGED_ACCESS"},
		{0, "PERMISSIVE"},
		{1, "RESTRICTED"},
		{2, "STRONGLY_RESTRICTED"},
		{4, "STRONGLY_RESTRICTED"},
	}
	for _, tc := range tests {
		state, mode, _ := interpretPerfEventParanoid(tc.value)
		if state != tc.state || mode == "" {
			t.Fatalf("value %d: state=%q mode=%q", tc.value, state, mode)
		}
	}
}

func TestInterpretNamespaceLimit(t *testing.T) {
	state, _, exposed := interpretNamespaceLimit(0)
	if state != "DISABLED" || exposed == nil || *exposed {
		t.Fatalf("disabled: state=%q exposed=%v", state, exposed)
	}
	state, _, exposed = interpretNamespaceLimit(1024)
	if state != "AVAILABLE_WITH_LIMIT" || exposed != nil {
		t.Fatalf("available: state=%q exposed=%v", state, exposed)
	}
}

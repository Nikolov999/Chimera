package kernel

import "testing"

func TestAggregateMitigationSettings(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string]string
		state   string
		enabled *bool
	}{
		{"enabled", map[string]string{"A": "ON", "B": "enabled"}, "ENABLED", boolPtr(true)},
		{"disabled", map[string]string{"A": "OFF"}, "DISABLED", boolPtr(false)},
		{"default", map[string]string{"A": "NOTSET", "B": ""}, "PLATFORM_DEFAULT", nil},
		{"partial", map[string]string{"A": "ON", "B": "NOTSET"}, "PARTIAL_OR_DEFAULT", nil},
		{"mixed-off", map[string]string{"A": "ON", "B": "OFF"}, "MIXED_WITH_EXPLICIT_DISABLE", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, enabled, mode := aggregateMitigationSettings(tc.in)
			if state != tc.state || mode == "" {
				t.Fatalf("got state=%q mode=%q", state, mode)
			}
			if tc.enabled == nil {
				if enabled != nil {
					t.Fatalf("enabled=%v, want nil", *enabled)
				}
				return
			}
			if enabled == nil || *enabled != *tc.enabled {
				t.Fatalf("enabled=%v, want %v", enabled, *tc.enabled)
			}
		})
	}
}

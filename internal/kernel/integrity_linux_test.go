//go:build linux

package kernel

import "testing"

func TestParseLinuxLockdownMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"[none] integrity confidentiality", "none"},
		{"none [integrity] confidentiality", "integrity"},
		{"none integrity [confidentiality]", "confidentiality"},
		{"integrity", "integrity"},
	}
	for _, tc := range cases {
		got, ok := parseLinuxLockdownMode(tc.in)
		if !ok || got != tc.want {
			t.Fatalf("parseLinuxLockdownMode(%q)=(%q,%v), want %q,true", tc.in, got, ok, tc.want)
		}
	}
	if _, ok := parseLinuxLockdownMode("garbage"); ok {
		t.Fatal("expected invalid lockdown state to fail")
	}
}

func TestKernelConfigBool(t *testing.T) {
	cfg := "CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_FORCE=y\n# CONFIG_OTHER is not set\n"
	if v, ok := kernelConfigBool(cfg, "CONFIG_MODULE_SIG_FORCE"); !ok || !v {
		t.Fatalf("expected CONFIG_MODULE_SIG_FORCE=y, got %v,%v", v, ok)
	}
	if v, ok := kernelConfigBool("# CONFIG_MODULE_SIG_FORCE is not set\n", "CONFIG_MODULE_SIG_FORCE"); !ok || v {
		t.Fatalf("expected disabled config, got %v,%v", v, ok)
	}
}

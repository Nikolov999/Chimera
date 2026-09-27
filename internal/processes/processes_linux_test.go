//go:build linux

package processes

import "testing"

func TestLinuxCapabilityNamesAndPrivilegeExcess(t *testing.T) {
	// CAP_SYS_ADMIN is bit 21.
	st := linuxStatus{uid: "1000", euid: "1000", gid: "1000", egid: "1000", capEff: "0000000000200000", capPrm: "0000000000200000"}
	ctx := linuxRuntimePrivilege(88, st)
	if ctx.State != "EXCESS" || len(ctx.HighImpactPrivileges) != 1 || ctx.HighImpactPrivileges[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("unexpected privilege context: %#v", ctx)
	}
}

func TestLinuxPrivilegeRootWithoutTransitionIsElevatedNotExcess(t *testing.T) {
	st := linuxStatus{uid: "0", euid: "0", gid: "0", egid: "0", capEff: "0000000000000000", capPrm: "0000000000000000"}
	ctx := linuxRuntimePrivilege(1, st)
	if ctx.State != "ELEVATED" || ctx.IdentityTransition || len(ctx.ExcessSignals) != 0 {
		t.Fatalf("ordinary root identity should not be labeled excess: %#v", ctx)
	}
}

func TestLinuxExecutableBackingClass(t *testing.T) {
	cases := map[string]string{
		"":                          "anonymous",
		"[heap]":                    "anonymous",
		"[vdso]":                    "special",
		"memfd:jit-cache (deleted)": "anonymous",
		"/usr/lib/libc.so.6":        "file",
	}
	for in, want := range cases {
		if got := linuxExecutableBackingClass(in); got != want {
			t.Fatalf("classify %q: got %q want %q", in, got, want)
		}
	}
}

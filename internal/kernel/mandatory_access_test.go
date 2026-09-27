package kernel

import (
	"reflect"
	"testing"
)

func TestParseLinuxLSMList(t *testing.T) {
	got := parseLinuxLSMList("lockdown,capability,yama,apparmor,bpf,landlock,apparmor\n")
	want := []string{"lockdown", "capability", "yama", "apparmor", "bpf", "landlock"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseLinuxLSMList() = %#v, want %#v", got, want)
	}
}

func TestSummarizeAppArmorProfiles(t *testing.T) {
	total, enforce, complain, other := summarizeAppArmorProfiles("usr.bin.foo (enforce)\nusr.bin.bar (complain)\ncustom (kill)\n")
	if total != 3 || enforce != 1 || complain != 1 || other != 1 {
		t.Fatalf("unexpected AppArmor profile summary: total=%d enforce=%d complain=%d other=%d", total, enforce, complain, other)
	}
}

func TestParseCSRUtilStatus(t *testing.T) {
	state, mode, enabled, ok := parseCSRUtilStatus("System Integrity Protection status: enabled.")
	if !ok || state != "ENABLED" || mode == "" || enabled == nil || !*enabled {
		t.Fatalf("unexpected enabled SIP parse: state=%q mode=%q enabled=%v ok=%v", state, mode, enabled, ok)
	}
	state, _, enabled, ok = parseCSRUtilStatus("System Integrity Protection status: disabled.")
	if !ok || state != "DISABLED" || enabled == nil || *enabled {
		t.Fatalf("unexpected disabled SIP parse: state=%q enabled=%v ok=%v", state, enabled, ok)
	}
}

package processes

import (
	"strings"
	"testing"
)

func TestFix58WindowsTrustCandidatesPrioritizePrivilegedAndDeduplicate(t *testing.T) {
	items := []Process{
		{PID: 10, ExecutablePath: `C:\\Tools\\user.exe`, Principal: Principal{Elevated: false}},
		{PID: 11, ExecutablePath: `C:\\Windows\\System32\\svc.exe`, Principal: Principal{Elevated: true}},
		{PID: 12, ExecutablePath: `c:\\windows\\system32\\SVC.exe`, Principal: Principal{Elevated: false}},
		{PID: 13, ExecutablePath: `C:\\Tools\\other.exe`, Principal: Principal{Elevated: false}},
	}
	got := makeWindowsTrustCandidates(items)
	if len(got) != 3 {
		t.Fatalf("candidate count=%d want 3: %#v", len(got), got)
	}
	if !strings.EqualFold(got[0].Path, `C:\\Windows\\System32\\svc.exe`) || got[0].Priority != 0 {
		t.Fatalf("first candidate must be privileged: %#v", got[0])
	}
	if got[1].Priority != 1 || got[2].Priority != 1 {
		t.Fatalf("non-privileged priorities=%#v", got)
	}
}

func TestFix58WindowsTrustNDJSONPreservesValidRowsAroundMalformedOutput(t *testing.T) {
	raw := []byte("{\"path\":\"C:\\\\a.exe\",\"status\":\"Valid\",\"reason\":\"ok\"}\r\nnot-json\r\n{\"path\":\"C:\\\\b.exe\",\"status\":\"NotSigned\",\"reason\":\"\"}\r\n")
	rows, malformed := decodeWindowsTrustNDJSON(raw)
	if malformed != 1 || len(rows) != 2 {
		t.Fatalf("rows=%#v malformed=%d", rows, malformed)
	}
	if rows[0].Status != "Valid" || rows[1].Status != "NotSigned" {
		t.Fatalf("unexpected statuses: %#v", rows)
	}
}

func TestFix58WindowsTrustBoundaryDoesNotOverwriteCompletedRows(t *testing.T) {
	inv := Inventory{Processes: []Process{
		{PID: 1, ExecutablePath: `C:\\a.exe`, Trust: TrustContext{State: "SIGNED_VALID", Signature: "Valid"}},
		{PID: 2, ExecutablePath: `C:\\b.exe`, Trust: TrustContext{State: "UNKNOWN", Signature: "UNKNOWN"}},
	}}
	completed := map[string]windowsTrustRow{strings.ToLower(`C:\\a.exe`): {Path: `C:\\a.exe`, Status: "Valid"}}
	markWindowsTrustUnresolved(&inv, completed, "safe collection boundary: test")
	if inv.Processes[0].Trust.State != "SIGNED_VALID" {
		t.Fatalf("completed row was overwritten: %#v", inv.Processes[0].Trust)
	}
	if inv.Processes[1].Trust.State != "UNKNOWN" || !strings.Contains(inv.Processes[1].Trust.Reason, "safe collection boundary") {
		t.Fatalf("uncompleted row boundary=%#v", inv.Processes[1].Trust)
	}
}

func TestFix58ApplyWindowsTrustRowNormalizesAuthenticodeStates(t *testing.T) {
	cases := []struct{ status, want string }{
		{"Valid", "SIGNED_VALID"},
		{"NotSigned", "UNSIGNED"},
		{"HashMismatch", "HASH_MISMATCH"},
		{"NotTrusted", "SIGNATURE_UNTRUSTED"},
		{"UnknownError", "UNKNOWN"},
	}
	for _, tc := range cases {
		p := Process{}
		applyWindowsTrustRow(&p, windowsTrustRow{Path: `C:\\x.exe`, Status: tc.status})
		if p.Trust.State != tc.want {
			t.Fatalf("status %q -> %q want %q", tc.status, p.Trust.State, tc.want)
		}
	}
}

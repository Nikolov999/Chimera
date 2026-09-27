//go:build windows

package processes

import (
	"strings"
	"testing"
)

func TestFix17WindowsTokenMergeDoesNotDiscardBaseProcess(t *testing.T) {
	rows := []winProc{{PID: 100, Name: "base.exe"}, {PID: 200, Name: "other.exe"}}
	tokens := []winTokenProc{{PID: 100, TokenAvailable: true, TokenElevated: true, Integrity: "HIGH", EnabledPrivileges: []string{"SeDebugPrivilege"}}}
	mergeWindowsTokenRows(rows, tokens, "")
	if !rows[0].TokenAvailable || !rows[0].TokenElevated || rows[0].Integrity != "HIGH" {
		t.Fatalf("token enrichment was not merged: %#v", rows[0])
	}
	if rows[1].TokenAvailable || !strings.Contains(rows[1].TokenReason, "token record unavailable") {
		t.Fatalf("missing token row must remain a process with unavailable enrichment: %#v", rows[1])
	}
}

func TestFix17WindowsTokenStageFailureIsBoundedPerProcess(t *testing.T) {
	rows := []winProc{{PID: 100, Name: "base.exe"}}
	mergeWindowsTokenRows(rows, nil, strings.Repeat("x", 4096))
	if rows[0].TokenAvailable {
		t.Fatal("failed token stage must not become available")
	}
	if len(rows[0].TokenReason) > 2051 {
		t.Fatalf("provider detail was not bounded: %d", len(rows[0].TokenReason))
	}
}

func TestFix17DecodeWindowsProcessArray(t *testing.T) {
	rows, err := decodeWindowsProcessRows([]byte(`[{"pid":4,"name":"System","state":"RUNNING"}]`))
	if err != nil || len(rows) != 1 || rows[0].PID != 4 {
		t.Fatalf("unexpected decode result: %#v err=%v", rows, err)
	}
}

func TestFix24TokenIdentityEnrichmentMergesWithoutReplacingBaseProcess(t *testing.T) {
	rows := []winProc{{PID: 100, Name: "base.exe", Path: `C:\\base.exe`}}
	tokens := []winTokenProc{{PID: 100, User: "svc", Domain: "HOST", SID: "S-1-5-21-1-2-3-1001", TokenAvailable: true}}
	mergeWindowsTokenRows(rows, tokens, "")
	if rows[0].Name != "base.exe" || rows[0].Path != `C:\\base.exe` {
		t.Fatalf("token enrichment replaced base process fields: %#v", rows[0])
	}
	if rows[0].User != "svc" || rows[0].Domain != "HOST" || rows[0].SID != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("token identity enrichment was not merged: %#v", rows[0])
	}
}

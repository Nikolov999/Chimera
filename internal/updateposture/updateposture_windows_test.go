//go:build windows

package updateposture

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix50WindowsStageFailureClassification(t *testing.T) {
	cases := []struct {
		typ, msg string
		want     evidence.State
	}{
		{"COMMAND_UNAVAILABLE", "Get-WindowsPackage is unavailable", evidence.StateUnavailable},
		{"System.UnauthorizedAccessException", "Access denied", evidence.StateDenied},
		{"System.InvalidOperationException", "servicing stack returned an error", evidence.StateDegraded},
	}
	for _, tc := range cases {
		if got := windowsStageFailureState(tc.typ, tc.msg); got != tc.want {
			t.Fatalf("windowsStageFailureState(%q,%q)=%s want=%s", tc.typ, tc.msg, got, tc.want)
		}
	}
}

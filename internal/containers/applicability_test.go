package containers

import (
	"runtime"
	"strings"
	"testing"
)

func TestLocalInstanceCollectionApplicability(t *testing.T) {
	ok, reason := localInstanceCollectionApplicable("containerd")
	if runtime.GOOS == "linux" {
		if !ok || reason != "" {
			t.Fatalf("linux containerd applicability=(%v,%q)", ok, reason)
		}
	} else {
		if ok || !strings.Contains(strings.ToLower(reason), "not applicable") {
			t.Fatalf("non-linux containerd applicability=(%v,%q)", ok, reason)
		}
	}
}

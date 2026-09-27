package filesystem

import "testing"

func TestPhase080ClassifyTempCandidate(t *testing.T) {
	cases := []struct {
		path, source, scope string
		shared              bool
	}{
		{"/tmp", "Linux temporary area", TempScopeSharedSystem, true},
		{"/dev/shm", "Linux shared-memory temporary area", TempScopeSharedMemory, true},
		{"/home/alice/.cache/tmp", "process environment / os.TempDir", TempScopeProcess, false},
	}
	for _, tc := range cases {
		scope, shared := classifyTempCandidate(tc.path, tc.source)
		if scope != tc.scope || shared != tc.shared {
			t.Fatalf("%s: got %s/%t want %s/%t", tc.path, scope, shared, tc.scope, tc.shared)
		}
	}
}

func TestPhase080TempDirectoryNormalizationDeterministic(t *testing.T) {
	in := []TempDirectoryRecord{
		{Path: "/var/tmp", Scope: TempScopeSharedSystem, State: "OBSERVED", PermissionModel: "POSIX_MODE", DiscoverySources: []string{"b"}, CollectionSource: "test", Confidence: "HIGH"},
		{Path: "/tmp", Scope: TempScopeSharedSystem, State: "OBSERVED", PermissionModel: "POSIX_MODE", DiscoverySources: []string{"a"}, CollectionSource: "test", Confidence: "HIGH"},
	}
	out := normalizeTempDirectories(in)
	if len(out) != 2 || out[0].Path != "/tmp" || out[1].Path != "/var/tmp" {
		t.Fatalf("unexpected order: %#v", out)
	}
	if out[0].ID == "" || out[1].ID == "" || out[0].ID == out[1].ID {
		t.Fatalf("invalid stable ids: %#v", out)
	}
}

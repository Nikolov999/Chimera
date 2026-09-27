//go:build linux

package processes

import "testing"

func TestLinuxExecutionLocationClassification(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		check func(LocationContext) bool
	}{
		{"system", "/usr/bin/sshd", func(c LocationContext) bool { return c.State == "NORMAL" && !c.WeakControl }},
		{"temp", "/tmp/agent", func(c LocationContext) bool { return c.State == "WEAK" && c.Temporary && c.UserWritable }},
		{"downloads", "/home/alice/Downloads/tool", func(c LocationContext) bool { return c.Downloads && c.UserWritable && c.WeakControl }},
		{"home", "/home/alice/bin/tool", func(c LocationContext) bool { return c.UserWritable && c.WeakControl && !c.Downloads }},
		{"removable", "/run/media/alice/USB/tool", func(c LocationContext) bool { return c.Removable && c.WeakControl }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Process{ID: "proc-test", PID: 10, ExecutablePath: tc.path}
			got := classifyExecutionLocation(p, "linux")
			if !tc.check(got) {
				t.Fatalf("unexpected classification for %s: %#v", tc.path, got)
			}
		})
	}
}

func TestExecutionLocationPreservesDeletedBacking(t *testing.T) {
	p := Process{ID: "proc-deleted", PID: 11, ExecutablePath: "/usr/bin/tool", Trust: TrustContext{DeletedBacking: true}}
	got := classifyExecutionLocation(p, "linux")
	if got.State != "WEAK" || !got.DeletedBacking || !got.WeakControl {
		t.Fatalf("deleted backing was not preserved: %#v", got)
	}
}

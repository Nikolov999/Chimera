//go:build linux

package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSystemdUnitFileNames(t *testing.T) {
	got := parseSystemdUnitFileNames("ssh.service enabled enabled\nfoo@.service indirect enabled\ncron.service disabled enabled\nssh.service enabled enabled\n")
	if len(got) != 2 || got[0] != "cron.service" || got[1] != "ssh.service" {
		t.Fatalf("unexpected names: %#v", got)
	}
}

func TestParseSystemdShow(t *testing.T) {
	raw := `Id=ssh.service
Description=OpenSSH server
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
MainPID=321
User=
Group=
ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; }
FragmentPath=/usr/lib/systemd/system/ssh.service
SourcePath=
Type=notify

Id=demo.service
Description=Demo
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=disabled
MainPID=0
User=demo
Group=demo
ExecStart={ path=/opt/demo/bin/demo ; argv[]=/opt/demo/bin/demo ; }
FragmentPath=/etc/systemd/system/demo.service
SourcePath=
Type=simple
`
	got := parseSystemdShow(raw)
	if len(got) != 2 {
		t.Fatalf("expected two services, got %#v", got)
	}
	if got[0].Name != "ssh.service" || got[0].ExecutablePath != "/usr/sbin/sshd" || got[0].RuntimePID != 321 || got[0].RuntimeState != "RUNNING" || got[0].Account != "root" || got[0].PrivilegeContext != "ROOT" {
		t.Fatalf("unexpected ssh service: %#v", got[0])
	}
	if got[1].StartMode != "disabled" || got[1].RuntimeState != "STOPPED" || got[1].Account != "demo" {
		t.Fatalf("unexpected demo service: %#v", got[1])
	}
}

func TestParseSystemdUnitFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.service")
	data := `[Unit]
Description=Demo Service
[Service]
Type=simple
User=svc-demo
Group=svc-demo
ExecStart=/opt/demo/bin/demo --foreground
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseSystemdUnitFile(path, "demo.service")
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "Demo Service" || got.ExecutablePath != "/opt/demo/bin/demo" || got.Account != "svc-demo" || got.ServiceType != "simple" {
		t.Fatalf("unexpected service: %#v", got)
	}
}

func TestSystemdExecPath(t *testing.T) {
	cases := map[string]string{
		`{ path=/usr/bin/example ; argv[]=/usr/bin/example --x ; }`: "/usr/bin/example",
		`/opt/demo/bin/demo --foreground`:                           "/opt/demo/bin/demo",
		`"/opt/My Tool/tool" --run`:                                 "/opt/My Tool/tool",
		``:                                                          "",
	}
	for in, want := range cases {
		if got := systemdExecPath(in); got != want {
			t.Fatalf("systemdExecPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseSystemdShowIncludesPhase045Hardening(t *testing.T) {
	raw := `Id=locked.service
Description=Locked service
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
MainPID=777
User=svc-locked
Group=svc-locked
ExecStart={ path=/usr/local/bin/locked ; argv[]=/usr/local/bin/locked ; }
FragmentPath=/etc/systemd/system/locked.service
SourcePath=
Type=simple
DynamicUser=no
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=disconnected
PrivateDevices=yes
PrivateNetwork=no
CapabilityBoundingSet=cap_net_bind_service
AmbientCapabilities=
RestrictNamespaces=~user
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0027
`
	got := parseSystemdShow(raw)
	if len(got) != 1 || got[0].SystemdHardening == nil {
		t.Fatalf("expected one hardened systemd service: %#v", got)
	}
	h := got[0].SystemdHardening
	if h.State != "COMPLETE" || h.User != "svc-locked" || !h.UserConfigured || h.NoNewPrivileges != "YES" || h.ProtectSystem != "STRICT" || h.ProtectHome != "READ_ONLY" || h.PrivateTmp != "DISCONNECTED" {
		t.Fatalf("unexpected primary hardening posture: %#v", h)
	}
	if h.CapabilityBoundingSetState != "RESTRICTED" || h.RestrictNamespacesState != "RESTRICTED" || len(h.AmbientCapabilities) != 0 || h.ProtectKernelModules != "YES" || h.MemoryDenyWriteExecute != "YES" || h.UMask != "0027" {
		t.Fatalf("unexpected isolation/capability posture: %#v", h)
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("hardening validation failed: %v", err)
	}
}

func TestParseSystemdUnitFileHardeningIsConservativelyDegraded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hardened.service")
	data := `[Unit]
Description=Hardened Service
[Service]
Type=simple
User=svc-demo
ExecStart=/opt/demo/bin/demo
NoNewPrivileges=yes
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseSystemdUnitFile(path, "hardened.service")
	if err != nil {
		t.Fatal(err)
	}
	if got.SystemdHardening == nil {
		t.Fatal("expected systemd hardening metadata")
	}
	h := got.SystemdHardening
	if h.State != "DEGRADED" || h.NoNewPrivileges != "YES" || h.ProtectSystem != "STRICT" || h.CapabilityBoundingSetState != "RESTRICTED" {
		t.Fatalf("unexpected direct-file posture: %#v", h)
	}
	if h.ProtectHome != "UNKNOWN" || h.PrivateTmp != "UNKNOWN" || h.RestrictNamespacesState != "UNKNOWN" {
		t.Fatalf("absent direct-file directives must remain unknown: %#v", h)
	}
}

func TestCapabilitySetStateRecognizesBroadDefaultLikeSet(t *testing.T) {
	caps := []string{
		"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid",
		"cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin", "cap_net_raw", "cap_ipc_lock",
		"cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin",
	}
	if got := capabilitySetState(caps, strings.Join(caps, " ")); got != "UNRESTRICTED" {
		t.Fatalf("broad default-like capability set classified as %q", got)
	}
	if got := capabilitySetState([]string{"cap_net_bind_service"}, "cap_net_bind_service"); got != "RESTRICTED" {
		t.Fatalf("narrow capability set classified as %q", got)
	}
}

func TestFix62SystemdLifecycleExecutableFallsBackWhenExecStartMissing(t *testing.T) {
	values := map[string]string{
		"ExecStart":    "",
		"ExecStartPre": "{ path=/usr/lib/example/prepare ; argv[]=/usr/lib/example/prepare --ready ; }",
		"ExecStop":     "{ path=/usr/lib/example/stop ; argv[]=/usr/lib/example/stop ; }",
	}
	if got := systemdLifecycleExecPath(values); got != "/usr/lib/example/prepare" {
		t.Fatalf("lifecycle executable=%q want ExecStartPre fallback", got)
	}
}

func TestFix63SystemdLifecycleExecutableIncludesExecCondition(t *testing.T) {
	values := map[string]string{
		"ExecStart":     "",
		"ExecCondition": "{ path=/usr/lib/example/check ; argv[]=/usr/lib/example/check --ready ; }",
	}
	if got := systemdLifecycleExecPath(values); got != "/usr/lib/example/check" {
		t.Fatalf("lifecycle executable=%q want ExecCondition fallback", got)
	}
}

func TestFix64SystemdExecTokenStripsInvocationPrefixes(t *testing.T) {
	for raw, want := range map[string]string{
		"-/usr/bin/true --quiet": "/usr/bin/true",
		"!!/usr/bin/false":       "/usr/bin/false",
		"@:/usr/bin/echo hello":  "/usr/bin/echo",
	} {
		if got := systemdExecPath(raw); got != want {
			t.Fatalf("systemdExecPath(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestFix62ParseSystemdShowUsesLifecycleExecutableFallback(t *testing.T) {
	raw := `Id=cleanup.service
Description=Cleanup
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=static
MainPID=0
User=
Group=
ExecStart=
ExecStartPre=
ExecStartPost=
ExecReload=
ExecStop={ path=/usr/bin/true ; argv[]=/usr/bin/true ; }
ExecStopPost=
FragmentPath=/usr/lib/systemd/system/cleanup.service
SourcePath=
Type=oneshot

`
	got := parseSystemdShow(raw)
	if len(got) != 1 || got[0].ExecutablePath != "/usr/bin/true" {
		t.Fatalf("unexpected lifecycle fallback parse: %#v", got)
	}
}

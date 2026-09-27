package containers

import "testing"

func TestParseRuntimeInspectPrivilegedSecurityPosture(t *testing.T) {
	raw := `[{
		"Id":"abcdef0123456789",
		"Name":"/web",
		"Config":{"User":""},
		"HostConfig":{
			"Privileged":true,
			"PidMode":"host",
			"NetworkMode":"host",
			"UsernsMode":"host",
			"CapAdd":["SYS_ADMIN","NET_BIND_SERVICE"],
			"CapDrop":[],
			"SecurityOpt":["seccomp=unconfined","apparmor=unconfined"],
			"ReadonlyRootfs":false,
			"NoNewPrivileges":false,
			"Devices":[{"PathOnHost":"/dev/kvm","PathInContainer":"/dev/kvm","CgroupPermissions":"rwm"}],
			"DeviceCgroupRules":["a *:* rwm"]
		}
	}]`
	got, err := parseRuntimeInspect("docker", raw, "REMAPPED")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("security records=%d", len(got))
	}
	p := got[0]
	if p.PrivilegedState != "TRUE" || p.RootExecutionState != "TRUE" || p.PIDNamespace != "HOST" || p.NetworkNamespace != "HOST" || p.UserNamespace != "HOST" {
		t.Fatalf("unexpected privileged posture: %#v", p)
	}
	if p.CapabilityAssessmentState != "OBSERVED" || len(p.DangerousCapabilities) != 1 || p.DangerousCapabilities[0] != "SYS_ADMIN" || p.CapabilityBoundingState != "UNBOUNDED" {
		t.Fatalf("unexpected capabilities: %#v", p)
	}
	if p.SeccompState != "UNCONFINED" || p.MandatoryAccessControlState != "UNCONFINED" || p.ReadOnlyRootFSState != "FALSE" || p.NoNewPrivilegesState != "FALSE" {
		t.Fatalf("unexpected isolation controls: %#v", p)
	}
	if p.DeviceCount != 1 || p.DeviceCgroupRuleCount != 1 || p.UnrestrictedDeviceAccessState != "TRUE" {
		t.Fatalf("unexpected device posture: %#v", p)
	}
}

func TestParseRuntimeInspectUsesDefaultUserNamespaceAndNonRoot(t *testing.T) {
	raw := `[{
		"Id":"1234567890abcdef",
		"Name":"worker",
		"Config":{"User":"10001:10001"},
		"AppArmorProfile":"docker-default",
		"HostConfig":{
			"Privileged":false,
			"PidMode":"",
			"NetworkMode":"bridge",
			"UsernsMode":"",
			"CapAdd":null,
			"CapDrop":["ALL"],
			"SecurityOpt":["no-new-privileges"],
			"ReadonlyRootfs":true,
			"Devices":null,
			"DeviceCgroupRules":null
		}
	}]`
	got, err := parseRuntimeInspect("docker", raw, "REMAPPED")
	if err != nil {
		t.Fatal(err)
	}
	p := got[0]
	if p.PrivilegedState != "FALSE" || p.RootExecutionState != "FALSE" || p.PIDNamespace != "PRIVATE" || p.NetworkNamespace != "PRIVATE" || p.UserNamespace != "REMAPPED" {
		t.Fatalf("unexpected isolated posture: %#v", p)
	}
	if p.CapabilityAssessmentState != "OBSERVED" || len(p.DangerousCapabilities) != 0 || p.CapabilityBoundingState != "REDUCED" || p.UnrestrictedDeviceAccessState != "FALSE" {
		t.Fatalf("unexpected least-privilege posture: %#v", p)
	}
	if p.SeccompState != "DEFAULT" || p.MandatoryAccessControlState != "ENFORCED" || p.ReadOnlyRootFSState != "TRUE" || p.NoNewPrivilegesState != "TRUE" {
		t.Fatalf("unexpected hardened isolation controls: %#v", p)
	}
}

func TestUnrestrictedDeviceRuleDetectionIsExact(t *testing.T) {
	if !hasUnrestrictedDeviceRule([]string{"a *:* rwm"}) {
		t.Fatal("expected wildcard all-device rule to be detected")
	}
	if hasUnrestrictedDeviceRule([]string{"c 10:200 rwm", "a *:* r"}) {
		t.Fatal("specific/read-only device rules must not be called unrestricted")
	}
}

func TestParseRuntimeInspectDangerousMountPosture(t *testing.T) {
	raw := `[{
        "Id":"mount-test",
        "Name":"/builder",
        "Config":{"User":"1000"},
        "HostConfig":{"Privileged":false,"PidMode":"","NetworkMode":"bridge","UsernsMode":"private","CapAdd":[],"Devices":[],"DeviceCgroupRules":[]},
        "Mounts":[
            {"Type":"bind","Source":"/","Destination":"/host","RW":false,"Propagation":"rprivate"},
            {"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":false},
            {"Type":"bind","Source":"/home/alice/.ssh","Destination":"/keys","RW":false},
            {"Type":"bind","Source":"/dev/kvm","Destination":"/dev/kvm","RW":true},
            {"Type":"bind","Source":"/etc/kubernetes","Destination":"/host-kube","RW":false},
            {"Type":"volume","Source":"appdata","Destination":"/data","RW":true}
        ]
    }]`
	got, err := parseRuntimeInspect("docker", raw, "REMAPPED")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("records=%d", len(got))
	}
	p := got[0]
	if p.MountAssessmentState != "OBSERVED" || p.MountCount != 6 || p.MountsTruncated {
		t.Fatalf("unexpected mount inventory: %#v", p)
	}
	if p.HostRootMountState != "TRUE" || p.RuntimeSocketMountState != "TRUE" || p.CredentialMountState != "TRUE" || p.DeviceMountState != "TRUE" || p.SensitiveHostPathMountState != "TRUE" {
		t.Fatalf("dangerous mount classification missing: %#v", p)
	}
	for _, m := range p.Mounts {
		if m.Type == "volume" && len(m.RiskTags) != 0 {
			t.Fatalf("named volume misclassified: %#v", m)
		}
	}
}

func TestMandatoryAccessControlPostureDetectsDirectUnconfinedProfile(t *testing.T) {
	if got := mandatoryAccessControlPosture("docker", nil, true, "unconfined", true, "", true); got != "UNCONFINED" {
		t.Fatalf("mandatory access state=%s", got)
	}
}

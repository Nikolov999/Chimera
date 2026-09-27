//go:build linux

package firewall

import "testing"

func TestParseIPTablesDefaults(t *testing.T) {
	in, out, fwd, rules, seen := parseIPTables("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n")
	if !seen || in != "DROP" || out != "ACCEPT" || fwd != "DROP" || rules != 1 {
		t.Fatalf("unexpected parse: %q %q %q %d %t", in, out, fwd, rules, seen)
	}
}
func TestParseUFWDefaults(t *testing.T) {
	e, in, out, fwd, log := parseUFW("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
	if e != "ENABLED" || in != "DENY" || out != "ALLOW" || fwd != "DISABLED" || log != "on (low)" {
		t.Fatalf("unexpected parse: %q %q %q %q %q", e, in, out, fwd, log)
	}
}
func TestParseNFTRulesetBaseChains(t *testing.T) {
	p, tables, chains, rules := parseNFTRuleset("table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n ct state established accept\n }\n chain output {\n type filter hook output priority 0; policy accept;\n }\n}\n")
	if tables != 1 || chains != 2 || len(p) != 2 || rules != 1 {
		t.Fatalf("unexpected nft parse tables=%d chains=%d policies=%#v rules=%d", tables, chains, p, rules)
	}
	if p[0].DefaultInbound != "DROP" || p[1].DefaultOutbound != "ACCEPT" {
		t.Fatalf("unexpected policies: %#v", p)
	}
}

func TestParseActiveFirewalldZones(t *testing.T) {
	got := parseActiveFirewalldZones("public\n  interfaces: eth0\ndocker\n  interfaces: docker0\n")
	if len(got) != 2 || got[0] != "docker" || got[1] != "public" {
		t.Fatalf("unexpected active zones: %#v", got)
	}
}

func TestParseIPTablesRestrictionsPhase058(t *testing.T) {
	out := `-P INPUT DROP
-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 8080 -j ACCEPT
-A FORWARD -p tcp --dport 443 -j ACCEPT`
	rules := parseIPTablesRestrictions(out, "iptables", "ipv4")
	if len(rules) != 2 {
		t.Fatalf("rules=%#v", rules)
	}
	if rules[0].Protocol != "TCP" || len(rules[0].LocalPorts) != 1 || rules[0].LocalPorts[0].Start != 22 || rules[0].Action != "ACCEPT" || len(rules[0].RemoteAddresses) != 1 {
		t.Fatalf("first=%#v", rules[0])
	}
}

func TestParseNFTRestrictionsPhase058(t *testing.T) {
	out := `table inet filter {
 chain input {
  type filter hook input priority 0; policy drop;
  ip saddr 10.0.0.0/8 tcp dport 22 accept
  tcp dport 8080 accept
 }
}`
	rules := parseNFTRestrictions(out)
	if len(rules) != 2 {
		t.Fatalf("rules=%#v", rules)
	}
	if rules[0].Protocol != "TCP" || rules[0].LocalPorts[0].Start != 22 || rules[0].Action != "ACCEPT" {
		t.Fatalf("first=%#v", rules[0])
	}
}

func TestParseUFWRestrictionsPhase058(t *testing.T) {
	out := `Status: active

[ 1] 22/tcp                     ALLOW IN    10.0.0.0/8
[ 2] 8080/tcp                   DENY IN     Anywhere`
	rules := parseUFWRestrictions(out)
	if len(rules) != 2 {
		t.Fatalf("rules=%#v", rules)
	}
	if rules[0].LocalPorts[0].Start != 22 || rules[0].Action != "ALLOW" || rules[0].RemoteAddresses[0] != "10.0.0.0/8" {
		t.Fatalf("first=%#v", rules[0])
	}
}

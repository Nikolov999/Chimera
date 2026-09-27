package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
)

// SSHSecurityRules implements over local sshd configuration,
// filesystem permission metadata, and sshd -T effective configuration where
// available. The rules never connect to an SSH endpoint or authenticate.
func SSHSecurityRules() []Rule {
	return []Rule{
		{
			ID: "CHM-NET-020", Title: "Direct SSH root login is restricted", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.ssh.root_login", ExpectedState: "PermitRootLogin is disabled; at minimum password-based root login is prohibited",
			Risk:        "Direct remote root login removes a user-to-privilege separation boundary and increases the impact of stolen or guessed authentication material.",
			Remediation: "Set PermitRootLogin no where operationally possible. If direct root key access is required, constrain it explicitly and avoid password-based root login.",
			Evaluate:    evaluateSSHRootLogin,
		},
		{
			ID: "CHM-NET-021", Title: "SSH password authentication is hardened", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.ssh.password_authentication", ExpectedState: "empty-password authentication is disabled and password/interactive authentication is disabled or explicitly justified",
			Risk:        "Password and keyboard-interactive SSH authentication increase exposure to credential guessing, password reuse, and stolen-password attacks. Empty-password authentication is materially unsafe.",
			Remediation: "Set PermitEmptyPasswords no. Prefer public-key or other strong authentication and disable PasswordAuthentication and keyboard-interactive authentication where they are not required.",
			Evaluate:    evaluateSSHPasswordAuthentication,
		},
		{
			ID: "CHM-NET-022", Title: "SSH daemon configuration resists untrusted modification", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.ssh.configuration_permissions", ExpectedState: "sshd configuration and included files are owned by a trusted administrative principal and are not broadly writable",
			Risk:        "A lower-privilege user who can modify sshd configuration can weaken authentication, forwarding, algorithm, or access controls before the daemon is restarted or reloaded.",
			Remediation: "Restrict sshd configuration ownership to the platform administrative boundary and remove group/world or broad low-privilege write grants from the main configuration and included files.",
			Evaluate:    evaluateSSHConfigPermissions,
		},
		{
			ID: "CHM-NET-023", Title: "SSH forwarding capabilities are constrained", Category: "network", Severity: SeverityMedium,
			AffectedObject: "network.ssh.forwarding", ExpectedState: "remote forwarding cannot expose listeners broadly and unused forwarding/tunneling capabilities are disabled",
			Risk:        "Broad TCP forwarding, agent forwarding, X11 forwarding, tunnels, or permissive GatewayPorts can turn an SSH account into a path around intended network boundaries.",
			Remediation: "Disable unused forwarding features. Set GatewayPorts no unless explicitly required, and constrain AllowTcpForwarding, AllowAgentForwarding, X11Forwarding, and PermitTunnel to operational need.",
			Evaluate:    evaluateSSHForwarding,
		},
		{
			ID: "CHM-NET-024", Title: "SSH algorithm policy excludes known weak choices", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.ssh.algorithms", ExpectedState: "effective SSH ciphers, MACs, key-exchange algorithms, and host-key algorithms exclude known legacy/weak choices",
			Risk:        "Legacy SSH cryptographic algorithms can weaken transport integrity, confidentiality, or server authentication and may preserve compatibility with obsolete clients at unnecessary security cost.",
			Remediation: "Remove legacy CBC/RC4/3DES ciphers, MD5/SHA-1 MACs, SHA-1 Diffie-Hellman groups, ssh-dss, and SHA-1 ssh-rsa host-key algorithms unless a documented compatibility exception exists.",
			Evaluate:    evaluateSSHAlgorithms,
		},
	}
}

func sshApplicability(idx Index) (applicable bool, unavailable bool, evKeys []string) {
	key := "ssh_security.applicability"
	o, ok := idx[key]
	if !ok {
		return false, true, []string{key}
	}
	if o.State == evidence.StateNotApplicable {
		return false, false, []string{key}
	}
	if o.State != evidence.StateObserved {
		return false, true, []string{key}
	}
	return true, false, []string{key}
}

func sshNotApplicableOrUnknown(idx Index) *Evaluation {
	applicable, unavailable, keys := sshApplicability(idx)
	if !applicable && !unavailable {
		return &Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "local SSH daemon/configuration not detected", Applicability: NotApplicable, EvidenceKeys: keys}
	}
	if unavailable {
		return &Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SSH applicability evidence is unavailable", Applicability: Undetermined, EvidenceKeys: keys}
	}
	return nil
}

func sshSetting(idx Index, name string) (remotemgmt.SSHSetting, evidence.Observation, bool) {
	key := "ssh_security.setting." + strings.ToLower(name)
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return remotemgmt.SSHSetting{}, o, false
	}
	v, ok := o.Value.(remotemgmt.SSHSetting)
	return v, o, ok
}

func evaluateSSHRootLogin(idx Index) Evaluation {
	if early := sshNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	key := "ssh_security.setting.permitrootlogin"
	s, o, ok := sshSetting(idx, "permitrootlogin")
	if !ok {
		conf := evidence.ConfidenceLow
		state := "PermitRootLogin effective state unavailable"
		if o.State != "" {
			conf = o.Confidence
			state = observedText(o)
		}
		return Evaluation{Status: StatusUnknown, Confidence: conf, ObservedState: state, Applicability: Applicable, EvidenceKeys: []string{"ssh_security.applicability", key}}
	}
	switch strings.ToLower(strings.TrimSpace(s.Value)) {
	case "no":
		return Evaluation{Status: StatusPass, Confidence: s.Confidence, ObservedState: "PermitRootLogin no", Applicability: Applicable, EvidenceKeys: []string{"ssh_security.applicability", key}}
	case "prohibit-password", "without-password", "forced-commands-only":
		return Evaluation{Status: StatusWarn, Confidence: s.Confidence, ObservedState: "PermitRootLogin " + s.Value + "; direct root access remains possible under constrained authentication", Applicability: Applicable, EvidenceKeys: []string{"ssh_security.applicability", key}}
	case "yes":
		return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "PermitRootLogin yes", Applicability: Applicable, EvidenceKeys: []string{"ssh_security.applicability", key}}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: s.Confidence, ObservedState: "unrecognized PermitRootLogin value: " + s.Value, Applicability: Applicable, EvidenceKeys: []string{"ssh_security.applicability", key}}
	}
}

func evaluateSSHPasswordAuthentication(idx Index) Evaluation {
	if early := sshNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	names := []string{"permitemptypasswords", "passwordauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication"}
	keys := []string{"ssh_security.applicability"}
	values := map[string]string{}
	confidence := evidence.ConfidenceExact
	observed := 0
	for _, name := range names {
		key := "ssh_security.setting." + name
		keys = append(keys, key)
		s, _, ok := sshSetting(idx, name)
		if !ok {
			continue
		}
		observed++
		values[name] = strings.ToLower(strings.TrimSpace(s.Value))
		confidence = lowerConfidence(confidence, s.Confidence)
	}
	if observed == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SSH authentication settings are unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	if values["permitemptypasswords"] == "yes" {
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: "PermitEmptyPasswords yes", Applicability: Applicable, EvidenceKeys: keys}
	}
	password := values["passwordauthentication"] == "yes"
	interactive := values["kbdinteractiveauthentication"] == "yes" || values["challengeresponseauthentication"] == "yes"
	if password || interactive {
		enabled := []string{}
		if password {
			enabled = append(enabled, "password authentication")
		}
		if interactive {
			enabled = append(enabled, "keyboard-interactive/challenge-response authentication")
		}
		return Evaluation{Status: StatusWarn, Confidence: confidence, ObservedState: strings.Join(enabled, " and ") + " enabled", Applicability: Applicable, EvidenceKeys: keys}
	}
	if values["passwordauthentication"] == "no" && (values["kbdinteractiveauthentication"] == "no" || values["challengeresponseauthentication"] == "no") {
		return Evaluation{Status: StatusPass, Confidence: confidence, ObservedState: "password and interactive authentication are disabled; empty passwords are not enabled", Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusUnknown, Confidence: lowerConfidence(confidence, evidence.ConfidenceMedium), ObservedState: "SSH authentication controls are only partially resolved", Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSSHConfigPermissions(idx Index) Evaluation {
	if early := sshNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"ssh_security.applicability"}
	weakWrite, weakOwner, unavailable, observed := 0, 0, 0, 0
	confidence := evidence.ConfidenceExact
	for key, o := range idx {
		if !strings.HasPrefix(key, "ssh_security.file.") {
			continue
		}
		keys = append(keys, key)
		if o.State != evidence.StateObserved {
			unavailable++
			confidence = lowerConfidence(confidence, o.Confidence)
			continue
		}
		f, ok := o.Value.(remotemgmt.SSHFilePosture)
		if !ok {
			unavailable++
			confidence = lowerConfidence(confidence, evidence.ConfidenceLow)
			continue
		}
		observed++
		confidence = lowerConfidence(confidence, f.Confidence)
		if f.BroadlyWritable {
			weakWrite++
		}
		if !f.TrustedOwner {
			weakOwner++
		}
	}
	sort.Strings(keys)
	if weakWrite > 0 {
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: fmt.Sprintf("%d SSH configuration file(s) are broadly writable", weakWrite), Applicability: Applicable, EvidenceKeys: keys}
	}
	if weakOwner > 0 {
		return Evaluation{Status: StatusWarn, Confidence: confidence, ObservedState: fmt.Sprintf("%d SSH configuration file(s) are not owned by a trusted administrative principal", weakOwner), Applicability: Applicable, EvidenceKeys: keys}
	}
	if observed == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SSH configuration permission metadata is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	if unavailable > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: lowerConfidence(confidence, evidence.ConfidenceMedium), ObservedState: fmt.Sprintf("%d SSH configuration file(s) are secure in observed metadata; %d file posture record(s) are unresolved", observed, unavailable), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: confidence, ObservedState: fmt.Sprintf("%d SSH configuration file(s) have trusted ownership and no broad write grants", observed), Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSSHForwarding(idx Index) Evaluation {
	if early := sshNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	names := []string{"gatewayports", "allowtcpforwarding", "allowagentforwarding", "x11forwarding", "permittunnel"}
	keys := []string{"ssh_security.applicability"}
	values := map[string]string{}
	confidence := evidence.ConfidenceExact
	observed := 0
	for _, name := range names {
		key := "ssh_security.setting." + name
		keys = append(keys, key)
		s, _, ok := sshSetting(idx, name)
		if !ok {
			continue
		}
		observed++
		values[name] = strings.ToLower(strings.TrimSpace(s.Value))
		confidence = lowerConfidence(confidence, s.Confidence)
	}
	if observed == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SSH forwarding controls are unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	if values["gatewayports"] == "yes" || values["gatewayports"] == "clientspecified" {
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: "GatewayPorts " + values["gatewayports"] + " permits remote forwards to bind beyond loopback", Applicability: Applicable, EvidenceKeys: keys}
	}
	broad := []string{}
	if v := values["allowtcpforwarding"]; v == "yes" || v == "all" || v == "remote" || v == "local" {
		broad = append(broad, "TCP forwarding="+v)
	}
	if values["allowagentforwarding"] == "yes" {
		broad = append(broad, "agent forwarding")
	}
	if values["x11forwarding"] == "yes" {
		broad = append(broad, "X11 forwarding")
	}
	if v := values["permittunnel"]; v == "yes" || v == "point-to-point" || v == "ethernet" {
		broad = append(broad, "tunnel="+v)
	}
	if len(broad) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: confidence, ObservedState: "enabled forwarding capabilities: " + strings.Join(broad, ", "), Applicability: Applicable, EvidenceKeys: keys}
	}
	if observed < len(names) {
		return Evaluation{Status: StatusUnknown, Confidence: lowerConfidence(confidence, evidence.ConfidenceMedium), ObservedState: "observed forwarding controls are constrained but some effective settings are unresolved", Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: confidence, ObservedState: "SSH forwarding/tunneling controls are constrained", Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSSHAlgorithms(idx Index) Evaluation {
	if early := sshNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"ssh_security.applicability"}
	weak := []string{}
	observed, unavailable := 0, 0
	confidence := evidence.ConfidenceExact
	for key, o := range idx {
		if !strings.HasPrefix(key, "ssh_security.algorithms.") {
			continue
		}
		keys = append(keys, key)
		if o.State != evidence.StateObserved {
			unavailable++
			confidence = lowerConfidence(confidence, o.Confidence)
			continue
		}
		a, ok := o.Value.(remotemgmt.SSHAlgorithmPosture)
		if !ok {
			unavailable++
			confidence = lowerConfidence(confidence, evidence.ConfidenceLow)
			continue
		}
		observed++
		confidence = lowerConfidence(confidence, a.Confidence)
		for _, v := range a.Weak {
			weak = append(weak, a.Family+":"+v)
		}
	}
	sort.Strings(keys)
	sort.Strings(weak)
	if len(weak) > 0 {
		sample := weak
		if len(sample) > 8 {
			sample = sample[:8]
		}
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: fmt.Sprintf("%d known weak SSH algorithm choice(s) enabled: %s", len(weak), strings.Join(sample, ", ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if observed == 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "effective SSH algorithm policy is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	if unavailable > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: lowerConfidence(confidence, evidence.ConfidenceMedium), ObservedState: fmt.Sprintf("no weak algorithms observed in %d resolved family/families; %d family/families unresolved", observed, unavailable), Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: confidence, ObservedState: fmt.Sprintf("%d SSH algorithm family/families resolved with no known weak choices", observed), Applicability: Applicable, EvidenceKeys: keys}
}

func lowerConfidence(a, b evidence.Confidence) evidence.Confidence {
	rank := func(c evidence.Confidence) int {
		switch c {
		case evidence.ConfidenceLow:
			return 0
		case evidence.ConfidenceMedium:
			return 1
		case evidence.ConfidenceHigh:
			return 2
		case evidence.ConfidenceExact:
			return 3
		default:
			return 0
		}
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

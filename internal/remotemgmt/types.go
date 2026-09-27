package remotemgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

const (
	SchemaVersion    = "chimera.remote-management/v3"
	CollectorName    = "remote-management"
	CollectorVersion = "remote-management/phase062-v1"
)

type Control struct {
	ID                string              `json:"id"`
	Family            string              `json:"family"`
	Name              string              `json:"name"`
	State             evidence.State      `json:"state"`
	Value             string              `json:"value,omitempty"`
	Source            string              `json:"source"`
	Confidence        evidence.Confidence `json:"confidence"`
	AffectsEnablement bool                `json:"affects_enablement"`
	Reason            string              `json:"reason,omitempty"`
}

type Surface struct {
	ID               string              `json:"id"`
	Family           string              `json:"family"`
	Role             string              `json:"role"`
	ConfiguredState  string              `json:"configured_state"`
	RuntimeState     string              `json:"runtime_state"`
	ListenerState    string              `json:"listener_state"`
	BindingState     string              `json:"binding_state"`
	FirewallCoverage string              `json:"firewall_coverage"`
	ServiceIDs       []string            `json:"service_ids,omitempty"`
	EndpointIDs      []string            `json:"endpoint_ids,omitempty"`
	ControlIDs       []string            `json:"control_ids,omitempty"`
	LocalPorts       []uint16            `json:"local_ports,omitempty"`
	RiskTags         []string            `json:"risk_tags,omitempty"`
	Source           string              `json:"source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type Summary struct {
	Surfaces            int `json:"surfaces"`
	Enabled             int `json:"enabled"`
	Active              int `json:"active"`
	Listening           int `json:"listening"`
	External            int `json:"external"`
	FirewallPresent     int `json:"firewall_present"`
	FirewallAbsent      int `json:"firewall_absent"`
	FirewallAmbiguous   int `json:"firewall_ambiguous"`
	FirewallUnavailable int `json:"firewall_unavailable"`
	Controls            int `json:"controls"`
	ControlsUnavailable int `json:"controls_unavailable"`
}

type Report struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Surfaces         []Surface              `json:"surfaces"`
	Controls         []Control              `json:"controls"`
	SSHSecurity      SSHSecurity            `json:"ssh_security"`
	SMBSecurity      SMBSecurity            `json:"smb_security"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context, svc services.Inventory, net netinv.Inventory, fw firewall.Inventory) Report {
	at := time.Now().UTC()
	r := Report{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at}
	r.Controls = collectPlatformControls(ctx)
	r.Controls = normalizeControls(r.Controls)
	r.Surfaces = deriveSurfaces(svc, net, fw, r.Controls)
	r.SSHSecurity = collectSSHSecurity(ctx, hasSSHSurface(r.Surfaces))
	r.SMBSecurity = collectSMBSecurity(ctx, svc, net)
	r.Summary = summarize(r.Surfaces, r.Controls)
	for _, c := range r.Controls {
		if c.State != evidence.StateObserved && c.State != evidence.StateNotApplicable {
			reason := strings.TrimSpace(c.Reason)
			if reason == "" {
				reason = string(c.State)
			}
			r.Degraded = append(r.Degraded, c.ID+": "+reason)
		}
	}
	r.Degraded = append(r.Degraded, r.SSHSecurity.Degraded...)
	r.Degraded = append(r.Degraded, r.SMBSecurity.Degraded...)
	r.Degraded = uniqueStrings(r.Degraded)
	r.Evidence = buildEvidence(r)
	return r
}

func (r Report) Validate() error {
	if r.Schema != SchemaVersion || r.EvidenceSchema != evidence.SchemaVersion || r.Collector != CollectorName || r.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected remote-management collector contract")
	}
	if r.Platform == "" || r.Architecture == "" || r.CollectedAt.IsZero() {
		return fmt.Errorf("remote-management collector identity is incomplete")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, s := range r.Surfaces {
		if s.ID == "" || s.Family == "" || s.Role == "" || s.ConfiguredState == "" || s.RuntimeState == "" || s.ListenerState == "" || s.BindingState == "" || s.FirewallCoverage == "" || s.Source == "" || s.Confidence == "" {
			return fmt.Errorf("remote-management surface %d is incomplete", i)
		}
		if _, ok := seen[s.ID]; ok {
			return fmt.Errorf("duplicate remote-management surface id %q", s.ID)
		}
		seen[s.ID] = struct{}{}
		if last != "" && s.ID < last {
			return fmt.Errorf("remote-management surfaces are not deterministically ordered")
		}
		last = s.ID
	}
	last = ""
	for i, c := range r.Controls {
		if c.ID == "" || c.Family == "" || c.Name == "" || c.Source == "" || c.State == "" || c.Confidence == "" {
			return fmt.Errorf("remote-management control %d is incomplete", i)
		}
		if c.State != evidence.StateObserved && c.State != evidence.StateNotApplicable && strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("remote-management control %q requires reason", c.ID)
		}
		if last != "" && c.ID < last {
			return fmt.Errorf("remote-management controls are not deterministically ordered")
		}
		last = c.ID
	}
	if r.Summary != summarize(r.Surfaces, r.Controls) {
		return fmt.Errorf("remote-management summary does not match records")
	}
	if err := validateSSHSecurity(r.SSHSecurity); err != nil {
		return fmt.Errorf("validate SSH security posture: %w", err)
	}
	if err := validateSMBSecurity(r.SMBSecurity); err != nil {
		return fmt.Errorf("validate SMB security posture: %w", err)
	}
	return evidence.ValidateAll(r.Evidence)
}

func deriveSurfaces(svc services.Inventory, net netinv.Inventory, fw firewall.Inventory, controls []Control) []Surface {
	type agg struct {
		family, role                  string
		services                      []string
		endpoints                     []string
		ports                         []uint16
		controls                      []string
		serviceEnabled, serviceActive bool
		listener, external, wildcard  bool
		coverage                      []string
		conf                          evidence.Confidence
	}
	m := map[string]*agg{}
	ensure := func(family, role string) *agg {
		if a := m[family]; a != nil {
			return a
		}
		a := &agg{family: family, role: role, conf: evidence.ConfidenceHigh}
		m[family] = a
		return a
	}
	for _, s := range svc.Services {
		family, role, ok := classifyService(s)
		if !ok {
			continue
		}
		a := ensure(family, role)
		a.services = append(a.services, s.ID)
		if serviceEnabled(s) {
			a.serviceEnabled = true
		}
		if serviceActive(s) {
			a.serviceActive = true
		}
		if s.Confidence == evidence.ConfidenceLow {
			a.conf = evidence.ConfidenceLow
		} else if s.Confidence == evidence.ConfidenceMedium && a.conf != evidence.ConfidenceLow {
			a.conf = evidence.ConfidenceMedium
		}
	}
	coverage := map[string]firewall.ListenerCoverage{}
	for _, c := range fw.ListenerCoverage {
		coverage[c.EndpointID] = c
	}
	for _, ep := range net.Endpoints {
		family, role, ok := classifyEndpoint(ep)
		if !ok {
			continue
		}
		a := ensure(family, role)
		a.listener = true
		a.endpoints = append(a.endpoints, ep.ID)
		a.ports = append(a.ports, ep.LocalPort)
		if ep.InterfaceBinding.Class == "ALL_INTERFACES" || ep.InterfaceBinding.Class == "NON_LOOPBACK" {
			a.external = true
		}
		if ep.InterfaceBinding.Class == "ALL_INTERFACES" {
			a.wildcard = true
		}
		if c, ok := coverage[ep.ID]; ok && ep.InterfaceBinding.Class != "LOOPBACK" {
			a.coverage = append(a.coverage, c.State)
		}
		if ep.Confidence == evidence.ConfidenceLow {
			a.conf = evidence.ConfidenceLow
		} else if ep.Confidence == evidence.ConfidenceMedium && a.conf != evidence.ConfidenceLow {
			a.conf = evidence.ConfidenceMedium
		}
	}
	for _, c := range controls {
		a := ensure(c.Family, roleForFamily(c.Family))
		a.controls = append(a.controls, c.ID)
		if c.State != evidence.StateObserved && a.conf != evidence.ConfidenceLow {
			a.conf = evidence.ConfidenceMedium
		}
	}
	out := make([]Surface, 0, len(m))
	for _, a := range m {
		configured := "UNKNOWN"
		explicitEnabled, explicitDisabled := false, false
		for _, id := range a.controls {
			for _, c := range controls {
				if c.ID != id || c.State != evidence.StateObserved || !c.AffectsEnablement {
					continue
				}
				v := strings.ToUpper(strings.TrimSpace(c.Value))
				if v == "ENABLED" || v == "ON" || v == "TRUE" || v == "1" {
					explicitEnabled = true
				}
				if v == "DISABLED" || v == "OFF" || v == "FALSE" || v == "0" {
					explicitDisabled = true
				}
			}
		}
		if explicitEnabled || a.serviceEnabled || a.serviceActive || a.listener {
			configured = "ENABLED"
		} else if explicitDisabled || len(a.services) > 0 {
			configured = "DISABLED"
		}
		runtimeState := "UNKNOWN"
		if a.serviceActive || a.listener {
			runtimeState = "ACTIVE"
		} else if len(a.services) > 0 {
			runtimeState = "INACTIVE"
		}
		listenerState := "ABSENT"
		if a.listener {
			listenerState = "PRESENT"
		}
		binding := "ABSENT"
		if a.listener {
			binding = "LOOPBACK_ONLY"
		}
		if a.external {
			binding = "EXTERNAL"
		}
		if a.wildcard {
			binding = "ALL_INTERFACES"
		}
		fwState := "NOT_APPLICABLE"
		if a.external {
			fwState = aggregateCoverage(a.coverage)
		}
		tags := []string{}
		if configured == "ENABLED" {
			tags = append(tags, "enabled")
		}
		if a.listener {
			tags = append(tags, "listener-present")
		}
		if a.external {
			tags = append(tags, "external-bind")
		}
		if a.wildcard {
			tags = append(tags, "wildcard-bind")
		}
		if fwState == firewall.CoverageAbsent {
			tags = append(tags, "firewall-coverage-absent")
		}
		if fwState == firewall.CoverageAmbiguous || fwState == firewall.CoverageUnavailable {
			tags = append(tags, "firewall-coverage-unresolved")
		}
		for _, p := range a.ports {
			if a.family == "WINRM" && p == 5985 {
				tags = append(tags, "winrm-http-transport")
			}
		}
		for _, id := range a.controls {
			for _, c := range controls {
				if c.ID != id || c.State != evidence.StateObserved {
					continue
				}
				name := strings.ToLower(c.Name)
				value := strings.ToUpper(strings.TrimSpace(c.Value))
				if a.family == "RDP" && strings.Contains(name, "network level authentication") && value == "DISABLED" {
					tags = append(tags, "rdp-nla-disabled")
				}
				if a.family == "WINRM" && strings.Contains(name, "allow unencrypted") && value == "ENABLED" {
					tags = append(tags, "winrm-allow-unencrypted")
				}
				if a.family == "WINRM" && strings.Contains(name, "basic authentication") && value == "ENABLED" {
					tags = append(tags, "winrm-basic-auth-enabled")
				}
			}
		}
		s := Surface{Family: a.family, Role: a.role, ConfiguredState: configured, RuntimeState: runtimeState, ListenerState: listenerState, BindingState: binding, FirewallCoverage: fwState, ServiceIDs: uniqueStrings(a.services), EndpointIDs: uniqueStrings(a.endpoints), ControlIDs: uniqueStrings(a.controls), LocalPorts: uniquePorts(a.ports), RiskTags: uniqueStrings(tags), Source: "/048 services + listeners + firewall correlation + /061 local remote-management configuration", Confidence: a.conf}
		s.ID = stableSurfaceID(s.Family)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func classifyService(s services.Service) (string, string, bool) {
	if s.Exposure != nil && strings.EqualFold(s.Exposure.State, "CLASSIFIED") {
		family := strings.ToUpper(strings.TrimSpace(s.Exposure.Family))
		switch family {
		case "SSH", "RDP", "WINRM", "VNC", "REMOTE_REGISTRY", "COCKPIT":
			return family, roleForFamily(family), true
		}
	}
	text := strings.ToLower(strings.Join([]string{s.Name, s.DisplayName, s.Executable, s.ExecutablePath}, " "))
	switch {
	case strings.Contains(text, "sshd") || strings.Contains(text, "openssh"):
		return "SSH", "REMOTE_ADMIN", true
	case strings.Contains(text, "termservice") || strings.Contains(text, "xrdp"):
		return "RDP", "REMOTE_DESKTOP", true
	case strings.Contains(text, "winrm"):
		return "WINRM", "REMOTE_ADMIN", true
	case strings.Contains(text, "screensharing") || strings.Contains(text, "vnc"):
		return "VNC", "REMOTE_DESKTOP", true
	case strings.Contains(text, "remoteregistry"):
		return "REMOTE_REGISTRY", "REMOTE_ADMIN", true
	case strings.Contains(text, "cockpit"):
		return "COCKPIT", "ADMIN_CONSOLE", true
	}
	return "", "", false
}

func classifyEndpoint(ep netinv.Endpoint) (string, string, bool) {
	text := strings.ToLower(strings.Join([]string{ep.Owner.ServiceName, ep.Owner.ProcessName, ep.Owner.Executable}, " "))
	switch {
	case ep.LocalPort == 22 || strings.Contains(text, "sshd") || strings.Contains(text, "openssh"):
		return "SSH", "REMOTE_ADMIN", true
	case ep.LocalPort == 3389 || strings.Contains(text, "termservice") || strings.Contains(text, "xrdp"):
		return "RDP", "REMOTE_DESKTOP", true
	case ep.LocalPort == 5985 || ep.LocalPort == 5986 || strings.Contains(text, "winrm"):
		return "WINRM", "REMOTE_ADMIN", true
	case (ep.LocalPort >= 5900 && ep.LocalPort <= 5999) || strings.Contains(text, "screensharing") || strings.Contains(text, "vnc"):
		return "VNC", "REMOTE_DESKTOP", true
	case strings.Contains(text, "remoteregistry"):
		return "REMOTE_REGISTRY", "REMOTE_ADMIN", true
	case ep.LocalPort == 9090 && strings.Contains(text, "cockpit"):
		return "COCKPIT", "ADMIN_CONSOLE", true
	}
	return "", "", false
}

func roleForFamily(f string) string {
	switch strings.ToUpper(f) {
	case "RDP", "VNC":
		return "REMOTE_DESKTOP"
	case "COCKPIT":
		return "ADMIN_CONSOLE"
	default:
		return "REMOTE_ADMIN"
	}
}
func serviceEnabled(s services.Service) bool {
	v := strings.ToUpper(s.StartMode)
	return v == "ENABLED" || v == "AUTOMATIC" || v == "AUTO" || v == "BOOT" || v == "SYSTEM" || v == "RUN_AT_LOAD" || v == "KEEP_ALIVE"
}
func serviceActive(s services.Service) bool {
	v := strings.ToUpper(s.RuntimeState)
	return v == "RUNNING" || v == "ACTIVE" || v == "STARTED"
}
func aggregateCoverage(states []string) string {
	if len(states) == 0 {
		return firewall.CoverageUnavailable
	}
	present, absent, ambiguous, unavailable := false, false, false, false
	for _, s := range states {
		switch s {
		case firewall.CoverageAbsent:
			absent = true
		case firewall.CoveragePresent:
			present = true
		case firewall.CoverageAmbiguous:
			ambiguous = true
		case firewall.CoverageUnavailable:
			unavailable = true
		}
	}
	if absent {
		return firewall.CoverageAbsent
	}
	if ambiguous {
		return firewall.CoverageAmbiguous
	}
	if unavailable {
		return firewall.CoverageUnavailable
	}
	if present {
		return firewall.CoveragePresent
	}
	return firewall.CoverageUnavailable
}

func normalizeControls(in []Control) []Control {
	out := make([]Control, 0, len(in))
	seen := map[string]struct{}{}
	for _, c := range in {
		c.Family = strings.ToUpper(strings.TrimSpace(c.Family))
		c.Name = strings.TrimSpace(c.Name)
		c.Value = strings.ToUpper(strings.TrimSpace(c.Value))
		c.Source = strings.TrimSpace(c.Source)
		c.Reason = strings.TrimSpace(c.Reason)
		if c.Family == "" || c.Name == "" {
			continue
		}
		if c.Source == "" {
			c.Source = "local remote-management configuration"
		}
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceHigh
		}
		c.ID = stableControlID(c.Family, c.Name)
		if _, ok := seen[c.ID]; ok {
			continue
		}
		seen[c.ID] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func stableControlID(family, name string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(family)) + "\x00" + strings.ToLower(strings.TrimSpace(name))))
	return "rmc-" + hex.EncodeToString(sum[:8])
}
func stableSurfaceID(family string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(family))))
	return "rms-" + hex.EncodeToString(sum[:8])
}
func uniqueStrings(in []string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func uniquePorts(in []uint16) []uint16 {
	m := map[uint16]struct{}{}
	out := []uint16{}
	for _, v := range in {
		if v == 0 {
			continue
		}
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func summarize(surfaces []Surface, controls []Control) Summary {
	s := Summary{Surfaces: len(surfaces), Controls: len(controls)}
	for _, x := range surfaces {
		if x.ConfiguredState == "ENABLED" {
			s.Enabled++
		}
		if x.RuntimeState == "ACTIVE" {
			s.Active++
		}
		if x.ListenerState == "PRESENT" {
			s.Listening++
		}
		if x.BindingState == "EXTERNAL" || x.BindingState == "ALL_INTERFACES" {
			s.External++
		}
		switch x.FirewallCoverage {
		case firewall.CoveragePresent:
			s.FirewallPresent++
		case firewall.CoverageAbsent:
			s.FirewallAbsent++
		case firewall.CoverageAmbiguous:
			s.FirewallAmbiguous++
		case firewall.CoverageUnavailable:
			s.FirewallUnavailable++
		}
	}
	for _, c := range controls {
		if c.State != evidence.StateObserved && c.State != evidence.StateNotApplicable {
			s.ControlsUnavailable++
		}
	}
	return s
}

func hasSSHSurface(surfaces []Surface) bool {
	for _, s := range surfaces {
		if strings.EqualFold(s.Family, "SSH") {
			return true
		}
	}
	return false
}

func buildSSHEvidence(s SSHSecurity, at time.Time) []evidence.Observation {
	source := "local SSH security assessment"
	if s.State == sshStateNotApplicable {
		return []evidence.Observation{
			evidence.NewState("ssh_security.applicability", evidence.StateNotApplicable, source, at, evidence.ConfidenceHigh, "local SSH daemon/configuration was not detected"),
		}
	}
	out := []evidence.Observation{
		evidence.NewObserved("ssh_security.applicability", "APPLICABLE", source, at, evidence.ConfidenceHigh),
		evidence.NewObserved("ssh_security.summary", s.Summary, source, at, evidence.ConfidenceHigh),
	}
	for _, setting := range s.Settings {
		key := "ssh_security.setting." + strings.ToLower(setting.Name)
		if setting.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, setting, setting.Source, at, setting.Confidence))
		} else {
			out = append(out, evidence.NewState(key, setting.State, setting.Source, at, setting.Confidence, setting.Reason))
		}
	}
	for _, file := range s.Files {
		key := "ssh_security.file." + file.ID
		if file.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, file, file.Source, at, file.Confidence))
		} else {
			out = append(out, evidence.NewState(key, file.State, file.Source, at, file.Confidence, file.Reason))
		}
	}
	for _, alg := range s.Algorithms {
		key := "ssh_security.algorithms." + strings.ToLower(alg.Family)
		if alg.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, alg, alg.Source, at, alg.Confidence))
		} else {
			out = append(out, evidence.NewState(key, alg.State, alg.Source, at, alg.Confidence, alg.Reason))
		}
	}
	return out
}
func buildEvidence(r Report) []evidence.Observation {
	out := []evidence.Observation{evidence.NewObserved("remote_management.summary", r.Summary, "remote-management/file-sharing collector", r.CollectedAt, evidence.ConfidenceHigh)}
	for _, s := range r.Surfaces {
		out = append(out, evidence.NewObserved("remote_management.surface."+s.ID, s, s.Source, r.CollectedAt, s.Confidence))
	}
	for _, c := range r.Controls {
		key := "remote_management.control." + c.ID
		if c.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, c, c.Source, r.CollectedAt, c.Confidence))
		} else {
			out = append(out, evidence.NewState(key, c.State, c.Source, r.CollectedAt, c.Confidence, c.Reason))
		}
	}
	out = append(out, buildSSHEvidence(r.SSHSecurity, r.CollectedAt)...)
	out = append(out, buildSMBEvidence(r.SMBSecurity, r.CollectedAt)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

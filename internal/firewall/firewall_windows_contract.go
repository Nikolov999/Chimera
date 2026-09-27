package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Post-117 Fix45: Windows Defender Firewall acquisition is split into a cheap
// base stage (profiles + rule identities) and a bulk filter-enrichment stage.
// Keeping the wire contracts in a platform-neutral file lets Linux CI exercise
// malformed-record isolation even though the provider itself runs only on Windows.

type winProfile struct {
	Name                    string
	Enabled                 bool
	DefaultInboundAction    string
	DefaultOutboundAction   string
	AllowInboundRules       string
	AllowLocalFirewallRules string
	AllowLocalIPsecRules    string
	NotifyOnListen          bool
	LogAllowed              bool
	LogBlocked              bool
	LogFileName             string
	LogMaxSizeKilobytes     int
	ActiveState             string
	ActiveInterfaces        string
}

type winRuleBase struct {
	CorrelationID string
	InstanceID    string
	Name          string
	DisplayName   string
	Action        string
	Direction     string
	Profile       string
}

type winRuleFilter struct {
	RuleID        string
	Protocol      string
	LocalPort     string
	LocalAddress  string
	RemoteAddress string
	Interface     string
	Program       string
	Service       string
}

type winFirewallStageError struct {
	Stage   string
	Command string
	Type    string
	Message string
}

// winFirewallStageErrorList accepts null, one object, or an array. Windows
// PowerShell 5.1 can collapse a single-element collection during JSON
// serialization depending on how the property was constructed. Provider
// diagnostics must never make otherwise usable firewall evidence undecodable.
type winFirewallStageErrorList []winFirewallStageError

func (l *winFirewallStageErrorList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*l = nil
		return nil
	}
	switch b[0] {
	case '[':
		var items []winFirewallStageError
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		*l = items
		return nil
	case '{':
		var item winFirewallStageError
		if err := json.Unmarshal(b, &item); err != nil {
			return err
		}
		*l = []winFirewallStageError{item}
		return nil
	default:
		return fmt.Errorf("expected firewall stage-error object or array")
	}
}

type winFirewallBasePayload struct {
	Profiles                []winProfile
	Rules                   []winRuleBase
	RuleCount               int
	InboundEnabledRuleCount int
	RulesTruncated          bool
	ServiceStatus           string
	ProfilesObserved        bool
	RulesObserved           bool
	ServiceObserved         bool
	StageErrors             []winFirewallStageError
	MalformedRecords        int
}

type winFirewallFilterPayload struct {
	Records             []winRuleFilter
	PortComplete        bool
	AddressComplete     bool
	InterfaceComplete   bool
	ApplicationComplete bool
	ServiceComplete     bool
	StageErrors         []winFirewallStageError
	MalformedRecords    int
}

func (p winFirewallFilterPayload) complete() bool {
	return p.PortComplete && p.AddressComplete && p.InterfaceComplete && p.ApplicationComplete && p.ServiceComplete && p.MalformedRecords == 0
}

type rawJSONList []json.RawMessage

func (l *rawJSONList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*l = nil
		return nil
	}
	switch b[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		*l = items
		return nil
	case '{':
		*l = []json.RawMessage{append(json.RawMessage(nil), b...)}
		return nil
	default:
		return fmt.Errorf("expected object or array")
	}
}

type winFirewallBaseWire struct {
	Profiles                rawJSONList               `json:"Profiles"`
	Rules                   rawJSONList               `json:"Rules"`
	RuleCount               int                       `json:"RuleCount"`
	InboundEnabledRuleCount int                       `json:"InboundEnabledRuleCount"`
	RulesTruncated          bool                      `json:"RulesTruncated"`
	ServiceStatus           string                    `json:"ServiceStatus"`
	ProfilesObserved        bool                      `json:"ProfilesObserved"`
	RulesObserved           bool                      `json:"RulesObserved"`
	ServiceObserved         bool                      `json:"ServiceObserved"`
	StageErrors             winFirewallStageErrorList `json:"StageErrors"`
}

type winFirewallFilterWire struct {
	Records             rawJSONList               `json:"Records"`
	PortComplete        bool                      `json:"PortComplete"`
	AddressComplete     bool                      `json:"AddressComplete"`
	InterfaceComplete   bool                      `json:"InterfaceComplete"`
	ApplicationComplete bool                      `json:"ApplicationComplete"`
	ServiceComplete     bool                      `json:"ServiceComplete"`
	StageErrors         winFirewallStageErrorList `json:"StageErrors"`
}

func decodeWindowsFirewallBasePayload(b []byte) (winFirewallBasePayload, error) {
	var wire winFirewallBaseWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return winFirewallBasePayload{}, fmt.Errorf("decode Windows firewall base stage: %w", err)
	}
	out := winFirewallBasePayload{
		RuleCount:               wire.RuleCount,
		InboundEnabledRuleCount: wire.InboundEnabledRuleCount,
		RulesTruncated:          wire.RulesTruncated,
		ServiceStatus:           strings.TrimSpace(wire.ServiceStatus),
		ProfilesObserved:        wire.ProfilesObserved,
		RulesObserved:           wire.RulesObserved,
		ServiceObserved:         wire.ServiceObserved,
		StageErrors:             normalizeWindowsFirewallStageErrors(wire.StageErrors),
	}
	for i, raw := range wire.Profiles {
		var p winProfile
		if err := json.Unmarshal(raw, &p); err != nil {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "PROFILE_RECORD", Command: "decode", Type: "JSON", Message: fmt.Sprintf("profile record %d: %v", i, err)})
			continue
		}
		if strings.TrimSpace(p.Name) == "" {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "PROFILE_RECORD", Command: "normalize", Type: "SCHEMA", Message: fmt.Sprintf("profile record %d has empty Name", i)})
			continue
		}
		out.Profiles = append(out.Profiles, p)
	}
	seenRules := map[string]struct{}{}
	for i, raw := range wire.Rules {
		var r winRuleBase
		if err := json.Unmarshal(raw, &r); err != nil {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "RULE_RECORD", Command: "decode", Type: "JSON", Message: fmt.Sprintf("rule record %d: %v", i, err)})
			continue
		}
		r.CorrelationID = strings.TrimSpace(r.CorrelationID)
		r.InstanceID = strings.TrimSpace(r.InstanceID)
		r.Name = strings.TrimSpace(r.Name)
		if r.CorrelationID == "" {
			r.CorrelationID = firstNonBlank(r.Name, r.InstanceID)
		}
		if r.CorrelationID == "" {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "RULE_RECORD", Command: "normalize", Type: "SCHEMA", Message: fmt.Sprintf("rule record %d has no correlation identity", i)})
			continue
		}
		if _, exists := seenRules[strings.ToLower(r.CorrelationID)]; exists {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "RULE_RECORD", Command: "normalize", Type: "SCHEMA", Message: fmt.Sprintf("duplicate firewall rule correlation identity %q", r.CorrelationID)})
			continue
		}
		seenRules[strings.ToLower(r.CorrelationID)] = struct{}{}
		out.Rules = append(out.Rules, r)
	}
	out.StageErrors = normalizeWindowsFirewallStageErrors(out.StageErrors)
	return out, nil
}

func decodeWindowsFirewallFilterPayload(b []byte) (winFirewallFilterPayload, error) {
	var wire winFirewallFilterWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return winFirewallFilterPayload{}, fmt.Errorf("decode Windows firewall filter stage: %w", err)
	}
	out := winFirewallFilterPayload{
		PortComplete: wire.PortComplete, AddressComplete: wire.AddressComplete,
		InterfaceComplete: wire.InterfaceComplete, ApplicationComplete: wire.ApplicationComplete,
		ServiceComplete: wire.ServiceComplete, StageErrors: normalizeWindowsFirewallStageErrors(wire.StageErrors),
	}
	seen := map[string]struct{}{}
	for i, raw := range wire.Records {
		var r winRuleFilter
		if err := json.Unmarshal(raw, &r); err != nil {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "FILTER_RECORD", Command: "decode", Type: "JSON", Message: fmt.Sprintf("filter record %d: %v", i, err)})
			continue
		}
		r.RuleID = strings.TrimSpace(r.RuleID)
		if r.RuleID == "" {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "FILTER_RECORD", Command: "normalize", Type: "SCHEMA", Message: fmt.Sprintf("filter record %d has empty RuleID", i)})
			continue
		}
		key := strings.ToLower(r.RuleID)
		if _, exists := seen[key]; exists {
			out.MalformedRecords++
			out.StageErrors = append(out.StageErrors, winFirewallStageError{Stage: "FILTER_RECORD", Command: "normalize", Type: "SCHEMA", Message: fmt.Sprintf("duplicate filter record for rule %q", r.RuleID)})
			continue
		}
		seen[key] = struct{}{}
		out.Records = append(out.Records, r)
	}
	out.StageErrors = normalizeWindowsFirewallStageErrors(out.StageErrors)
	return out, nil
}

func normalizeWindowsFirewallStageErrors(in []winFirewallStageError) []winFirewallStageError {
	seen := map[string]struct{}{}
	out := make([]winFirewallStageError, 0, len(in))
	for _, e := range in {
		e.Stage = strings.ToUpper(strings.TrimSpace(e.Stage))
		e.Command = strings.TrimSpace(e.Command)
		e.Type = strings.TrimSpace(e.Type)
		e.Message = strings.TrimSpace(e.Message)
		if e.Stage == "" && e.Message == "" {
			continue
		}
		key := strings.Join([]string{e.Stage, e.Command, e.Type, e.Message}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join([]string{out[i].Stage, out[i].Command, out[i].Type, out[i].Message}, "\x00") < strings.Join([]string{out[j].Stage, out[j].Command, out[j].Type, out[j].Message}, "\x00")
	})
	return out
}

func windowsFirewallStageReason(errors []winFirewallStageError) string {
	parts := make([]string, 0, len(errors))
	for _, e := range normalizeWindowsFirewallStageErrors(errors) {
		label := "stage=" + fallback(e.Stage, "UNKNOWN")
		if e.Command != "" {
			label += " command=" + e.Command
		}
		if e.Type != "" {
			label += " type=" + e.Type
		}
		if e.Message != "" {
			label += " reason=" + e.Message
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "; ")
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

package profile

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/services"
)

func enterprisePolicyRules(p Descriptor) []assessment.Rule {
	if !p.Custom {
		return nil
	}
	out := make([]assessment.Rule, 0, 2)
	if len(p.ExpectedServices) > 0 || strings.TrimSpace(p.ServicePolicyMode) != "" {
		profileCopy := cloneDescriptor(p)
		out = append(out, assessment.Rule{
			ID: "CHM-ENT-001", Title: "Enterprise expected-service policy is satisfied", Category: "enterprise-policy", Severity: assessment.SeverityMedium,
			AffectedObject: "enterprise.expected_services",
			ExpectedState:  "required services are present in the expected state and allowlist-mode profiles have no unapproved active services",
			Risk:           "A production host that is missing a required service or running an unapproved service has drifted from its declared environment role and can expose unplanned attack surface or operational control gaps.",
			Remediation:    "Reconcile the host with the approved service inventory. Restore required services through the normal change process, remove unneeded services, or add a narrowly justified service exception to the custom Chimera profile.",
			Evaluate:       func(idx assessment.Index) assessment.Evaluation { return evaluateServicePolicy(profileCopy, idx) },
		})
	}
	if len(p.ExpectedPorts) > 0 || strings.TrimSpace(p.PortPolicyMode) != "" {
		profileCopy := cloneDescriptor(p)
		out = append(out, assessment.Rule{
			ID: "CHM-ENT-002", Title: "Enterprise expected-listener policy is satisfied", Category: "enterprise-policy", Severity: assessment.SeverityHigh,
			AffectedObject: "enterprise.expected_ports",
			ExpectedState:  "required local listeners are present at the declared binding scope and allowlist-mode profiles have no unapproved listening/bound ports",
			Risk:           "Unexpected or missing listeners can indicate configuration drift, accidental network exposure, or a service role that no longer matches the enterprise policy assigned to the host.",
			Remediation:    "Reconcile listeners with the approved environment policy. Bind required services to the intended interfaces, remove unexpected listeners, or document a narrowly justified port exception in the custom Chimera profile.",
			Evaluate:       func(idx assessment.Index) assessment.Evaluation { return evaluatePortPolicy(profileCopy, idx) },
		})
	}
	return out
}

func evaluateServicePolicy(p Descriptor, idx assessment.Index) assessment.Evaluation {
	inventory, inventoryOK := idx["service.inventory.count"]
	items := make([]serviceEvidence, 0)
	keys := []string{"service.inventory.count"}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "service.item.") || obs.State != evidence.StateObserved {
			continue
		}
		svc, ok := obs.Value.(services.Service)
		if !ok {
			continue
		}
		items = append(items, serviceEvidence{key: key, service: svc, confidence: obs.Confidence})
	}
	sort.Slice(items, func(i, j int) bool {
		a := strings.ToLower(items[i].service.Name + "\x00" + items[i].service.Manager + "\x00" + items[i].key)
		b := strings.ToLower(items[j].service.Name + "\x00" + items[j].service.Manager + "\x00" + items[j].key)
		return a < b
	})
	coverageIncomplete, coverageKeys, coverageReasons := sourceCoverage(idx, "service.source.", "service.inventory.provider")
	keys = append(keys, coverageKeys...)

	missing := make([]string, 0)
	mismatched := make([]string, 0)
	matchedKeys := make([]string, 0)
	for _, expected := range p.ExpectedServices {
		matches := matchingServices(expected, items)
		if len(matches) == 0 {
			if expected.Required {
				missing = append(missing, serviceLabel(expected))
			}
			continue
		}
		stateOK := false
		for _, item := range matches {
			matchedKeys = append(matchedKeys, item.key)
			if serviceStateMatches(expected.State, item.service) {
				stateOK = true
			}
		}
		if expected.Required && !stateOK {
			mismatched = append(mismatched, serviceLabel(expected)+" state="+strings.ToUpper(expected.State))
		}
	}

	unexpected := make([]string, 0)
	if strings.EqualFold(p.ServicePolicyMode, ServiceModeAllowlist) {
		for _, item := range items {
			if !serviceIsActive(item.service) {
				continue
			}
			if serviceExpected(item.service, p.ExpectedServices) || exceptionAllowsService(p.AllowedExceptions, item.service) {
				continue
			}
			unexpected = append(unexpected, fmt.Sprintf("%s(%s,%s)", item.service.Name, item.service.Manager, item.service.RuntimeState))
			matchedKeys = append(matchedKeys, item.key)
		}
	}

	keys = append(keys, matchedKeys...)
	keys = uniqueSortedStrings(keys)
	conf := enterpriseEvidenceConfidence(inventory, items)
	if !inventoryOK || inventory.State != evidence.StateObserved {
		reason := "service inventory is unavailable or degraded; enterprise expected-service policy cannot be proven"
		if inventoryOK && strings.TrimSpace(inventory.Reason) != "" {
			reason += ": " + inventory.Reason
		}
		return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: reason, Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	if len(mismatched) > 0 || len(unexpected) > 0 {
		parts := make([]string, 0, 2)
		if len(mismatched) > 0 {
			parts = append(parts, "state mismatch="+strings.Join(mismatched, ", "))
		}
		if len(unexpected) > 0 {
			parts = append(parts, "unapproved active="+strings.Join(unexpected, ", "))
		}
		return assessment.Evaluation{Status: assessment.StatusFail, Confidence: conf, ObservedState: strings.Join(parts, "; "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	if len(missing) > 0 {
		if coverageIncomplete {
			return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: "required service absence cannot be proven because service-provider coverage is incomplete: " + strings.Join(coverageReasons, "; "), Applicability: assessment.Applicable, EvidenceKeys: keys}
		}
		return assessment.Evaluation{Status: assessment.StatusFail, Confidence: conf, ObservedState: "missing required=" + strings.Join(missing, ", "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	mode := p.ServicePolicyMode
	if mode == "" {
		mode = ServiceModeRequired
	}
	if mode == ServiceModeAllowlist && coverageIncomplete {
		return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: "service allowlist cannot be proven complete because service-provider coverage is incomplete: " + strings.Join(coverageReasons, "; "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	return assessment.Evaluation{Status: assessment.StatusPass, Confidence: conf, ObservedState: fmt.Sprintf("enterprise service policy satisfied: mode=%s expected=%d observed=%d", mode, len(p.ExpectedServices), len(items)), Applicability: assessment.Applicable, EvidenceKeys: keys}
}

func evaluatePortPolicy(p Descriptor, idx assessment.Index) assessment.Evaluation {
	inventory, inventoryOK := idx["network.inventory.count"]
	items := make([]portEvidence, 0)
	keys := []string{"network.inventory.count"}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "network.endpoint.") || obs.State != evidence.StateObserved {
			continue
		}
		ep, ok := obs.Value.(netinv.Endpoint)
		if !ok {
			continue
		}
		items = append(items, portEvidence{key: key, endpoint: ep, confidence: obs.Confidence})
	}
	sort.Slice(items, func(i, j int) bool {
		a := fmt.Sprintf("%s/%05d/%s/%s", items[i].endpoint.Protocol, items[i].endpoint.LocalPort, items[i].endpoint.LocalAddress, items[i].key)
		b := fmt.Sprintf("%s/%05d/%s/%s", items[j].endpoint.Protocol, items[j].endpoint.LocalPort, items[j].endpoint.LocalAddress, items[j].key)
		return a < b
	})
	coverageIncomplete, coverageKeys, coverageReasons := sourceCoverage(idx, "network.source.", "")
	keys = append(keys, coverageKeys...)

	missing := make([]string, 0)
	matchedKeys := make([]string, 0)
	for _, expected := range p.ExpectedPorts {
		matches := matchingPorts(expected, items)
		for _, item := range matches {
			matchedKeys = append(matchedKeys, item.key)
		}
		if expected.Required && len(matches) == 0 {
			missing = append(missing, portLabel(expected))
		}
	}

	unexpected := make([]string, 0)
	if strings.EqualFold(p.PortPolicyMode, PortModeAllowlist) {
		for _, item := range items {
			if portExpected(item.endpoint, p.ExpectedPorts) || exceptionAllowsPort(p.AllowedExceptions, item.endpoint) {
				continue
			}
			unexpected = append(unexpected, fmt.Sprintf("%s/%d@%s[%s]", item.endpoint.Protocol, item.endpoint.LocalPort, item.endpoint.LocalAddress, item.endpoint.InterfaceBinding.Class))
			matchedKeys = append(matchedKeys, item.key)
		}
	}

	keys = append(keys, matchedKeys...)
	keys = uniqueSortedStrings(keys)
	conf := enterprisePortConfidence(inventory, items)
	if !inventoryOK || inventory.State != evidence.StateObserved {
		reason := "network listener inventory is unavailable or degraded; enterprise expected-port policy cannot be proven"
		if inventoryOK && strings.TrimSpace(inventory.Reason) != "" {
			reason += ": " + inventory.Reason
		}
		return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: reason, Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	if len(unexpected) > 0 {
		return assessment.Evaluation{Status: assessment.StatusFail, Confidence: conf, ObservedState: "unapproved listeners=" + strings.Join(unexpected, ", "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	if len(missing) > 0 {
		if coverageIncomplete {
			return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: "required listener absence cannot be proven because network-provider coverage is incomplete: " + strings.Join(coverageReasons, "; "), Applicability: assessment.Applicable, EvidenceKeys: keys}
		}
		return assessment.Evaluation{Status: assessment.StatusFail, Confidence: conf, ObservedState: "missing required=" + strings.Join(missing, ", "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	mode := p.PortPolicyMode
	if mode == "" {
		mode = PortModeRequired
	}
	if mode == PortModeAllowlist && coverageIncomplete {
		return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: conf, ObservedState: "listener allowlist cannot be proven complete because network-provider coverage is incomplete: " + strings.Join(coverageReasons, "; "), Applicability: assessment.Applicable, EvidenceKeys: keys}
	}
	return assessment.Evaluation{Status: assessment.StatusPass, Confidence: conf, ObservedState: fmt.Sprintf("enterprise listener policy satisfied: mode=%s expected=%d observed=%d", mode, len(p.ExpectedPorts), len(items)), Applicability: assessment.Applicable, EvidenceKeys: keys}
}

func sourceCoverage(idx assessment.Index, prefix, explicitKey string) (bool, []string, []string) {
	incomplete := false
	keys := make([]string, 0)
	reasons := make([]string, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, prefix) && (explicitKey == "" || key != explicitKey) {
			continue
		}
		keys = append(keys, key)
		switch obs.State {
		case evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported:
			incomplete = true
			reason := key + "=" + string(obs.State)
			if strings.TrimSpace(obs.Reason) != "" {
				reason += "(" + strings.TrimSpace(obs.Reason) + ")"
			}
			reasons = append(reasons, reason)
		}
	}
	keys = uniqueSortedStrings(keys)
	sort.Strings(reasons)
	if incomplete && len(reasons) == 0 {
		reasons = []string{"provider coverage incomplete"}
	}
	return incomplete, keys, reasons
}

type serviceEvidence struct {
	key        string
	service    services.Service
	confidence evidence.Confidence
}
type portEvidence struct {
	key        string
	endpoint   netinv.Endpoint
	confidence evidence.Confidence
}

func matchingServices(expected ExpectedService, items []serviceEvidence) []serviceEvidence {
	out := make([]serviceEvidence, 0)
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(expected.Name), strings.TrimSpace(item.service.Name)) && !strings.EqualFold(strings.TrimSpace(expected.Name), strings.TrimSpace(item.service.DisplayName)) {
			continue
		}
		if strings.TrimSpace(expected.Manager) != "" && !strings.EqualFold(strings.TrimSpace(expected.Manager), strings.TrimSpace(item.service.Manager)) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func serviceExpected(svc services.Service, expected []ExpectedService) bool {
	for _, e := range expected {
		if len(matchingServices(e, []serviceEvidence{{service: svc}})) > 0 {
			return true
		}
	}
	return false
}

func serviceStateMatches(want string, svc services.Service) bool {
	switch strings.ToUpper(strings.TrimSpace(want)) {
	case "", "ANY":
		return true
	case "RUNNING":
		return strings.EqualFold(svc.RuntimeState, "running") || strings.EqualFold(svc.RuntimeState, "active")
	case "STOPPED":
		return strings.EqualFold(svc.RuntimeState, "stopped") || strings.EqualFold(svc.RuntimeState, "inactive")
	case "ENABLED":
		return !strings.EqualFold(svc.StartMode, "disabled") && !strings.EqualFold(svc.StartMode, "masked")
	case "DISABLED":
		return strings.EqualFold(svc.StartMode, "disabled") || strings.EqualFold(svc.StartMode, "masked")
	default:
		return false
	}
}

func serviceIsActive(svc services.Service) bool {
	return strings.EqualFold(svc.RuntimeState, "running") || strings.EqualFold(svc.RuntimeState, "active") || (!strings.EqualFold(svc.StartMode, "disabled") && !strings.EqualFold(svc.StartMode, "masked"))
}

func matchingPorts(expected ExpectedPort, items []portEvidence) []portEvidence {
	out := make([]portEvidence, 0)
	for _, item := range items {
		if !strings.EqualFold(expected.Protocol, item.endpoint.Protocol) || expected.Port != item.endpoint.LocalPort {
			continue
		}
		if !bindingMatches(expected.Binding, item.endpoint.InterfaceBinding.Class) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func portExpected(ep netinv.Endpoint, expected []ExpectedPort) bool {
	for _, e := range expected {
		if len(matchingPorts(e, []portEvidence{{endpoint: ep}})) > 0 {
			return true
		}
	}
	return false
}

func bindingMatches(want, got string) bool {
	want = strings.ToUpper(strings.TrimSpace(want))
	got = strings.ToUpper(strings.TrimSpace(got))
	switch want {
	case "", "ANY":
		return true
	case "EXTERNAL":
		return got == "NON_LOOPBACK" || got == "ALL_INTERFACES"
	default:
		return want == got
	}
}

func exceptionAllowsService(exceptions []AllowedException, svc services.Service) bool {
	values := []string{strings.ToLower(strings.TrimSpace(svc.Name)), strings.ToLower(strings.TrimSpace(svc.DisplayName))}
	for _, ex := range exceptions {
		if ex.Kind != "service" {
			continue
		}
		pattern := strings.ToLower(strings.TrimSpace(ex.Match))
		for _, value := range values {
			if wildcardMatch(pattern, value) {
				return true
			}
		}
	}
	return false
}

func exceptionAllowsPort(exceptions []AllowedException, ep netinv.Endpoint) bool {
	value := strings.ToLower(fmt.Sprintf("%s/%d", ep.Protocol, ep.LocalPort))
	for _, ex := range exceptions {
		if ex.Kind != "port" {
			continue
		}
		if wildcardMatch(strings.ToLower(strings.TrimSpace(ex.Match)), value) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

func serviceLabel(e ExpectedService) string {
	if strings.TrimSpace(e.Manager) == "" {
		return e.Name
	}
	return e.Name + "@" + e.Manager
}
func portLabel(e ExpectedPort) string {
	binding := strings.ToUpper(strings.TrimSpace(e.Binding))
	if binding == "" {
		binding = "ANY"
	}
	return fmt.Sprintf("%s/%d@%s", strings.ToUpper(e.Protocol), e.Port, binding)
}

func enterpriseEvidenceConfidence(inventory evidence.Observation, items []serviceEvidence) evidence.Confidence {
	conf := inventory.Confidence
	if conf == "" {
		conf = evidence.ConfidenceLow
	}
	for _, item := range items {
		conf = lowerConfidence(conf, item.confidence)
	}
	return conf
}
func enterprisePortConfidence(inventory evidence.Observation, items []portEvidence) evidence.Confidence {
	conf := inventory.Confidence
	if conf == "" {
		conf = evidence.ConfidenceLow
	}
	for _, item := range items {
		conf = lowerConfidence(conf, item.confidence)
	}
	return conf
}
func lowerConfidence(a, b evidence.Confidence) evidence.Confidence {
	rank := func(c evidence.Confidence) int {
		switch c {
		case evidence.ConfidenceExact:
			return 4
		case evidence.ConfidenceHigh:
			return 3
		case evidence.ConfidenceMedium:
			return 2
		case evidence.ConfidenceLow:
			return 1
		default:
			return 0
		}
	}
	if rank(a) == 0 {
		return b
	}
	if rank(b) == 0 {
		return a
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}
func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

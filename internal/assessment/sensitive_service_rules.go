package assessment

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// adds sensitive-service exposure assessment over the local
// listener inventory and service-role evidence. These rules are
// intentionally observational: a non-loopback bind proves local interface
// exposure, but it does not claim end-to-end reachability through host or
// upstream firewalls.
type sensitiveServiceKind struct {
	id             string
	title          string
	severity       Severity
	affectedObject string
	expected       string
	risk           string
	remediation    string
	families       []string
	roles          []string
	ownerTokens    []string
	ownerPortPairs map[string]map[uint16]struct{}
}

type sensitiveServiceCandidate struct {
	Item       networkExposureEvidenceItem
	MatchBasis string
	Confidence evidence.Confidence
}

func SensitiveServiceExposureRules() []Rule {
	kinds := []sensitiveServiceKind{
		{
			id: "CHM-NET-004", title: "Database listener exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.database",
			expected:       "database services are loopback-bound or intentionally exposed through a documented network boundary",
			risk:           "A database listener bound beyond loopback can expose data stores and administrative interfaces to adjacent or routed networks when firewall policy permits access.",
			remediation:    "Bind the database to loopback or the minimum required interface, restrict remote clients with host/network firewall policy, and require strong authenticated encrypted access when remote service is necessary.",
			families:       []string{"DATABASE"}, roles: []string{"DATABASE"},
			ownerTokens: []string{"mysqld", "mysql", "mariadbd", "postgres", "postgresql", "sqlservr", "mongod", "redis-server", "redis", "cassandra"},
		},
		{
			id: "CHM-NET-005", title: "Administrative console exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.admin_console",
			expected:       "administrative consoles are loopback-bound or intentionally exposed only through a controlled management boundary",
			risk:           "An administrative console available on a non-loopback interface can provide a high-impact management surface to other hosts when routing and firewall policy allow access.",
			remediation:    "Restrict the console to loopback or a dedicated management interface, require strong authentication and transport protection, and constrain source networks with firewall policy.",
			families:       []string{"COCKPIT"}, roles: []string{"ADMIN_CONSOLE"}, ownerTokens: []string{"cockpit", "cockpit-ws", "webmin", "adminer"},
		},
		{
			id: "CHM-NET-006", title: "SMB listener exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.smb",
			expected:       "SMB/file-sharing listeners are restricted to intended trusted interfaces and networks",
			risk:           "SMB exposed beyond loopback increases remote authentication and file-sharing attack surface and can expose shares or credential-exchange paths to adjacent networks.",
			remediation:    "Disable SMB where unnecessary, bind or scope it to intended interfaces, and enforce host/network firewall restrictions for trusted client networks only.",
			families:       []string{"SMB"}, ownerTokens: []string{"smbd", "samba", "lanmanserver"},
		},
		{
			id: "CHM-NET-007", title: "RDP listener exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.rdp",
			expected:       "remote-desktop listeners are restricted to intended management interfaces and networks",
			risk:           "RDP exposed on a non-loopback interface creates an interactive remote logon surface that can be targeted when routing and firewall policy permit access.",
			remediation:    "Disable RDP where unnecessary, restrict it to approved management networks, and enforce host firewall, strong authentication, and network-level authentication controls.",
			families:       []string{"RDP"}, ownerTokens: []string{"termservice", "termsrv"},
		},
		{
			id: "CHM-NET-008", title: "SSH listener exposure is constrained", severity: SeverityMedium,
			affectedObject: "network.sensitive.ssh",
			expected:       "SSH listeners are restricted to intended administration interfaces and networks",
			risk:           "SSH bound beyond loopback is a remote administration surface and becomes reachable to other hosts when routing and firewall policy permit it.",
			remediation:    "Disable SSH where unnecessary, bind it to the minimum required interface, and restrict source networks with firewall policy; will assess SSH-specific authentication and algorithm hardening.",
			families:       []string{"SSH"}, ownerTokens: []string{"sshd", "openssh"},
		},
		{
			id: "CHM-NET-009", title: "Docker API exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.docker_api",
			expected:       "Docker daemon APIs are not exposed on non-loopback TCP interfaces unless explicitly secured and required",
			risk:           "A remotely reachable Docker daemon API can grant powerful container and host-management capabilities. A non-loopback TCP bind materially increases this management surface even when authentication state is not yet known.",
			remediation:    "Prefer the local protected Docker socket. If TCP API access is required, bind only to a management interface and enforce mutually authenticated TLS plus strict firewall source restrictions.",
			ownerPortPairs: map[string]map[uint16]struct{}{
				"dockerd": {2375: {}, 2376: {}}, "docker": {2375: {}, 2376: {}},
			},
		},
		{
			id: "CHM-NET-010", title: "Orchestration API exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.orchestration_api",
			expected:       "local orchestration APIs are restricted to intended control-plane or management interfaces",
			risk:           "An orchestration control-plane API bound beyond loopback can expose cluster-management functions to other hosts when routing and firewall policy allow access.",
			remediation:    "Bind orchestration APIs only to required control-plane/management interfaces and constrain access with authenticated transport and narrowly scoped firewall policy.",
			ownerTokens:    []string{"kube-apiserver", "k3s", "k0s", "microk8s"},
		},
		{
			id: "CHM-NET-011", title: "Debugging endpoint exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.sensitive.debugging",
			expected:       "debugger and remote-debug interfaces are loopback-only or disabled outside controlled development environments",
			risk:           "Remote debugging interfaces can expose process inspection, code execution, or application-control capabilities. A non-loopback bind can make those capabilities available to other hosts when network policy permits access.",
			remediation:    "Disable remote debugging when not required. Otherwise bind to loopback or a dedicated isolated development interface and tightly restrict source access.",
			ownerTokens:    []string{"gdbserver", "dlv", "debugpy", "pydevd"},
			ownerPortPairs: map[string]map[uint16]struct{}{
				"chrome": {9222: {}}, "chromium": {9222: {}}, "node": {5858: {}, 9229: {}}, "java": {5005: {}}, "python": {5678: {}}, "python3": {5678: {}},
			},
		},
		{
			id: "CHM-NET-012", title: "Development-server exposure is constrained", severity: SeverityMedium,
			affectedObject: "network.sensitive.development_server",
			expected:       "development servers and notebook interfaces are loopback-only unless intentionally published through a controlled boundary",
			risk:           "Development servers commonly prioritize convenience over hardened production exposure. A non-loopback bind can expose debug features, source content, notebooks, or unaudited application surfaces to peers on the attached network.",
			remediation:    "Bind development servers to loopback by default. For intentional shared access, use a hardened reverse proxy or equivalent controlled boundary with authentication, transport protection, and firewall restrictions.",
			families:       []string{"JUPYTER"}, roles: []string{"DEVELOPER_INTERFACE"},
			ownerTokens: []string{"jupyter", "jupyter-lab", "jupyter-notebook", "vite", "webpack", "webpack-dev-server", "parcel", "flask", "django", "uvicorn"},
		},
	}

	rules := make([]Rule, 0, len(kinds))
	for _, kind := range kinds {
		rules = append(rules, sensitiveServiceRule(kind))
	}
	return rules
}

func sensitiveServiceRule(kind sensitiveServiceKind) Rule {
	return Rule{
		ID: kind.id, Title: kind.title, Category: "network", Severity: kind.severity,
		AffectedObject: kind.affectedObject, ExpectedState: kind.expected, Risk: kind.risk, Remediation: kind.remediation,
		Evaluate: func(idx Index) Evaluation {
			items, providerUsable := networkExposureItems(idx)
			candidates := sensitiveServiceCandidates(items, kind)
			if len(candidates) == 0 {
				if len(items) == 0 && !providerUsable {
					return networkExposureUnavailable(idx)
				}
				return Evaluation{
					Status: StatusPass, Confidence: evidence.ConfidenceHigh,
					ObservedState: "no matching sensitive local listener was identified",
					Applicability: Applicable, EvidenceKeys: networkInventoryEvidenceKeys(idx),
				}
			}

			external := make([]sensitiveServiceCandidate, 0)
			unknown := make([]sensitiveServiceCandidate, 0)
			for _, candidate := range candidates {
				switch candidate.Item.Endpoint.InterfaceBinding.Class {
				case "ALL_INTERFACES", "NON_LOOPBACK":
					external = append(external, candidate)
				case "LOOPBACK":
					// constrained as expected
				default:
					unknown = append(unknown, candidate)
				}
			}
			if len(external) > 0 {
				return Evaluation{
					Status: StatusWarn, Confidence: sensitiveCandidateConfidence(external),
					ObservedState: fmt.Sprintf("%d matching sensitive listener(s) are bound to all interfaces or a specific non-loopback address; host/upstream firewall reachability is not yet assessed", len(external)),
					Applicability: Applicable, EvidenceKeys: sensitiveCandidateEvidenceKeys(external),
				}
			}
			if len(unknown) > 0 {
				return Evaluation{
					Status: StatusUnknown, Confidence: evidence.ConfidenceLow,
					ObservedState: fmt.Sprintf("%d matching sensitive listener(s) have unresolved interface-binding scope", len(unknown)),
					Applicability: Applicable, EvidenceKeys: sensitiveCandidateEvidenceKeys(unknown),
				}
			}
			return Evaluation{
				Status: StatusPass, Confidence: sensitiveCandidateConfidence(candidates),
				ObservedState: fmt.Sprintf("%d matching sensitive listener(s) are constrained to loopback", len(candidates)),
				Applicability: Applicable, EvidenceKeys: sensitiveCandidateEvidenceKeys(candidates),
			}
		},
	}
}

func sensitiveServiceCandidates(items []networkExposureEvidenceItem, kind sensitiveServiceKind) []sensitiveServiceCandidate {
	out := make([]sensitiveServiceCandidate, 0)
	for _, item := range items {
		basis, confidence, ok := sensitiveServiceMatch(item, kind)
		if !ok {
			continue
		}
		out = append(out, sensitiveServiceCandidate{Item: item, MatchBasis: basis, Confidence: confidence})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Item.EndpointKey < out[j].Item.EndpointKey
	})
	return out
}

func sensitiveServiceMatch(item networkExposureEvidenceItem, kind sensitiveServiceKind) (string, evidence.Confidence, bool) {
	if item.Exposure != nil && strings.EqualFold(item.Exposure.State, "CLASSIFIED") {
		family := strings.ToUpper(strings.TrimSpace(item.Exposure.Family))
		role := strings.ToUpper(strings.TrimSpace(item.Exposure.Role))
		if stringInFold(family, kind.families...) {
			return "service-family:" + family, evidence.ConfidenceHigh, true
		}
		if stringInFold(role, kind.roles...) {
			return "service-role:" + role, evidence.ConfidenceHigh, true
		}
	}

	tokens := endpointOwnerTokens(item)
	for _, token := range kind.ownerTokens {
		if _, ok := tokens[strings.ToLower(token)]; ok {
			return "owner:" + strings.ToLower(token), evidence.ConfidenceMedium, true
		}
	}
	for owner, ports := range kind.ownerPortPairs {
		if _, ok := tokens[strings.ToLower(owner)]; !ok {
			continue
		}
		if _, ok := ports[item.Endpoint.LocalPort]; ok {
			return fmt.Sprintf("owner-port:%s/%d", strings.ToLower(owner), item.Endpoint.LocalPort), evidence.ConfidenceMedium, true
		}
	}
	return "", evidence.ConfidenceLow, false
}

func endpointOwnerTokens(item networkExposureEvidenceItem) map[string]struct{} {
	texts := []string{
		item.ItemName(),
		item.Endpoint.Owner.ProcessName,
		item.Endpoint.Owner.ServiceName,
		item.Endpoint.Owner.Executable,
	}
	if item.Service != nil {
		texts = append(texts, item.Service.Name, item.Service.DisplayName, item.Service.Executable, item.Service.ExecutablePath)
	}
	out := map[string]struct{}{}
	for _, text := range texts {
		text = strings.TrimSpace(strings.ReplaceAll(text, `\\`, "/"))
		if text == "" {
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(text), ".exe"))
		if base != "" && base != "." {
			out[base] = struct{}{}
		}
		for _, token := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
			return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_'
		}) {
			token = strings.TrimSuffix(token, ".exe")
			if token != "" {
				out[token] = struct{}{}
			}
		}
	}
	return out
}

func (item networkExposureEvidenceItem) ItemName() string {
	if item.Service != nil {
		return item.Service.Name
	}
	return ""
}

func stringInFold(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func sensitiveCandidateConfidence(items []sensitiveServiceCandidate) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	confidence := evidence.ConfidenceHigh
	for _, item := range items {
		if item.Confidence == evidence.ConfidenceLow || item.Item.Endpoint.Confidence == evidence.ConfidenceLow {
			return evidence.ConfidenceLow
		}
		if item.Confidence == evidence.ConfidenceMedium || item.Item.Endpoint.Confidence == evidence.ConfidenceMedium || item.Item.Endpoint.Owner.State == "UNAVAILABLE" {
			confidence = evidence.ConfidenceMedium
		}
	}
	return confidence
}

func sensitiveCandidateEvidenceKeys(items []sensitiveServiceCandidate) []string {
	keys := make([]string, 0, len(items)*3)
	for _, candidate := range items {
		item := candidate.Item
		keys = append(keys, item.EndpointKey)
		if item.ServiceKey != "" {
			keys = append(keys, item.ServiceKey)
		}
		if item.ExposureKey != "" {
			keys = append(keys, item.ExposureKey)
		}
	}
	sort.Strings(keys)
	return uniqueStrings(keys)
}

package assessment

import (
	"fmt"
	"sort"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// LegacyProtocolExposureRules implements . The rules correlate the
// local listener inventory with service classification and
// conservative local owner identity. They do not connect to listeners, send
// protocol probes, authenticate, capture traffic, or claim that a cleartext
// mode is actually negotiated on the wire.
func LegacyProtocolExposureRules() []Rule {
	kinds := []sensitiveServiceKind{
		{
			id: "CHM-NET-013", title: "Legacy remote-administration protocol exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.legacy.remote_admin",
			expected:       "Telnet and rsh-family remote-administration services are disabled or constrained to loopback-only local exposure",
			risk:           "Telnet and rsh-family services rely on obsolete or weak remote-administration security assumptions and can expose authentication or command channels without modern transport protection. A non-loopback bind increases the local network attack surface even when firewall reachability has not yet been assessed.",
			remediation:    "Disable legacy remote-administration services and replace them with a supported encrypted management protocol such as SSH. If a temporary compatibility requirement exists, isolate the service to the minimum local interface and tightly restrict access with later firewall controls.",
			families:       []string{"TELNET", "RSH_FAMILY"},
			ownerTokens:    []string{"telnet", "telnetd", "tlntsvr", "rsh", "rshd", "rlogin", "rlogind", "rexec", "rexecd"},
		},
		{
			id: "CHM-NET-014", title: "Legacy cleartext-capable file-transfer exposure is constrained", severity: SeverityHigh,
			affectedObject: "network.legacy.file_transfer",
			expected:       "FTP/TFTP-class services are disabled or constrained to loopback-only exposure unless explicitly required behind a controlled boundary",
			risk:           "FTP-class services can permit cleartext credentials or data depending on configuration, while TFTP lacks normal authenticated transport protections. A non-loopback listener can expose these legacy transfer surfaces to adjacent or routed hosts when policy permits access.",
			remediation:    "Prefer SFTP, SCP, HTTPS, or another supported authenticated encrypted transfer mechanism. Where a legacy transfer service is unavoidable, bind it to the minimum required interface and enforce narrowly scoped firewall and network segmentation controls.",
			families:       []string{"FTP", "TFTP"},
			ownerTokens:    []string{"ftp", "ftpd", "vsftpd", "proftpd", "pureftpd", "ftpsvc", "tftp", "tftpd"},
		},
		{
			id: "CHM-NET-015", title: "Legacy information, identity, and diagnostic protocol exposure is constrained", severity: SeverityMedium,
			affectedObject: "network.legacy.information_identity_diagnostic",
			expected:       "finger, NIS/YP, and legacy inetd diagnostic services are disabled or constrained to loopback-only exposure",
			risk:           "Legacy information, identity, and diagnostic protocols can disclose host/user information, depend on obsolete trust models, or provide unauthenticated network behavior that is unnecessary on modern hosts. Non-loopback listeners increase attack surface and information exposure.",
			remediation:    "Disable obsolete information, identity, and diagnostic services where possible. Replace required identity functions with supported authenticated directory mechanisms and keep any unavoidable compatibility service isolated to trusted interfaces and networks.",
			families:       []string{"FINGER", "NIS_YP", "LEGACY_INETD_DIAGNOSTIC"},
			ownerTokens:    []string{"finger", "fingerd", "ypbind", "ypserv", "yppasswdd", "chargen", "daytime", "discard"},
		},
	}

	rules := make([]Rule, 0, len(kinds))
	for _, kind := range kinds {
		rules = append(rules, legacyProtocolRule(kind))
	}
	return rules
}

func legacyProtocolRule(kind sensitiveServiceKind) Rule {
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
					ObservedState: "no matching legacy/cleartext-capable local listener was identified from normalized service/listener metadata",
					Applicability: Applicable, EvidenceKeys: networkInventoryEvidenceKeys(idx),
				}
			}

			external := make([]sensitiveServiceCandidate, 0)
			unknown := make([]sensitiveServiceCandidate, 0)
			loopback := make([]sensitiveServiceCandidate, 0)
			for _, candidate := range candidates {
				switch candidate.Item.Endpoint.InterfaceBinding.Class {
				case "ALL_INTERFACES", "NON_LOOPBACK":
					external = append(external, candidate)
				case "LOOPBACK":
					loopback = append(loopback, candidate)
				default:
					unknown = append(unknown, candidate)
				}
			}
			if len(external) > 0 {
				return Evaluation{
					Status: StatusWarn, Confidence: sensitiveCandidateConfidence(external),
					ObservedState: fmt.Sprintf("%d matching legacy/cleartext-capable listener(s) are bound beyond loopback; classification is based on local service/listener metadata only and does not claim packet-level cleartext negotiation or end-to-end reachability", len(external)),
					Applicability: Applicable, EvidenceKeys: legacyProtocolEvidenceKeys(external),
				}
			}
			if len(unknown) > 0 {
				return Evaluation{
					Status: StatusUnknown, Confidence: evidence.ConfidenceLow,
					ObservedState: fmt.Sprintf("%d matching legacy/cleartext-capable listener(s) have unresolved interface-binding scope", len(unknown)),
					Applicability: Applicable, EvidenceKeys: legacyProtocolEvidenceKeys(unknown),
				}
			}
			return Evaluation{
				Status: StatusPass, Confidence: sensitiveCandidateConfidence(loopback),
				ObservedState: fmt.Sprintf("%d matching legacy/cleartext-capable listener(s) are constrained to loopback", len(loopback)),
				Applicability: Applicable, EvidenceKeys: legacyProtocolEvidenceKeys(loopback),
			}
		},
	}
}

func legacyProtocolEvidenceKeys(items []sensitiveServiceCandidate) []string {
	keys := sensitiveCandidateEvidenceKeys(items)
	sort.Strings(keys)
	return uniqueStrings(keys)
}

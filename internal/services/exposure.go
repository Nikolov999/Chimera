package services

import (
	"sort"
	"strings"
	"unicode"
)

const ServiceExposureSchemaVersion = "chimera.service-exposure/v1"

// ServiceExposurePosture is a conservative classification of a
// service's potential remote-facing role. It is derived only from local service
// identity/configuration metadata. It does not claim that a socket is listening
// or reachable; listener/firewall correlation begins in later network phases.
type ServiceExposurePosture struct {
	Schema              string   `json:"schema"`
	State               string   `json:"state"`
	Family              string   `json:"family"`
	Role                string   `json:"role"`
	RemoteCapable       bool     `json:"remote_capable"`
	Legacy              bool     `json:"legacy"`
	Deprecated          bool     `json:"deprecated"`
	CleartextCapable    bool     `json:"cleartext_capable"`
	InsecureByDesign    bool     `json:"insecure_by_design"`
	Activity            string   `json:"activity"`
	NetworkReachability string   `json:"network_reachability"`
	MatchBasis          []string `json:"match_basis,omitempty"`
	RiskTags            []string `json:"risk_tags,omitempty"`
}

func (p *ServiceExposurePosture) normalize() {
	if p == nil {
		return
	}
	p.Schema = ServiceExposureSchemaVersion
	p.State = normalizeWord(fallback(p.State, "UNCLASSIFIED"))
	p.Family = normalizeWord(fallback(p.Family, "UNKNOWN"))
	p.Role = normalizeWord(fallback(p.Role, "UNKNOWN"))
	p.Activity = normalizeWord(fallback(p.Activity, "UNKNOWN"))
	p.NetworkReachability = normalizeWord(fallback(p.NetworkReachability, "NOT_ASSESSED"))
	p.MatchBasis = uniqueSorted(p.MatchBasis)
	p.RiskTags = uniqueSorted(p.RiskTags)
}

func (p ServiceExposurePosture) Validate() error {
	if p.Schema != ServiceExposureSchemaVersion {
		return validationError("service exposure schema", p.Schema)
	}
	switch p.State {
	case "CLASSIFIED", "UNCLASSIFIED":
	default:
		return validationError("service exposure state", p.State)
	}
	if strings.TrimSpace(p.Family) == "" || strings.TrimSpace(p.Role) == "" || strings.TrimSpace(p.Activity) == "" || strings.TrimSpace(p.NetworkReachability) == "" {
		return validationError("service exposure posture", "required classification fields are empty")
	}
	if p.NetworkReachability != "NOT_ASSESSED" {
		return validationError("service exposure network reachability", "must remain NOT_ASSESSED")
	}
	if p.State == "CLASSIFIED" && (p.Family == "UNKNOWN" || p.Role == "UNKNOWN") {
		return validationError("service exposure classification", "CLASSIFIED records require a known family and role")
	}
	if p.State == "UNCLASSIFIED" && (p.RemoteCapable || p.Legacy || p.Deprecated || p.CleartextCapable || p.InsecureByDesign) {
		return validationError("service exposure classification", "UNCLASSIFIED records cannot assert risk capabilities")
	}
	return nil
}

type exposureClass struct {
	family           string
	role             string
	remoteCapable    bool
	legacy           bool
	deprecated       bool
	cleartextCapable bool
	insecureByDesign bool
	tokens           []string
	riskTags         []string
}

var exposureClasses = []exposureClass{
	{family: "TELNET", role: "REMOTE_ADMIN", remoteCapable: true, legacy: true, deprecated: true, cleartextCapable: true, insecureByDesign: true, tokens: []string{"telnet", "telnetd", "tlntsvr"}, riskTags: []string{"cleartext-authentication", "legacy-remote-admin"}},
	{family: "RSH_FAMILY", role: "REMOTE_ADMIN", remoteCapable: true, legacy: true, deprecated: true, cleartextCapable: true, insecureByDesign: true, tokens: []string{"rsh", "rshd", "rlogin", "rlogind", "rexec", "rexecd"}, riskTags: []string{"legacy-trust-authentication", "legacy-remote-execution"}},
	{family: "TFTP", role: "FILE_TRANSFER", remoteCapable: true, legacy: true, cleartextCapable: true, insecureByDesign: true, tokens: []string{"tftp", "tftpd"}, riskTags: []string{"unauthenticated-file-transfer", "cleartext-protocol"}},
	{family: "FTP", role: "FILE_TRANSFER", remoteCapable: true, legacy: true, cleartextCapable: true, tokens: []string{"ftp", "ftpd", "vsftpd", "proftpd", "pureftpd", "ftpsvc"}, riskTags: []string{"cleartext-capable", "legacy-file-transfer"}},
	{family: "FINGER", role: "LEGACY_INFORMATION", remoteCapable: true, legacy: true, deprecated: true, cleartextCapable: true, insecureByDesign: true, tokens: []string{"finger", "fingerd"}, riskTags: []string{"legacy-information-service"}},
	{family: "NIS_YP", role: "LEGACY_IDENTITY", remoteCapable: true, legacy: true, deprecated: true, cleartextCapable: true, tokens: []string{"ypbind", "ypserv", "yppasswdd"}, riskTags: []string{"legacy-network-identity"}},
	{family: "LEGACY_INETD_DIAGNOSTIC", role: "LEGACY_DIAGNOSTIC", remoteCapable: true, legacy: true, deprecated: true, cleartextCapable: true, insecureByDesign: true, tokens: []string{"chargen", "daytime", "discard"}, riskTags: []string{"legacy-diagnostic-service"}},
	{family: "REMOTE_REGISTRY", role: "REMOTE_REGISTRY", remoteCapable: true, tokens: []string{"remoteregistry"}, riskTags: []string{"sensitive-remote-management"}},
	{family: "WINRM", role: "REMOTE_ADMIN", remoteCapable: true, tokens: []string{"winrm"}, riskTags: []string{"remote-management"}},
	{family: "RDP", role: "REMOTE_DESKTOP", remoteCapable: true, tokens: []string{"termservice", "termsrv"}, riskTags: []string{"remote-desktop"}},
	{family: "SSH", role: "REMOTE_ADMIN", remoteCapable: true, tokens: []string{"ssh", "sshd", "openssh"}, riskTags: []string{"remote-management"}},
	{family: "VNC", role: "REMOTE_DESKTOP", remoteCapable: true, tokens: []string{"vnc", "vncserver", "x11vnc", "tigervnc", "screensharing"}, riskTags: []string{"remote-desktop"}},
	{family: "SMB", role: "FILE_SHARING", remoteCapable: true, tokens: []string{"smbd", "samba", "lanmanserver"}, riskTags: []string{"network-file-sharing"}},
	{family: "NFS", role: "FILE_SHARING", remoteCapable: true, tokens: []string{"nfs", "nfsserver", "nfsd"}, riskTags: []string{"network-file-sharing"}},
	{family: "WEB_SERVER", role: "WEB_SERVER", remoteCapable: true, tokens: []string{"apache", "apache2", "httpd", "nginx", "caddy", "lighttpd", "w3svc"}, riskTags: []string{"server-role"}},
	{family: "DATABASE", role: "DATABASE", remoteCapable: true, tokens: []string{"mysql", "mysqld", "mariadb", "postgres", "postgresql", "mssqlserver"}, riskTags: []string{"server-role"}},
	{family: "CONTAINER_RUNTIME", role: "CONTAINER_DAEMON", remoteCapable: true, tokens: []string{"docker", "podman", "containerd"}, riskTags: []string{"developer-or-server-role"}},
	{family: "COCKPIT", role: "ADMIN_CONSOLE", remoteCapable: true, tokens: []string{"cockpit"}, riskTags: []string{"web-admin-console"}},
	{family: "JUPYTER", role: "DEVELOPER_INTERFACE", remoteCapable: true, tokens: []string{"jupyter", "jupyterlab", "notebook"}, riskTags: []string{"developer-interface"}},
}

func classifyServiceExposure(items []Service) {
	for i := range items {
		p := classifyOneServiceExposure(items[i])
		items[i].Exposure = &p
	}
}

func classifyOneServiceExposure(s Service) ServiceExposurePosture {
	tokens := serviceIdentityTokens(s)
	p := ServiceExposurePosture{
		Schema:              ServiceExposureSchemaVersion,
		State:               "UNCLASSIFIED",
		Family:              "UNKNOWN",
		Role:                "UNKNOWN",
		Activity:            serviceActivity(s),
		NetworkReachability: "NOT_ASSESSED",
	}
	for _, class := range exposureClasses {
		matches := matchedTokens(tokens, class.tokens)
		if len(matches) == 0 {
			continue
		}
		p.State = "CLASSIFIED"
		p.Family = class.family
		p.Role = class.role
		p.RemoteCapable = class.remoteCapable
		p.Legacy = class.legacy
		p.Deprecated = class.deprecated
		p.CleartextCapable = class.cleartextCapable
		p.InsecureByDesign = class.insecureByDesign
		p.MatchBasis = matches
		p.RiskTags = append([]string(nil), class.riskTags...)
		break
	}
	p.normalize()
	return p
}

func serviceIdentityTokens(s Service) map[string]struct{} {
	texts := []string{s.Name, s.DisplayName, s.ServiceType}
	if s.ExecutablePath != "" {
		base := strings.ReplaceAll(strings.TrimSpace(s.ExecutablePath), `\`, "/")
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		base = strings.TrimSuffix(strings.ToLower(base), ".exe")
		if base != "" {
			texts = append(texts, base)
		}
	}
	out := map[string]struct{}{}
	for _, text := range texts {
		for _, token := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
			return !(unicode.IsLetter(r) || unicode.IsDigit(r))
		}) {
			token = strings.TrimSuffix(token, "exe")
			if token != "" {
				out[token] = struct{}{}
			}
		}
	}
	return out
}

func matchedTokens(observed map[string]struct{}, candidates []string) []string {
	out := []string{}
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if _, ok := observed[candidate]; ok {
			out = append(out, candidate)
		}
	}
	sort.Strings(out)
	return out
}

func serviceActivity(s Service) string {
	runtimeState := strings.ToUpper(strings.TrimSpace(s.RuntimeState))
	if runtimeState == "RUNNING" || runtimeState == "ACTIVE" || runtimeState == "STARTED" {
		return "ACTIVE"
	}
	start := strings.ToUpper(strings.TrimSpace(s.StartMode))
	switch start {
	case "ENABLED", "ENABLED_RUNTIME", "AUTOMATIC", "AUTO", "BOOT", "SYSTEM", "RUN_AT_LOAD", "KEEP_ALIVE":
		return "ENABLED_INACTIVE"
	case "DISABLED", "MASKED":
		return "DISABLED"
	}
	if runtimeState == "STOPPED" || runtimeState == "INACTIVE" || runtimeState == "DEAD" || runtimeState == "FAILED" || runtimeState == "EXITED" {
		return "INACTIVE"
	}
	return "UNKNOWN"
}

func exposureActive(p *ServiceExposurePosture) bool {
	if p == nil {
		return false
	}
	return p.Activity == "ACTIVE" || p.Activity == "ENABLED_INACTIVE"
}

func validationError(field, value string) error {
	return &serviceValidationError{field: field, value: value}
}

type serviceValidationError struct {
	field string
	value string
}

func (e *serviceValidationError) Error() string { return e.field + ": " + e.value }

package assessment

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/processes"
	"github.com/Nikolov999/chimera/internal/services"
)

// CrossDomainCorrelationPackVersion identifies the rule pack that
// joins already-normalized local evidence across process, service, filesystem,
// network, and identity domains. It performs no collection or probing itself.
const CrossDomainCorrelationPackVersion = "chimera.rules/cross-domain-v1-phase107"

const maxCorrelationEvidence = 64

var crossDomainRuleIDs = []string{
	"CHM-COR-001",
	"CHM-COR-002",
	"CHM-COR-003",
}

// CrossDomainCorrelationRules returns 's bounded correlation pack.
// These rules deliberately operate on normalized evidence only; collectors
// remain domain-specific and do not embed cross-domain finding logic.
func CrossDomainCorrelationRules() []Rule {
	return []Rule{
		{
			ID:             "CHM-COR-001",
			Title:          "Privileged writable service is externally exposed",
			Category:       "correlation",
			Severity:       SeverityHigh,
			AffectedObject: "correlation.service.privileged_writable_external",
			ExpectedState:  "externally bound services do not combine privileged execution with lower-privilege-writable executable, configuration, parent, or search-path boundaries",
			Risk:           "A remotely reachable service that executes with elevated authority across a writable local path boundary combines network exposure with a local privilege boundary weakness. Compromise or unintended modification of that boundary can materially increase host impact.",
			Remediation:    "Restrict the listener to the intended interfaces and firewall scope, remove unnecessary service privilege, and restore trusted ownership/write permissions on the executable, configuration, parent directories, and search path before reassessment.",
			Evaluate:       evaluatePrivilegedWritableExternalService,
		},
		{
			ID:             "CHM-COR-002",
			Title:          "Elevated weak-path process owns an external listener",
			Category:       "correlation",
			Severity:       SeverityHigh,
			AffectedObject: "correlation.process.elevated_weak_path_external",
			ExpectedState:  "processes owning non-loopback listeners do not execute elevated from files or parent directories writable by lower-privilege principals",
			Risk:           "An externally listening elevated process whose executable boundary is writable by a lower-privilege principal joins a network entry point directly to a local privilege-integrity weakness.",
			Remediation:    "Constrain or remove the external listener, run the process with the least authority required, and correct executable and parent-directory ownership/ACLs so lower-privilege principals cannot modify the execution boundary.",
			Evaluate:       evaluateElevatedWeakPathExternalProcess,
		},
		{
			ID:             "CHM-COR-003",
			Title:          "Externally exposed service uses a privileged interactive local account",
			Category:       "correlation",
			Severity:       SeverityMedium,
			AffectedObject: "correlation.service.privileged_interactive_identity_external",
			ExpectedState:  "externally bound services use dedicated least-privilege non-interactive identities unless an explicit platform requirement is documented",
			Risk:           "A remote-facing service running under a privileged local identity that is also login-capable increases the blast radius of a service compromise and weakens separation between service and interactive administration contexts.",
			Remediation:    "Use a dedicated least-privilege service identity, disable interactive login for service-only accounts where supported, and constrain the listener and firewall policy to the minimum required scope.",
			Evaluate:       evaluatePrivilegedInteractiveServiceIdentity,
		},
	}
}

// ValidateCrossDomainCorrelationRulePack freezes the public rule-ID
// contract and verifies that every rule remains executable and categorized as a
// cross-domain correlation rule.
func ValidateCrossDomainCorrelationRulePack(rules []Rule) error {
	if len(rules) != len(crossDomainRuleIDs) {
		return fmt.Errorf("cross-domain correlation rule count=%d want=%d", len(rules), len(crossDomainRuleIDs))
	}
	want := make(map[string]struct{}, len(crossDomainRuleIDs))
	for _, id := range crossDomainRuleIDs {
		want[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return err
		}
		if r.Category != "correlation" {
			return fmt.Errorf("cross-domain rule %q category=%q", r.ID, r.Category)
		}
		if _, ok := want[r.ID]; !ok {
			return fmt.Errorf("unexpected cross-domain rule id %q", r.ID)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate cross-domain rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

type correlatedService struct {
	ServiceKey    string
	Service       services.Service
	PathKey       string
	Path          *services.ServicePathIntegrity
	ProcessKey    string
	Process       *processes.Process
	PermissionKey string
	Permission    *processes.PathPermissionContext
	PrivilegeKey  string
	Privilege     *processes.RuntimePrivilegeContext
	AccountKey    string
	Account       *accounts.Account
	FilesystemKey string
	Filesystem    *fsinv.ExecutableRecord
	Endpoints     []correlatedEndpoint
}

type correlatedEndpoint struct {
	Key      string
	Endpoint netinv.Endpoint
}

type correlationIndex struct {
	Platform    string
	Services    []correlatedService
	Processes   map[int]processRecord
	Permissions map[string]permissionRecord
	Privileges  map[string]privilegeRecord
	Accounts    []accountRecord
	Files       []filesystemRecord
	Endpoints   []correlatedEndpoint
}

type processRecord struct {
	Key string
	Val processes.Process
}

type permissionRecord struct {
	Key string
	Val processes.PathPermissionContext
}

type privilegeRecord struct {
	Key string
	Val processes.RuntimePrivilegeContext
}

type accountRecord struct {
	Key string
	Val accounts.Account
}

type filesystemRecord struct {
	Key string
	Val fsinv.ExecutableRecord
}

func buildCorrelationIndex(idx Index) correlationIndex {
	ci := correlationIndex{
		Processes:   map[int]processRecord{},
		Permissions: map[string]permissionRecord{},
		Privileges:  map[string]privilegeRecord{},
	}
	ci.Platform = observedString(idx, "service.platform")
	if ci.Platform == "" {
		ci.Platform = observedString(idx, "process.platform")
	}
	if ci.Platform == "" {
		ci.Platform = observedString(idx, "network.platform")
	}

	keys := make([]string, 0, len(idx))
	for key := range idx {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	serviceRecords := make([]correlatedService, 0)
	pathByID := map[string]struct {
		key string
		val services.ServicePathIntegrity
	}{}
	for _, key := range keys {
		o := idx[key]
		if o.State != evidence.StateObserved {
			continue
		}
		switch {
		case strings.HasPrefix(key, "service.item."):
			if v, ok := o.Value.(services.Service); ok {
				serviceRecords = append(serviceRecords, correlatedService{ServiceKey: key, Service: v})
			}
		case strings.HasPrefix(key, "service.path_integrity."):
			if v, ok := o.Value.(services.ServicePathIntegrity); ok {
				pathByID[strings.TrimPrefix(key, "service.path_integrity.")] = struct {
					key string
					val services.ServicePathIntegrity
				}{key: key, val: v}
			}
		case strings.HasPrefix(key, "process.item."):
			if v, ok := o.Value.(processes.Process); ok && v.PID > 0 {
				ci.Processes[v.PID] = processRecord{Key: key, Val: v}
			}
		case strings.HasPrefix(key, "process.permission."):
			if v, ok := o.Value.(processes.PathPermissionContext); ok {
				ci.Permissions[v.ProcessID] = permissionRecord{Key: key, Val: v}
			}
		case strings.HasPrefix(key, "process.privilege."):
			if v, ok := o.Value.(processes.RuntimePrivilegeContext); ok {
				ci.Privileges[v.ProcessID] = privilegeRecord{Key: key, Val: v}
			}
		case strings.HasPrefix(key, "account.item."):
			if v, ok := o.Value.(accounts.Account); ok {
				ci.Accounts = append(ci.Accounts, accountRecord{Key: key, Val: v})
			}
		case strings.HasPrefix(key, "filesystem.executable."):
			if v, ok := o.Value.(fsinv.ExecutableRecord); ok {
				ci.Files = append(ci.Files, filesystemRecord{Key: key, Val: v})
			}
		case strings.HasPrefix(key, "network.endpoint."):
			if v, ok := o.Value.(netinv.Endpoint); ok {
				ci.Endpoints = append(ci.Endpoints, correlatedEndpoint{Key: key, Endpoint: v})
			}
		}
	}

	for i := range serviceRecords {
		s := &serviceRecords[i]
		if p, ok := pathByID[s.Service.ID]; ok {
			copy := p.val
			s.PathKey, s.Path = p.key, &copy
		}
		if pr, ok := ci.Processes[s.Service.RuntimePID]; ok && s.Service.RuntimePID > 0 {
			copy := pr.Val
			s.ProcessKey, s.Process = pr.Key, &copy
			if per, ok := ci.Permissions[pr.Val.ID]; ok {
				copy := per.Val
				s.PermissionKey, s.Permission = per.Key, &copy
			}
			if pv, ok := ci.Privileges[pr.Val.ID]; ok {
				copy := pv.Val
				s.PrivilegeKey, s.Privilege = pv.Key, &copy
			}
		}
		for _, ar := range ci.Accounts {
			if principalEquivalent(s.Service.Account, ar.Val, ci.Platform) {
				copy := ar.Val
				s.AccountKey, s.Account = ar.Key, &copy
				break
			}
		}
		for _, fr := range ci.Files {
			if pathsEquivalent(s.Service.ExecutablePath, fr.Val.Path, ci.Platform) || pathsEquivalent(s.Service.ExecutablePath, fr.Val.ResolvedPath, ci.Platform) {
				copy := fr.Val
				s.FilesystemKey, s.Filesystem = fr.Key, &copy
				break
			}
		}
		for _, ep := range ci.Endpoints {
			if endpointBelongsToService(ep.Endpoint, s.Service) {
				s.Endpoints = append(s.Endpoints, ep)
			}
		}
	}
	ci.Services = serviceRecords
	return ci
}

func evaluatePrivilegedWritableExternalService(idx Index) Evaluation {
	ci := buildCorrelationIndex(idx)
	matches := make([]string, 0)
	keys := make([]string, 0)
	confidence := evidence.ConfidenceHigh
	for _, s := range ci.Services {
		weak, weakBasis := serviceWeakBoundary(s)
		if !weak || !servicePrivileged(s) {
			continue
		}
		external := externalServiceEndpoints(s.Endpoints)
		if len(external) == 0 {
			continue
		}
		if s.Account != nil && s.Account.Privileged && s.Filesystem != nil && (s.Filesystem.UntrustedWrite || s.Filesystem.BroadlyWritable) && s.Process != nil && s.Permission != nil {
			confidence = evidence.ConfidenceExact
		}
		matches = append(matches, formatServiceCorrelation(s, external[0], weakBasis))
		keys = appendCorrelationKeys(keys, s.ServiceKey, s.PathKey, s.ProcessKey, s.PermissionKey, s.PrivilegeKey, s.AccountKey, s.FilesystemKey, external[0].Key)
	}
	if len(matches) > 0 {
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: fmt.Sprintf("%d privileged externally bound service(s) cross a writable execution/configuration boundary: %s", len(matches), summarizeCorrelationMatches(matches)), Applicability: Applicable, EvidenceKeys: keys}
	}
	return correlationPassOrUnknown(idx, "no privileged externally bound service crossed an observed lower-privilege-writable execution/configuration boundary", "service.inventory.count", "network.inventory.count")
}

func evaluateElevatedWeakPathExternalProcess(idx Index) Evaluation {
	ci := buildCorrelationIndex(idx)
	matches := make([]string, 0)
	keys := make([]string, 0)
	confidence := evidence.ConfidenceHigh
	for pid, pr := range ci.Processes {
		per, ok := ci.Permissions[pr.Val.ID]
		if !ok || !(per.Val.UntrustedExecutableWrite || per.Val.UntrustedParentWrite) {
			continue
		}
		priv := ci.Privileges[pr.Val.ID]
		if !processElevated(pr.Val, priv.Val) {
			continue
		}
		for _, ep := range ci.Endpoints {
			if ep.Endpoint.Owner.PID != pid || !isExternalEndpoint(ep.Endpoint) {
				continue
			}
			fsKey := ""
			for _, fr := range ci.Files {
				if pathsEquivalent(pr.Val.ExecutablePath, fr.Val.Path, ci.Platform) || pathsEquivalent(pr.Val.ExecutablePath, fr.Val.ResolvedPath, ci.Platform) {
					if fr.Val.UntrustedWrite || fr.Val.BroadlyWritable {
						fsKey = fr.Key
						confidence = evidence.ConfidenceExact
					}
					break
				}
			}
			matches = append(matches, fmt.Sprintf("%s pid=%d %s %s:%d", fallbackCorrelation(pr.Val.Name, pr.Val.ExecutablePath), pid, ep.Endpoint.Protocol, ep.Endpoint.LocalAddress, ep.Endpoint.LocalPort))
			keys = appendCorrelationKeys(keys, pr.Key, per.Key, priv.Key, fsKey, ep.Key)
			break
		}
	}
	if len(matches) > 0 {
		return Evaluation{Status: StatusFail, Confidence: confidence, ObservedState: fmt.Sprintf("%d elevated process(es) with weak executable/parent write boundaries own non-loopback listeners: %s", len(matches), summarizeCorrelationMatches(matches)), Applicability: Applicable, EvidenceKeys: keys}
	}
	return correlationPassOrUnknown(idx, "no elevated process with an observed lower-privilege-writable executable boundary owned a non-loopback listener", "process.inventory.count", "network.inventory.count")
}

func evaluatePrivilegedInteractiveServiceIdentity(idx Index) Evaluation {
	ci := buildCorrelationIndex(idx)
	matches := make([]string, 0)
	keys := make([]string, 0)
	for _, s := range ci.Services {
		if s.Account == nil || !s.Account.Privileged || !s.Account.ServiceAccount || strings.ToUpper(strings.TrimSpace(s.Account.LoginCapability)) != "LOGIN_CAPABLE" {
			continue
		}
		external := externalServiceEndpoints(s.Endpoints)
		if len(external) == 0 {
			continue
		}
		matches = append(matches, fmt.Sprintf("%s account=%s %s %s:%d", s.Service.Name, s.Account.Principal, external[0].Endpoint.Protocol, external[0].Endpoint.LocalAddress, external[0].Endpoint.LocalPort))
		keys = appendCorrelationKeys(keys, s.ServiceKey, s.AccountKey, s.ProcessKey, s.PrivilegeKey, external[0].Key)
	}
	if len(matches) > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d externally bound service(s) use privileged login-capable local service identities: %s", len(matches), summarizeCorrelationMatches(matches)), Applicability: Applicable, EvidenceKeys: keys}
	}
	return correlationPassOrUnknown(idx, "no externally bound service was correlated to a privileged login-capable local service identity", "service.inventory.count", "network.inventory.count", "account.inventory.count")
}

func correlationPassOrUnknown(idx Index, pass string, required ...string) Evaluation {
	keys := make([]string, 0, len(required))
	for _, key := range required {
		o, ok := idx[key]
		if !ok {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "required cross-domain inventory evidence is missing: " + key, Applicability: Undetermined, EvidenceKeys: appendCorrelationKeys(keys, key)}
		}
		keys = appendCorrelationKeys(keys, key)
		if o.State != evidence.StateObserved {
			return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "required cross-domain inventory evidence is " + string(o.State) + ": " + key, Applicability: Undetermined, EvidenceKeys: keys}
		}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: pass, Applicability: Applicable, EvidenceKeys: keys}
}

func serviceWeakBoundary(s correlatedService) (bool, string) {
	basis := make([]string, 0)
	if s.Path != nil {
		if s.Path.Executable.LowerPrivilegeWritable {
			basis = append(basis, "writable executable")
		}
		if s.Path.ExecutableDirectory.LowerPrivilegeWritable {
			basis = append(basis, "writable executable directory")
		}
		if s.Path.Configuration.LowerPrivilegeWritable {
			basis = append(basis, "writable configuration")
		}
		if s.Path.ConfigurationDirectory.LowerPrivilegeWritable {
			basis = append(basis, "writable configuration directory")
		}
		if s.Path.SearchPathWritable {
			basis = append(basis, "writable search path")
		}
	}
	if s.Permission != nil {
		if s.Permission.UntrustedExecutableWrite {
			basis = append(basis, "process executable writable")
		}
		if s.Permission.UntrustedParentWrite {
			basis = append(basis, "process parent writable")
		}
	}
	if s.Filesystem != nil && (s.Filesystem.UntrustedWrite || s.Filesystem.BroadlyWritable) {
		basis = append(basis, "filesystem executable writable")
	}
	basis = uniqueStrings(basis)
	return len(basis) > 0, strings.Join(basis, ", ")
}

func servicePrivileged(s correlatedService) bool {
	switch strings.ToUpper(strings.TrimSpace(s.Service.PrivilegeContext)) {
	case "ROOT", "SYSTEM", "PRIVILEGED", "ROOT_EQUIVALENT":
		return true
	}
	if s.Account != nil && s.Account.Privileged {
		return true
	}
	if s.Process != nil && s.Process.Principal.Elevated {
		return true
	}
	if s.Privilege != nil && processPrivilegeElevated(*s.Privilege) {
		return true
	}
	return false
}

func processElevated(p processes.Process, privilege processes.RuntimePrivilegeContext) bool {
	if p.Principal.Elevated {
		return true
	}
	return processPrivilegeElevated(privilege)
}

func processPrivilegeElevated(p processes.RuntimePrivilegeContext) bool {
	if p.ElevatedUserContext || len(p.HighImpactPrivileges) > 0 || len(p.EffectiveCapabilities) > 0 {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(p.AccountClass)) {
	case "ROOT", "SYSTEM", "ADMIN", "ADMINISTRATOR", "ROOT_EQUIVALENT", "PRIVILEGED":
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(p.TokenElevation)) {
	case "ELEVATED", "FULL", "YES", "TRUE":
		return true
	}
	return false
}

func externalServiceEndpoints(in []correlatedEndpoint) []correlatedEndpoint {
	out := make([]correlatedEndpoint, 0, len(in))
	for _, ep := range in {
		if isExternalEndpoint(ep.Endpoint) {
			out = append(out, ep)
		}
	}
	return out
}

func isExternalEndpoint(ep netinv.Endpoint) bool {
	if ep.InterfaceBinding.IsLoopback || strings.EqualFold(ep.InterfaceBinding.Class, "LOOPBACK") {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(ep.InterfaceBinding.Class)) {
	case "ALL_INTERFACES", "NON_LOOPBACK":
		return true
	default:
		return false
	}
}

func endpointBelongsToService(ep netinv.Endpoint, svc services.Service) bool {
	if svc.RuntimePID > 0 && ep.Owner.PID > 0 && svc.RuntimePID == ep.Owner.PID {
		return true
	}
	if strings.TrimSpace(ep.Owner.ServiceName) != "" && canonicalPrincipal(ep.Owner.ServiceName) == canonicalPrincipal(svc.Name) {
		return true
	}
	return false
}

func principalEquivalent(serviceAccount string, a accounts.Account, platform string) bool {
	left := canonicalPrincipal(serviceAccount)
	if left == "" || left == "unknown" {
		return false
	}
	candidates := []string{a.Name, a.Principal, a.SID, a.UID}
	for _, candidate := range candidates {
		right := canonicalPrincipal(candidate)
		if right == "" {
			continue
		}
		if left == right {
			return true
		}
	}
	return false
}

func canonicalPrincipal(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, `.\`)
	v = strings.TrimPrefix(v, "./")
	v = strings.ReplaceAll(v, "/", `\`)
	return v
}

func pathsEquivalent(a, b, platform string) bool {
	a = normalizeCorrelationPath(a, platform)
	b = normalizeCorrelationPath(b, platform)
	return a != "" && b != "" && a == b
}

func normalizeCorrelationPath(v, platform string) string {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, `\`, "/")
	v = filepath.Clean(v)
	if strings.EqualFold(platform, "windows") || strings.EqualFold(platform, "darwin") {
		v = strings.ToLower(v)
	}
	return v
}

func observedString(idx Index, key string) string {
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return ""
	}
	v, _ := o.Value.(string)
	return strings.TrimSpace(v)
}

func appendCorrelationKeys(dst []string, items ...string) []string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == item {
				found = true
				break
			}
		}
		if !found && len(dst) < maxCorrelationEvidence {
			dst = append(dst, item)
		}
	}
	return dst
}

func summarizeCorrelationMatches(items []string) string {
	const max = 5
	if len(items) <= max {
		return strings.Join(items, "; ")
	}
	return strings.Join(items[:max], "; ") + fmt.Sprintf("; +%d more", len(items)-max)
}

func formatServiceCorrelation(s correlatedService, ep correlatedEndpoint, weakBasis string) string {
	name := fallbackCorrelation(s.Service.Name, s.Service.ExecutablePath)
	return fmt.Sprintf("%s pid=%d %s %s:%d (%s)", name, s.Service.RuntimePID, ep.Endpoint.Protocol, ep.Endpoint.LocalAddress, ep.Endpoint.LocalPort, weakBasis)
}

func fallbackCorrelation(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	return "unnamed"
}

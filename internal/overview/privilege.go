package overview

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// PrivilegeSchemaVersion identifies Chimera's normalized effective-privilege
// context. It is intentionally separate from the general evidence schema so
// privilege-aware collectors can evolve behind a stable contract.
const PrivilegeSchemaVersion = "chimera.privilege/v1"

const (
	AdminGroupMember        = "MEMBER"
	AdminGroupNotMember     = "NOT_MEMBER"
	AdminGroupUnknown       = "UNKNOWN"
	AdminGroupNotApplicable = "NOT_APPLICABLE"
)

// ElevationOpportunity records a class of local evidence that the current
// non-elevated execution context may not be able to read completely. These are
// collection-depth notes, not findings and not a request to elevate.
type ElevationOpportunity struct {
	Area        string `json:"area"`
	Requirement string `json:"requirement"`
	Reason      string `json:"reason"`
}

// finalizePrivilege normalizes platform-specific privilege facts and adds the
// explicit collection-depth contract. Elevation remains optional.
func finalizePrivilege(p Privilege) Privilege {
	p.Schema = PrivilegeSchemaVersion
	p.Level = strings.TrimSpace(p.Level)
	p.Principal = strings.TrimSpace(p.Principal)
	p.PrincipalID = strings.TrimSpace(p.PrincipalID)
	p.EffectiveUID = strings.TrimSpace(p.EffectiveUID)
	p.EffectiveGID = strings.TrimSpace(p.EffectiveGID)
	p.AdministrativeGroup = strings.TrimSpace(p.AdministrativeGroup)
	p.IntegrityLevel = strings.TrimSpace(p.IntegrityLevel)
	p.ElevationState = strings.TrimSpace(p.ElevationState)
	p.CollectionTier = strings.TrimSpace(p.CollectionTier)
	p.DetectionSource = strings.TrimSpace(p.DetectionSource)
	p.Detail = strings.TrimSpace(p.Detail)

	if p.AdministrativeGroup == "" {
		p.AdministrativeGroup = AdminGroupUnknown
	}
	if p.CollectionTier == "" {
		if p.Elevated {
			p.CollectionTier = "elevated"
		} else if p.Level != "" && !strings.EqualFold(p.Level, "unknown") {
			p.CollectionTier = "standard"
		} else {
			p.CollectionTier = "unknown"
		}
	}

	known := p.Level != "" && !strings.EqualFold(p.Level, "unknown")
	p.DeeperEvidenceAvailable = known && !p.Elevated
	if p.DeeperEvidenceAvailable {
		p.ElevationNote = "deeper evidence available with elevation; elevation is optional and Chimera continues in read-only standard collection mode"
		p.DeeperEvidence = platformElevationOpportunities(runtime.GOOS)
	} else if p.Elevated {
		p.ElevationNote = "elevated collection context active; Chimera remains read-only"
	} else {
		p.ElevationNote = "effective privilege could not be determined; Chimera will not assume elevated access"
	}
	return p
}

func platformElevationOpportunities(goos string) []ElevationOpportunity {
	var out []ElevationOpportunity
	switch goos {
	case "linux":
		out = []ElevationOpportunity{
			{Area: "protected kernel and security-control metadata", Requirement: "root", Reason: "some procfs, sysfs, securityfs, and policy providers restrict complete state to privileged readers"},
			{Area: "complete local firewall policy metadata", Requirement: "root", Reason: "nftables/iptables and related providers can restrict ruleset visibility"},
			{Area: "restricted process, service, and system configuration metadata", Requirement: "root", Reason: "some ownership, namespace, service, and protected configuration details are permission-gated"},
		}
	case "windows":
		out = []ElevationOpportunity{
			{Area: "protected operating-system and security-policy metadata", Requirement: "elevated administrator token", Reason: "some local policy, registry, and security providers require an elevated token"},
			{Area: "complete firewall, Defender, service, and scheduled-execution metadata", Requirement: "elevated administrator token", Reason: "provider visibility can be reduced for a filtered or standard token"},
			{Area: "restricted process and system-object metadata", Requirement: "elevated administrator token", Reason: "protected processes and system objects may expose only partial metadata to a non-elevated token"},
		}
	case "darwin":
		out = []ElevationOpportunity{
			{Area: "protected security-control and system configuration metadata", Requirement: "root", Reason: "some system policy and protected configuration providers restrict complete state"},
			{Area: "restricted launch, service, process, and storage metadata", Requirement: "root", Reason: "some system-owned objects and FileVault-related metadata are permission-gated"},
			{Area: "protected firewall and network-policy metadata", Requirement: "root", Reason: "some packet-filter and system network policy details require privileged access"},
		}
	default:
		out = []ElevationOpportunity{
			{Area: "platform-protected local security metadata", Requirement: "platform administrator", Reason: "the current platform may restrict security evidence to privileged readers"},
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Area < out[j].Area })
	return out
}

func adminGroupState(member bool) string {
	if member {
		return AdminGroupMember
	}
	return AdminGroupNotMember
}

// Validate enforces the privilege-context invariants used by privilege-aware
// collectors and machine-readable output.
func (p Privilege) Validate() error {
	if p.Schema != PrivilegeSchemaVersion {
		return fmt.Errorf("unexpected privilege schema %q", p.Schema)
	}
	if strings.TrimSpace(p.Level) == "" {
		return fmt.Errorf("privilege level is required")
	}
	switch p.AdministrativeGroup {
	case AdminGroupMember, AdminGroupNotMember, AdminGroupUnknown, AdminGroupNotApplicable:
	default:
		return fmt.Errorf("invalid administrative group state %q", p.AdministrativeGroup)
	}
	switch p.CollectionTier {
	case "standard", "elevated", "unknown":
	default:
		return fmt.Errorf("invalid collection tier %q", p.CollectionTier)
	}
	if strings.TrimSpace(p.ElevationNote) == "" {
		return fmt.Errorf("elevation note is required")
	}
	if p.Elevated && p.CollectionTier != "elevated" {
		return fmt.Errorf("elevated privilege requires elevated collection tier")
	}
	if p.Elevated && p.DeeperEvidenceAvailable {
		return fmt.Errorf("elevated context cannot advertise deeper evidence through elevation")
	}
	if p.DeeperEvidenceAvailable {
		if p.CollectionTier != "standard" {
			return fmt.Errorf("deeper evidence availability requires standard collection tier")
		}
		if len(p.DeeperEvidence) == 0 {
			return fmt.Errorf("deeper evidence availability requires at least one opportunity")
		}
	}
	for i, opportunity := range p.DeeperEvidence {
		if strings.TrimSpace(opportunity.Area) == "" || strings.TrimSpace(opportunity.Requirement) == "" || strings.TrimSpace(opportunity.Reason) == "" {
			return fmt.Errorf("elevation opportunity %d is incomplete", i)
		}
	}
	return nil
}

// String provides a compact deterministic human representation when the
// privilege context is embedded as an evidence value in finding output.
func (p Privilege) String() string {
	parts := []string{
		"level=" + p.Level,
		"elevated=" + fmt.Sprintf("%t", p.Elevated),
		"collection_tier=" + p.CollectionTier,
	}
	if p.Principal != "" {
		parts = append(parts, "principal="+p.Principal)
	}
	if p.ElevationState != "" {
		parts = append(parts, "elevation_state="+p.ElevationState)
	}
	if p.AdministrativeGroup != "" {
		parts = append(parts, "admin_group="+p.AdministrativeGroup)
	}
	if p.IntegrityLevel != "" {
		parts = append(parts, "integrity="+p.IntegrityLevel)
	}
	return strings.Join(parts, "; ")
}

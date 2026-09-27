package overview

import (
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type Control struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Source string `json:"source,omitempty"`
}

type Privilege struct {
	Schema                  string                 `json:"schema"`
	Level                   string                 `json:"level"`
	Elevated                bool                   `json:"elevated"`
	Principal               string                 `json:"principal,omitempty"`
	PrincipalID             string                 `json:"principal_id,omitempty"`
	EffectiveUID            string                 `json:"effective_uid,omitempty"`
	EffectiveGID            string                 `json:"effective_gid,omitempty"`
	AdministrativeGroup     string                 `json:"administrative_group_state"`
	IntegrityLevel          string                 `json:"integrity_level,omitempty"`
	ElevationState          string                 `json:"elevation_state,omitempty"`
	CollectionTier          string                 `json:"collection_tier"`
	DetectionSource         string                 `json:"detection_source,omitempty"`
	Detail                  string                 `json:"detail,omitempty"`
	DeeperEvidenceAvailable bool                   `json:"deeper_evidence_available"`
	ElevationNote           string                 `json:"elevation_note"`
	DeeperEvidence          []ElevationOpportunity `json:"deeper_evidence,omitempty"`
}

type Overview struct {
	EvidenceSchema   string                 `json:"evidence_schema"`
	Evidence         []evidence.Observation `json:"evidence"`
	CollectedAt      time.Time              `json:"collected_at"`
	Hostname         string                 `json:"hostname"`
	CurrentUser      string                 `json:"current_user"`
	OS               string                 `json:"os"`
	OSVersion        string                 `json:"os_version,omitempty"`
	OSBuild          string                 `json:"os_build,omitempty"`
	Kernel           string                 `json:"kernel"`
	Architecture     string                 `json:"architecture"`
	BootTime         *time.Time             `json:"boot_time,omitempty"`
	UptimeSeconds    int64                  `json:"uptime_seconds"`
	PrivilegeSchema  string                 `json:"privilege_schema"`
	Privilege        Privilege              `json:"privilege"`
	CPUModel         string                 `json:"cpu_model,omitempty"`
	LogicalCPUs      int                    `json:"logical_cpus"`
	MemoryTotalBytes uint64                 `json:"memory_total_bytes"`
	ProcessCount     int                    `json:"process_count"`
	ListenerCount    int                    `json:"listener_count"`
	ListenerScope    string                 `json:"listener_scope,omitempty"`
	SecurityControls []Control              `json:"security_controls"`
	Degraded         []string               `json:"degraded,omitempty"`
}

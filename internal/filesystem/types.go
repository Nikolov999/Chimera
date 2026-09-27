package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion      = "chimera.filesystem/v1"
	CollectorName      = "filesystem-security"
	CollectorVersion   = "filesystem/phase085-v1"
	maxPaths           = 4096
	maxMounts          = 4096
	maxExecutables     = 8192
	maxExecutableDirs  = 128
	maxSearchPaths     = 256
	maxPrivilegedFiles = 4096
	maxSensitiveFiles  = 2048
	maxACLBoundaries   = 512
	maxTempDirectories = 64
	maxNetworkShares   = 2048
)

type PermissionCapability struct {
	State  evidence.State `json:"state"`
	Model  string         `json:"model"`
	Source string         `json:"source"`
	Reason string         `json:"reason,omitempty"`
}

type PathRecord struct {
	ID               string              `json:"id"`
	Kind             string              `json:"kind"`
	Path             string              `json:"path"`
	State            evidence.State      `json:"state"`
	Exists           bool                `json:"exists"`
	Directory        bool                `json:"directory"`
	Symlink          bool                `json:"symlink"`
	Mode             string              `json:"mode,omitempty"`
	OwnerID          string              `json:"owner_id,omitempty"`
	GroupID          string              `json:"group_id,omitempty"`
	PermissionModel  string              `json:"permission_model"`
	MountPoint       string              `json:"mount_point,omitempty"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type ExecutableRecord struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	ResolvedPath     string              `json:"resolved_path,omitempty"`
	Directory        string              `json:"directory"`
	State            evidence.State      `json:"state"`
	Exists           bool                `json:"exists"`
	Regular          bool                `json:"regular"`
	Symlink          bool                `json:"symlink"`
	Executable       bool                `json:"executable"`
	Mode             string              `json:"mode,omitempty"`
	OwnerID          string              `json:"owner_id,omitempty"`
	GroupID          string              `json:"group_id,omitempty"`
	PermissionModel  string              `json:"permission_model"`
	GroupWritable    bool                `json:"group_writable"`
	OtherWritable    bool                `json:"other_writable"`
	BroadlyWritable  bool                `json:"broadly_writable"`
	UntrustedWrite   bool                `json:"untrusted_write"`
	WritePrincipals  []string            `json:"write_principals,omitempty"`
	DiscoverySource  string              `json:"discovery_source"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type PrivilegedFileRecord struct {
	ID                  string              `json:"id"`
	Path                string              `json:"path"`
	State               evidence.State      `json:"state"`
	Exists              bool                `json:"exists"`
	Regular             bool                `json:"regular"`
	Executable          bool                `json:"executable"`
	Mode                string              `json:"mode,omitempty"`
	OwnerID             string              `json:"owner_id,omitempty"`
	GroupID             string              `json:"group_id,omitempty"`
	SetUID              bool                `json:"setuid"`
	SetGID              bool                `json:"setgid"`
	Capabilities        []string            `json:"capabilities,omitempty"`
	InheritableCaps     []string            `json:"inheritable_capabilities,omitempty"`
	CapabilityEffective bool                `json:"capability_effective"`
	CapabilityRevision  int                 `json:"capability_revision,omitempty"`
	CapabilityRootID    string              `json:"capability_root_id,omitempty"`
	PackageOwnership    string              `json:"package_ownership"`
	PackageID           string              `json:"package_id,omitempty"`
	PackageProvider     string              `json:"package_provider,omitempty"`
	Classification      string              `json:"classification"`
	ReviewRequired      bool                `json:"review_required"`
	ReviewReasons       []string            `json:"review_reasons,omitempty"`
	DiscoverySource     string              `json:"discovery_source"`
	CollectionSource    string              `json:"collection_source"`
	Confidence          evidence.Confidence `json:"confidence"`
	Reason              string              `json:"reason,omitempty"`
}

type SensitiveFileRecord struct {
	ID                string              `json:"id"`
	Kind              string              `json:"kind"`
	Scope             string              `json:"scope"`
	Path              string              `json:"path"`
	ResolvedPath      string              `json:"resolved_path,omitempty"`
	AccessPolicy      string              `json:"access_policy"`
	State             evidence.State      `json:"state"`
	Exists            bool                `json:"exists"`
	Directory         bool                `json:"directory"`
	Symlink           bool                `json:"symlink"`
	Mode              string              `json:"mode,omitempty"`
	OwnerID           string              `json:"owner_id,omitempty"`
	GroupID           string              `json:"group_id,omitempty"`
	ExpectedOwnerID   string              `json:"expected_owner_id,omitempty"`
	OwnerState        string              `json:"owner_state"`
	PermissionModel   string              `json:"permission_model"`
	GroupWritable     bool                `json:"group_writable"`
	OtherWritable     bool                `json:"other_writable"`
	BroadlyWritable   bool                `json:"broadly_writable"`
	UntrustedWrite    bool                `json:"untrusted_write"`
	GroupAccessible   bool                `json:"group_accessible"`
	OtherAccessible   bool                `json:"other_accessible"`
	BroadlyAccessible bool                `json:"broadly_accessible"`
	UntrustedAccess   bool                `json:"untrusted_access"`
	ReadPrincipals    []string            `json:"read_principals,omitempty"`
	WritePrincipals   []string            `json:"write_principals,omitempty"`
	DiscoverySource   string              `json:"discovery_source"`
	CollectionSource  string              `json:"collection_source"`
	Confidence        evidence.Confidence `json:"confidence"`
	Reason            string              `json:"reason,omitempty"`
}

type SearchPathRecord struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	ResolvedPath     string              `json:"resolved_path,omitempty"`
	State            evidence.State      `json:"state"`
	Exists           bool                `json:"exists"`
	Directory        bool                `json:"directory"`
	Symlink          bool                `json:"symlink"`
	Mode             string              `json:"mode,omitempty"`
	OwnerID          string              `json:"owner_id,omitempty"`
	GroupID          string              `json:"group_id,omitempty"`
	PermissionModel  string              `json:"permission_model"`
	GroupWritable    bool                `json:"group_writable"`
	OtherWritable    bool                `json:"other_writable"`
	BroadlyWritable  bool                `json:"broadly_writable"`
	UntrustedWrite   bool                `json:"untrusted_write"`
	WritePrincipals  []string            `json:"write_principals,omitempty"`
	Contexts         []string            `json:"contexts"`
	DiscoverySources []string            `json:"discovery_sources"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

const (
	MountAccessReadOnly  = "READ_ONLY"
	MountAccessReadWrite = "READ_WRITE"
	MountAccessUnknown   = "UNKNOWN"

	MountClassLocal     = "LOCAL"
	MountClassNetwork   = "NETWORK"
	MountClassRemovable = "REMOVABLE"
	MountClassVirtual   = "VIRTUAL"
	MountClassOptical   = "OPTICAL"
	MountClassUnknown   = "UNKNOWN"

	MountEncryptionEncrypted     = "ENCRYPTED"
	MountEncryptionNotObserved   = "NOT_OBSERVED"
	MountEncryptionUnknown       = "UNKNOWN"
	MountEncryptionNotApplicable = "NOT_APPLICABLE"
)

type MountBoundary struct {
	ID                 string              `json:"id"`
	Path               string              `json:"path"`
	Device             string              `json:"device,omitempty"`
	BackingSource      string              `json:"backing_source,omitempty"`
	Filesystem         string              `json:"filesystem,omitempty"`
	Options            []string            `json:"options,omitempty"`
	AccessMode         string              `json:"access_mode"`
	ReadOnly           bool                `json:"read_only"`
	Writable           bool                `json:"writable"`
	Classification     string              `json:"classification"`
	Network            bool                `json:"network"`
	Removable          bool                `json:"removable"`
	MajorMinor         string              `json:"major_minor,omitempty"`
	VolumeLabel        string              `json:"volume_label,omitempty"`
	EncryptionState    string              `json:"encryption_state"`
	EncryptionType     string              `json:"encryption_type,omitempty"`
	EncryptionEvidence string              `json:"encryption_evidence,omitempty"`
	State              evidence.State      `json:"state"`
	CollectionSource   string              `json:"collection_source"`
	Confidence         evidence.Confidence `json:"confidence"`
	Reason             string              `json:"reason,omitempty"`
}

const (
	NetworkShareDirectionMounted  = "MOUNTED"
	NetworkShareDirectionExported = "EXPORTED"

	NetworkShareProtocolNFS   = "NFS"
	NetworkShareProtocolSMB   = "SMB"
	NetworkShareProtocolOther = "OTHER"
)

// NetworkShareRecord is 's normalized metadata-only view of a local
// network-backed mount or a locally exported NFS share. SMB server exports are
// already collected by the SMB provider and are correlated by the
// filesystem rules rather than re-read here. No remote enumeration,
// authentication, or network traffic is performed.
type NetworkShareRecord struct {
	ID               string              `json:"id"`
	Direction        string              `json:"direction"`
	Protocol         string              `json:"protocol"`
	Name             string              `json:"name,omitempty"`
	LocalPath        string              `json:"local_path,omitempty"`
	Remote           string              `json:"remote,omitempty"`
	SecurityOptions  []string            `json:"security_options,omitempty"`
	AccessMode       string              `json:"access_mode"`
	ReadOnly         bool                `json:"read_only"`
	Writable         bool                `json:"writable"`
	AccessKnown      bool                `json:"access_known"`
	GuestAllowed     bool                `json:"guest_allowed"`
	AnonymousAllowed bool                `json:"anonymous_allowed"`
	BroadAccess      bool                `json:"broad_access"`
	BroadWrite       bool                `json:"broad_write"`
	DangerousOptions []string            `json:"dangerous_options,omitempty"`
	State            evidence.State      `json:"state"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Paths                           int `json:"paths"`
	SecurityRoots                   int `json:"security_roots"`
	TempAreas                       int `json:"temp_areas"`
	SearchPaths                     int `json:"search_paths"`
	SensitiveLocations              int `json:"sensitive_locations"`
	ExistingPaths                   int `json:"existing_paths"`
	UnavailablePaths                int `json:"unavailable_paths"`
	DeniedPaths                     int `json:"denied_paths"`
	MountBoundaries                 int `json:"mount_boundaries"`
	ReadOnlyMounts                  int `json:"read_only_mounts"`
	WritableMounts                  int `json:"writable_mounts"`
	NetworkMounts                   int `json:"network_mounts"`
	RemovableMounts                 int `json:"removable_mounts"`
	VirtualMounts                   int `json:"virtual_mounts"`
	EncryptedMounts                 int `json:"encrypted_mounts"`
	UnknownEncryptionMounts         int `json:"unknown_encryption_mounts"`
	NetworkShares                   int `json:"network_shares"`
	MountedNetworkShares            int `json:"mounted_network_shares"`
	ExportedNetworkShares           int `json:"exported_network_shares"`
	NFSNetworkShares                int `json:"nfs_network_shares"`
	SMBNetworkShares                int `json:"smb_network_shares"`
	GuestNetworkShares              int `json:"guest_network_shares"`
	AnonymousNetworkShares          int `json:"anonymous_network_shares"`
	BroadNetworkShares              int `json:"broad_network_shares"`
	BroadWritableNetworkShares      int `json:"broad_writable_network_shares"`
	DangerousNetworkShares          int `json:"dangerous_network_shares"`
	UnavailableNetworkShareMetadata int `json:"unavailable_network_share_metadata"`
	ExecutableDirectories           int `json:"executable_directories"`
	Executables                     int `json:"executables"`
	BroadlyWritableExecutables      int `json:"broadly_writable_executables"`
	UntrustedWritableExecutables    int `json:"untrusted_writable_executables"`
	UnavailableExecutableMetadata   int `json:"unavailable_executable_metadata"`
	PrivilegedSearchPaths           int `json:"privileged_search_paths"`
	WritablePrivilegedSearchPaths   int `json:"writable_privileged_search_paths"`
	UntrustedPrivilegedSearchPaths  int `json:"untrusted_privileged_search_paths"`
	LoaderSearchPaths               int `json:"loader_search_paths"`
	WritableLoaderSearchPaths       int `json:"writable_loader_search_paths"`
	UnavailableSearchPathMetadata   int `json:"unavailable_search_path_metadata"`
	PrivilegedFiles                 int `json:"privileged_files"`
	SetUIDFiles                     int `json:"setuid_files"`
	SetGIDFiles                     int `json:"setgid_files"`
	CapabilityFiles                 int `json:"capability_files"`
	CustomPrivilegedFiles           int `json:"custom_privileged_files"`
	UnmanagedPrivilegedFiles        int `json:"unmanaged_privileged_files"`
	UnavailablePrivilegedMetadata   int `json:"unavailable_privileged_metadata"`
	SensitiveFiles                  int `json:"sensitive_files"`
	SensitiveRestrictedReadFiles    int `json:"sensitive_restricted_read_files"`
	SensitiveBroadlyWritable        int `json:"sensitive_broadly_writable"`
	SensitiveUntrustedWritable      int `json:"sensitive_untrusted_writable"`
	SensitiveBroadlyAccessible      int `json:"sensitive_broadly_accessible"`
	SensitiveUntrustedAccessible    int `json:"sensitive_untrusted_accessible"`
	SensitiveOwnerMismatches        int `json:"sensitive_owner_mismatches"`
	UnavailableSensitiveMetadata    int `json:"unavailable_sensitive_metadata"`
	ACLBoundaries                   int `json:"acl_boundaries"`
	ExtendedACLBoundaries           int `json:"extended_acl_boundaries"`
	DangerousACLBoundaries          int `json:"dangerous_acl_boundaries"`
	ReviewACLBoundaries             int `json:"review_acl_boundaries"`
	UnavailableACLMetadata          int `json:"unavailable_acl_metadata"`
	TempDirectories                 int `json:"temp_directories"`
	SharedTempDirectories           int `json:"shared_temp_directories"`
	UnsafeTempDirectories           int `json:"unsafe_temp_directories"`
	UnsafeTempOwnership             int `json:"unsafe_temp_ownership"`
	UnsafeTempPermissions           int `json:"unsafe_temp_permissions"`
	UnsafeTempParentBoundaries      int `json:"unsafe_temp_parent_boundaries"`
	UnavailableTempMetadata         int `json:"unavailable_temp_metadata"`
}

type Inventory struct {
	Schema               string                 `json:"schema"`
	EvidenceSchema       string                 `json:"evidence_schema"`
	Collector            string                 `json:"collector"`
	CollectorVersion     string                 `json:"collector_version"`
	Platform             string                 `json:"platform"`
	Architecture         string                 `json:"architecture"`
	CollectedAt          time.Time              `json:"collected_at"`
	PermissionCapability PermissionCapability   `json:"permission_capability"`
	Paths                []PathRecord           `json:"paths"`
	MountBoundaries      []MountBoundary        `json:"mount_boundaries"`
	NetworkShares        []NetworkShareRecord   `json:"network_shares"`
	Executables          []ExecutableRecord     `json:"executables"`
	SearchPaths          []SearchPathRecord     `json:"search_paths"`
	PrivilegedFiles      []PrivilegedFileRecord `json:"privileged_files"`
	SensitiveFiles       []SensitiveFileRecord  `json:"sensitive_files"`
	ACLBoundaries        []ACLBoundaryRecord    `json:"acl_boundaries"`
	TempDirectories      []TempDirectoryRecord  `json:"temp_directories"`
	Sources              []SourceStatus         `json:"sources"`
	Summary              Summary                `json:"summary"`
	Evidence             []evidence.Observation `json:"evidence"`
	Degraded             []string               `json:"degraded,omitempty"`
}

type candidate struct {
	Kind   string
	Path   string
	Source string
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
	}
	inv.PermissionCapability = platformPermissionCapability()
	mounts, mountSource, mountDegraded := collectPlatformMounts(ctx)
	inv.MountBoundaries = normalizeMounts(mounts)
	inv.Sources = append(inv.Sources, mountSource)
	inv.Degraded = append(inv.Degraded, mountDegraded...)
	networkShares, networkShareSources, networkShareDegraded := collectNetworkShares(ctx, inv.MountBoundaries)
	inv.NetworkShares = normalizeNetworkShares(networkShares)
	inv.Sources = append(inv.Sources, networkShareSources...)
	inv.Degraded = append(inv.Degraded, networkShareDegraded...)

	candidates := append([]candidate(nil), platformCandidates()...)
	candidates = append(candidates, environmentCandidates()...)
	candidates = normalizeCandidates(candidates)
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			inv.Paths = append(inv.Paths, PathRecord{
				ID: stablePathID(c.Kind, c.Path), Kind: c.Kind, Path: c.Path,
				State: evidence.StateUnavailable, PermissionModel: inv.PermissionCapability.Model,
				CollectionSource: c.Source, Confidence: evidence.ConfidenceLow, Reason: ctx.Err().Error(),
			})
			continue
		}
		inv.Paths = append(inv.Paths, inspectPath(c, inv.PermissionCapability, inv.MountBoundaries))
	}
	inv.Paths = normalizePaths(inv.Paths)
	inv.Sources = append(inv.Sources, SourceStatus{ID: "path-metadata", State: evidence.StateObserved, Source: "local filesystem metadata via os.Lstat", ItemCount: len(inv.Paths)})
	execDirs := executableSearchDirectories()
	inv.Summary.ExecutableDirectories = len(execDirs)
	execCtx, execCancel, _ := filesystemEnrichmentStageContext(ctx, filesystemStageExecutable)
	executables, executableSource, executableDegraded := collectPlatformExecutables(execCtx, execDirs, inv.PermissionCapability)
	execCancel()
	executables, executableRepairDegraded := repairPlatformExecutableRecords(executables, inv.PermissionCapability)
	if len(executableRepairDegraded) > 0 && executableSource.State == evidence.StateObserved {
		executableSource.State = evidence.StateDegraded
		executableSource.Reason = "one or more executable provider records required record-level degradation"
	}
	inv.Executables = normalizeExecutables(executables)
	inv.Sources = append(inv.Sources, executableSource)
	inv.Degraded = append(inv.Degraded, executableDegraded...)
	inv.Degraded = append(inv.Degraded, executableRepairDegraded...)
	searchCandidates := privilegedSearchPathCandidates()
	searchCtx, searchCancel, _ := filesystemEnrichmentStageContext(ctx, filesystemStageSearchPath)
	searchPaths, searchSource, searchDegraded := collectPlatformSearchPaths(searchCtx, searchCandidates, inv.PermissionCapability)
	searchCancel()
	searchPaths, repairDegraded := repairPlatformSearchPathRecords(searchPaths, inv.PermissionCapability)
	if len(repairDegraded) > 0 && searchSource.State == evidence.StateObserved {
		searchSource.State = evidence.StateDegraded
		searchSource.Reason = "one or more search-path provider records required record-level degradation"
	}
	inv.SearchPaths = normalizeSearchPaths(searchPaths)
	inv.Sources = append(inv.Sources, searchSource)
	inv.Degraded = append(inv.Degraded, searchDegraded...)
	inv.Degraded = append(inv.Degraded, repairDegraded...)
	privilegedFiles, privilegedSource, privilegedDegraded := collectPlatformPrivilegedFiles(ctx, inv.MountBoundaries)
	inv.PrivilegedFiles = normalizePrivilegedFiles(privilegedFiles)
	inv.Sources = append(inv.Sources, privilegedSource)
	inv.Degraded = append(inv.Degraded, privilegedDegraded...)
	sensitiveCtx, sensitiveCancel, _ := filesystemEnrichmentStageContext(ctx, filesystemStageSensitive)
	sensitiveFiles, sensitiveSource, sensitiveDegraded := collectPlatformSensitiveFiles(sensitiveCtx, inv.PermissionCapability)
	sensitiveCancel()
	inv.SensitiveFiles = normalizeSensitiveFiles(sensitiveFiles)
	inv.Sources = append(inv.Sources, sensitiveSource)
	inv.Degraded = append(inv.Degraded, sensitiveDegraded...)

	// Fix51 gives the small temporary-directory boundary stage an independent
	// budget before the potentially much larger generic ACL-boundary inventory.
	// A slow high-impact ACL set can therefore no longer starve TEMP evidence.
	tempCandidates := tempDirectoryCandidates(inv)
	tempCtx, tempCancel, _ := filesystemEnrichmentStageContext(ctx, filesystemStageTemp)
	tempDirectories, tempSource, tempDegraded := collectPlatformTempDirectories(tempCtx, tempCandidates, inv.PermissionCapability)
	tempCancel()
	tempDirectories, tempRepairDegraded := repairPlatformTempDirectoryRecords(tempDirectories, inv.PermissionCapability)
	if len(tempRepairDegraded) > 0 && tempSource.State == evidence.StateObserved {
		tempSource.State = evidence.StateDegraded
		tempSource.Reason = "one or more temporary-directory provider records required record-level degradation"
	}
	inv.TempDirectories = normalizeTempDirectories(tempDirectories)
	inv.Sources = append(inv.Sources, tempSource)
	inv.Degraded = append(inv.Degraded, tempDegraded...)
	inv.Degraded = append(inv.Degraded, tempRepairDegraded...)

	aclCandidates := aclBoundaryCandidates(inv)
	aclCtx, aclCancel, _ := filesystemEnrichmentStageContext(ctx, filesystemStageACL)
	aclBoundaries, aclSource, aclDegraded := collectPlatformACLBoundaries(aclCtx, aclCandidates)
	aclCancel()
	inv.ACLBoundaries = normalizeACLBoundaries(aclBoundaries)
	inv.Sources = append(inv.Sources, aclSource)
	inv.Degraded = append(inv.Degraded, aclDegraded...)

	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Paths, inv.MountBoundaries, inv.NetworkShares, inv.Executables, inv.SearchPaths, inv.PrivilegedFiles, inv.SensitiveFiles, inv.ACLBoundaries, inv.TempDirectories, len(execDirs))
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected filesystem collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("filesystem inventory identity is incomplete")
	}
	if inv.PermissionCapability.State == "" || strings.TrimSpace(inv.PermissionCapability.Model) == "" || strings.TrimSpace(inv.PermissionCapability.Source) == "" {
		return fmt.Errorf("filesystem permission capability is incomplete")
	}
	if len(inv.Paths) > maxPaths || len(inv.MountBoundaries) > maxMounts || len(inv.NetworkShares) > maxNetworkShares || len(inv.Executables) > maxExecutables || len(inv.SearchPaths) > maxSearchPaths || len(inv.PrivilegedFiles) > maxPrivilegedFiles || len(inv.SensitiveFiles) > maxSensitiveFiles || len(inv.ACLBoundaries) > maxACLBoundaries || len(inv.TempDirectories) > maxTempDirectories {
		return fmt.Errorf("filesystem inventory exceeds record limits")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, p := range inv.Paths {
		if p.ID == "" || strings.TrimSpace(p.Kind) == "" || strings.TrimSpace(p.Path) == "" || p.State == "" || strings.TrimSpace(p.PermissionModel) == "" || strings.TrimSpace(p.CollectionSource) == "" || p.Confidence == "" {
			return fmt.Errorf("filesystem path record %d is incomplete", i)
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate filesystem path id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		key := pathSortKey(p)
		if last != "" && key < last {
			return fmt.Errorf("filesystem path records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, x := range inv.Executables {
		if x.ID == "" || strings.TrimSpace(x.Path) == "" || strings.TrimSpace(x.Directory) == "" || x.State == "" || strings.TrimSpace(x.PermissionModel) == "" || strings.TrimSpace(x.DiscoverySource) == "" || strings.TrimSpace(x.CollectionSource) == "" || x.Confidence == "" {
			return fmt.Errorf("filesystem executable record %d is incomplete", i)
		}
		if _, ok := seen[x.ID]; ok {
			return fmt.Errorf("duplicate filesystem executable id %q", x.ID)
		}
		seen[x.ID] = struct{}{}
		key := executableSortKey(x)
		if last != "" && key < last {
			return fmt.Errorf("filesystem executable records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, sp := range inv.SearchPaths {
		if sp.ID == "" || strings.TrimSpace(sp.Path) == "" || sp.State == "" || strings.TrimSpace(sp.PermissionModel) == "" || strings.TrimSpace(sp.CollectionSource) == "" || sp.Confidence == "" || len(sp.Contexts) == 0 || len(sp.DiscoverySources) == 0 {
			return fmt.Errorf("filesystem search-path record %d is incomplete", i)
		}
		if _, ok := seen[sp.ID]; ok {
			return fmt.Errorf("duplicate filesystem search-path id %q", sp.ID)
		}
		seen[sp.ID] = struct{}{}
		key := searchPathSortKey(sp)
		if last != "" && key < last {
			return fmt.Errorf("filesystem search-path records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, pf := range inv.PrivilegedFiles {
		if pf.ID == "" || strings.TrimSpace(pf.Path) == "" || pf.State == "" || strings.TrimSpace(pf.PackageOwnership) == "" || strings.TrimSpace(pf.Classification) == "" || strings.TrimSpace(pf.DiscoverySource) == "" || strings.TrimSpace(pf.CollectionSource) == "" || pf.Confidence == "" {
			return fmt.Errorf("filesystem privileged-file record %d is incomplete", i)
		}
		if _, ok := seen[pf.ID]; ok {
			return fmt.Errorf("duplicate filesystem privileged-file id %q", pf.ID)
		}
		seen[pf.ID] = struct{}{}
		key := privilegedFileSortKey(pf)
		if last != "" && key < last {
			return fmt.Errorf("filesystem privileged-file records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, sf := range inv.SensitiveFiles {
		if sf.ID == "" || strings.TrimSpace(sf.Kind) == "" || strings.TrimSpace(sf.Scope) == "" || strings.TrimSpace(sf.Path) == "" || strings.TrimSpace(sf.AccessPolicy) == "" || sf.State == "" || strings.TrimSpace(sf.OwnerState) == "" || strings.TrimSpace(sf.PermissionModel) == "" || strings.TrimSpace(sf.DiscoverySource) == "" || strings.TrimSpace(sf.CollectionSource) == "" || sf.Confidence == "" {
			return fmt.Errorf("filesystem sensitive-file record %d is incomplete", i)
		}
		if _, ok := seen[sf.ID]; ok {
			return fmt.Errorf("duplicate filesystem sensitive-file id %q", sf.ID)
		}
		seen[sf.ID] = struct{}{}
		key := sensitiveFileSortKey(sf)
		if last != "" && key < last {
			return fmt.Errorf("filesystem sensitive-file records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, acl := range inv.ACLBoundaries {
		if acl.ID == "" || strings.TrimSpace(acl.Path) == "" || len(acl.Contexts) == 0 || acl.State == "" || strings.TrimSpace(acl.ACLModel) == "" || len(acl.DiscoverySources) == 0 || strings.TrimSpace(acl.CollectionSource) == "" || acl.Confidence == "" {
			return fmt.Errorf("filesystem ACL boundary record %d is incomplete", i)
		}
		if _, ok := seen[acl.ID]; ok {
			return fmt.Errorf("duplicate filesystem ACL boundary id %q", acl.ID)
		}
		seen[acl.ID] = struct{}{}
		key := aclBoundarySortKey(acl)
		if last != "" && key < last {
			return fmt.Errorf("filesystem ACL boundary records are not deterministically ordered")
		}
		last = key
		for gi, g := range acl.Grants {
			if strings.TrimSpace(g.Principal) == "" || strings.TrimSpace(g.PrincipalClass) == "" || strings.TrimSpace(g.Access) == "" || len(g.Rights) == 0 {
				return fmt.Errorf("filesystem ACL boundary record %d grant %d is incomplete", i, gi)
			}
		}
	}
	seen = map[string]struct{}{}
	last = ""
	for i, td := range inv.TempDirectories {
		if td.ID == "" || strings.TrimSpace(td.Path) == "" || strings.TrimSpace(td.Scope) == "" || td.State == "" || strings.TrimSpace(td.PermissionModel) == "" || len(td.DiscoverySources) == 0 || strings.TrimSpace(td.CollectionSource) == "" || td.Confidence == "" {
			return fmt.Errorf("filesystem temporary-directory record %d is incomplete", i)
		}
		if _, ok := seen[td.ID]; ok {
			return fmt.Errorf("duplicate filesystem temporary-directory id %q", td.ID)
		}
		seen[td.ID] = struct{}{}
		key := tempDirectorySortKey(td)
		if last != "" && key < last {
			return fmt.Errorf("filesystem temporary-directory records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, sh := range inv.NetworkShares {
		if sh.ID == "" || strings.TrimSpace(sh.Direction) == "" || strings.TrimSpace(sh.Protocol) == "" || strings.TrimSpace(sh.AccessMode) == "" || sh.State == "" || strings.TrimSpace(sh.CollectionSource) == "" || sh.Confidence == "" {
			return fmt.Errorf("filesystem network-share record %d is incomplete", i)
		}
		if sh.Direction != NetworkShareDirectionMounted && sh.Direction != NetworkShareDirectionExported {
			return fmt.Errorf("filesystem network-share record %d has invalid direction %q", i, sh.Direction)
		}
		if sh.Protocol != NetworkShareProtocolNFS && sh.Protocol != NetworkShareProtocolSMB && sh.Protocol != NetworkShareProtocolOther {
			return fmt.Errorf("filesystem network-share record %d has invalid protocol %q", i, sh.Protocol)
		}
		if sh.Direction == NetworkShareDirectionMounted && strings.TrimSpace(sh.LocalPath) == "" {
			return fmt.Errorf("filesystem mounted network-share record %d requires a local path", i)
		}
		if sh.Direction == NetworkShareDirectionExported && strings.TrimSpace(sh.LocalPath) == "" {
			return fmt.Errorf("filesystem exported network-share record %d requires a local path", i)
		}
		if _, ok := seen[sh.ID]; ok {
			return fmt.Errorf("duplicate filesystem network-share id %q", sh.ID)
		}
		seen[sh.ID] = struct{}{}
		key := networkShareSortKey(sh)
		if last != "" && key < last {
			return fmt.Errorf("filesystem network-share records are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, m := range inv.MountBoundaries {
		if m.ID == "" || strings.TrimSpace(m.Path) == "" || m.State == "" || strings.TrimSpace(m.AccessMode) == "" || strings.TrimSpace(m.Classification) == "" || strings.TrimSpace(m.EncryptionState) == "" || strings.TrimSpace(m.CollectionSource) == "" || m.Confidence == "" {
			return fmt.Errorf("filesystem mount record %d is incomplete", i)
		}
		if _, ok := seen[m.ID]; ok {
			return fmt.Errorf("duplicate filesystem mount id %q", m.ID)
		}
		seen[m.ID] = struct{}{}
		key := mountSortKey(m)
		if last != "" && key < last {
			return fmt.Errorf("filesystem mount records are not deterministically ordered")
		}
		last = key
	}
	last = ""
	for i, src := range inv.Sources {
		if strings.TrimSpace(src.ID) == "" || src.State == "" || strings.TrimSpace(src.Source) == "" {
			return fmt.Errorf("filesystem source record %d is incomplete", i)
		}
		if last != "" && src.ID < last {
			return fmt.Errorf("filesystem source records are not deterministically ordered")
		}
		last = src.ID
	}
	if inv.Summary != summarize(inv.Paths, inv.MountBoundaries, inv.NetworkShares, inv.Executables, inv.SearchPaths, inv.PrivilegedFiles, inv.SensitiveFiles, inv.ACLBoundaries, inv.TempDirectories, len(executableSearchDirectories())) {
		return fmt.Errorf("filesystem summary does not match records")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func inspectPath(c candidate, cap PermissionCapability, mounts []MountBoundary) PathRecord {
	p := PathRecord{
		ID: stablePathID(c.Kind, c.Path), Kind: c.Kind, Path: c.Path,
		State: evidence.StateObserved, PermissionModel: cap.Model,
		CollectionSource: c.Source, Confidence: evidence.ConfidenceHigh,
	}
	info, err := os.Lstat(c.Path)
	if err != nil {
		if os.IsPermission(err) {
			p.State = evidence.StateDenied
			p.Reason = err.Error()
		} else if os.IsNotExist(err) {
			p.State = evidence.StateObserved
			p.Exists = false
			p.Reason = "path does not exist on this host"
		} else {
			p.State = evidence.StateUnavailable
			p.Reason = err.Error()
		}
		p.MountPoint = mountForPath(c.Path, mounts)
		return p
	}
	p.Exists = true
	p.Directory = info.IsDir()
	p.Symlink = info.Mode()&os.ModeSymlink != 0
	p.Mode = info.Mode().String()
	p.OwnerID, p.GroupID = platformOwnership(info)
	p.MountPoint = mountForPath(c.Path, mounts)
	return p
}

func environmentCandidates() []candidate {
	out := []candidate{}
	seen := map[string]struct{}{}
	add := func(kind, path, source string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		key := strings.ToUpper(kind) + "|" + platformPathKey(path)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, candidate{Kind: strings.ToUpper(kind), Path: path, Source: source})
	}
	for _, t := range platformTempEnvironmentPaths() {
		add("TEMP", t, "process environment temporary-directory metadata")
	}
	for _, part := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		if abs, err := filepath.Abs(part); err == nil {
			part = abs
		}
		add("SEARCH_PATH", part, "process PATH environment metadata")
	}
	return out
}

func normalizeCandidates(in []candidate) []candidate {
	out := make([]candidate, 0, len(in))
	seen := map[string]struct{}{}
	for _, c := range in {
		c.Kind = strings.ToUpper(strings.TrimSpace(c.Kind))
		c.Path = strings.TrimSpace(c.Path)
		c.Source = strings.TrimSpace(c.Source)
		if c.Kind == "" || c.Path == "" {
			continue
		}
		c.Path = filepath.Clean(c.Path)
		if c.Source == "" {
			c.Source = "local filesystem inventory"
		}
		key := c.Kind + "|" + platformPathKey(c.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
		if len(out) >= maxPaths {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return platformPathKey(out[i].Path) < platformPathKey(out[j].Path)
	})
	return out
}

func normalizePaths(in []PathRecord) []PathRecord {
	out := make([]PathRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, p := range in {
		p.Kind = strings.ToUpper(strings.TrimSpace(p.Kind))
		p.Path = filepath.Clean(strings.TrimSpace(p.Path))
		p.CollectionSource = strings.TrimSpace(p.CollectionSource)
		p.PermissionModel = strings.TrimSpace(p.PermissionModel)
		if p.ID == "" {
			p.ID = stablePathID(p.Kind, p.Path)
		}
		if p.Confidence == "" {
			p.Confidence = evidence.ConfidenceLow
		}
		if _, ok := seen[p.ID]; ok {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return pathSortKey(out[i]) < pathSortKey(out[j]) })
	return out
}

func normalizeMounts(in []MountBoundary) []MountBoundary {
	out := make([]MountBoundary, 0, len(in))
	seen := map[string]struct{}{}
	for _, m := range in {
		m.Path = filepath.Clean(strings.TrimSpace(m.Path))
		if m.Path == "." || m.Path == "" {
			continue
		}
		m.Device = strings.TrimSpace(m.Device)
		m.BackingSource = strings.TrimSpace(m.BackingSource)
		if m.BackingSource == "" {
			m.BackingSource = m.Device
		}
		m.Filesystem = strings.TrimSpace(m.Filesystem)
		m.Options = uniqueSorted(m.Options)
		m.AccessMode = strings.ToUpper(strings.TrimSpace(m.AccessMode))
		if m.AccessMode == "" {
			if m.ReadOnly {
				m.AccessMode = MountAccessReadOnly
			} else if containsStringFold(m.Options, "rw") || containsStringFold(m.Options, "read-write") {
				m.AccessMode = MountAccessReadWrite
			} else {
				m.AccessMode = MountAccessUnknown
			}
		}
		m.ReadOnly = m.AccessMode == MountAccessReadOnly
		m.Writable = m.AccessMode == MountAccessReadWrite
		m.Classification = strings.ToUpper(strings.TrimSpace(m.Classification))
		if m.Classification == "" {
			m.Classification = classifyMount(m.Filesystem, m.BackingSource, m.Network, m.Removable)
		}
		m.Network = m.Network || m.Classification == MountClassNetwork
		m.Removable = m.Removable || m.Classification == MountClassRemovable
		m.MajorMinor = strings.TrimSpace(m.MajorMinor)
		m.VolumeLabel = strings.TrimSpace(m.VolumeLabel)
		m.EncryptionState = strings.ToUpper(strings.TrimSpace(m.EncryptionState))
		if m.EncryptionState == "" {
			if m.Classification == MountClassVirtual || m.Classification == MountClassOptical {
				m.EncryptionState = MountEncryptionNotApplicable
			} else {
				m.EncryptionState = MountEncryptionUnknown
			}
		}
		m.EncryptionType = strings.TrimSpace(m.EncryptionType)
		m.EncryptionEvidence = strings.TrimSpace(m.EncryptionEvidence)
		m.CollectionSource = strings.TrimSpace(m.CollectionSource)
		if m.CollectionSource == "" {
			m.CollectionSource = "local mount metadata"
		}
		if m.State == "" {
			m.State = evidence.StateObserved
		}
		if m.Confidence == "" {
			m.Confidence = evidence.ConfidenceHigh
		}
		if m.ID == "" {
			m.ID = stableMountID(m.Path, m.Device, m.Filesystem)
		}
		key := platformPathKey(m.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
		if len(out) >= maxMounts {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return mountSortKey(out[i]) < mountSortKey(out[j]) })
	return out
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func summarize(paths []PathRecord, mounts []MountBoundary, networkShares []NetworkShareRecord, executables []ExecutableRecord, searchPaths []SearchPathRecord, privilegedFiles []PrivilegedFileRecord, sensitiveFiles []SensitiveFileRecord, aclBoundaries []ACLBoundaryRecord, tempDirectories []TempDirectoryRecord, executableDirectories int) Summary {
	var s Summary
	s.Paths = len(paths)
	s.MountBoundaries = len(mounts)
	s.Executables = len(executables)
	s.ExecutableDirectories = executableDirectories
	for _, p := range paths {
		switch p.Kind {
		case "ROOT":
			s.SecurityRoots++
		case "TEMP":
			s.TempAreas++
		case "SEARCH_PATH":
			s.SearchPaths++
		case "SENSITIVE_CONFIG":
			s.SensitiveLocations++
		}
		if p.Exists {
			s.ExistingPaths++
		}
		if p.State == evidence.StateUnavailable {
			s.UnavailablePaths++
		}
		if p.State == evidence.StateDenied {
			s.DeniedPaths++
		}
	}
	for _, x := range executables {
		if x.BroadlyWritable {
			s.BroadlyWritableExecutables++
		}
		if x.UntrustedWrite {
			s.UntrustedWritableExecutables++
		}
		if x.State != evidence.StateObserved {
			s.UnavailableExecutableMetadata++
		}
	}
	for _, sp := range searchPaths {
		s.PrivilegedSearchPaths++
		if sp.BroadlyWritable {
			s.WritablePrivilegedSearchPaths++
		}
		if sp.UntrustedWrite {
			s.UntrustedPrivilegedSearchPaths++
		}
		if containsString(sp.Contexts, "LOADER") {
			s.LoaderSearchPaths++
			if sp.UntrustedWrite {
				s.WritableLoaderSearchPaths++
			}
		}
		if sp.State != evidence.StateObserved {
			s.UnavailableSearchPathMetadata++
		}
	}
	for _, pf := range privilegedFiles {
		s.PrivilegedFiles++
		if pf.SetUID {
			s.SetUIDFiles++
		}
		if pf.SetGID {
			s.SetGIDFiles++
		}
		if len(pf.Capabilities) > 0 || len(pf.InheritableCaps) > 0 {
			s.CapabilityFiles++
		}
		if pf.ReviewRequired {
			s.CustomPrivilegedFiles++
		}
		if pf.PackageOwnership == "UNMANAGED" {
			s.UnmanagedPrivilegedFiles++
		}
		if pf.State != evidence.StateObserved {
			s.UnavailablePrivilegedMetadata++
		}
	}
	for _, sf := range sensitiveFiles {
		s.SensitiveFiles++
		if sf.AccessPolicy == SensitivePolicyOwnerOnly || sf.AccessPolicy == SensitivePolicyNoWorldRead {
			s.SensitiveRestrictedReadFiles++
		}
		if sf.BroadlyWritable {
			s.SensitiveBroadlyWritable++
		}
		if sf.UntrustedWrite {
			s.SensitiveUntrustedWritable++
		}
		if sf.BroadlyAccessible {
			s.SensitiveBroadlyAccessible++
		}
		if sf.UntrustedAccess {
			s.SensitiveUntrustedAccessible++
		}
		if sf.OwnerState == SensitiveOwnerUnexpected {
			s.SensitiveOwnerMismatches++
		}
		if sf.State != evidence.StateObserved {
			s.UnavailableSensitiveMetadata++
		}
	}
	for _, acl := range aclBoundaries {
		s.ACLBoundaries++
		if acl.HasExtendedACL {
			s.ExtendedACLBoundaries++
		}
		if acl.DangerousBroadWrite || acl.DangerousBroadControl {
			s.DangerousACLBoundaries++
		}
		if acl.ReviewWriteGrant {
			s.ReviewACLBoundaries++
		}
		if acl.State != evidence.StateObserved {
			s.UnavailableACLMetadata++
		}
	}
	for _, td := range tempDirectories {
		s.TempDirectories++
		if td.Shared {
			s.SharedTempDirectories++
		}
		if td.UnsafeOwnership || td.UnsafePermissions || td.ParentUnsafe {
			s.UnsafeTempDirectories++
		}
		if td.UnsafeOwnership {
			s.UnsafeTempOwnership++
		}
		if td.UnsafePermissions {
			s.UnsafeTempPermissions++
		}
		if td.ParentUnsafe {
			s.UnsafeTempParentBoundaries++
		}
		if td.State != evidence.StateObserved || (td.ParentState != "" && td.ParentState != evidence.StateObserved) {
			s.UnavailableTempMetadata++
		}
	}
	for _, m := range mounts {
		if m.ReadOnly {
			s.ReadOnlyMounts++
		}
		if m.Writable {
			s.WritableMounts++
		}
		if m.Network {
			s.NetworkMounts++
		}
		if m.Removable {
			s.RemovableMounts++
		}
		if m.Classification == MountClassVirtual {
			s.VirtualMounts++
		}
		if m.EncryptionState == MountEncryptionEncrypted {
			s.EncryptedMounts++
		}
		if m.EncryptionState == MountEncryptionUnknown || m.EncryptionState == MountEncryptionNotObserved {
			s.UnknownEncryptionMounts++
		}
	}
	for _, sh := range networkShares {
		s.NetworkShares++
		if sh.Direction == NetworkShareDirectionMounted {
			s.MountedNetworkShares++
		}
		if sh.Direction == NetworkShareDirectionExported {
			s.ExportedNetworkShares++
		}
		switch sh.Protocol {
		case NetworkShareProtocolNFS:
			s.NFSNetworkShares++
		case NetworkShareProtocolSMB:
			s.SMBNetworkShares++
		}
		if sh.GuestAllowed {
			s.GuestNetworkShares++
		}
		if sh.AnonymousAllowed {
			s.AnonymousNetworkShares++
		}
		if sh.BroadAccess {
			s.BroadNetworkShares++
		}
		if sh.BroadWrite {
			s.BroadWritableNetworkShares++
		}
		if len(sh.DangerousOptions) > 0 {
			s.DangerousNetworkShares++
		}
		if sh.State != evidence.StateObserved || !sh.AccessKnown {
			s.UnavailableNetworkShareMetadata++
		}
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	out := make([]evidence.Observation, 0, 2+len(inv.Sources)+len(inv.Paths)+len(inv.MountBoundaries)+len(inv.NetworkShares)+len(inv.Executables)+len(inv.SearchPaths)+len(inv.PrivilegedFiles)+len(inv.SensitiveFiles)+len(inv.ACLBoundaries)+len(inv.TempDirectories))
	if inv.PermissionCapability.State == evidence.StateObserved {
		out = append(out, evidence.NewObserved("filesystem.permission_capability", inv.PermissionCapability, inv.PermissionCapability.Source, inv.CollectedAt, evidence.ConfidenceHigh))
	} else {
		out = append(out, evidence.NewState("filesystem.permission_capability", inv.PermissionCapability.State, inv.PermissionCapability.Source, inv.CollectedAt, evidence.ConfidenceMedium, fallback(inv.PermissionCapability.Reason, "permission capability unavailable")))
	}
	out = append(out, evidence.NewObserved("filesystem.summary", inv.Summary, "filesystem security inventory", inv.CollectedAt, evidence.ConfidenceHigh))
	for _, src := range inv.Sources {
		key := "filesystem.source." + src.ID
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, src, src.Source, inv.CollectedAt, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState(key, src.State, src.Source, inv.CollectedAt, evidence.ConfidenceMedium, fallback(src.Reason, "filesystem source unavailable")))
		}
	}
	for _, p := range inv.Paths {
		key := "filesystem.path." + p.ID
		if p.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, p, p.CollectionSource, inv.CollectedAt, p.Confidence))
		} else {
			out = append(out, evidence.NewState(key, p.State, p.CollectionSource, inv.CollectedAt, p.Confidence, fallback(p.Reason, "path metadata unavailable")))
		}
	}
	for _, x := range inv.Executables {
		key := "filesystem.executable." + x.ID
		if x.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, x, x.CollectionSource, inv.CollectedAt, x.Confidence))
		} else {
			out = append(out, evidence.NewState(key, x.State, x.CollectionSource, inv.CollectedAt, x.Confidence, fallback(x.Reason, "executable permission metadata unavailable")))
		}
	}
	for _, sp := range inv.SearchPaths {
		key := "filesystem.search_path." + sp.ID
		if sp.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, sp, sp.CollectionSource, inv.CollectedAt, sp.Confidence))
		} else {
			out = append(out, evidence.NewState(key, sp.State, sp.CollectionSource, inv.CollectedAt, sp.Confidence, fallback(sp.Reason, "privileged search-path metadata unavailable")))
		}
	}
	for _, pf := range inv.PrivilegedFiles {
		key := "filesystem.privileged_executable." + pf.ID
		if pf.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, pf, pf.CollectionSource, inv.CollectedAt, pf.Confidence))
		} else {
			out = append(out, evidence.NewState(key, pf.State, pf.CollectionSource, inv.CollectedAt, pf.Confidence, fallback(pf.Reason, "privileged executable metadata unavailable")))
		}
	}
	for _, sf := range inv.SensitiveFiles {
		key := "filesystem.sensitive_file." + sf.ID
		if sf.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, sf, sf.CollectionSource, inv.CollectedAt, sf.Confidence))
		} else {
			out = append(out, evidence.NewState(key, sf.State, sf.CollectionSource, inv.CollectedAt, sf.Confidence, fallback(sf.Reason, "sensitive-file permission metadata unavailable")))
		}
	}
	for _, acl := range inv.ACLBoundaries {
		key := "filesystem.acl_boundary." + acl.ID
		if acl.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, acl, acl.CollectionSource, inv.CollectedAt, acl.Confidence))
		} else {
			out = append(out, evidence.NewState(key, acl.State, acl.CollectionSource, inv.CollectedAt, acl.Confidence, fallback(acl.Reason, "ACL boundary metadata unavailable")))
		}
	}
	for _, td := range inv.TempDirectories {
		key := "filesystem.temp_directory." + td.ID
		if td.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, td, td.CollectionSource, inv.CollectedAt, td.Confidence))
		} else {
			out = append(out, evidence.NewState(key, td.State, td.CollectionSource, inv.CollectedAt, td.Confidence, fallback(td.Reason, "temporary-directory security metadata unavailable")))
		}
	}
	for _, sh := range inv.NetworkShares {
		key := "filesystem.network_share." + sh.ID
		if sh.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, sh, sh.CollectionSource, inv.CollectedAt, sh.Confidence))
		} else {
			out = append(out, evidence.NewState(key, sh.State, sh.CollectionSource, inv.CollectedAt, sh.Confidence, fallback(sh.Reason, "network-share metadata unavailable")))
		}
	}
	for _, m := range inv.MountBoundaries {
		key := "filesystem.mount." + m.ID
		if m.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, m, m.CollectionSource, inv.CollectedAt, m.Confidence))
		} else {
			out = append(out, evidence.NewState(key, m.State, m.CollectionSource, inv.CollectedAt, m.Confidence, fallback(m.Reason, "mount metadata unavailable")))
		}
	}
	return out
}

func mountForPath(path string, mounts []MountBoundary) string {
	target := platformPathKey(filepath.Clean(path))
	best := ""
	bestLen := -1
	for _, m := range mounts {
		mp := platformPathKey(filepath.Clean(m.Path))
		if pathWithinMount(target, mp) && len(mp) > bestLen {
			best, bestLen = m.Path, len(mp)
		}
	}
	return best
}

func pathWithinMount(path, mount string) bool {
	if runtime.GOOS == "windows" {
		if path == mount {
			return true
		}
		mount = strings.TrimRight(mount, `\\/`)
		return strings.HasPrefix(path, mount+`\\`) || strings.HasPrefix(path, mount+`/`)
	}
	if mount == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mount || strings.HasPrefix(path, strings.TrimRight(mount, "/")+"/")
}

func classifyMount(filesystem, source string, network, removable bool) string {
	if network {
		return MountClassNetwork
	}
	if removable {
		return MountClassRemovable
	}
	fs := strings.ToLower(strings.TrimSpace(filesystem))
	src := strings.ToLower(strings.TrimSpace(source))
	if isNetworkFilesystem(fs) || strings.HasPrefix(src, "//") || strings.Contains(src, "://") {
		return MountClassNetwork
	}
	if isVirtualFilesystem(fs) {
		return MountClassVirtual
	}
	if fs == "iso9660" || fs == "udf" || fs == "cdfs" {
		return MountClassOptical
	}
	if strings.HasPrefix(src, "/dev/") || (len(src) >= 2 && src[1] == ':') {
		return MountClassLocal
	}
	return MountClassUnknown
}

func isNetworkFilesystem(fs string) bool {
	switch strings.ToLower(strings.TrimSpace(fs)) {
	case "nfs", "nfs4", "cifs", "smbfs", "smb3", "afpfs", "webdav", "davfs", "davfs2", "sshfs", "9p", "fuse.sshfs", "ceph", "glusterfs":
		return true
	default:
		return false
	}
}

func isVirtualFilesystem(fs string) bool {
	switch strings.ToLower(strings.TrimSpace(fs)) {
	case "proc", "procfs", "sysfs", "devtmpfs", "devfs", "devpts", "tmpfs", "ramfs", "cgroup", "cgroup2", "pstore", "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs", "overlay", "nsfs", "binfmt_misc", "efivarfs", "bpf", "rpc_pipefs", "virtiofs":
		return true
	default:
		return false
	}
}

func containsStringFold(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

func platformPathKey(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func pathSortKey(p PathRecord) string     { return p.Kind + "|" + platformPathKey(p.Path) + "|" + p.ID }
func mountSortKey(m MountBoundary) string { return platformPathKey(m.Path) + "|" + m.ID }

func stablePathID(kind, path string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(kind)) + "|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}
func stableMountID(path, device, fs string) string {
	sum := sha256.Sum256([]byte(platformPathKey(path) + "|" + strings.TrimSpace(device) + "|" + strings.ToLower(strings.TrimSpace(fs))))
	return hex.EncodeToString(sum[:8])
}

func normalizePrivilegedFiles(in []PrivilegedFileRecord) []PrivilegedFileRecord {
	out := make([]PrivilegedFileRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, pf := range in {
		pf.Path = filepath.Clean(strings.TrimSpace(pf.Path))
		if pf.Path == "." || pf.Path == "" {
			continue
		}
		pf.Capabilities = uniqueSortedUpper(pf.Capabilities)
		pf.InheritableCaps = uniqueSortedUpper(pf.InheritableCaps)
		pf.ReviewReasons = uniqueSorted(pf.ReviewReasons)
		pf.PackageOwnership = strings.ToUpper(strings.TrimSpace(pf.PackageOwnership))
		pf.PackageID = strings.TrimSpace(pf.PackageID)
		pf.PackageProvider = strings.TrimSpace(pf.PackageProvider)
		pf.Classification = strings.ToUpper(strings.TrimSpace(pf.Classification))
		pf.DiscoverySource = strings.TrimSpace(pf.DiscoverySource)
		pf.CollectionSource = strings.TrimSpace(pf.CollectionSource)
		if pf.ID == "" {
			pf.ID = stablePrivilegedFileID(pf.Path)
		}
		if pf.Confidence == "" {
			pf.Confidence = evidence.ConfidenceLow
		}
		if _, ok := seen[pf.ID]; ok {
			continue
		}
		seen[pf.ID] = struct{}{}
		out = append(out, pf)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := privilegedFilePriority(out[i]), privilegedFilePriority(out[j])
		if pi != pj {
			return pi < pj
		}
		return privilegedFileSortKey(out[i]) < privilegedFileSortKey(out[j])
	})
	if len(out) > maxPrivilegedFiles {
		out = out[:maxPrivilegedFiles]
	}
	// Public records remain path-ordered after priority selection so JSON and
	// snapshots preserve the same deterministic ordering convention as the rest
	// of the filesystem inventory.
	sort.Slice(out, func(i, j int) bool { return privilegedFileSortKey(out[i]) < privilegedFileSortKey(out[j]) })
	return out
}

func privilegedFilePriority(p PrivilegedFileRecord) int {
	if len(p.Capabilities) > 0 || len(p.InheritableCaps) > 0 {
		return 0
	}
	if p.SetUID {
		return 1
	}
	lower := strings.ToLower(filepath.Clean(p.Path))
	if strings.HasPrefix(lower, "/usr/") || strings.HasPrefix(lower, "/bin/") || strings.HasPrefix(lower, "/sbin/") {
		return 2
	}
	return 3
}

func privilegedFileSortKey(p PrivilegedFileRecord) string {
	return platformPathKey(p.Path) + "|" + p.ID
}

func stablePrivilegedFileID(path string) string {
	sum := sha256.Sum256([]byte("PRIVILEGED_FILE|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func fallback(v, alt string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return alt
}

func executableSearchDirectories() []string {
	items := append([]string(nil), platformExecutableDirectories()...)
	items = append(items, filepath.SplitList(os.Getenv("PATH"))...)
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if abs, err := filepath.Abs(item); err == nil {
			item = abs
		}
		item = filepath.Clean(item)
		key := platformPathKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
		if len(out) >= maxExecutableDirs {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return platformPathKey(out[i]) < platformPathKey(out[j]) })
	return out
}

func normalizeExecutables(in []ExecutableRecord) []ExecutableRecord {
	out := make([]ExecutableRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, x := range in {
		x.Path = filepath.Clean(strings.TrimSpace(x.Path))
		x.ResolvedPath = strings.TrimSpace(x.ResolvedPath)
		if x.ResolvedPath != "" {
			x.ResolvedPath = filepath.Clean(x.ResolvedPath)
		}
		x.Directory = filepath.Clean(strings.TrimSpace(x.Directory))
		x.PermissionModel = strings.TrimSpace(x.PermissionModel)
		x.DiscoverySource = strings.TrimSpace(x.DiscoverySource)
		x.CollectionSource = strings.TrimSpace(x.CollectionSource)
		x.WritePrincipals = uniqueSorted(x.WritePrincipals)
		if x.ID == "" {
			x.ID = stableExecutableID(x.Path)
		}
		if x.Confidence == "" {
			x.Confidence = evidence.ConfidenceLow
		}
		if _, ok := seen[x.ID]; ok {
			continue
		}
		seen[x.ID] = struct{}{}
		out = append(out, x)
		if len(out) >= maxExecutables {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return executableSortKey(out[i]) < executableSortKey(out[j]) })
	return out
}

func executableSortKey(x ExecutableRecord) string { return platformPathKey(x.Path) + "|" + x.ID }

func stableExecutableID(path string) string {
	sum := sha256.Sum256([]byte("EXECUTABLE|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}

func normalizeSearchPaths(in []SearchPathRecord) []SearchPathRecord {
	out := make([]SearchPathRecord, 0, len(in))
	byKey := map[string]int{}
	for _, sp := range in {
		sp.Path = filepath.Clean(strings.TrimSpace(sp.Path))
		if sp.Path == "." || sp.Path == "" {
			continue
		}
		sp.ResolvedPath = strings.TrimSpace(sp.ResolvedPath)
		if sp.ResolvedPath != "" {
			sp.ResolvedPath = filepath.Clean(sp.ResolvedPath)
		}
		sp.PermissionModel = strings.TrimSpace(sp.PermissionModel)
		sp.CollectionSource = strings.TrimSpace(sp.CollectionSource)
		sp.Contexts = uniqueSortedUpper(sp.Contexts)
		sp.DiscoverySources = uniqueSorted(sp.DiscoverySources)
		sp.WritePrincipals = uniqueSorted(sp.WritePrincipals)
		if sp.ID == "" {
			sp.ID = stableSearchPathID(sp.Path)
		}
		if sp.Confidence == "" {
			sp.Confidence = evidence.ConfidenceLow
		}
		key := platformPathKey(sp.Path)
		if pos, ok := byKey[key]; ok {
			existing := &out[pos]
			existing.Contexts = uniqueSortedUpper(append(existing.Contexts, sp.Contexts...))
			existing.DiscoverySources = uniqueSorted(append(existing.DiscoverySources, sp.DiscoverySources...))
			continue
		}
		byKey[key] = len(out)
		out = append(out, sp)
		if len(out) >= maxSearchPaths {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return searchPathSortKey(out[i]) < searchPathSortKey(out[j]) })
	return out
}

func searchPathSortKey(sp SearchPathRecord) string { return platformPathKey(sp.Path) + "|" + sp.ID }
func stableSearchPathID(path string) string {
	sum := sha256.Sum256([]byte("PRIVILEGED_SEARCH_PATH|" + platformPathKey(path)))
	return hex.EncodeToString(sum[:8])
}
func uniqueSortedUpper(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, strings.ToUpper(strings.TrimSpace(v)))
	}
	return uniqueSorted(out)
}
func containsString(in []string, want string) bool {
	want = strings.ToUpper(strings.TrimSpace(want))
	for _, v := range in {
		if strings.ToUpper(strings.TrimSpace(v)) == want {
			return true
		}
	}
	return false
}

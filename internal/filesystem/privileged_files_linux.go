//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxPrivilegedDiscoveryPaths      = 4096
	maxCapabilityFallbackEntries     = 150000
	maxOwnershipProbes               = 512
	linuxPrivilegedDiscoveryBudget   = 4 * time.Second
	linuxPrivilegedFallbackMinBudget = 600 * time.Millisecond
)

var linuxCapabilityNames = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
	"CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
	"CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
	"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

type linuxCapabilityData struct {
	Permitted   []string
	Inheritable []string
	Effective   bool
	Revision    int
	RootID      string
}

func collectPlatformPrivilegedFiles(ctx context.Context, mounts []MountBoundary) ([]PrivilegedFileRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStagePrivilegedLinux)
	defer stageCancel()
	ctx = stageCtx
	roots := linuxPrivilegedScanRoots(mounts)
	if len(roots) == 0 {
		return nil, SourceStatus{ID: "linux-privileged-files", State: evidence.StateUnavailable, Source: "Linux set-ID/file-capability metadata", Reason: "no bounded Linux privileged-file scan roots exist"}, []string{"Linux privileged-file inventory: no scan roots exist"}
	}

	paths := map[string]*PrivilegedFileRecord{}
	degraded := []string{}
	complete := false

	// Fix68 removes the two competing recursive traversals used by Fix61-Fix67.
	// On a busy full Kali scan, `find` and `getcap -r` could each be correct in
	// isolation yet both lose the same four-second discovery child to I/O
	// contention. One bounded `find` traversal now enumerates executable files;
	// Chimera then inspects set-ID mode bits and security.capability xattrs from
	// that shared candidate set. This preserves the same five/four-second stage
	// ceilings while eliminating duplicate recursive filesystem work.
	findPath, findLookupErr := exec.LookPath("find")
	if findLookupErr == nil {
		candidates, traversalComplete, traversalErr := discoverExecutablePrivilegeCandidatesWithFind(ctx, findPath, roots)
		if traversalErr != nil {
			degraded = append(degraded, "privileged executable candidate discovery degraded: "+traversalErr.Error())
		}
		probeComplete, probeDegraded := inspectLinuxPrivilegeCandidates(ctx, candidates, paths)
		degraded = append(degraded, probeDegraded...)
		complete = traversalComplete && probeComplete

		// If the native traversal failed before producing anything useful, use one
		// Go metadata walk for both set-ID and file-capability discovery. Do not run
		// two fallback walks over the same roots.
		if !complete && len(candidates) == 0 && linuxStageHasTime(ctx, linuxPrivilegedFallbackMinBudget) {
			degraded = append(degraded, "find returned no usable executable candidates; using single-pass Go privileged-file metadata fallback")
			fallbackComplete, fallbackErr := fallbackDiscoverPrivilegeSurfaces(ctx, roots, paths)
			if fallbackErr != nil {
				degraded = append(degraded, "privileged-file fallback discovery degraded: "+fallbackErr.Error())
			}
			if fallbackComplete && fallbackErr == nil {
				complete = true
			}
		}
	} else {
		degraded = append(degraded, "find unavailable; using single-pass Go privileged-file metadata fallback")
		fallbackComplete, fallbackErr := fallbackDiscoverPrivilegeSurfaces(ctx, roots, paths)
		complete = fallbackComplete && fallbackErr == nil
		if fallbackErr != nil {
			degraded = append(degraded, "privileged-file fallback discovery degraded: "+fallbackErr.Error())
		}
		if !fallbackComplete && fallbackErr == nil {
			degraded = append(degraded, fmt.Sprintf("privileged-file fallback reached bounded metadata limit of %d entries", maxCapabilityFallbackEntries))
		}
	}

	out := make([]PrivilegedFileRecord, 0, len(paths))
	keys := make([]string, 0, len(paths))
	for path := range paths {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	for _, path := range keys {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "privileged-file metadata collection interrupted: "+ctx.Err().Error())
			break
		}
		rec := *paths[path]
		if !populatePrivilegedMetadata(&rec) {
			continue
		}
		out = append(out, rec)
	}

	attributePrivilegedFiles(ctx, out, &degraded)
	for i := range out {
		classifyPrivilegedFile(&out[i])
		out[i].Capabilities = uniqueSortedUpper(out[i].Capabilities)
		out[i].InheritableCaps = uniqueSortedUpper(out[i].InheritableCaps)
		out[i].ReviewReasons = uniqueSorted(out[i].ReviewReasons)
	}

	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 || !complete {
		state = evidence.StateDegraded
		reason = "privileged-file inventory completed with bounded/provider limitations"
	}
	if ctx != nil && ctx.Err() != nil && len(out) == 0 {
		state = evidence.StateUnavailable
		reason = ctx.Err().Error()
	}
	return out, SourceStatus{
		ID: "linux-privileged-files", State: state,
		Source:    "single-pass Linux executable traversal with set-ID mode, security.capability xattr, and native package-ownership metadata",
		ItemCount: len(out), Reason: reason,
	}, uniqueSorted(degraded)
}

func linuxPrivilegedScanRoots(mounts []MountBoundary) []string {
	candidates := []string{
		"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec",
		"/usr/local", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/bin", "/sbin",
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, root := range candidates {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		clean := filepath.Clean(root)
		if resolved, err := filepath.EvalSymlinks(clean); err == nil && strings.TrimSpace(resolved) != "" {
			clean = filepath.Clean(resolved)
		}
		if linuxPathUsesRemoteFilesystem(clean, mounts) {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func discoverExecutablePrivilegeCandidatesWithFind(ctx context.Context, findPath string, roots []string) ([]string, bool, error) {
	base := context.Background()
	if ctx != nil {
		base = ctx
	}
	traversalCtx, cancel := context.WithTimeout(base, linuxPrivilegedDiscoveryBudget)
	defer cancel()

	args := append([]string(nil), roots...)
	args = append(args, "-xdev", "-type", "f", "-perm", "/111", "-print0")
	stdout, stderr, err := runMetadataCommand(traversalCtx, findPath, args...)
	paths := splitNULPaths(stdout, maxCapabilityFallbackEntries)
	if len(paths) >= maxCapabilityFallbackEntries {
		return paths, false, fmt.Errorf("executable candidate traversal reached bounded discovery limit of %d paths", maxCapabilityFallbackEntries)
	}
	if err != nil {
		return paths, false, fmt.Errorf("find: %v%s", err, commandStderrSuffix(stderr))
	}
	if strings.TrimSpace(string(stderr)) != "" {
		return paths, false, fmt.Errorf("find reported partial traversal errors%s", commandStderrSuffix(stderr))
	}
	return paths, true, nil
}

func inspectLinuxPrivilegeCandidates(ctx context.Context, candidates []string, records map[string]*PrivilegedFileRecord) (bool, []string) {
	unresolvedMetadata := 0
	unresolvedCapabilities := 0
	for _, path := range candidates {
		if ctx != nil && ctx.Err() != nil {
			return false, []string{"privileged executable candidate inspection interrupted: " + ctx.Err().Error()}
		}
		info, err := os.Lstat(path)
		if err != nil {
			unresolvedMetadata++
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			continue
		}
		var rec *PrivilegedFileRecord
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			rec = ensurePrivilegedRecord(records, path)
		}
		capData, present, capErr := readLinuxFileCapabilities(path)
		if capErr != nil {
			unresolvedCapabilities++
			continue
		}
		if !present {
			continue
		}
		if rec == nil {
			rec = ensurePrivilegedRecord(records, path)
		}
		rec.Capabilities = capData.Permitted
		rec.InheritableCaps = capData.Inheritable
		rec.CapabilityEffective = capData.Effective
		rec.CapabilityRevision = capData.Revision
		rec.CapabilityRootID = capData.RootID
	}
	degraded := []string{}
	if unresolvedMetadata > 0 {
		degraded = append(degraded, fmt.Sprintf("privileged executable metadata unavailable for %d candidate(s)", unresolvedMetadata))
	}
	if unresolvedCapabilities > 0 {
		degraded = append(degraded, fmt.Sprintf("security.capability xattr inspection unavailable for %d executable candidate(s)", unresolvedCapabilities))
	}
	return unresolvedMetadata == 0 && unresolvedCapabilities == 0, degraded
}

func linuxStageHasTime(ctx context.Context, minimum time.Duration) bool {
	if ctx == nil {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > minimum
}

func linuxPathUsesRemoteFilesystem(path string, mounts []MountBoundary) bool {
	bestLen := -1
	filesystem := ""
	for _, m := range mounts {
		mp := filepath.Clean(m.Path)
		if !pathWithinMount(path, mp) {
			continue
		}
		if len(mp) > bestLen {
			bestLen = len(mp)
			filesystem = strings.ToLower(strings.TrimSpace(m.Filesystem))
		}
	}
	for _, remote := range []string{"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "ceph", "glusterfs", "9p", "afs", "autofs"} {
		if filesystem == remote || strings.HasPrefix(filesystem, remote+".") {
			return true
		}
	}
	return false
}

func discoverSetIDWithFind(ctx context.Context, findPath string, roots []string) ([]string, error) {
	args := append([]string(nil), roots...)
	args = append(args, "-xdev", "-type", "f", "-perm", "/111", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print0")
	stdout, stderr, err := runMetadataCommand(ctx, findPath, args...)
	paths := splitNULPaths(stdout, maxPrivilegedDiscoveryPaths)
	if err != nil {
		return paths, fmt.Errorf("find: %v%s", err, commandStderrSuffix(stderr))
	}
	if len(paths) >= maxPrivilegedDiscoveryPaths {
		return paths, fmt.Errorf("find result reached bounded discovery limit of %d paths", maxPrivilegedDiscoveryPaths)
	}
	return paths, nil
}

func discoverCapabilitiesWithGetcap(ctx context.Context, getcapPath string, roots []string) (map[string]linuxCapabilityData, error) {
	args := append([]string{"-r"}, roots...)
	stdout, stderr, err := runMetadataCommand(ctx, getcapPath, args...)
	out := map[string]linuxCapabilityData{}
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path, data, ok := parseGetcapLine(line)
		if ok {
			out[path] = data
		}
		if len(out) >= maxPrivilegedDiscoveryPaths {
			return out, fmt.Errorf("getcap result reached bounded discovery limit of %d paths", maxPrivilegedDiscoveryPaths)
		}
	}
	if err != nil {
		return out, fmt.Errorf("getcap: %v%s", err, commandStderrSuffix(stderr))
	}
	if strings.TrimSpace(string(stderr)) != "" {
		return out, fmt.Errorf("getcap reported partial traversal errors%s", commandStderrSuffix(stderr))
	}
	return out, nil
}

func parseGetcapLine(line string) (string, linuxCapabilityData, bool) {
	idx := strings.LastIndex(line, " ")
	if idx <= 0 || idx+1 >= len(line) {
		return "", linuxCapabilityData{}, false
	}
	path := strings.TrimSpace(line[:idx])
	expr := strings.TrimSpace(line[idx+1:])
	if path == "" || expr == "" {
		return "", linuxCapabilityData{}, false
	}
	var data linuxCapabilityData
	for _, assignment := range strings.Split(expr, " ") {
		parts := strings.SplitN(assignment, "=", 2)
		if len(parts) != 2 {
			continue
		}
		flags := strings.ToLower(parts[1])
		if strings.Contains(flags, "e") {
			data.Effective = true
		}
		for _, raw := range strings.Split(parts[0], ",") {
			name := strings.ToUpper(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			if !strings.HasPrefix(name, "CAP_") {
				name = "CAP_" + name
			}
			if strings.Contains(flags, "p") || strings.Contains(flags, "e") {
				data.Permitted = append(data.Permitted, name)
			}
			if strings.Contains(flags, "i") {
				data.Inheritable = append(data.Inheritable, name)
			}
		}
	}
	data.Permitted = uniqueSortedUpper(data.Permitted)
	data.Inheritable = uniqueSortedUpper(data.Inheritable)
	if len(data.Permitted) == 0 && len(data.Inheritable) == 0 {
		return "", linuxCapabilityData{}, false
	}
	return filepath.Clean(path), data, true
}

func fallbackDiscoverPrivilegeSurfaces(ctx context.Context, roots []string, records map[string]*PrivilegedFileRecord) (bool, error) {
	entries := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if os.IsPermission(err) && d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			entries++
			if entries > maxCapabilityFallbackEntries {
				return fs.SkipAll
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return nil
			}
			var rec *PrivilegedFileRecord
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				rec = ensurePrivilegedRecord(records, path)
			}
			data, present, capErr := readLinuxFileCapabilities(path)
			if capErr != nil || !present {
				return nil
			}
			if rec == nil {
				rec = ensurePrivilegedRecord(records, path)
			}
			rec.Capabilities = data.Permitted
			rec.InheritableCaps = data.Inheritable
			rec.CapabilityEffective = data.Effective
			rec.CapabilityRevision = data.Revision
			rec.CapabilityRootID = data.RootID
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if entries > maxCapabilityFallbackEntries {
			return false, nil
		}
		if ctx != nil && ctx.Err() != nil {
			return false, ctx.Err()
		}
	}
	return true, nil
}

func fallbackDiscoverSetID(ctx context.Context, roots []string, records map[string]*PrivilegedFileRecord) error {
	entries := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if os.IsPermission(err) {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				return nil
			}
			entries++
			if entries > maxCapabilityFallbackEntries {
				return fs.SkipAll
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				ensurePrivilegedRecord(records, path)
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if entries > maxCapabilityFallbackEntries || (ctx != nil && ctx.Err() != nil) {
			break
		}
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

func fallbackDiscoverCapabilities(ctx context.Context, roots []string, records map[string]*PrivilegedFileRecord) (bool, error) {
	entries := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if os.IsPermission(err) && d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			entries++
			if entries > maxCapabilityFallbackEntries {
				return fs.SkipAll
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return nil
			}
			data, present, err := readLinuxFileCapabilities(path)
			if err != nil || !present {
				return nil
			}
			rec := ensurePrivilegedRecord(records, path)
			rec.Capabilities = data.Permitted
			rec.InheritableCaps = data.Inheritable
			rec.CapabilityEffective = data.Effective
			rec.CapabilityRevision = data.Revision
			rec.CapabilityRootID = data.RootID
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if entries > maxCapabilityFallbackEntries {
			return false, nil
		}
		if ctx != nil && ctx.Err() != nil {
			return false, ctx.Err()
		}
	}
	return true, nil
}

func ensurePrivilegedRecord(records map[string]*PrivilegedFileRecord, path string) *PrivilegedFileRecord {
	path = filepath.Clean(strings.TrimSpace(path))
	if rec, ok := records[path]; ok {
		return rec
	}
	rec := &PrivilegedFileRecord{
		ID: stablePrivilegedFileID(path), Path: path, State: evidence.StateObserved,
		PackageOwnership: "UNKNOWN", Classification: "UNRESOLVED",
		DiscoverySource:  "bounded Linux set-ID/file-capability discovery",
		CollectionSource: "Linux lstat mode metadata and security.capability xattr",
		Confidence:       evidence.ConfidenceHigh,
	}
	records[path] = rec
	return rec
}

func populatePrivilegedMetadata(rec *PrivilegedFileRecord) bool {
	info, err := os.Lstat(rec.Path)
	if err != nil {
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = appendFilesystemReason(rec.Reason, err.Error())
		return true
	}
	rec.Exists = true
	rec.Regular = info.Mode().IsRegular()
	rec.Executable = rec.Regular && info.Mode().Perm()&0111 != 0
	if !rec.Regular {
		return false
	}
	rec.Mode = info.Mode().String()
	rec.SetUID = info.Mode()&os.ModeSetuid != 0
	rec.SetGID = info.Mode()&os.ModeSetgid != 0
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
		rec.GroupID = strconv.FormatUint(uint64(st.Gid), 10)
	}
	if len(rec.Capabilities) == 0 && len(rec.InheritableCaps) == 0 {
		if data, present, err := readLinuxFileCapabilities(rec.Path); err == nil && present {
			rec.Capabilities = data.Permitted
			rec.InheritableCaps = data.Inheritable
			rec.CapabilityEffective = data.Effective
			rec.CapabilityRevision = data.Revision
			rec.CapabilityRootID = data.RootID
		} else if err != nil {
			rec.Reason = appendFilesystemReason(rec.Reason, "capability xattr detail unavailable: "+err.Error())
		}
	}
	return rec.SetUID || rec.SetGID || len(rec.Capabilities) > 0 || len(rec.InheritableCaps) > 0
}

func readLinuxFileCapabilities(path string) (linuxCapabilityData, bool, error) {
	sz, err := syscall.Getxattr(path, "security.capability", nil)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			return linuxCapabilityData{}, false, nil
		}
		return linuxCapabilityData{}, false, err
	}
	if sz == 0 {
		return linuxCapabilityData{}, false, nil
	}
	if sz > 256 {
		return linuxCapabilityData{}, false, fmt.Errorf("security.capability xattr is unexpectedly large: %d bytes", sz)
	}
	buf := make([]byte, sz)
	n, err := syscall.Getxattr(path, "security.capability", buf)
	if err != nil {
		return linuxCapabilityData{}, false, err
	}
	data, err := decodeLinuxFileCapabilities(buf[:n])
	if err != nil {
		return linuxCapabilityData{}, false, err
	}
	if len(data.Permitted) == 0 && len(data.Inheritable) == 0 {
		return linuxCapabilityData{}, false, nil
	}
	return data, true, nil
}

func decodeLinuxFileCapabilities(raw []byte) (linuxCapabilityData, error) {
	if len(raw) < 12 {
		return linuxCapabilityData{}, fmt.Errorf("security.capability xattr too short: %d", len(raw))
	}
	magic := binary.LittleEndian.Uint32(raw[0:4])
	revisionBits := magic & 0xff000000
	var revision int
	var words int
	var required int
	switch revisionBits {
	case 0x01000000:
		revision, words, required = 1, 1, 12
	case 0x02000000:
		revision, words, required = 2, 2, 20
	case 0x03000000:
		revision, words, required = 3, 2, 24
	default:
		return linuxCapabilityData{}, fmt.Errorf("unsupported security.capability revision 0x%08x", revisionBits)
	}
	if len(raw) < required {
		return linuxCapabilityData{}, fmt.Errorf("security.capability revision %d requires %d bytes, got %d", revision, required, len(raw))
	}
	var permitted uint64
	var inheritable uint64
	for i := 0; i < words; i++ {
		off := 4 + i*8
		permitted |= uint64(binary.LittleEndian.Uint32(raw[off:off+4])) << (32 * i)
		inheritable |= uint64(binary.LittleEndian.Uint32(raw[off+4:off+8])) << (32 * i)
	}
	data := linuxCapabilityData{Effective: magic&0x1 != 0, Revision: revision}
	data.Permitted = capabilityNamesFromMask(permitted)
	data.Inheritable = capabilityNamesFromMask(inheritable)
	if revision == 3 {
		data.RootID = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[20:24])), 10)
	}
	return data, nil
}

func capabilityNamesFromMask(mask uint64) []string {
	out := []string{}
	for bit := 0; bit < 64; bit++ {
		if mask&(uint64(1)<<bit) == 0 {
			continue
		}
		if bit < len(linuxCapabilityNames) {
			out = append(out, linuxCapabilityNames[bit])
		} else {
			out = append(out, fmt.Sprintf("CAP_%d", bit))
		}
	}
	return out
}

func attributePrivilegedFiles(ctx context.Context, records []PrivilegedFileRecord, degraded *[]string) {
	provider := ""
	for _, candidate := range []string{"dpkg-query", "rpm", "pacman", "apk"} {
		if _, err := exec.LookPath(candidate); err == nil {
			provider = candidate
			break
		}
	}
	if provider == "" {
		for i := range records {
			records[i].PackageOwnership = "UNKNOWN"
			records[i].PackageProvider = "none"
		}
		*degraded = append(*degraded, "native package ownership provider unavailable for privileged executable attribution")
		return
	}

	limit := len(records)
	if limit > maxOwnershipProbes {
		limit = maxOwnershipProbes
		*degraded = append(*degraded, fmt.Sprintf("package ownership attribution limited to %d privileged executable(s)", maxOwnershipProbes))
	}

	probeIndexes := make([]int, 0, limit)
	for i := range records {
		if obviousCustomPrivilegedPath(records[i].Path) {
			records[i].PackageOwnership = "UNKNOWN"
			records[i].PackageProvider = provider
			records[i].Reason = appendFilesystemReason(records[i].Reason, "package ownership probe skipped because the path is already classified within a custom/user/temporary software boundary")
			continue
		}
		if len(probeIndexes) >= limit {
			records[i].PackageOwnership = "UNKNOWN"
			records[i].PackageProvider = provider
			records[i].Reason = appendFilesystemReason(records[i].Reason, "package ownership not probed because bounded attribution limit was reached")
			continue
		}
		probeIndexes = append(probeIndexes, i)
	}

	// Debian-family hosts are the common high-cardinality case on Kali. One
	// dpkg-query process accepts many exact paths, so package attribution is
	// completed in a few bounded batches instead of spawning once per
	// privileged executable after the recursive discovery stage.
	if provider == "dpkg-query" && len(probeIndexes) > 0 {
		paths := make([]string, 0, len(probeIndexes))
		for _, i := range probeIndexes {
			paths = append(paths, filepath.Clean(records[i].Path))
		}
		owners := queryFilesystemDpkgOwnersBatch(ctx, paths)
		for _, i := range probeIndexes {
			path := filepath.Clean(records[i].Path)
			owner, ok := owners[path]
			if !ok {
				owner = filesystemPackageOwner{Ownership: "UNKNOWN", Reason: "dpkg-query batch returned no result for privileged executable"}
			}
			records[i].PackageOwnership = owner.Ownership
			records[i].PackageID = owner.PackageID
			records[i].PackageProvider = provider
			if owner.Reason != "" && owner.Ownership == "UNKNOWN" {
				records[i].Reason = appendFilesystemReason(records[i].Reason, owner.Reason)
			}
		}
		return
	}

	for _, i := range probeIndexes {
		ownership, id, reason := queryLinuxPackageOwner(ctx, provider, records[i].Path)
		records[i].PackageOwnership = ownership
		records[i].PackageID = id
		records[i].PackageProvider = provider
		if reason != "" && ownership == "UNKNOWN" {
			records[i].Reason = appendFilesystemReason(records[i].Reason, reason)
		}
	}
}

type filesystemPackageOwner struct {
	Ownership string
	PackageID string
	Reason    string
}

func queryFilesystemDpkgOwnersBatch(ctx context.Context, paths []string) map[string]filesystemPackageOwner {
	const batchSize = 128
	out := make(map[string]filesystemPackageOwner, len(paths))
	ordered := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		ordered = append(ordered, path)
	}
	providerPath, err := exec.LookPath("dpkg-query")
	if err != nil {
		for _, path := range ordered {
			out[path] = filesystemPackageOwner{Ownership: "UNKNOWN", Reason: "dpkg-query executable became unavailable during attribution"}
		}
		return out
	}
	for start := 0; start < len(ordered); start += batchSize {
		end := start + batchSize
		if end > len(ordered) {
			end = len(ordered)
		}
		chunk := ordered[start:end]
		if ctx != nil && ctx.Err() != nil {
			for _, path := range chunk {
				out[path] = filesystemPackageOwner{Ownership: "UNKNOWN", Reason: ctx.Err().Error()}
			}
			continue
		}
		args := append([]string{"-S"}, chunk...)
		stdout, stderr, runErr := runMetadataCommand(ctx, providerPath, args...)
		matched := parseFilesystemDpkgSearchOutput(string(stdout))
		for path, pkg := range matched {
			out[path] = filesystemPackageOwner{Ownership: "PACKAGE_MANAGED", PackageID: pkg}
		}
		stderrText := strings.TrimSpace(string(stderr))
		for _, path := range chunk {
			if _, ok := out[path]; ok {
				continue
			}
			switch {
			case ctx != nil && ctx.Err() != nil:
				out[path] = filesystemPackageOwner{Ownership: "UNKNOWN", Reason: ctx.Err().Error()}
			case runErr == nil:
				out[path] = filesystemPackageOwner{Ownership: "UNMANAGED"}
			case filesystemDpkgOnlyMissing(stderrText):
				out[path] = filesystemPackageOwner{Ownership: "UNMANAGED"}
			default:
				reason := stderrText
				if reason == "" {
					reason = runErr.Error()
				}
				out[path] = filesystemPackageOwner{Ownership: "UNKNOWN", Reason: reason}
			}
		}
	}
	return out
}

func parseFilesystemDpkgSearchOutput(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		owner := strings.TrimSpace(line[:idx])
		path := filepath.Clean(strings.TrimSpace(line[idx+2:]))
		if owner == "" || path == "" || path == "." || strings.Contains(strings.ToLower(owner), "diversion") {
			continue
		}
		out[path] = owner
	}
	return out
}

func filesystemDpkgOnlyMissing(stderr string) bool {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return false
	}
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if !strings.Contains(line, "no path found matching pattern") {
			return false
		}
	}
	return true
}

func queryLinuxPackageOwner(ctx context.Context, provider, path string) (string, string, string) {
	base := context.Background()
	if ctx != nil {
		base = ctx
	}
	probeCtx, cancel := context.WithTimeout(base, 1200*time.Millisecond)
	defer cancel()
	var args []string
	switch provider {
	case "dpkg-query":
		args = []string{"-S", path}
	case "rpm":
		args = []string{"-qf", "--qf", "%{NAME}\n", path}
	case "pacman":
		args = []string{"-Qo", path}
	case "apk":
		args = []string{"info", "--who-owns", path}
	default:
		return "UNKNOWN", "", "unsupported package ownership provider"
	}
	stdout, stderr, err := runMetadataCommand(probeCtx, provider, args...)
	text := strings.TrimSpace(string(stdout))
	if err != nil {
		combined := strings.ToLower(text + " " + string(stderr) + " " + err.Error())
		if packageOwnershipNegative(combined) {
			return "UNMANAGED", "", ""
		}
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return "UNKNOWN", "", "package ownership probe timed out"
		}
		return "UNKNOWN", "", strings.TrimSpace(provider + " ownership probe failed" + commandStderrSuffix(stderr))
	}
	id := parseLinuxPackageOwner(provider, text)
	if id == "" {
		return "UNKNOWN", "", provider + " returned no parseable package owner"
	}
	return "PACKAGE_MANAGED", id, ""
}

func parseLinuxPackageOwner(provider, text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	switch provider {
	case "dpkg-query":
		line := strings.Split(text, "\n")[0]
		if idx := strings.Index(line, ": "); idx > 0 {
			owner := strings.TrimSpace(line[:idx])
			if !strings.Contains(strings.ToLower(owner), "diversion") {
				return owner
			}
		}
	case "rpm":
		return strings.Fields(text)[0]
	case "pacman":
		const marker = " is owned by "
		if idx := strings.Index(text, marker); idx >= 0 {
			fields := strings.Fields(text[idx+len(marker):])
			if len(fields) > 0 {
				return fields[0]
			}
		}
	case "apk":
		// apk commonly emits: "/path is owned by package-version".
		const marker = " is owned by "
		if idx := strings.Index(text, marker); idx >= 0 {
			fields := strings.Fields(text[idx+len(marker):])
			if len(fields) > 0 {
				return fields[0]
			}
		}
		fields := strings.Fields(text)
		if len(fields) > 0 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func packageOwnershipNegative(s string) bool {
	for _, marker := range []string{"no path found matching pattern", "is not owned by any package", "no package owns", "could not find owner", "not owned", "no such package"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func classifyPrivilegedFile(rec *PrivilegedFileRecord) {
	reasons := []string{}
	if obviousCustomPrivilegedPath(rec.Path) {
		reasons = append(reasons, "privilege-bearing executable is located in a local/custom/user/temporary software boundary")
	}
	if rec.PackageOwnership == "UNMANAGED" {
		reasons = append(reasons, "native package database reports no owning package")
	}
	if rec.SetUID && rec.OwnerID != "" && rec.OwnerID != "0" {
		reasons = append(reasons, "setuid target is owned by non-root UID "+rec.OwnerID)
	}
	if rec.SetGID && rec.GroupID != "" && rec.GroupID != "0" && rec.PackageOwnership != "PACKAGE_MANAGED" {
		reasons = append(reasons, "unmanaged/custom setgid target uses non-root GID "+rec.GroupID)
	}
	if info, err := os.Stat(rec.Path); err == nil {
		perm := info.Mode().Perm()
		if perm&0022 != 0 {
			reasons = append(reasons, "privilege-bearing executable is writable by group or other principals")
		}
	}
	rec.ReviewReasons = uniqueSorted(reasons)
	rec.ReviewRequired = len(rec.ReviewReasons) > 0
	switch {
	case rec.ReviewRequired:
		rec.Classification = "CUSTOM_OR_UNEXPECTED"
	case rec.PackageOwnership == "PACKAGE_MANAGED":
		rec.Classification = "PACKAGE_MANAGED_STANDARD"
	default:
		rec.Classification = "STANDARD_UNRESOLVED"
	}
	if rec.PackageOwnership == "UNKNOWN" {
		rec.Confidence = evidence.ConfidenceMedium
	}
}

func obviousCustomPrivilegedPath(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	for _, prefix := range []string{"/usr/local/", "/opt/", "/home/", "/root/", "/tmp/", "/var/tmp/"} {
		if strings.HasPrefix(lower, prefix) || lower == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}

func runMetadataCommand(ctx context.Context, path string, args ...string) ([]byte, []byte, error) {
	base := context.Background()
	if ctx != nil {
		base = ctx
	}
	cmd := exec.CommandContext(base, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func splitNULPaths(data []byte, limit int) []string {
	parts := bytes.Split(data, []byte{0})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, raw := range parts {
		path := filepath.Clean(strings.TrimSpace(string(raw)))
		if path == "." || path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
		if len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out
}

func commandStderrSuffix(stderr []byte) string {
	text := strings.TrimSpace(string(stderr))
	if text == "" {
		return ""
	}
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	return "; stderr=" + text
}

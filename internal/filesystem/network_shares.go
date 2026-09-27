package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectNetworkShares(ctx context.Context, mounts []MountBoundary) ([]NetworkShareRecord, []SourceStatus, []string) {
	mounted := mountedNetworkShares(mounts)
	exported, exportSource, degraded := collectPlatformNFSExports(ctx)
	out := append(mounted, exported...)
	out = normalizeNetworkShares(out)

	mountedState := evidence.StateObserved
	mountedReason := ""
	if ctx != nil && ctx.Err() != nil {
		mountedState = evidence.StateDegraded
		mountedReason = "network-share derivation interrupted: " + ctx.Err().Error()
		degraded = append(degraded, mountedReason)
	}
	sources := []SourceStatus{
		{ID: "network-mounted-shares", State: mountedState, Source: "normalized local mount/volume metadata; no remote enumeration", ItemCount: len(mounted), Reason: mountedReason},
		exportSource,
	}
	return out, sources, uniqueSorted(degraded)
}

func mountedNetworkShares(mounts []MountBoundary) []NetworkShareRecord {
	out := make([]NetworkShareRecord, 0)
	for _, m := range mounts {
		if !m.Network && !isNetworkFilesystem(m.Filesystem) {
			continue
		}
		protocol := networkProtocolFromFilesystem(m.Filesystem, m.BackingSource)
		opts, dangerous, guest, anonymous := networkMountSecurityOptions(m.Options, protocol)
		accessKnown := m.AccessMode == MountAccessReadOnly || m.AccessMode == MountAccessReadWrite
		sh := NetworkShareRecord{
			Direction:        NetworkShareDirectionMounted,
			Protocol:         protocol,
			LocalPath:        m.Path,
			Remote:           m.BackingSource,
			SecurityOptions:  opts,
			AccessMode:       m.AccessMode,
			ReadOnly:         m.ReadOnly,
			Writable:         m.Writable,
			AccessKnown:      accessKnown,
			GuestAllowed:     guest,
			AnonymousAllowed: anonymous,
			BroadAccess:      guest || anonymous,
			BroadWrite:       (guest || anonymous) && accessKnown && m.Writable,
			DangerousOptions: dangerous,
			State:            m.State,
			CollectionSource: m.CollectionSource + " -> network-share normalization",
			Confidence:       m.Confidence,
			Reason:           m.Reason,
		}
		sh.ID = stableNetworkShareID(sh)
		out = append(out, sh)
	}
	return out
}

func networkProtocolFromFilesystem(fs, source string) string {
	v := strings.ToLower(strings.TrimSpace(fs))
	switch v {
	case "nfs", "nfs4":
		return NetworkShareProtocolNFS
	case "cifs", "smbfs", "smb3":
		return NetworkShareProtocolSMB
	}
	s := strings.ToLower(strings.TrimSpace(source))
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, `\\`) {
		return NetworkShareProtocolSMB
	}
	return NetworkShareProtocolOther
}

func networkMountSecurityOptions(options []string, protocol string) (safe []string, dangerous []string, guest, anonymous bool) {
	for _, raw := range options {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		lower := strings.ToLower(raw)
		name, value := splitOption(lower)
		switch name {
		case "ro", "rw", "nosuid", "nodev", "noexec", "suid", "dev", "exec", "guest", "noperm", "nounix", "seal", "vers", "version", "sec", "proto", "port":
			if name == "vers" || name == "version" || name == "sec" {
				safe = append(safe, name+"="+sanitizeNetworkOptionValue(value))
			} else {
				safe = append(safe, name)
			}
		}
		if name == "guest" || ((name == "user" || name == "username") && strings.EqualFold(strings.TrimSpace(value), "guest")) {
			guest = true
			dangerous = append(dangerous, "guest-access")
		}
		if name == "sec" && strings.EqualFold(strings.TrimSpace(value), "none") {
			anonymous = true
			dangerous = append(dangerous, "sec=none")
		}
		if protocol == NetworkShareProtocolSMB {
			switch name {
			case "noperm":
				dangerous = append(dangerous, "noperm")
			case "vers", "version":
				v := strings.TrimSpace(value)
				if v == "1" || v == "1.0" || strings.EqualFold(v, "nt1") {
					dangerous = append(dangerous, "legacy-smb1")
				}
			}
		}
		if protocol == NetworkShareProtocolNFS && (name == "vers" || name == "version") {
			v := strings.TrimSpace(value)
			if v == "2" || v == "2.0" {
				dangerous = append(dangerous, "legacy-nfs2")
			}
		}
		if name == "suid" {
			dangerous = append(dangerous, "suid-enabled")
		}
		if name == "dev" {
			dangerous = append(dangerous, "device-nodes-enabled")
		}
	}
	return uniqueSorted(safe), uniqueSorted(dangerous), guest, anonymous
}

func splitOption(v string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(v), "=", 2)
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func sanitizeNetworkOptionValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 64 {
		return v[:64]
	}
	return v
}

func normalizeNetworkShares(in []NetworkShareRecord) []NetworkShareRecord {
	out := make([]NetworkShareRecord, 0, len(in))
	seen := map[string]struct{}{}
	for _, sh := range in {
		sh.Direction = strings.ToUpper(strings.TrimSpace(sh.Direction))
		sh.Protocol = strings.ToUpper(strings.TrimSpace(sh.Protocol))
		if sh.Protocol == "CIFS" {
			sh.Protocol = NetworkShareProtocolSMB
		}
		if sh.Protocol == "NFS4" {
			sh.Protocol = NetworkShareProtocolNFS
		}
		if sh.Protocol == "" {
			sh.Protocol = NetworkShareProtocolOther
		}
		sh.Name = strings.TrimSpace(sh.Name)
		sh.LocalPath = strings.TrimSpace(sh.LocalPath)
		if sh.LocalPath != "" {
			sh.LocalPath = filepath.Clean(sh.LocalPath)
		}
		sh.Remote = strings.TrimSpace(sh.Remote)
		sh.SecurityOptions = uniqueSorted(sh.SecurityOptions)
		sh.DangerousOptions = uniqueSorted(sh.DangerousOptions)
		sh.AccessMode = strings.ToUpper(strings.TrimSpace(sh.AccessMode))
		if sh.AccessMode == "" {
			sh.AccessMode = MountAccessUnknown
		}
		sh.ReadOnly = sh.AccessMode == MountAccessReadOnly
		sh.Writable = sh.AccessMode == MountAccessReadWrite
		if sh.AccessMode == MountAccessReadOnly || sh.AccessMode == MountAccessReadWrite {
			sh.AccessKnown = true
		}
		sh.CollectionSource = strings.TrimSpace(sh.CollectionSource)
		if sh.CollectionSource == "" {
			sh.CollectionSource = "local network-share metadata"
		}
		if sh.State == "" {
			sh.State = evidence.StateObserved
		}
		if sh.Confidence == "" {
			sh.Confidence = evidence.ConfidenceMedium
		}
		sh.Reason = strings.TrimSpace(sh.Reason)
		if sh.ID == "" {
			sh.ID = stableNetworkShareID(sh)
		}
		if _, ok := seen[sh.ID]; ok {
			continue
		}
		seen[sh.ID] = struct{}{}
		out = append(out, sh)
		if len(out) >= maxNetworkShares {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return networkShareSortKey(out[i]) < networkShareSortKey(out[j]) })
	return out
}

func stableNetworkShareID(sh NetworkShareRecord) string {
	basis := strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(sh.Direction)),
		strings.ToUpper(strings.TrimSpace(sh.Protocol)),
		platformPathKey(strings.TrimSpace(sh.LocalPath)),
		strings.ToLower(strings.TrimSpace(sh.Name)),
		strings.ToLower(strings.TrimSpace(sh.Remote)),
	}, "|")
	sum := sha256.Sum256([]byte(basis))
	return "nshare-" + hex.EncodeToString(sum[:8])
}

func networkShareSortKey(sh NetworkShareRecord) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", sh.Direction, sh.Protocol, platformPathKey(sh.LocalPath), strings.ToLower(sh.Name), strings.ToLower(sh.Remote))
}

func broadNFSAudience(client string) bool {
	v := strings.ToLower(strings.TrimSpace(client))
	if v == "" {
		return false
	}
	if v == "*" || v == "0.0.0.0/0" || v == "::/0" || v == "all machines" || v == "all" {
		return true
	}
	return strings.Contains(v, "*")
}

//go:build linux

package filesystem

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	posixACLVersion = 0x0002
	aclUserObj      = 0x0001
	aclUser         = 0x0002
	aclGroupObj     = 0x0004
	aclGroup        = 0x0008
	aclMask         = 0x0010
	aclOther        = 0x0020
)

type posixACLEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

func collectPlatformACLBoundaries(ctx context.Context, candidates []aclBoundaryCandidate) ([]ACLBoundaryRecord, SourceStatus, []string) {
	stageCtx, stageCancel := unixFilesystemStageContext(ctx, filesystemStageACL)
	defer stageCancel()
	ctx = stageCtx
	out := make([]ACLBoundaryRecord, 0, len(candidates))
	degraded := []string{}
	unresolved := 0
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "ACL boundary inventory interrupted: "+ctx.Err().Error())
			break
		}
		rec := inspectLinuxACLBoundary(c)
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if unresolved > 0 || len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("Linux ACL boundary inventory completed with %d unresolved/unsupported record(s)", unresolved)
	}
	if ctx != nil && ctx.Err() != nil && len(out) == 0 {
		state = evidence.StateUnavailable
		reason = ctx.Err().Error()
	}
	return out, SourceStatus{ID: "acl-boundaries", State: state, Source: "Linux native POSIX ACL xattr metadata on selected high-impact paths", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func inspectLinuxACLBoundary(c aclBoundaryCandidate) ACLBoundaryRecord {
	rec := ACLBoundaryRecord{
		ID: stableACLBoundaryID(c.Path), Path: c.Path, Contexts: append([]string(nil), c.Contexts...),
		State: evidence.StateObserved, ACLModel: "POSIX_ACL", DiscoverySources: append([]string(nil), c.Sources...),
		CollectionSource: "Linux system.posix_acl_access/default xattr metadata", Confidence: evidence.ConfidenceExact,
	}
	info, err := os.Stat(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			rec.Exists = false
			rec.Reason = "path does not exist on this host"
			return rec
		}
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec
	}
	rec.Exists = true
	rec.Directory = info.IsDir()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
	}

	access, present, err := readLinuxPOSIXACL(c.Path, "system.posix_acl_access")
	if err != nil {
		if linuxACLUnsupported(err) {
			rec.State = evidence.StateUnsupported
			rec.Reason = "filesystem does not expose POSIX ACL access metadata: " + err.Error()
			rec.Confidence = evidence.ConfidenceHigh
			return rec
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = "POSIX ACL access metadata unavailable: " + err.Error()
		rec.Confidence = evidence.ConfidenceMedium
		return rec
	}
	if present {
		rec.HasExtendedACL = true
		rec.Grants = append(rec.Grants, linuxACLGrants(access, false, rec.OwnerID)...)
	}

	if rec.Directory {
		def, defaultPresent, derr := readLinuxPOSIXACL(c.Path, "system.posix_acl_default")
		if derr != nil && !linuxACLUnsupported(derr) {
			if errors.Is(derr, syscall.EACCES) || errors.Is(derr, syscall.EPERM) {
				rec.State = evidence.StateDenied
			} else {
				rec.State = evidence.StateUnavailable
			}
			rec.Reason = "POSIX default ACL metadata unavailable: " + derr.Error()
			rec.Confidence = evidence.ConfidenceMedium
			return rec
		}
		if defaultPresent {
			rec.HasExtendedACL = true
			rec.Grants = append(rec.Grants, linuxACLGrants(def, true, rec.OwnerID)...)
		}
	}
	classifyACLBoundary(&rec)
	return rec
}

func readLinuxPOSIXACL(path, attr string) ([]posixACLEntry, bool, error) {
	n, err := syscall.Getxattr(path, attr, nil)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if n == 0 {
		return nil, false, nil
	}
	raw := make([]byte, n)
	n, err = syscall.Getxattr(path, attr, raw)
	if err != nil {
		return nil, false, err
	}
	raw = raw[:n]
	if len(raw) < 4 || binary.LittleEndian.Uint32(raw[:4]) != posixACLVersion {
		return nil, true, fmt.Errorf("unsupported POSIX ACL xattr format")
	}
	body := raw[4:]
	if len(body)%8 != 0 {
		return nil, true, fmt.Errorf("malformed POSIX ACL xattr length %d", len(raw))
	}
	entries := make([]posixACLEntry, 0, len(body)/8)
	for len(body) >= 8 {
		entries = append(entries, posixACLEntry{
			Tag: binary.LittleEndian.Uint16(body[0:2]), Perm: binary.LittleEndian.Uint16(body[2:4]), ID: binary.LittleEndian.Uint32(body[4:8]),
		})
		body = body[8:]
	}
	return entries, true, nil
}

func linuxACLUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS)
}

func linuxACLGrants(entries []posixACLEntry, defaultACL bool, ownerID string) []ACLGrant {
	mask := uint16(7)
	for _, e := range entries {
		if e.Tag == aclMask {
			mask = e.Perm & 7
			break
		}
	}
	out := []ACLGrant{}
	for _, e := range entries {
		if e.Tag == aclMask {
			continue
		}
		effectivePerm := e.Perm & 7
		if e.Tag == aclUser || e.Tag == aclGroup || e.Tag == aclGroupObj {
			effectivePerm &= mask
		}
		rights := posixRights(effectivePerm)
		if len(rights) == 0 {
			continue
		}
		class, principal, principalID := linuxACLPrincipal(e)
		trusted := false
		broad := false
		switch e.Tag {
		case aclUserObj:
			trusted = true
			principalID = ownerID
			principal = "owner:" + fallback(ownerID, "unknown")
		case aclUser:
			trusted = principalID == "0" || (ownerID != "" && principalID == ownerID)
		case aclGroupObj:
			trusted = principalID == "0"
		case aclGroup:
			trusted = principalID == "0"
		case aclOther:
			broad = true
		}
		if defaultACL {
			class = "DEFAULT_" + class
			principal = "default:" + principal
		}
		out = append(out, ACLGrant{
			Principal: principal, PrincipalID: principalID, PrincipalClass: class, Access: ACLGrantAllow,
			Rights: rights, Inherited: defaultACL, Effective: true, Broad: broad, Trusted: trusted,
			WriteLike: containsString(rights, "WRITE"), ControlLike: false,
		})
	}
	return out
}

func linuxACLPrincipal(e posixACLEntry) (class, principal, id string) {
	switch e.Tag {
	case aclUserObj:
		return "OWNER", "owner", ""
	case aclUser:
		id = strconv.FormatUint(uint64(e.ID), 10)
		return "NAMED_USER", "user:" + id, id
	case aclGroupObj:
		return "OWNING_GROUP", "owning-group", ""
	case aclGroup:
		id = strconv.FormatUint(uint64(e.ID), 10)
		return "NAMED_GROUP", "group:" + id, id
	case aclOther:
		return "OTHER", "other", ""
	default:
		return "UNKNOWN", "tag:" + strconv.Itoa(int(e.Tag)), ""
	}
}

func posixRights(perm uint16) []string {
	out := []string{}
	if perm&4 != 0 {
		out = append(out, "READ")
	}
	if perm&2 != 0 {
		out = append(out, "WRITE")
	}
	if perm&1 != 0 {
		out = append(out, "EXECUTE")
	}
	return out
}

//go:build linux || darwin

package accounts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSSHKeyPosture(ctx context.Context, inv *Inventory) {
	p := SSHKeyPosture{Source: "local filesystem SSH metadata (path/ownership/mode only)"}
	problems := []string{}
	examined := 0
	for _, a := range inv.Accounts {
		if examined >= maxSSHKeyAccounts || len(p.Records) >= maxSSHKeyRecords {
			problems = append(problems, fmt.Sprintf("SSH metadata account/record limit reached (%d accounts, %d records)", maxSSHKeyAccounts, maxSSHKeyRecords))
			break
		}
		if err := ctx.Err(); err != nil {
			problems = append(problems, "SSH metadata collection deadline reached: "+err.Error())
			break
		}
		home := filepath.Clean(strings.TrimSpace(a.Home))
		if home == "." || home == "" || !filepath.IsAbs(home) {
			continue
		}
		sshDir := filepath.Join(home, ".ssh")
		info, err := os.Lstat(sshDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			examined++
			p.Records = append(p.Records, unavailableSSHRecord(a, sshDir, "SSH_DIRECTORY", err))
			problems = append(problems, a.Principal+" .ssh metadata: "+err.Error())
			continue
		}
		examined++
		// Record the home ancestor only when an SSH trust directory exists; this
		// keeps bounded to paths that can affect SSH key-based access.
		if hr, ok := unixSSHRecord(a, home, "HOME_DIRECTORY"); ok {
			p.Records = append(p.Records, hr)
		}
		dirRecord, _ := unixSSHRecordFromInfo(a, sshDir, "SSH_DIRECTORY", info)
		p.Records = append(p.Records, dirRecord)
		if !info.IsDir() {
			problems = append(problems, sshDir+" exists but is not a directory")
			continue
		}
		entries, err := os.ReadDir(sshDir)
		if err != nil {
			problems = append(problems, a.Principal+" .ssh listing: "+err.Error())
			continue
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				problems = append(problems, "SSH metadata collection deadline reached: "+err.Error())
				break
			}
			kind := ""
			if isAuthorizedKeysName(entry.Name()) {
				kind = "AUTHORIZED_KEYS"
			} else if isSSHPrivateKeyCandidateName(entry.Name()) {
				kind = "PRIVATE_KEY_CANDIDATE"
			}
			if kind == "" {
				continue
			}
			path := filepath.Join(sshDir, entry.Name())
			rec, ok := unixSSHRecord(a, path, kind)
			if ok {
				p.Records = append(p.Records, rec)
			} else {
				p.Records = append(p.Records, unavailableSSHRecord(a, path, kind, fmt.Errorf("metadata unavailable")))
				problems = append(problems, path+" metadata unavailable")
			}
			if len(p.Records) >= maxSSHKeyRecords {
				break
			}
		}
	}
	if examined == 0 {
		p.State = evidence.StateObserved
		if len(inv.Accounts) == 0 {
			p.State = evidence.StateUnavailable
			p.Reason = "no local accounts were available to scope SSH key posture"
		}
	} else if len(problems) > 0 {
		p.State = evidence.StateDegraded
		p.Reason = strings.Join(uniqueSorted(problems), "; ")
		inv.Degraded = append(inv.Degraded, "ssh-key-posture: "+p.Reason)
	} else {
		p.State = evidence.StateObserved
	}
	inv.SSHKeyPosture = p
}

func unixSSHRecord(a Account, path, kind string) (SSHKeyPathRecord, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return SSHKeyPathRecord{}, false
	}
	return unixSSHRecordFromInfo(a, path, kind, info)
}

func unixSSHRecordFromInfo(a Account, path, kind string, info os.FileInfo) (SSHKeyPathRecord, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return unavailableSSHRecord(a, path, kind, fmt.Errorf("native ownership metadata unavailable")), false
	}
	perm := info.Mode().Perm()
	groupRead := perm&0040 != 0
	groupWrite := perm&0020 != 0
	otherRead := perm&0004 != 0
	otherWrite := perm&0002 != 0
	ownerID := strconv.FormatUint(uint64(st.Uid), 10)
	expected := strings.TrimSpace(a.UID)
	ownerMatch := "UNKNOWN"
	if expected != "" {
		if ownerID == expected {
			ownerMatch = "MATCH"
		} else if st.Uid == 0 {
			ownerMatch = "TRUSTED_SYSTEM"
		} else {
			ownerMatch = "MISMATCH"
		}
	}
	symlink := info.Mode()&os.ModeSymlink != 0
	basis := []string{}
	switch kind {
	case "HOME_DIRECTORY", "SSH_DIRECTORY", "AUTHORIZED_KEYS":
		if groupWrite {
			basis = append(basis, "group-writable path")
		}
		if otherWrite {
			basis = append(basis, "world-writable path")
		}
	case "PRIVATE_KEY_CANDIDATE":
		if groupRead {
			basis = append(basis, "private-key candidate is group-readable")
		}
		if otherRead {
			basis = append(basis, "private-key candidate is world-readable")
		}
		if groupWrite {
			basis = append(basis, "private-key candidate is group-writable")
		}
		if otherWrite {
			basis = append(basis, "private-key candidate is world-writable")
		}
	}
	if ownerMatch == "MISMATCH" {
		basis = append(basis, "path owner does not match the local account or root")
	}
	if symlink && kind != "HOME_DIRECTORY" {
		basis = append(basis, "security-sensitive SSH path is a symbolic link")
	}
	return SSHKeyPathRecord{
		ID: stableSSHKeyID(a.ID, a.Principal, path, kind), AccountID: a.ID, Principal: a.Principal, Privileged: a.Privileged,
		Path: path, Kind: kind, State: evidence.StateObserved, Directory: info.IsDir(), Symlink: symlink,
		Mode: info.Mode().String(), OwnerID: ownerID, GroupID: strconv.FormatUint(uint64(st.Gid), 10), OwnerMatch: ownerMatch,
		GroupReadable: groupRead, GroupWritable: groupWrite, OtherReadable: otherRead, OtherWritable: otherWrite,
		BroadRead: groupRead || otherRead, BroadWrite: groupWrite || otherWrite, Insecure: len(basis) > 0, InsecureBasis: basis,
		Source: "lstat metadata; no SSH key contents read", Confidence: evidence.ConfidenceExact,
	}, true
}

func unavailableSSHRecord(a Account, path, kind string, err error) SSHKeyPathRecord {
	reason := "SSH path metadata unavailable"
	if err != nil {
		reason = err.Error()
	}
	state := evidence.StateUnavailable
	if errors.Is(err, os.ErrPermission) {
		state = evidence.StateDenied
	}
	return SSHKeyPathRecord{ID: stableSSHKeyID(a.ID, a.Principal, path, kind), AccountID: a.ID, Principal: a.Principal, Privileged: a.Privileged, Path: path, Kind: kind, State: state, OwnerMatch: "UNKNOWN", Source: "lstat metadata; no SSH key contents read", Confidence: evidence.ConfidenceLow, Reason: reason}
}

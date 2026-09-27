package accounts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxSSHKeyRecords  = 4096
	maxSSHKeyAccounts = 512
)

// SSHKeyPathRecord is a metadata-only view of a local SSH trust/key path.
// Chimera never reads or emits private-key bytes. also avoids
// retaining authorized_keys contents; only path, ownership and access-boundary
// metadata is normalized.
type SSHKeyPathRecord struct {
	ID            string              `json:"id"`
	AccountID     string              `json:"account_id"`
	Principal     string              `json:"principal"`
	Privileged    bool                `json:"privileged_account"`
	Path          string              `json:"path"`
	Kind          string              `json:"kind"`
	State         evidence.State      `json:"state"`
	Directory     bool                `json:"directory"`
	Symlink       bool                `json:"symlink"`
	Mode          string              `json:"mode,omitempty"`
	Owner         string              `json:"owner,omitempty"`
	OwnerID       string              `json:"owner_id,omitempty"`
	GroupID       string              `json:"group_id,omitempty"`
	OwnerMatch    string              `json:"owner_match"`
	GroupReadable bool                `json:"group_readable"`
	GroupWritable bool                `json:"group_writable"`
	OtherReadable bool                `json:"other_readable"`
	OtherWritable bool                `json:"other_writable"`
	BroadRead     bool                `json:"broad_read"`
	BroadWrite    bool                `json:"broad_write"`
	Insecure      bool                `json:"insecure"`
	InsecureBasis []string            `json:"insecure_basis,omitempty"`
	Source        string              `json:"source"`
	Confidence    evidence.Confidence `json:"confidence"`
	Reason        string              `json:"reason,omitempty"`
}

type SSHKeyPostureSummary struct {
	AccountsExamined                 int `json:"accounts_examined"`
	AccountsWithSSHDirectory         int `json:"accounts_with_ssh_directory"`
	SSHDirectories                   int `json:"ssh_directories"`
	AuthorizedKeysFiles              int `json:"authorized_keys_files"`
	PrivateKeyCandidates             int `json:"private_key_candidates"`
	PrivilegedAuthorizedKeysFiles    int `json:"privileged_authorized_keys_files"`
	InsecureSSHDirectories           int `json:"insecure_ssh_directories"`
	InsecureAuthorizedKeysFiles      int `json:"insecure_authorized_keys_files"`
	InsecurePrivateKeyCandidates     int `json:"insecure_private_key_candidates"`
	InsecurePrivilegedAuthorizedKeys int `json:"insecure_privileged_authorized_keys"`
	UnavailableRecords               int `json:"unavailable_records"`
}

// SSHKeyPosture is the cross-platform local SSH key and
// authorized_keys permission surface.
type SSHKeyPosture struct {
	State   evidence.State       `json:"state"`
	Source  string               `json:"source"`
	Reason  string               `json:"reason,omitempty"`
	Records []SSHKeyPathRecord   `json:"records,omitempty"`
	Summary SSHKeyPostureSummary `json:"summary"`
}

func stableSSHKeyID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "ssh-path-" + hex.EncodeToString(sum[:10])
}

func normalizeSSHKeyPosture(platform string, p SSHKeyPosture) SSHKeyPosture {
	p.Source = strings.TrimSpace(p.Source)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Source == "" {
		p.Source = "local SSH key/authorized_keys metadata provider"
	}
	if p.State == "" {
		switch strings.ToLower(strings.TrimSpace(platform)) {
		case "linux", "darwin", "windows":
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "SSH key/authorized_keys metadata provider returned no state")
		default:
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "SSH key/authorized_keys assessment is not supported on this platform")
		}
	}

	seen := map[string]struct{}{}
	out := make([]SSHKeyPathRecord, 0, len(p.Records))
	for _, r := range p.Records {
		r.AccountID = strings.TrimSpace(r.AccountID)
		r.Principal = strings.TrimSpace(r.Principal)
		r.Path = strings.TrimSpace(r.Path)
		r.Kind = strings.ToUpper(strings.TrimSpace(r.Kind))
		r.Mode = strings.TrimSpace(r.Mode)
		r.Owner = strings.TrimSpace(r.Owner)
		r.OwnerID = strings.TrimSpace(r.OwnerID)
		r.GroupID = strings.TrimSpace(r.GroupID)
		r.OwnerMatch = strings.ToUpper(strings.TrimSpace(r.OwnerMatch))
		r.Source = strings.TrimSpace(r.Source)
		r.Reason = strings.TrimSpace(r.Reason)
		r.InsecureBasis = uniqueSorted(r.InsecureBasis)
		if r.OwnerMatch == "" {
			r.OwnerMatch = "UNKNOWN"
		}
		if r.State == "" {
			r.State = evidence.StateUnavailable
		}
		if r.Source == "" {
			r.Source = fallback(r.Path, "local SSH metadata provider")
		}
		if r.Confidence == "" {
			r.Confidence = evidence.ConfidenceHigh
		}
		if r.ID == "" && r.Principal != "" && r.Path != "" && r.Kind != "" {
			r.ID = stableSSHKeyID(r.AccountID, r.Principal, strings.ToLower(r.Path), r.Kind)
		}
		if r.State != evidence.StateObserved && r.Reason == "" {
			r.Reason = "SSH path metadata was not observable"
		}
		if r.ID == "" || r.Principal == "" || r.Path == "" || r.Kind == "" {
			continue
		}
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if strings.ToLower(out[i].Principal) != strings.ToLower(out[j].Principal) {
			return strings.ToLower(out[i].Principal) < strings.ToLower(out[j].Principal)
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxSSHKeyRecords {
		out = out[:maxSSHKeyRecords]
		if p.State == evidence.StateObserved {
			p.State = evidence.StateDegraded
		}
		p.Reason = fallback(p.Reason, fmt.Sprintf("SSH key metadata record limit reached (%d)", maxSSHKeyRecords))
	}
	p.Records = out
	p.Summary = summarizeSSHKeyPosture(p)
	return p
}

func summarizeSSHKeyPosture(p SSHKeyPosture) SSHKeyPostureSummary {
	s := SSHKeyPostureSummary{}
	accounts := map[string]struct{}{}
	withSSH := map[string]struct{}{}
	for _, r := range p.Records {
		if r.AccountID != "" {
			accounts[r.AccountID] = struct{}{}
		} else {
			accounts[strings.ToLower(r.Principal)] = struct{}{}
		}
		if r.State != evidence.StateObserved {
			s.UnavailableRecords++
			continue
		}
		switch r.Kind {
		case "SSH_DIRECTORY":
			s.SSHDirectories++
			if r.AccountID != "" {
				withSSH[r.AccountID] = struct{}{}
			} else {
				withSSH[strings.ToLower(r.Principal)] = struct{}{}
			}
			if r.Insecure {
				s.InsecureSSHDirectories++
			}
		case "AUTHORIZED_KEYS":
			s.AuthorizedKeysFiles++
			if r.Privileged {
				s.PrivilegedAuthorizedKeysFiles++
				if r.Insecure {
					s.InsecurePrivilegedAuthorizedKeys++
				}
			}
			if r.Insecure {
				s.InsecureAuthorizedKeysFiles++
			}
		case "PRIVATE_KEY_CANDIDATE":
			s.PrivateKeyCandidates++
			if r.Insecure {
				s.InsecurePrivateKeyCandidates++
			}
		}
	}
	s.AccountsExamined = len(accounts)
	s.AccountsWithSSHDirectory = len(withSSH)
	return s
}

func validateSSHKeyPosture(platform string, p SSHKeyPosture) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("SSH key posture state/source is incomplete")
	}
	supported := platform == "linux" || platform == "darwin" || platform == "windows"
	if !supported && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("unsupported-platform SSH key posture must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && p.State != evidence.StateDegraded && p.State != evidence.StateNotApplicable && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed SSH key posture requires a reason")
	}
	if len(p.Records) > maxSSHKeyRecords {
		return fmt.Errorf("SSH key posture exceeds record limit")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, r := range p.Records {
		if r.ID == "" || r.Principal == "" || r.Path == "" || r.Kind == "" || r.State == "" || r.Source == "" || r.Confidence == "" || r.OwnerMatch == "" {
			return fmt.Errorf("SSH key posture record %d is incomplete", i)
		}
		if r.State != evidence.StateObserved && r.Reason == "" {
			return fmt.Errorf("SSH key posture record %q non-observed without reason", r.ID)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate SSH key posture record %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		k := strings.ToLower(r.Principal) + "\x00" + r.Path + "\x00" + r.ID
		if last != "" && k < last {
			return fmt.Errorf("SSH key posture records are not deterministically ordered")
		}
		last = k
	}
	if p.Summary != summarizeSSHKeyPosture(p) {
		return fmt.Errorf("SSH key posture summary does not match records")
	}
	return nil
}

func isSSHPrivateKeyCandidateName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "identity":
		return true
	default:
		return false
	}
}

func isAuthorizedKeysName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorized_keys", "authorized_keys2":
		return true
	default:
		return false
	}
}

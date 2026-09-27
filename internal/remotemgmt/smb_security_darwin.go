//go:build darwin

package remotemgmt

import (
	"bufio"
	"context"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformSMBSecurity(ctx context.Context) smbPlatformResult {
	result := smbPlatformResult{ShareInventoryState: evidence.StateUnavailable, ShareInventorySource: "sharing -l"}
	sharing, err := exec.LookPath("sharing")
	if err != nil {
		result.Settings = unavailableSMBSettingsDarwin("macOS sharing provider unavailable")
		result.ShareInventoryReason = "sharing command unavailable"
		return result
	}
	b, err := exec.CommandContext(ctx, sharing, "-l").CombinedOutput()
	if err != nil {
		result.Settings = unavailableSMBSettingsDarwin("macOS sharing provider unavailable")
		result.ShareInventoryReason = "sharing -l unavailable: " + err.Error()
		result.Degraded = append(result.Degraded, result.ShareInventoryReason)
		return result
	}
	shares, detected := parseDarwinSharing(string(b))
	result.Detected = detected
	result.EvaluationSource = "sharing -l"
	result.Shares = shares
	result.ShareInventoryState = evidence.StateObserved
	result.ShareInventorySource = "sharing -l"
	result.Settings = unavailableSMBSettingsDarwin("effective macOS SMB dialect/signing/encryption server policy is not exposed by this read-only provider")
	if detected {
		result.Degraded = append(result.Degraded, "effective macOS SMB dialect/signing/encryption policy is unavailable from the local sharing provider")
	}
	return result
}

func unavailableSMBSettingsDarwin(reason string) []SMBSetting {
	names := []string{"min_protocol", "max_protocol", "signing", "encryption", "guest_policy"}
	out := make([]SMBSetting, 0, len(names))
	for _, name := range names {
		out = append(out, SMBSetting{Name: name, Scope: "server", State: evidence.StateUnavailable, Source: "macOS local SMB provider", Confidence: evidence.ConfidenceLow, Reason: reason})
	}
	return out
}

func parseDarwinSharing(text string) ([]SMBShare, bool) {
	type current struct {
		name, path              string
		smbBlock                bool
		shared, guest, readOnly *bool
	}
	out := []SMBShare{}
	cur := current{}
	flush := func() {
		if cur.name == "" && cur.path == "" {
			return
		}
		if cur.shared != nil && !*cur.shared {
			cur = current{}
			return
		}
		if !cur.smbBlock && cur.shared == nil {
			cur = current{}
			return
		}
		name := strings.TrimSpace(cur.name)
		if name == "" {
			name = strings.TrimSpace(cur.path)
		}
		writable, known := false, false
		if cur.readOnly != nil {
			writable = !*cur.readOnly
			known = true
		}
		guest := cur.guest != nil && *cur.guest
		tags := []string{}
		if guest {
			tags = append(tags, "guest-access")
		}
		if guest && known && writable {
			tags = append(tags, "guest-writable")
		}
		sensitive := smbSensitivePath(cur.path)
		if sensitive {
			tags = append(tags, "sensitive-path")
		}
		sh := SMBShare{Name: name, Path: strings.TrimSpace(cur.path), State: evidence.StateObserved, GuestAllowed: guest, Writable: writable, WritableKnown: known, BroadRead: guest, BroadWrite: guest && known && writable, SensitivePath: sensitive, RiskTags: tags, Source: "sharing -l", Confidence: evidence.ConfidenceHigh}
		sh.ID = smbShareID(sh.Name, sh.Path)
		out = append(out, sh)
		cur = current{}
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "name:") && !strings.Contains(lower, "smb:") {
			if cur.name != "" || cur.path != "" {
				flush()
			}
			cur.name = strings.TrimSpace(line[len("name:"):])
			continue
		}
		if strings.HasPrefix(lower, "path:") {
			cur.path = strings.TrimSpace(line[len("path:"):])
			continue
		}
		if strings.HasPrefix(lower, "smb:") || strings.Contains(lower, "smb: {") {
			cur.smbBlock = true
			continue
		}
		if strings.HasPrefix(lower, "shared:") {
			v := parseDarwinBool(strings.TrimSpace(line[len("shared:"):]))
			cur.shared = &v
			cur.smbBlock = true
			continue
		}
		if strings.HasPrefix(lower, "guest access:") {
			v := parseDarwinBool(strings.TrimSpace(line[len("guest access:"):]))
			cur.guest = &v
			cur.smbBlock = true
			continue
		}
		if strings.HasPrefix(lower, "read-only:") {
			v := parseDarwinBool(strings.TrimSpace(line[len("read-only:"):]))
			cur.readOnly = &v
			cur.smbBlock = true
			continue
		}
	}
	flush()
	return out, len(out) > 0 || strings.Contains(strings.ToLower(text), "smb:")
}

func parseDarwinBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.Trim(v, ",}"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

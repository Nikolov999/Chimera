//go:build linux

package storage

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context) ([]Volume, []SourceStatus, []string) {
	const mountInfo = "/proc/self/mountinfo"
	f, err := os.Open(mountInfo)
	if err != nil {
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		reason := "Linux mounted-volume inventory unavailable: " + err.Error()
		return nil, []SourceStatus{{ID: "linux-mounts", State: state, Source: mountInfo, Reason: reason}}, []string{reason}
	}
	defer f.Close()

	volumes := []Volume{}
	degraded := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		v, ok := parseLinuxMount(scanner.Text())
		if !ok || !linuxSecurityRelevantVolume(v) {
			continue
		}
		enrichLinuxEncryption(&v)
		if v.EncryptionState == EncryptionUnknown && (v.SystemVolume || v.Fixed) {
			degraded = append(degraded, "Linux encryption posture unresolved for "+fallback(v.MountPoint, v.Device)+": "+fallback(v.Reason, "block encryption metadata unavailable"))
		}
		volumes = append(volumes, v)
		if len(volumes) >= maxVolumes {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		degraded = append(degraded, "Linux mountinfo read degraded: "+err.Error())
	}
	if ctx != nil && ctx.Err() != nil {
		degraded = append(degraded, "Linux storage collection interrupted: "+ctx.Err().Error())
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(degraded, "; ")
	}
	return volumes, []SourceStatus{{ID: "linux-mounts", State: state, Source: mountInfo + " + /sys/dev/block device-mapper metadata", ItemCount: len(volumes), Reason: reason}}, degraded
}

func parseLinuxMount(line string) (Volume, bool) {
	halves := strings.SplitN(line, " - ", 2)
	if len(halves) != 2 {
		return Volume{}, false
	}
	left, right := strings.Fields(halves[0]), strings.Fields(halves[1])
	if len(left) < 6 || len(right) < 2 {
		return Volume{}, false
	}
	mountPoint := unescapeMount(left[4])
	fs := right[0]
	source := unescapeMount(right[1])
	v := Volume{
		MountPoint: mountPoint, Device: source, Filesystem: fs, SystemVolume: mountPoint == "/",
		Fixed: strings.HasPrefix(source, "/dev/"), EncryptionState: EncryptionUnknown,
		ProtectionState: ProtectionUnknown, LockState: LockUnknown, State: evidence.StateObserved,
		CollectionSource: "/proc/self/mountinfo + /sys/dev/block", Confidence: evidence.ConfidenceHigh,
	}
	if len(left) > 2 {
		v.MajorMinor = left[2]
	}
	return v, true
}

func linuxSecurityRelevantVolume(v Volume) bool {
	fs := strings.ToLower(strings.TrimSpace(v.Filesystem))
	src := strings.ToLower(strings.TrimSpace(v.Device))
	if strings.HasPrefix(src, "/dev/") {
		return true
	}
	if v.SystemVolume {
		return true
	}
	switch fs {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "vfat", "exfat", "ntfs", "ntfs3":
		return true
	}
	return false
}

func enrichLinuxEncryption(v *Volume) {
	if v == nil {
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(v.Device), "/dev/") {
		v.EncryptionState = EncryptionUnknown
		v.ProtectionState = ProtectionUnknown
		v.LockState = LockUnknown
		v.Reason = "mounted filesystem is not backed by a directly visible /dev block device; underlying host/storage encryption cannot be inferred"
		v.Confidence = evidence.ConfidenceMedium
		return
	}
	majorMinor := strings.TrimSpace(v.MajorMinor)
	if majorMinor == "" || majorMinor == "0:0" {
		v.Reason = "block-device identity unavailable for encryption correlation"
		v.Confidence = evidence.ConfidenceMedium
		return
	}
	enc, product, method, observed := linuxEncryptionStack(majorMinor, map[string]bool{})
	if !observed {
		v.Reason = "Linux block-device encryption stack could not be resolved"
		v.Confidence = evidence.ConfidenceMedium
		return
	}
	v.LockState = LockUnlocked
	if enc {
		v.EncryptionState = EncryptionEncrypted
		v.ProtectionState = ProtectionEnabled
		v.EncryptionProduct = product
		v.EncryptionMethod = method
		v.EncryptionPercentage = percent(100)
		v.Confidence = evidence.ConfidenceExact
	} else {
		v.EncryptionState = EncryptionUnencrypted
		v.ProtectionState = ProtectionDisabled
		v.EncryptionProduct = "dm-crypt/LUKS"
		v.Confidence = evidence.ConfidenceHigh
	}
	if removable, known := linuxRemovable(majorMinor); known {
		v.Removable = removable
		v.Fixed = !removable
	}
}

func linuxEncryptionStack(majorMinor string, seen map[string]bool) (bool, string, string, bool) {
	majorMinor = strings.TrimSpace(majorMinor)
	if majorMinor == "" || seen[majorMinor] {
		return false, "", "", false
	}
	seen[majorMinor] = true
	base := filepath.Join("/sys/dev/block", majorMinor)
	if raw, err := os.ReadFile(filepath.Join(base, "dm", "uuid")); err == nil {
		uuid := strings.TrimSpace(string(raw))
		upper := strings.ToUpper(uuid)
		if strings.HasPrefix(upper, "CRYPT-") {
			product := "dm-crypt"
			method := "device-mapper CRYPT mapping"
			switch {
			case strings.HasPrefix(upper, "CRYPT-LUKS1-"):
				product, method = "LUKS1/dm-crypt", "LUKS1"
			case strings.HasPrefix(upper, "CRYPT-LUKS2-"):
				product, method = "LUKS2/dm-crypt", "LUKS2"
			case strings.HasPrefix(upper, "CRYPT-PLAIN-"):
				product, method = "dm-crypt plain", "plain dm-crypt"
			}
			return true, product, method, true
		}
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return false, "", "", false
	}
	slaves, err := os.ReadDir(filepath.Join(resolved, "slaves"))
	if err == nil && len(slaves) > 0 {
		observed := false
		for _, slave := range slaves {
			raw, err := os.ReadFile(filepath.Join(resolved, "slaves", slave.Name(), "dev"))
			if err != nil {
				continue
			}
			enc, product, method, childObserved := linuxEncryptionStack(strings.TrimSpace(string(raw)), seen)
			observed = observed || childObserved
			if enc {
				return true, product, method, true
			}
		}
		if observed {
			return false, "", "", true
		}
	}
	return false, "", "", true
}

func linuxRemovable(majorMinor string) (bool, bool) {
	resolved, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", strings.TrimSpace(majorMinor)))
	if err != nil {
		return false, false
	}
	for cur := resolved; strings.HasPrefix(cur, "/sys/"); cur = filepath.Dir(cur) {
		raw, err := os.ReadFile(filepath.Join(cur, "removable"))
		if err == nil {
			switch strings.TrimSpace(string(raw)) {
			case "1":
				return true, true
			case "0":
				return false, true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
	}
	return false, false
}

func unescapeMount(v string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(v)
}

func percent(v float64) *float64 { return &v }

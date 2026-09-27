//go:build linux

package filesystem

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformMounts(ctx context.Context) ([]MountBoundary, SourceStatus, []string) {
	const path = "/proc/self/mountinfo"
	f, err := os.Open(path)
	if err != nil {
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		return nil, SourceStatus{ID: "mount-boundaries", State: state, Source: path, Reason: err.Error()}, []string{"mount/volume inventory unavailable: " + err.Error()}
	}
	defer f.Close()
	out := []MountBoundary{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		if m, ok := parseLinuxMountInfoLine(scanner.Text()); ok {
			enrichLinuxMount(&m)
			out = append(out, m)
		}
		if len(out) >= maxMounts {
			break
		}
	}
	degraded := []string{}
	if err := scanner.Err(); err != nil {
		degraded = append(degraded, "mountinfo read degraded: "+err.Error())
	}
	if ctx != nil && ctx.Err() != nil {
		degraded = append(degraded, "mount/volume inventory interrupted: "+ctx.Err().Error())
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(degraded, "; ")
	}
	return out, SourceStatus{ID: "mount-boundaries", State: state, Source: path + " + /sys/dev/block metadata", ItemCount: len(out), Reason: reason}, degraded
}

func parseLinuxMountInfoLine(line string) (MountBoundary, bool) {
	halves := strings.SplitN(line, " - ", 2)
	if len(halves) != 2 {
		return MountBoundary{}, false
	}
	left := strings.Fields(halves[0])
	right := strings.Fields(halves[1])
	if len(left) < 6 || len(right) < 2 {
		return MountBoundary{}, false
	}
	mount := unescapeMountField(left[4])
	opts := strings.Split(left[5], ",")
	fs := right[0]
	device := unescapeMountField(right[1])
	if len(right) >= 3 {
		opts = append(opts, strings.Split(right[2], ",")...)
	}
	access := MountAccessUnknown
	if containsStringFold(opts, "ro") {
		access = MountAccessReadOnly
	} else if containsStringFold(opts, "rw") {
		access = MountAccessReadWrite
	}
	class := classifyMount(fs, device, false, false)
	enc := MountEncryptionUnknown
	if class == MountClassVirtual || class == MountClassOptical {
		enc = MountEncryptionNotApplicable
	}
	return MountBoundary{
		Path: mount, Device: device, BackingSource: device, Filesystem: fs, Options: opts,
		AccessMode: access, ReadOnly: access == MountAccessReadOnly, Writable: access == MountAccessReadWrite,
		Classification: class, Network: class == MountClassNetwork, MajorMinor: left[2],
		EncryptionState: enc, State: evidence.StateObserved, CollectionSource: "/proc/self/mountinfo",
		Confidence: evidence.ConfidenceExact,
	}, true
}

func enrichLinuxMount(m *MountBoundary) {
	if m == nil {
		return
	}
	if m.Classification == MountClassNetwork || m.Classification == MountClassVirtual || m.Classification == MountClassOptical {
		return
	}
	if removable, known := linuxBlockRemovable(m.MajorMinor); known {
		m.Removable = removable
		if removable {
			m.Classification = MountClassRemovable
		} else if m.Classification == MountClassUnknown {
			m.Classification = MountClassLocal
		}
	}
	if encrypted, typ, detail, observed := linuxBlockEncryption(m.MajorMinor, map[string]bool{}); observed {
		if encrypted {
			m.EncryptionState = MountEncryptionEncrypted
			m.EncryptionType = typ
			m.EncryptionEvidence = detail
		} else if m.EncryptionState != MountEncryptionNotApplicable {
			m.EncryptionState = MountEncryptionNotObserved
			m.EncryptionEvidence = detail
		}
	}
}

func linuxBlockRemovable(majorMinor string) (bool, bool) {
	majorMinor = strings.TrimSpace(majorMinor)
	if majorMinor == "" || majorMinor == "0:0" {
		return false, false
	}
	base := filepath.Join("/sys/dev/block", majorMinor)
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return false, false
	}
	for cur := resolved; strings.HasPrefix(cur, "/sys/"); cur = filepath.Dir(cur) {
		raw, err := os.ReadFile(filepath.Join(cur, "removable"))
		if err == nil {
			v := strings.TrimSpace(string(raw))
			if v == "1" {
				return true, true
			}
			if v == "0" {
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

func linuxBlockEncryption(majorMinor string, seen map[string]bool) (bool, string, string, bool) {
	majorMinor = strings.TrimSpace(majorMinor)
	if majorMinor == "" || seen[majorMinor] {
		return false, "", "", false
	}
	seen[majorMinor] = true
	base := filepath.Join("/sys/dev/block", majorMinor)
	if raw, err := os.ReadFile(filepath.Join(base, "dm", "uuid")); err == nil {
		uuid := strings.TrimSpace(string(raw))
		if strings.HasPrefix(strings.ToUpper(uuid), "CRYPT-") {
			return true, "dm-crypt", "Linux device-mapper CRYPT layer observed in /sys/dev/block", true
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
			devRaw, err := os.ReadFile(filepath.Join(resolved, "slaves", slave.Name(), "dev"))
			if err != nil {
				continue
			}
			enc, typ, detail, childObserved := linuxBlockEncryption(strings.TrimSpace(string(devRaw)), seen)
			observed = observed || childObserved
			if enc {
				return true, typ, detail, true
			}
		}
		if observed {
			return false, "", "no dm-crypt layer observed in traversed Linux block-device stack", true
		}
	}
	return false, "", "no dm-crypt layer observed for directly observable Linux block device", true
}

func unescapeMountField(v string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(v)
}

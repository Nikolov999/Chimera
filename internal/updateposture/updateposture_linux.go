//go:build linux

package updateposture

import (
	"context"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

var aptInstRE = regexp.MustCompile(`^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)(?:\s+([^\)]*))?\)`)

func collectPlatform(ctx context.Context, r *Result) {
	attempted := 0
	if commandAvailable("apt-get") {
		attempted++
		collectAPT(ctx, r)
	}
	if commandAvailable("dnf") {
		attempted++
		collectDNF(ctx, r, "dnf")
	} else if commandAvailable("yum") {
		attempted++
		collectDNF(ctx, r, "yum")
	}
	if commandAvailable("zypper") {
		attempted++
		collectZypper(ctx, r)
	}
	if commandAvailable("apk") {
		attempted++
		collectAPK(ctx, r)
	}
	if commandAvailable("pacman") {
		attempted++
		collectPacman(ctx, r)
	}
	if attempted == 0 {
		addProvider(r, "linux-updates", evidence.StateUnavailable, "native Linux package metadata", 0, 0, time.Time{}, FreshnessUnknown, "none of apt-get, dnf/yum, zypper, apk, or pacman was available")
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		r.RebootRequired = true
	}
}

func collectAPT(ctx context.Context, r *Result) {
	meta := newestMTime("/var/lib/apt/lists")
	text, err := run(ctx, "apt-get", "-s", "--no-download", "-o", "Debug::NoLocking=1", "upgrade")
	if err != nil {
		addProvider(r, "apt", stateForError(ctx, err), "APT local package lists", 0, 0, meta, freshness(meta, r.CollectedAt), err.Error())
		return
	}
	start := len(r.Updates)
	sec := 0
	for _, line := range strings.Split(text, "\n") {
		m := aptInstRE.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) == 0 {
			continue
		}
		pkg, installed, candidate, origin := m[1], m[2], m[3], m[4]
		class := ClassificationOther
		reason := "APT local package lists report a newer candidate version"
		if strings.Contains(strings.ToLower(origin), "security") {
			class = ClassificationSecurity
			sec++
			reason = "APT local package lists identify the candidate through a security pocket/repository"
		}
		r.Updates = append(r.Updates, Update{Product: pkg, PackageID: pkg, InstalledVersion: installed, CandidateVersion: candidate, Architecture: runtime.GOARCH, Classification: class, Source: "apt-get simulation using local package lists", Confidence: evidence.ConfidenceHigh, Reason: reason})
	}
	addProvider(r, "apt", evidence.StateObserved, "APT local package lists", len(r.Updates)-start, sec, meta, freshness(meta, r.CollectedAt), "")
}

func collectDNF(ctx context.Context, r *Result, name string) {
	meta := newestMTime("/var/cache/dnf", "/var/cache/yum")
	text, err := run(ctx, name, "--cacheonly", "-q", "check-update")
	// dnf/yum returns 100 when updates are available; preserve/parse output.
	if err != nil && strings.TrimSpace(text) == "" {
		addProvider(r, name, stateForError(ctx, err), strings.ToUpper(name)+" cached repository metadata", 0, 0, meta, freshness(meta, r.CollectedAt), err.Error())
		return
	}
	start := len(r.Updates)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(f[0]), "last") || strings.HasPrefix(f[0], "Obsoleting") {
			continue
		}
		pkgarch := f[0]
		ver := f[1]
		pkg := pkgarch
		arch := ""
		if i := strings.LastIndex(pkgarch, "."); i > 0 {
			pkg = pkgarch[:i]
			arch = pkgarch[i+1:]
		}
		if pkg == "" || ver == "" {
			continue
		}
		r.Updates = append(r.Updates, Update{Product: pkg, PackageID: pkg, InstalledVersion: "UNKNOWN", CandidateVersion: ver, Architecture: arch, Classification: ClassificationUnknown, Source: name + " --cacheonly check-update", Confidence: evidence.ConfidenceHigh, Reason: "cached RPM repository metadata reports a newer package version; security classification requires cached advisory metadata"})
	}
	secText, _ := run(ctx, name, "--cacheonly", "-q", "updateinfo", "list", "--security", "updates")
	sec := countSecurityAdvisories(secText)
	reason := ""
	if sec > 0 {
		reason = "cached security advisory metadata reports security updates; package-level classification remains conservative unless advisory-to-package linkage is exact"
		r.Limitations = append(r.Limitations, reason)
	}
	addProvider(r, name, evidence.StateObserved, strings.ToUpper(name)+" cached repository/advisory metadata", len(r.Updates)-start, sec, meta, freshness(meta, r.CollectedAt), reason)
}

func countSecurityAdvisories(text string) int {
	seen := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 {
			continue
		}
		id := f[0]
		l := strings.ToLower(line)
		if strings.Contains(l, "security") || strings.Contains(strings.ToUpper(id), "RHSA-") || strings.Contains(strings.ToUpper(id), "USN-") {
			seen[id] = struct{}{}
		}
	}
	return len(seen)
}

func collectZypper(ctx context.Context, r *Result) {
	meta := newestMTime("/var/cache/zypp")
	text, err := run(ctx, "zypper", "--no-refresh", "--non-interactive", "list-updates")
	if err != nil && strings.TrimSpace(text) == "" {
		addProvider(r, "zypper", stateForError(ctx, err), "zypper cached repository metadata", 0, 0, meta, freshness(meta, r.CollectedAt), err.Error())
		return
	}
	start := len(r.Updates)
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		p := splitPipes(line)
		if len(p) < 5 || strings.EqualFold(p[2], "Name") {
			continue
		}
		name := p[2]
		cur := p[3]
		next := p[4]
		if name == "" || next == "" {
			continue
		}
		r.Updates = append(r.Updates, Update{Product: name, PackageID: name, InstalledVersion: cur, CandidateVersion: next, Classification: ClassificationUnknown, Source: "zypper --no-refresh list-updates", Confidence: evidence.ConfidenceHigh, Reason: "cached zypper metadata reports a newer package version"})
	}
	secText, _ := run(ctx, "zypper", "--no-refresh", "--non-interactive", "list-patches", "--category", "security")
	sec := 0
	for _, line := range strings.Split(secText, "\n") {
		if strings.Contains(strings.ToLower(line), "security") && strings.Contains(line, "|") {
			sec++
		}
	}
	addProvider(r, "zypper", evidence.StateObserved, "zypper cached repository/patch metadata", len(r.Updates)-start, sec, meta, freshness(meta, r.CollectedAt), "")
}
func splitPipes(s string) []string {
	p := strings.Split(s, "|")
	for i := range p {
		p[i] = strings.TrimSpace(p[i])
	}
	return p
}

func collectAPK(ctx context.Context, r *Result) {
	meta := newestMTime("/var/cache/apk", "/var/lib/apk")
	text, err := run(ctx, "apk", "version", "-l", "<")
	if err != nil {
		addProvider(r, "apk", stateForError(ctx, err), "APK local installed/repository indexes", 0, 0, meta, freshness(meta, r.CollectedAt), err.Error())
		return
	}
	start := len(r.Updates)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "<" {
			continue
		}
		name, old := splitAPK(f[0])
		_, next := splitAPK(f[2])
		r.Updates = append(r.Updates, Update{Product: name, PackageID: name, InstalledVersion: old, CandidateVersion: next, Classification: ClassificationUnknown, Source: "apk version using local indexes", Confidence: evidence.ConfidenceHigh, Reason: "APK local indexes report a newer version; local metadata does not provide a reliable security classification"})
	}
	addProvider(r, "apk", evidence.StateObserved, "APK local installed/repository indexes", len(r.Updates)-start, 0, meta, freshness(meta, r.CollectedAt), "")
}
func splitAPK(v string) (string, string) {
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == '-' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
			return v[:i], v[i+1:]
		}
	}
	return v, "UNKNOWN"
}

func collectPacman(ctx context.Context, r *Result) {
	meta := newestMTime("/var/lib/pacman/sync")
	text, err := run(ctx, "pacman", "-Qu")
	if err != nil && strings.TrimSpace(text) == "" {
		addProvider(r, "pacman", evidence.StateObserved, "pacman local sync database", 0, 0, meta, freshness(meta, r.CollectedAt), "")
		return
	}
	start := len(r.Updates)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "->" {
			continue
		}
		r.Updates = append(r.Updates, Update{Product: f[0], PackageID: f[0], InstalledVersion: f[1], CandidateVersion: f[3], Classification: ClassificationUnknown, Source: "pacman -Qu using local sync database", Confidence: evidence.ConfidenceHigh, Reason: "pacman local sync metadata reports a newer version; package-level security classification is unavailable"})
	}
	addProvider(r, "pacman", evidence.StateObserved, "pacman local sync database", len(r.Updates)-start, 0, meta, freshness(meta, r.CollectedAt), "")
}

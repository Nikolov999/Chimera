//go:build linux

package software

import (
	"context"
	"runtime"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	attempted := 0
	if commandAvailable("dpkg-query") {
		attempted++
		collectDPKG(ctx, inv)
	}
	if commandAvailable("rpm") {
		attempted++
		collectRPM(ctx, inv)
	}
	if commandAvailable("apk") {
		attempted++
		collectAPK(ctx, inv)
	}
	if commandAvailable("pacman") {
		attempted++
		collectPacman(ctx, inv)
	}
	if commandAvailable("snap") {
		attempted++
		collectSnap(ctx, inv)
	}
	if commandAvailable("flatpak") {
		attempted++
		collectFlatpak(ctx, inv)
	}
	if attempted == 0 {
		addSource(inv, "linux-packages", evidence.StateUnavailable, "native Linux package managers", 0, "none of dpkg-query, rpm, apk, pacman, snap, or flatpak was available")
	}
}

func collectDPKG(ctx context.Context, inv *Inventory) {
	const format = `${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${Maintainer}\n`
	text, err := run(ctx, "dpkg-query", "-W", "-f="+format)
	if err != nil {
		addSource(inv, "dpkg", stateForError(ctx, err), "dpkg-query", 0, err.Error())
		return
	}
	start := len(inv.Items)
	for _, f := range tabLines(text, 5) {
		name := f[0]
		arch := f[2]
		if strings.HasSuffix(name, ":"+arch) {
			name = strings.TrimSuffix(name, ":"+arch)
		}
		sourcePkg := f[3]
		if sourcePkg == "" {
			sourcePkg = name
		}
		inv.Items = append(inv.Items, Item{
			Kind: "package", Product: name, PackageID: name, Version: f[1], Architecture: arch,
			Vendor: f[4], PackageSource: "dpkg:" + sourcePkg, InstallPath: "UNKNOWN",
			SupportState: "UNKNOWN", SupportReason: "package lifecycle intelligence is introduced in ",
			CollectionSource: "dpkg-query status database", Confidence: evidence.ConfidenceExact,
		})
	}
	addSource(inv, "dpkg", evidence.StateObserved, "dpkg-query", len(inv.Items)-start, "")
}

func collectRPM(ctx context.Context, inv *Inventory) {
	text, err := run(ctx, "rpm", "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLPREFIX}\n`)
	if err != nil {
		addSource(inv, "rpm", stateForError(ctx, err), "rpm database", 0, err.Error())
		return
	}
	start := len(inv.Items)
	for _, f := range tabLines(text, 5) {
		path := f[4]
		if path == "(none)" {
			path = "UNKNOWN"
		}
		inv.Items = append(inv.Items, Item{
			Kind: "package", Product: f[0], PackageID: f[0], Version: f[1], Architecture: f[2], Vendor: f[3],
			PackageSource: "rpm", InstallPath: path, SupportState: "UNKNOWN",
			SupportReason: "package lifecycle intelligence is introduced in ", CollectionSource: "rpm database", Confidence: evidence.ConfidenceExact,
		})
	}
	addSource(inv, "rpm", evidence.StateObserved, "rpm database", len(inv.Items)-start, "")
}

func collectAPK(ctx context.Context, inv *Inventory) {
	text, err := run(ctx, "apk", "list", "--installed")
	if err != nil {
		addSource(inv, "apk", stateForError(ctx, err), "apk installed database", 0, err.Error())
		return
	}
	start := len(inv.Items)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		nv, arch := fields[0], fields[1]
		name, version := splitAPKNameVersion(nv)
		if name == "" {
			continue
		}
		source := "apk"
		if i := strings.Index(line, "{"); i >= 0 {
			if j := strings.Index(line[i:], "}"); j > 1 {
				source = "apk:" + strings.TrimSpace(line[i+1:i+j])
			}
		}
		inv.Items = append(inv.Items, Item{Kind: "package", Product: name, PackageID: name, Version: version, Architecture: arch, Vendor: "UNKNOWN", PackageSource: source, InstallPath: "UNKNOWN", SupportState: "UNKNOWN", SupportReason: "package lifecycle intelligence is introduced in ", CollectionSource: "apk installed database", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "apk", evidence.StateObserved, "apk installed database", len(inv.Items)-start, "")
}

func splitAPKNameVersion(v string) (string, string) {
	// APK package versions begin after the final name separator preceding a
	// numeric version token. This avoids naive first-hyphen splitting.
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] != '-' || i+1 >= len(v) {
			continue
		}
		c := v[i+1]
		if c >= '0' && c <= '9' {
			return v[:i], v[i+1:]
		}
	}
	return v, "UNKNOWN"
}

func collectPacman(ctx context.Context, inv *Inventory) {
	text, err := run(ctx, "pacman", "-Q")
	if err != nil {
		addSource(inv, "pacman", stateForError(ctx, err), "pacman local database", 0, err.Error())
		return
	}
	start := len(inv.Items)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		inv.Items = append(inv.Items, Item{Kind: "package", Product: f[0], PackageID: f[0], Version: f[1], Architecture: runtime.GOARCH, Vendor: "UNKNOWN", PackageSource: "pacman", InstallPath: "UNKNOWN", SupportState: "UNKNOWN", SupportReason: "package lifecycle intelligence is introduced in ", CollectionSource: "pacman local database", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "pacman", evidence.StateObserved, "pacman local database", len(inv.Items)-start, "")
}

func collectSnap(ctx context.Context, inv *Inventory) {
	text, err := run(ctx, "snap", "list")
	if err != nil {
		addSource(inv, "snap", stateForError(ctx, err), "snapd local state", 0, err.Error())
		return
	}
	start := len(inv.Items)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if i == 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "name ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		vendor := "UNKNOWN"
		source := "snap"
		if len(f) >= 4 {
			source = "snap:" + f[3]
		}
		if len(f) >= 5 {
			vendor = strings.TrimSuffix(f[4], "**")
		}
		inv.Items = append(inv.Items, Item{Kind: "application", Product: f[0], PackageID: f[0], Version: f[1], Architecture: runtime.GOARCH, Vendor: vendor, PackageSource: source, InstallPath: "UNKNOWN", SupportState: "UNKNOWN", SupportReason: "application lifecycle intelligence is introduced in ", CollectionSource: "snapd local state", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "snap", evidence.StateObserved, "snapd local state", len(inv.Items)-start, "")
}

func collectFlatpak(ctx context.Context, inv *Inventory) {
	text, err := run(ctx, "flatpak", "list", "--app", "--columns=application,name,version,arch,origin,installation")
	if err != nil {
		addSource(inv, "flatpak", stateForError(ctx, err), "flatpak local installations", 0, err.Error())
		return
	}
	start := len(inv.Items)
	for _, f := range tabLines(text, 6) {
		product := f[1]
		if product == "" {
			product = f[0]
		}
		source := "flatpak:" + f[4]
		if f[5] != "" {
			source += "/" + f[5]
		}
		inv.Items = append(inv.Items, Item{Kind: "application", Product: product, PackageID: f[0], Version: f[2], Architecture: f[3], Vendor: "UNKNOWN", PackageSource: source, InstallPath: "UNKNOWN", SupportState: "UNKNOWN", SupportReason: "application lifecycle intelligence is introduced in ", CollectionSource: "flatpak local installations", Confidence: evidence.ConfidenceHigh})
	}
	addSource(inv, "flatpak", evidence.StateObserved, "flatpak local installations", len(inv.Items)-start, "")
}

func stateForError(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil {
		return evidence.StateDegraded
	}
	if err == nil {
		return evidence.StateObserved
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access denied") {
		return evidence.StateDenied
	}
	return evidence.StateDegraded
}

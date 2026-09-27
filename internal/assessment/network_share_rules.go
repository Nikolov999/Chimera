package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
)

type filesystemNetworkShareEvidence struct {
	Key    string
	Record fsinv.NetworkShareRecord
}

func evaluateMountedNetworkShareAnonymousAccess(idx Index) Evaluation {
	items := filesystemNetworkShareItems(idx, fsinv.NetworkShareDirectionMounted, "")
	bad := []filesystemNetworkShareEvidence{}
	for _, item := range items {
		if item.Record.GuestAllowed || item.Record.AnonymousAllowed {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(bad, "anonymous/guest")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d mounted network share(s) use guest or anonymous client access: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if e, decided := networkShareSourceFallback(idx, "filesystem.source.network-mounted-shares", "mounted network-share"); decided {
		if len(items) == 0 || e.Status == StatusUnknown {
			return e
		}
	}
	if len(items) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no mounted network shares are present", Applicability: NotApplicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.network-mounted-shares")}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d mounted network share(s) use no observed guest/anonymous client option", len(items)), Applicability: Applicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.network-mounted-shares")}
}

func evaluateNFSExportScope(idx Index) Evaluation {
	items := filesystemNetworkShareItems(idx, fsinv.NetworkShareDirectionExported, fsinv.NetworkShareProtocolNFS)
	broadWrite := []filesystemNetworkShareEvidence{}
	broad := []filesystemNetworkShareEvidence{}
	for _, item := range items {
		if !item.Record.BroadAccess {
			continue
		}
		if item.Record.BroadWrite {
			broadWrite = append(broadWrite, item)
		} else {
			broad = append(broad, item)
		}
	}
	if len(broadWrite) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(broadWrite, "broad-write")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d NFS export(s) grant write access to a wildcard/all-machines audience: %s", len(broadWrite), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(broad) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(broad, "broad-scope")
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d NFS export(s) use a broad wildcard/all-machines client scope without confirmed broad write: %s", len(broad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if e, decided := networkShareSourceFallback(idx, "filesystem.source.nfs-exports", "NFS export"); decided {
		if len(items) == 0 || e.Status == StatusUnknown {
			return e
		}
	}
	if len(items) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local NFS exports are configured by the observed provider", Applicability: NotApplicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.nfs-exports")}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed NFS export client scope(s) avoid wildcard/all-machines exposure", len(items)), Applicability: Applicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.nfs-exports")}
}

func evaluateNFSExportIdentityBoundary(idx Index) Evaluation {
	items := filesystemNetworkShareItems(idx, fsinv.NetworkShareDirectionExported, fsinv.NetworkShareProtocolNFS)
	severe := []filesystemNetworkShareEvidence{}
	review := []filesystemNetworkShareEvidence{}
	for _, item := range items {
		if networkShareHasAnyTag(item.Record, "no_root_squash", "anonymous-uid-0", "anonymous-gid-0", "sec=none", "maproot-to-root", "mapall-to-root", "anonymous-access", "unmapped-user-access", "broad-root-access") {
			severe = append(severe, item)
			continue
		}
		if networkShareHasAnyTag(item.Record, "auth-sys-without-kerberos", "insecure-client-port") {
			review = append(review, item)
		}
	}
	if len(severe) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(severe, "identity-boundary")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d NFS export(s) weaken root, anonymous, or authentication identity boundaries: %s", len(severe), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(review) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(review, "identity-review")
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d NFS export(s) retain weaker client authentication/port assumptions that require review: %s", len(review), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if e, decided := networkShareSourceFallback(idx, "filesystem.source.nfs-exports", "NFS export"); decided {
		if len(items) == 0 || e.Status == StatusUnknown {
			return e
		}
	}
	if len(items) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no local NFS exports are configured by the observed provider", Applicability: NotApplicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.nfs-exports")}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d observed NFS export(s) preserve the assessed root/anonymous identity boundary", len(items)), Applicability: Applicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.nfs-exports")}
}

func evaluateMountedNetworkShareClientHardening(idx Index) Evaluation {
	items := filesystemNetworkShareItems(idx, fsinv.NetworkShareDirectionMounted, "")
	bad := []filesystemNetworkShareEvidence{}
	for _, item := range items {
		if networkShareHasAnyTag(item.Record, "noperm", "legacy-smb1", "legacy-nfs2") {
			bad = append(bad, item)
		}
	}
	if len(bad) > 0 {
		desc, keys := filesystemNetworkShareDescriptions(bad, "client-hardening")
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d mounted network share(s) use a permission-bypass or legacy protocol client option: %s", len(bad), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if e, decided := networkShareSourceFallback(idx, "filesystem.source.network-mounted-shares", "mounted network-share"); decided {
		if len(items) == 0 || e.Status == StatusUnknown {
			return e
		}
	}
	if len(items) == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no mounted network shares are present", Applicability: NotApplicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.network-mounted-shares")}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d mounted network share(s) avoid the assessed permission-bypass and legacy client options", len(items)), Applicability: Applicable, EvidenceKeys: sourceKeyIfPresent(idx, "filesystem.source.network-mounted-shares")}
}

func filesystemNetworkShareItems(idx Index, direction, protocol string) []filesystemNetworkShareEvidence {
	out := []filesystemNetworkShareEvidence{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "filesystem.network_share.") {
			continue
		}
		rec, ok := obs.Value.(fsinv.NetworkShareRecord)
		if !ok {
			continue
		}
		if direction != "" && !strings.EqualFold(rec.Direction, direction) {
			continue
		}
		if protocol != "" && !strings.EqualFold(rec.Protocol, protocol) {
			continue
		}
		out = append(out, filesystemNetworkShareEvidence{Key: key, Record: rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Record.LocalPath != out[j].Record.LocalPath {
			return out[i].Record.LocalPath < out[j].Record.LocalPath
		}
		if out[i].Record.Remote != out[j].Record.Remote {
			return out[i].Record.Remote < out[j].Record.Remote
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func networkShareHasAnyTag(rec fsinv.NetworkShareRecord, tags ...string) bool {
	wanted := map[string]struct{}{}
	for _, tag := range tags {
		wanted[strings.ToLower(strings.TrimSpace(tag))] = struct{}{}
	}
	for _, tag := range rec.DangerousOptions {
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(tag))]; ok {
			return true
		}
	}
	return false
}

func filesystemNetworkShareDescriptions(items []filesystemNetworkShareEvidence, mode string) ([]string, []string) {
	const maxDescriptions = 12
	const maxKeys = 64
	desc := make([]string, 0, minInt(len(items), maxDescriptions)+1)
	keys := make([]string, 0, minInt(len(items), maxKeys))
	for i, item := range items {
		if i < maxDescriptions {
			r := item.Record
			label := r.LocalPath
			if r.Name != "" {
				label = r.Name + "(" + r.LocalPath + ")"
			}
			detail := label + " [" + r.Protocol + "/" + r.Direction
			if r.Remote != "" {
				detail += "; remote=" + r.Remote
			}
			if r.AccessMode != "" {
				detail += "; access=" + r.AccessMode
			}
			if len(r.DangerousOptions) > 0 && mode != "broad-scope" && mode != "broad-write" {
				detail += "; flags=" + strings.Join(r.DangerousOptions, ",")
			}
			detail += "]"
			desc = append(desc, detail)
		}
		if i < maxKeys {
			keys = append(keys, item.Key)
		}
	}
	if len(items) > maxDescriptions {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-maxDescriptions))
	}
	return desc, uniqueAssessmentStrings(keys)
}

func networkShareSourceFallback(idx Index, key, label string) (Evaluation, bool) {
	src, ok := idx[key]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: label + " source evidence is missing", Applicability: Undetermined}, true
	}
	switch src.State {
	case evidence.StateObserved:
		return Evaluation{}, false
	case evidence.StateNotApplicable, evidence.StateUnsupported:
		return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: label + " provider is not applicable on this host: " + observedText(src), Applicability: NotApplicable, EvidenceKeys: []string{key}}, true
	default:
		return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: label + " inventory is incomplete: " + observedText(src), Applicability: Applicable, EvidenceKeys: []string{key}}, true
	}
}

func sourceKeyIfPresent(idx Index, key string) []string {
	if _, ok := idx[key]; ok {
		return []string{key}
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

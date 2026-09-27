package assessment

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
)

// SMBSecurityRules implements over normalized local SMB/file-sharing
// configuration and share metadata. The rules do not connect to SMB endpoints,
// enumerate remote shares, authenticate, or transmit network traffic.
func SMBSecurityRules() []Rule {
	return []Rule{
		{
			ID: "CHM-NET-025", Title: "Legacy SMB1 protocol is disabled", Category: "network", Severity: SeverityCritical,
			AffectedObject: "network.smb.protocol", ExpectedState: "SMB1/NT1 and older dialects are disabled; SMB2 or newer is the minimum accepted file-sharing protocol",
			Risk:        "SMB1 is obsolete and lacks modern protections. Enabling NT1/SMB1 preserves a high-risk legacy attack surface and downgrade compatibility that is unnecessary on current systems.",
			Remediation: "Disable SMB1/NT1 on the server and require SMB2 or newer. Validate legacy clients before removal rather than retaining SMB1 for broad compatibility.",
			Evaluate:    evaluateSMBLegacyProtocol,
		},
		{
			ID: "CHM-NET-026", Title: "SMB signing is required", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.smb.signing", ExpectedState: "SMB server signing is required for file-sharing sessions",
			Risk:        "Optional or disabled SMB signing can weaken integrity and authentication binding, increasing exposure to on-path manipulation and relay-style abuse in networks where an attacker can influence traffic.",
			Remediation: "Require SMB signing on the server and verify client compatibility. Remove policy exceptions that leave signing optional or disabled unless a documented compatibility constraint exists.",
			Evaluate:    evaluateSMBSigning,
		},
		{
			ID: "CHM-NET-027", Title: "SMB encryption policy protects file-sharing traffic", Category: "network", Severity: SeverityMedium,
			AffectedObject: "network.smb.encryption", ExpectedState: "SMB encryption is required globally or on every non-special exported data share when confidentiality is expected",
			Risk:        "Unencrypted SMB sessions can expose file contents and metadata to network observers even when authentication and signing are otherwise strong.",
			Remediation: "Require SMB encryption globally or on sensitive exported shares. Keep SMB3 enabled and avoid configurations that permit sensitive data shares to fall back to unencrypted transport.",
			Evaluate:    evaluateSMBEncryption,
		},
		{
			ID: "CHM-NET-028", Title: "SMB guest and anonymous access is constrained", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.smb.guest_access", ExpectedState: "insecure guest authentication, null-session access, and guest shares are disabled unless explicitly justified and tightly read-only",
			Risk:        "Guest or anonymous SMB access weakens identity accountability and can expose files or writable storage without a normal authenticated user boundary.",
			Remediation: "Disable insecure guest authentication and null sessions. Remove guest access from shares or restrict an explicitly required guest share to low-sensitivity read-only content with narrow network exposure.",
			Evaluate:    evaluateSMBGuestAccess,
		},
		{
			ID: "CHM-NET-029", Title: "SMB exported shares avoid dangerous local exposure", Category: "network", Severity: SeverityHigh,
			AffectedObject: "network.smb.shares", ExpectedState: "exported shares do not grant broad write access, expose sensitive system paths, or combine guest access with write capability",
			Risk:        "Broadly writable or sensitive-path SMB shares can let remote users modify data, place files into trusted locations, or access host configuration beyond the intended file-sharing boundary.",
			Remediation: "Remove broad write grants, keep guest shares read-only, stop exporting operating-system or privileged configuration paths, and restrict share ACLs to the minimum required principals.",
			Evaluate:    evaluateSMBShares,
		},
	}
}

func smbApplicability(idx Index) (bool, bool, []string) {
	key := "smb_security.applicability"
	o, ok := idx[key]
	if !ok {
		return false, true, []string{key}
	}
	if o.State == evidence.StateNotApplicable {
		return false, false, []string{key}
	}
	if o.State != evidence.StateObserved {
		return false, true, []string{key}
	}
	return true, false, []string{key}
}

func smbNotApplicableOrUnknown(idx Index) *Evaluation {
	applicable, unavailable, keys := smbApplicability(idx)
	if !applicable && !unavailable {
		return &Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "local SMB/file-sharing server configuration or surface not detected", Applicability: NotApplicable, EvidenceKeys: keys}
	}
	if unavailable {
		return &Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SMB applicability evidence is unavailable", Applicability: Undetermined, EvidenceKeys: keys}
	}
	return nil
}

func smbSetting(idx Index, scope, name string) (remotemgmt.SMBSetting, evidence.Observation, bool) {
	key := "smb_security.setting." + strings.ToLower(scope) + "." + strings.ToLower(name)
	o, ok := idx[key]
	if !ok || o.State != evidence.StateObserved {
		return remotemgmt.SMBSetting{}, o, false
	}
	v, ok := o.Value.(remotemgmt.SMBSetting)
	return v, o, ok
}

func smbShareItems(idx Index) ([]struct {
	Key   string
	Share remotemgmt.SMBShare
}, evidence.Observation, bool) {
	inv, invOK := idx["smb_security.shares_inventory"]
	items := []struct {
		Key   string
		Share remotemgmt.SMBShare
	}{}
	for key, o := range idx {
		if !strings.HasPrefix(key, "smb_security.share.") || o.State != evidence.StateObserved {
			continue
		}
		sh, ok := o.Value.(remotemgmt.SMBShare)
		if ok {
			items = append(items, struct {
				Key   string
				Share remotemgmt.SMBShare
			}{key, sh})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, inv, invOK
}

func evaluateSMBLegacyProtocol(idx Index) Evaluation {
	if early := smbNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"smb_security.applicability"}
	if s, o, ok := smbSetting(idx, "server", "smb1_enabled"); ok {
		key := "smb_security.setting.server.smb1_enabled"
		keys = append(keys, key)
		v := strings.ToLower(strings.TrimSpace(s.Value))
		if v == "true" || v == "1" || v == "yes" || v == "enabled" {
			return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "SMB1 protocol is enabled", Applicability: Applicable, EvidenceKeys: keys}
		}
		if v == "false" || v == "0" || v == "no" || v == "disabled" {
			return Evaluation{Status: StatusPass, Confidence: s.Confidence, ObservedState: "SMB1 protocol is disabled", Applicability: Applicable, EvidenceKeys: keys}
		}
		return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "unrecognized SMB1 state: " + s.Value, Applicability: Applicable, EvidenceKeys: keys}
	}
	key := "smb_security.setting.server.min_protocol"
	keys = append(keys, key)
	s, o, ok := smbSetting(idx, "server", "min_protocol")
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: observationConfidence(o), ObservedState: "effective minimum SMB protocol is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	v := normalizeSMBDialect(s.Value)
	if v == "" {
		return Evaluation{Status: StatusUnknown, Confidence: s.Confidence, ObservedState: "unrecognized minimum SMB protocol: " + s.Value, Applicability: Applicable, EvidenceKeys: keys}
	}
	if smbDialectRank(v) <= smbDialectRank("NT1") {
		return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "minimum SMB protocol permits legacy dialect " + v, Applicability: Applicable, EvidenceKeys: keys}
	}
	return Evaluation{Status: StatusPass, Confidence: s.Confidence, ObservedState: "minimum SMB protocol is " + v, Applicability: Applicable, EvidenceKeys: keys}
}

func evaluateSMBSigning(idx Index) Evaluation {
	if early := smbNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"smb_security.applicability"}
	if s, _, ok := smbSetting(idx, "server", "signing_required"); ok {
		keys = append(keys, "smb_security.setting.server.signing_required")
		if smbTruthy(s.Value) {
			return Evaluation{Status: StatusPass, Confidence: s.Confidence, ObservedState: "SMB signing is required", Applicability: Applicable, EvidenceKeys: keys}
		}
		if e, _, ok := smbSetting(idx, "server", "signing_enabled"); ok {
			keys = append(keys, "smb_security.setting.server.signing_enabled")
			if smbTruthy(e.Value) {
				return Evaluation{Status: StatusWarn, Confidence: lowerConfidence(s.Confidence, e.Confidence), ObservedState: "SMB signing is enabled but not required", Applicability: Applicable, EvidenceKeys: keys}
			}
		}
		return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "SMB signing is not required", Applicability: Applicable, EvidenceKeys: keys}
	}
	key := "smb_security.setting.server.signing"
	keys = append(keys, key)
	s, o, ok := smbSetting(idx, "server", "signing")
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: observationConfidence(o), ObservedState: "effective SMB signing policy is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	switch strings.ToLower(strings.TrimSpace(s.Value)) {
	case "mandatory", "required", "require":
		return Evaluation{Status: StatusPass, Confidence: s.Confidence, ObservedState: "SMB signing policy is " + s.Value, Applicability: Applicable, EvidenceKeys: keys}
	case "disabled", "off", "no", "false":
		return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "SMB signing is disabled", Applicability: Applicable, EvidenceKeys: keys}
	case "auto", "automatic", "default", "if_required", "yes", "true":
		return Evaluation{Status: StatusWarn, Confidence: s.Confidence, ObservedState: "SMB signing is not proven mandatory: " + s.Value, Applicability: Applicable, EvidenceKeys: keys}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: s.Confidence, ObservedState: "unrecognized SMB signing policy: " + s.Value, Applicability: Applicable, EvidenceKeys: keys}
	}
}

func evaluateSMBEncryption(idx Index) Evaluation {
	if early := smbNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"smb_security.applicability"}
	globalRequired := false
	globalKnown := false
	if s, _, ok := smbSetting(idx, "server", "encryption_default"); ok {
		keys = append(keys, "smb_security.setting.server.encryption_default")
		globalKnown = true
		globalRequired = smbTruthy(s.Value)
	}
	if s, _, ok := smbSetting(idx, "server", "encryption"); ok {
		keys = append(keys, "smb_security.setting.server.encryption")
		globalKnown = true
		switch strings.ToLower(strings.TrimSpace(s.Value)) {
		case "required", "mandatory", "yes", "true":
			globalRequired = true
		case "off", "no", "disabled", "never":
			globalRequired = false
		}
	}
	if globalRequired {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "SMB encryption is required by the server-wide policy", Applicability: Applicable, EvidenceKeys: keys}
	}
	shares, inv, invOK := smbShareItems(idx)
	keys = append(keys, "smb_security.shares_inventory")
	for _, item := range shares {
		keys = append(keys, item.Key)
	}
	if !invOK || inv.State != evidence.StateObserved {
		if globalKnown {
			return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceMedium, ObservedState: "server-wide SMB encryption is not required and per-share encryption inventory is unavailable", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
		}
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SMB encryption policy and share-level encryption state are unavailable", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	normal, unencrypted := 0, 0
	for _, item := range shares {
		if item.Share.Special {
			continue
		}
		normal++
		if !item.Share.EncryptionRequired {
			unencrypted++
		}
	}
	if normal == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no non-special SMB data shares are exported", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	if unencrypted == 0 {
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("all %d non-special SMB data share(s) require encryption", normal), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d of %d non-special SMB data share(s) do not require encryption", unencrypted, normal), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
}

func evaluateSMBGuestAccess(idx Index) Evaluation {
	if early := smbNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	keys := []string{"smb_security.applicability"}
	unresolvedPolicy := 0
	for _, name := range []string{"allow_insecure_guest_auth", "restrict_null_session_access", "null_session_shares", "map_to_guest"} {
		key := "smb_security.setting.server." + name
		if raw, exists := idx[key]; exists {
			keys = append(keys, key)
			if raw.State != evidence.StateObserved && raw.State != evidence.StateNotApplicable {
				unresolvedPolicy++
			}
		}
		if s, _, ok := smbSetting(idx, "server", name); ok {
			switch name {
			case "allow_insecure_guest_auth":
				if smbTruthy(s.Value) {
					return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "insecure SMB guest authentication is enabled", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
				}
			case "restrict_null_session_access":
				if !smbTruthy(s.Value) {
					return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: "SMB null-session access is not restricted", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
				}
			case "null_session_shares":
				if n, err := strconv.Atoi(strings.TrimSpace(s.Value)); err == nil && n > 0 {
					return Evaluation{Status: StatusFail, Confidence: s.Confidence, ObservedState: fmt.Sprintf("%d SMB null-session share(s) are configured", n), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
				}
			case "map_to_guest":
				v := strings.ToLower(strings.TrimSpace(s.Value))
				if v != "" && v != "never" && v != "no" && v != "disabled" {
					// Share evidence below determines whether this broad guest mapping
					// has an immediately exposed share; otherwise it remains a warning.
					keys = append(keys, key)
				}
			}
		}
	}
	shares, inv, invOK := smbShareItems(idx)
	keys = append(keys, "smb_security.shares_inventory")
	guest, writableGuest := 0, 0
	for _, item := range shares {
		keys = append(keys, item.Key)
		if item.Share.GuestAllowed {
			guest++
			if item.Share.WritableKnown && item.Share.Writable {
				writableGuest++
			}
		}
	}
	if writableGuest > 0 {
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d writable SMB guest share(s) are exported", writableGuest), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	if guest > 0 {
		return Evaluation{Status: StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d SMB share(s) permit guest access", guest), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	if !invOK || inv.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SMB share inventory is unavailable, so guest-share exposure cannot be fully determined", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	if s, _, ok := smbSetting(idx, "server", "map_to_guest"); ok {
		v := strings.ToLower(strings.TrimSpace(s.Value))
		if v != "" && v != "never" && v != "no" && v != "disabled" {
			return Evaluation{Status: StatusWarn, Confidence: s.Confidence, ObservedState: "Samba map-to-guest policy is enabled even though no guest share was identified: " + s.Value, Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
		}
	}
	if unresolvedPolicy > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d SMB guest/null-session policy setting(s) are unresolved", unresolvedPolicy), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: "no insecure guest/null-session policy or guest-enabled share was identified", Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
}

func evaluateSMBShares(idx Index) Evaluation {
	if early := smbNotApplicableOrUnknown(idx); early != nil {
		return *early
	}
	shares, inv, invOK := smbShareItems(idx)
	keys := []string{"smb_security.applicability", "smb_security.shares_inventory"}
	if !invOK || inv.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "SMB exported-share inventory is unavailable", Applicability: Applicable, EvidenceKeys: keys}
	}
	bad := []string{}
	accessUnknown := 0
	for _, item := range shares {
		keys = append(keys, item.Key)
		sh := item.Share
		if sh.Special {
			continue
		}
		if !sh.AccessKnown {
			accessUnknown++
		}
		if sh.BroadWrite {
			bad = append(bad, sh.Name+":broad-write")
		}
		if sh.GuestAllowed && sh.WritableKnown && sh.Writable {
			bad = append(bad, sh.Name+":guest-writable")
		}
		if sh.SensitivePath {
			bad = append(bad, sh.Name+":sensitive-path")
		}
		for _, tag := range sh.RiskTags {
			if tag == "wide-links-enabled" {
				bad = append(bad, sh.Name+":wide-links")
			}
		}
	}
	bad = uniqueEvidenceKeys(bad)
	if len(bad) > 0 {
		sample := bad
		if len(sample) > 8 {
			sample = sample[:8]
		}
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d dangerous SMB share exposure condition(s): %s", len(bad), strings.Join(sample, ", ")), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	if accessUnknown > 0 {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: fmt.Sprintf("%d non-special SMB share(s) lack complete share-level access metadata", accessUnknown), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
	}
	return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d exported SMB share(s) have no observed broad-write, writable-guest, sensitive-path, or wide-links exposure", len(shares)), Applicability: Applicable, EvidenceKeys: uniqueEvidenceKeys(keys)}
}

func normalizeSMBDialect(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "_")
	v = strings.ReplaceAll(v, ".", "_")
	switch v {
	case "CORE", "COREPLUS", "LANMAN1", "LANMAN2", "NT1", "SMB2", "SMB2_02", "SMB2_10", "SMB3", "SMB3_00", "SMB3_02", "SMB3_11":
		return v
	}
	if strings.HasPrefix(v, "SMB2") {
		return "SMB2"
	}
	if strings.HasPrefix(v, "SMB3") {
		return "SMB3"
	}
	return ""
}

func smbDialectRank(v string) int {
	ranks := map[string]int{"CORE": 0, "COREPLUS": 1, "LANMAN1": 2, "LANMAN2": 3, "NT1": 4, "SMB2": 5, "SMB2_02": 6, "SMB2_10": 7, "SMB3": 8, "SMB3_00": 9, "SMB3_02": 10, "SMB3_11": 11}
	return ranks[v]
}

func smbTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1", "enabled", "on", "required", "mandatory":
		return true
	default:
		return false
	}
}

func observationConfidence(o evidence.Observation) evidence.Confidence {
	if o.Confidence == "" {
		return evidence.ConfidenceLow
	}
	return o.Confidence
}

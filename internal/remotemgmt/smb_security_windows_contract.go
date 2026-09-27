package remotemgmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// windowsSMBJSON is the normalized, schema-stable representation consumed by
// the Windows SMB collector. The PowerShell provider is expected to emit these
// types explicitly; decodeWindowsSMBJSON additionally tolerates the historic
// numeric FolderEnumerationMode enum so one OS/runtime serialization detail
// cannot destroy the complete SMB assessment.
type windowsSMBJSON struct {
	Server             windowsSMBServerJSON
	Shares             []windowsSMBShareJSON
	AccessErrors       []string
	AccessFailures     []windowsSMBAccessFailureJSON
	Access             []windowsSMBAccessJSON
	ShareDecodeErrors  []string
	AccessDecodeErrors []string
}

type windowsSMBServerJSON struct {
	EnableSMB1Protocol       *bool    `json:"EnableSMB1Protocol"`
	EnableSMB2Protocol       *bool    `json:"EnableSMB2Protocol"`
	EnableSecuritySignature  *bool    `json:"EnableSecuritySignature"`
	RequireSecuritySignature *bool    `json:"RequireSecuritySignature"`
	EncryptData              *bool    `json:"EncryptData"`
	RejectUnencryptedAccess  *bool    `json:"RejectUnencryptedAccess"`
	AllowInsecureGuestAuth   *bool    `json:"AllowInsecureGuestAuth"`
	RestrictNullSessAccess   *bool    `json:"RestrictNullSessAccess"`
	NullSessionShares        []string `json:"NullSessionShares"`
}

type windowsSMBShareJSON struct {
	Name                  string `json:"Name"`
	Path                  string `json:"Path"`
	Description           string `json:"Description"`
	EncryptData           bool   `json:"EncryptData"`
	FolderEnumerationMode string `json:"FolderEnumerationMode"`
	Special               bool   `json:"Special"`
	Temporary             bool   `json:"Temporary"`
}

type windowsSMBAccessJSON struct {
	Name              string `json:"Name"`
	AccountName       string `json:"AccountName"`
	AccessControlType string `json:"AccessControlType"`
	AccessRight       string `json:"AccessRight"`
}

type windowsSMBAccessFailureJSON struct {
	Name          string `json:"Name"`
	ExceptionType string `json:"ExceptionType"`
	Message       string `json:"Message"`
}

type windowsSMBEnvelope struct {
	Server         windowsSMBServerJSON          `json:"Server"`
	Shares         []json.RawMessage             `json:"Shares"`
	AccessErrors   []string                      `json:"AccessErrors"`
	AccessFailures []windowsSMBAccessFailureJSON `json:"AccessFailures"`
	Access         []json.RawMessage             `json:"Access"`
}

type windowsSMBShareWire struct {
	Name                  string               `json:"Name"`
	Path                  string               `json:"Path"`
	Description           string               `json:"Description"`
	EncryptData           bool                 `json:"EncryptData"`
	FolderEnumerationMode windowsSMBEnumString `json:"FolderEnumerationMode"`
	Special               bool                 `json:"Special"`
	Temporary             bool                 `json:"Temporary"`
}

// windowsSMBEnumString accepts the explicit string form emitted by Fix28 and
// the numeric enum form emitted by some Windows PowerShell/SMB module builds.
// It is deliberately narrow: objects/arrays/bools remain invalid.
type windowsSMBEnumString string

func (v *windowsSMBEnumString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*v = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = windowsSMBEnumString(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return fmt.Errorf("expected string or numeric enum: %w", err)
	}
	if _, err := strconv.ParseInt(n.String(), 10, 64); err != nil {
		return fmt.Errorf("expected integral enum value, got %q", n.String())
	}
	*v = windowsSMBEnumString(n.String())
	return nil
}

func decodeWindowsSMBJSON(b []byte) (windowsSMBJSON, error) {
	var env windowsSMBEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return windowsSMBJSON{}, err
	}

	out := windowsSMBJSON{
		Server:         env.Server,
		AccessErrors:   append([]string(nil), env.AccessErrors...),
		AccessFailures: append([]windowsSMBAccessFailureJSON(nil), env.AccessFailures...),
		Shares:         make([]windowsSMBShareJSON, 0, len(env.Shares)),
		Access:         make([]windowsSMBAccessJSON, 0, len(env.Access)),
	}

	for i, raw := range env.Shares {
		var wire windowsSMBShareWire
		if err := json.Unmarshal(raw, &wire); err != nil {
			out.ShareDecodeErrors = append(out.ShareDecodeErrors, fmt.Sprintf("share record %d: %v", i, err))
			continue
		}
		if strings.TrimSpace(wire.Name) == "" {
			out.ShareDecodeErrors = append(out.ShareDecodeErrors, fmt.Sprintf("share record %d: missing Name", i))
			continue
		}
		out.Shares = append(out.Shares, windowsSMBShareJSON{
			Name:                  wire.Name,
			Path:                  wire.Path,
			Description:           wire.Description,
			EncryptData:           wire.EncryptData,
			FolderEnumerationMode: string(wire.FolderEnumerationMode),
			Special:               wire.Special,
			Temporary:             wire.Temporary,
		})
	}

	for i, raw := range env.Access {
		var a windowsSMBAccessJSON
		if err := json.Unmarshal(raw, &a); err != nil {
			out.AccessDecodeErrors = append(out.AccessDecodeErrors, fmt.Sprintf("access record %d: %v", i, err))
			continue
		}
		if strings.TrimSpace(a.Name) == "" {
			out.AccessDecodeErrors = append(out.AccessDecodeErrors, fmt.Sprintf("access record %d: missing Name", i))
			continue
		}
		out.Access = append(out.Access, a)
	}

	return out, nil
}

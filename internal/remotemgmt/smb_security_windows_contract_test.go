package remotemgmt

import (
	"strings"
	"testing"
)

func TestDecodeWindowsSMBJSONAcceptsStringFolderEnumerationMode(t *testing.T) {
	raw := []byte(`{
      "Server":{"EnableSMB1Protocol":false,"EnableSMB2Protocol":true,"EnableSecuritySignature":true,"RequireSecuritySignature":true,"EncryptData":false,"RejectUnencryptedAccess":true,"AllowInsecureGuestAuth":false,"RestrictNullSessAccess":true,"NullSessionShares":[]},
      "Shares":[{"Name":"Data","Path":"C:\\\\Data","Description":"","EncryptData":false,"FolderEnumerationMode":"AccessBased","Special":false,"Temporary":false}],
      "AccessErrors":[],
      "Access":[{"Name":"Data","AccountName":"BUILTIN\\\\Users","AccessControlType":"Allow","AccessRight":"Read"}]
    }`)
	got, err := decodeWindowsSMBJSON(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Shares) != 1 {
		t.Fatalf("shares=%d want 1; errors=%v", len(got.Shares), got.ShareDecodeErrors)
	}
	if got.Shares[0].FolderEnumerationMode != "AccessBased" {
		t.Fatalf("FolderEnumerationMode=%q", got.Shares[0].FolderEnumerationMode)
	}
	if len(got.Access) != 1 || got.Access[0].AccessRight != "Read" {
		t.Fatalf("access=%+v", got.Access)
	}
}

func TestDecodeWindowsSMBJSONAcceptsNumericFolderEnumerationMode(t *testing.T) {
	raw := []byte(`{
      "Server":{"EnableSMB1Protocol":false,"EnableSMB2Protocol":true,"NullSessionShares":[]},
      "Shares":[{"Name":"Data","Path":"C:\\\\Data","EncryptData":false,"FolderEnumerationMode":1,"Special":false,"Temporary":false}],
      "AccessErrors":[],"Access":[]
    }`)
	got, err := decodeWindowsSMBJSON(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Shares) != 1 {
		t.Fatalf("shares=%d want 1; errors=%v", len(got.Shares), got.ShareDecodeErrors)
	}
	if got.Shares[0].FolderEnumerationMode != "1" {
		t.Fatalf("numeric enum normalized to %q want 1", got.Shares[0].FolderEnumerationMode)
	}
}

func TestDecodeWindowsSMBJSONSkipsMalformedShareWithoutLosingServerSettings(t *testing.T) {
	raw := []byte(`{
      "Server":{"EnableSMB1Protocol":false,"EnableSMB2Protocol":true,"EnableSecuritySignature":true,"RequireSecuritySignature":true,"EncryptData":false,"RejectUnencryptedAccess":true,"AllowInsecureGuestAuth":false,"RestrictNullSessAccess":true,"NullSessionShares":[]},
      "Shares":[
        {"Name":"Good","Path":"C:\\\\Good","EncryptData":false,"FolderEnumerationMode":"Unrestricted","Special":false,"Temporary":false},
        {"Name":"Bad","Path":"C:\\\\Bad","EncryptData":false,"FolderEnumerationMode":{"unexpected":true},"Special":false,"Temporary":false}
      ],
      "AccessErrors":[],"Access":[]
    }`)
	got, err := decodeWindowsSMBJSON(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Server.EnableSMB2Protocol == nil || !*got.Server.EnableSMB2Protocol {
		t.Fatalf("server settings were not preserved: %+v", got.Server)
	}
	if len(got.Shares) != 1 || got.Shares[0].Name != "Good" {
		t.Fatalf("valid shares not preserved: %+v", got.Shares)
	}
	if len(got.ShareDecodeErrors) != 1 || !strings.Contains(got.ShareDecodeErrors[0], "share record 1") {
		t.Fatalf("share decode errors=%v", got.ShareDecodeErrors)
	}
}

func TestDecodeWindowsSMBJSONSkipsMalformedAccessRecord(t *testing.T) {
	raw := []byte(`{
      "Server":{"EnableSMB1Protocol":false,"EnableSMB2Protocol":true,"NullSessionShares":[]},
      "Shares":[{"Name":"Data","Path":"C:\\\\Data","EncryptData":false,"FolderEnumerationMode":"Unrestricted","Special":false,"Temporary":false}],
      "AccessErrors":[],
      "Access":[
        {"Name":"Data","AccountName":"Everyone","AccessControlType":"Allow","AccessRight":"Read"},
        {"AccountName":"Broken","AccessControlType":"Allow","AccessRight":"Full"}
      ]
    }`)
	got, err := decodeWindowsSMBJSON(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Access) != 1 {
		t.Fatalf("access=%d want 1; errors=%v", len(got.Access), got.AccessDecodeErrors)
	}
	if len(got.AccessDecodeErrors) != 1 || !strings.Contains(got.AccessDecodeErrors[0], "missing Name") {
		t.Fatalf("access errors=%v", got.AccessDecodeErrors)
	}
}

func TestDecodeWindowsSMBJSONRejectsInvalidTopLevelContract(t *testing.T) {
	_, err := decodeWindowsSMBJSON([]byte(`{"Server":{"EnableSMB2Protocol":"not-a-bool"},"Shares":[],"Access":[],"AccessErrors":[]}`))
	if err == nil {
		t.Fatal("expected invalid server contract to fail")
	}
}

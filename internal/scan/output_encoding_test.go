package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestFix53Hotfix1NormalizeAssessmentSnapshotJSONEncodings(t *testing.T) {
	t.Parallel()
	plain := []byte("{\"command\":\"scan\",\"note\":\"Chimera [31mΔ[0m\"}")

	cases := []struct {
		name string
		data []byte
	}{
		{name: "utf8", data: append([]byte(nil), plain...)},
		{name: "utf8-bom", data: append([]byte{0xEF, 0xBB, 0xBF}, plain...)},
		{name: "utf16le-bom", data: encodeFix53UTF16(plain, true, true)},
		{name: "utf16be-bom", data: encodeFix53UTF16(plain, false, true)},
		{name: "utf16le-no-bom", data: encodeFix53UTF16(plain, true, false)},
		{name: "utf16be-no-bom", data: encodeFix53UTF16(plain, false, false)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeAssessmentSnapshotJSON(tc.data)
			if err != nil {
				t.Fatalf("normalize %s: %v", tc.name, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("normalize %s mismatch:\n got: %q\nwant: %q", tc.name, got, plain)
			}
		})
	}
}

func TestFix53Hotfix1LoadAssessmentSnapshotFileAcceptsPowerShellUTF16(t *testing.T) {
	t.Parallel()
	// The deliberately incomplete scan result must fail at normal scan-schema
	// validation, not at JSON text decoding. That proves the public file loader
	// crossed the Windows PowerShell UTF-16 boundary successfully.
	plain := []byte("{\"command\":\"scan\",\"data\":{}}")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "utf16le-bom", data: encodeFix53UTF16(plain, true, true)},
		{name: "utf16be-bom", data: encodeFix53UTF16(plain, false, true)},
		{name: "utf8-bom", data: append([]byte{0xEF, 0xBB, 0xBF}, plain...)},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "scan.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadAssessmentSnapshotFile(path)
			if err == nil {
				t.Fatal("expected incomplete fixture to fail scan schema validation")
			}
			if strings.Contains(err.Error(), "decode assessment snapshot JSON") || strings.Contains(err.Error(), "normalize assessment snapshot text encoding") {
				t.Fatalf("loader failed at encoding boundary: %v", err)
			}
			if !strings.Contains(err.Error(), "unsupported scan schema") {
				t.Fatalf("loader did not reach scan schema validation: %v", err)
			}
		})
	}
}

func TestFix53Hotfix1RejectsMalformedUTF16(t *testing.T) {
	t.Parallel()
	_, err := normalizeAssessmentSnapshotJSON([]byte{0xFF, 0xFE, '{', 0x00, 0x7D})
	if err == nil || !strings.Contains(err.Error(), "odd byte length") {
		t.Fatalf("expected odd-length UTF-16 rejection, got %v", err)
	}
}

func encodeFix53UTF16(utf8JSON []byte, littleEndian, withBOM bool) []byte {
	words := utf16.Encode([]rune(string(utf8JSON)))
	out := make([]byte, 0, len(words)*2+2)
	if withBOM {
		if littleEndian {
			out = append(out, 0xFF, 0xFE)
		} else {
			out = append(out, 0xFE, 0xFF)
		}
	}
	for _, w := range words {
		if littleEndian {
			out = append(out, byte(w), byte(w>>8))
		} else {
			out = append(out, byte(w>>8), byte(w))
		}
	}
	return out
}

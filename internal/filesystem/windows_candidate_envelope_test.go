package filesystem

import (
	"strings"
	"testing"
)

func TestWindowsCandidateEnvelopeRoundTripPreservesIdentity(t *testing.T) {
	items := []windowsCandidateEnvelopeItem{
		{CandidateID: "temp-user", Path: `C:\\Users\\Demo User\\AppData\\Local\\Temp`},
		{CandidateID: "temp-system", Path: `C:\\Windows\\Temp\\`},
	}
	raw, err := marshalWindowsCandidateEnvelope(items)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := validateWindowsCandidateEnvelopeJSON(raw)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(got) != len(items) {
		t.Fatalf("got %d items, want %d", len(got), len(items))
	}
	for i := range items {
		if got[i] != items[i] {
			t.Fatalf("item %d changed across envelope: got %#v want %#v", i, got[i], items[i])
		}
	}
}

func TestWindowsCandidateEnvelopeFixtures(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "empty-items", raw: `{"schema_version":1,"items":[]}`},
		{name: "one-item", raw: `{"schema_version":1,"items":[{"candidate_id":"one","path":"C:\\\\Temp"}]}`},
		{name: "paths-with-spaces", raw: `{"schema_version":1,"items":[{"candidate_id":"one","path":"C:\\\\Program Files\\\\Tool"},{"candidate_id":"two","path":"C:\\\\Windows\\\\Temp\\\\"}]}`},
		{name: "malformed-json", raw: `{`, wantErr: "decode Windows candidate envelope"},
		{name: "missing-schema", raw: `{"items":[]}`, wantErr: "missing schema_version"},
		{name: "wrong-schema", raw: `{"schema_version":2,"items":[]}`, wantErr: "schema_version=2"},
		{name: "missing-items", raw: `{"schema_version":1}`, wantErr: "missing items"},
		{name: "null-items", raw: `{"schema_version":1,"items":null}`, wantErr: "not null"},
		{name: "single-object-items", raw: `{"schema_version":1,"items":{"candidate_id":"one","path":"C:\\\\Temp"}}`, wantErr: "must be an array"},
		{name: "duplicate-id", raw: `{"schema_version":1,"items":[{"candidate_id":"dup","path":"C:\\\\A"},{"candidate_id":"dup","path":"C:\\\\B"}]}`, wantErr: "duplicate candidate_id"},
		{name: "missing-id", raw: `{"schema_version":1,"items":[{"path":"C:\\\\A"}]}`, wantErr: "missing candidate_id"},
		{name: "blank-id", raw: `{"schema_version":1,"items":[{"candidate_id":"  ","path":"C:\\\\A"}]}`, wantErr: "missing candidate_id"},
		{name: "missing-path", raw: `{"schema_version":1,"items":[{"candidate_id":"one"}]}`, wantErr: "missing path"},
		{name: "blank-path", raw: `{"schema_version":1,"items":[{"candidate_id":"one","path":"  "}]}`, wantErr: "missing path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateWindowsCandidateEnvelopeJSON([]byte(tc.raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestWindowsCandidateEnvelopePowerShellUsesExplicitItemsBoundary(t *testing.T) {
	if strings.Contains(windowsCandidateEnvelopePowerShell, "@(ConvertFrom-Json") {
		t.Fatal("PowerShell helper must not wrap top-level ConvertFrom-Json directly in @(...)")
	}
	for _, required := range []string{"schema_version", "PSObject.Properties['items']", "candidate_id", "duplicate candidate_id", "Write-Output $entry"} {
		if !strings.Contains(windowsCandidateEnvelopePowerShell, required) {
			t.Fatalf("PowerShell helper missing %q", required)
		}
	}
}

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhase116CollectionJSONGolden(t *testing.T) {
	at := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	contract := CollectionResult{
		State:    StateDegraded,
		Timing:   Timing{StartedAt: at, CompletedAt: at.Add(125 * time.Millisecond), DurationMS: 125},
		Evidence: EvidenceCounts{Total: 3, Observed: 2, Degraded: 1},
		Providers: []ProviderResult{{
			Name: "software", State: StateDegraded,
			Timing:             Timing{StartedAt: at, CompletedAt: at.Add(100 * time.Millisecond), DurationMS: 100},
			Evidence:           EvidenceCounts{Total: 2, Observed: 2},
			DegradationReasons: []string{"one invalid provider observation quarantined"},
			InvalidEvidence:    1,
		}},
		DegradationReasons: []string{"one invalid provider observation quarantined"},
	}
	got, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "collection_contract.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("collection JSON contract changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

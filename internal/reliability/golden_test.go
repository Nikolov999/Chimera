package reliability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPhase116ReliabilityJSONGolden(t *testing.T) {
	got, err := json.MarshalIndent(CurrentContract(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "reliability_contract.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("JSON contract changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

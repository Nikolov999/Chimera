package releasecontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestV1ReleaseContractGoldenByPlatform(t *testing.T) {
	for _, platform := range SupportedPlatforms() {
		t.Run(platform, func(t *testing.T) {
			got, err := json.MarshalIndent(CurrentForPlatform(platform), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			want, err := os.ReadFile(filepath.Join("testdata", "v1_release_contract_"+platform+".golden.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s v1 release contract changed\n--- got ---\n%s\n--- want ---\n%s", platform, got, want)
			}
		})
	}
}

//go:build linux

package scheduled

import (
	"reflect"
	"testing"
)

func TestParseSystemdTimerUnitFileNamesSkipsUninstantiatedTemplates(t *testing.T) {
	raw := `apt-daily.timer enabled enabled
pg_basebackup@.timer disabled enabled
pg_dump@daily.timer enabled enabled
fstrim.timer enabled enabled
pg_basebackup@.timer disabled enabled
`
	got := parseSystemdTimerUnitFileNames(raw)
	want := []string{"apt-daily.timer", "fstrim.timer", "pg_dump@daily.timer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("timer names = %#v, want %#v", got, want)
	}
}

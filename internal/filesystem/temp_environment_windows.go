//go:build windows

package filesystem

import "os"

func platformTempEnvironmentPaths() []string {
	values := []string{os.TempDir(), os.Getenv("TMP"), os.Getenv("TEMP")}
	out := []string{}
	for _, raw := range values {
		out = append(out, splitWindowsTempPathValue(raw)...)
	}
	return uniqueSorted(out)
}

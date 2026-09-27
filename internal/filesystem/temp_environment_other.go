//go:build !windows

package filesystem

import "os"

func platformTempEnvironmentPaths() []string {
	if t := os.TempDir(); t != "" {
		return []string{t}
	}
	return nil
}

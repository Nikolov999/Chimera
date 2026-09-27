//go:build windows

package containers

import "os"

func endpointOwnerMetadata(info os.FileInfo) (uid, gid string, ok bool) {
	return "", "", false
}

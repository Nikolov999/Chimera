//go:build !linux && !darwin && !windows

package scheduled

import "os"

func enrichPathPosture(_ string, _ os.FileInfo, _ *PathPosture) {}

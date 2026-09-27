//go:build !windows

package filesystem

func repairPlatformSearchPathRecords(in []SearchPathRecord, _ PermissionCapability) ([]SearchPathRecord, []string) {
	return in, nil
}

func repairPlatformExecutableRecords(in []ExecutableRecord, _ PermissionCapability) ([]ExecutableRecord, []string) {
	return in, nil
}

func repairPlatformTempDirectoryRecords(in []TempDirectoryRecord, _ PermissionCapability) ([]TempDirectoryRecord, []string) {
	return in, nil
}

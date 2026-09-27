//go:build windows

package filesystem

func repairPlatformSearchPathRecords(in []SearchPathRecord, capability PermissionCapability) ([]SearchPathRecord, []string) {
	return repairSearchPathRecords(in, capability)
}

func repairPlatformExecutableRecords(in []ExecutableRecord, capability PermissionCapability) ([]ExecutableRecord, []string) {
	return repairExecutableRecords(in, capability)
}

func repairPlatformTempDirectoryRecords(in []TempDirectoryRecord, capability PermissionCapability) ([]TempDirectoryRecord, []string) {
	return repairTempDirectoryRecords(in, capability)
}

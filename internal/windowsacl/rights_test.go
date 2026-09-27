package windowsacl

import "testing"

// Representative .NET FileSystemRights composite values.
const (
	readAndExecute int64 = 131241
	modify         int64 = 197055
	fullControl    int64 = 2032127
	synchronize    int64 = 1048576
)

func TestMutatingRightsDoNotTreatReadExecuteAsWrite(t *testing.T) {
	for name, rights := range map[string]int64{
		"read-and-execute": readAndExecute,
		"synchronize":      synchronize,
	} {
		if HasMutatingRights(rights) {
			t.Fatalf("%s rights %d were incorrectly classified as mutating", name, rights)
		}
	}
}

func TestMutatingRightsRecognizeActualWriteCapabilities(t *testing.T) {
	cases := map[string]int64{
		"write-data":            WriteData,
		"append-data":           AppendData,
		"write-attributes":      WriteAttributes,
		"write-ea":              WriteExtendedAttributes,
		"delete-child":          DeleteSubdirectoriesAndFiles,
		"delete":                Delete,
		"change-permissions":    ChangePermissions,
		"take-ownership":        TakeOwnership,
		"modify-composite":      modify,
		"fullcontrol-composite": fullControl,
	}
	for name, rights := range cases {
		if !HasMutatingRights(rights) {
			t.Fatalf("%s rights %d were not classified as mutating", name, rights)
		}
	}
}

func TestRegistryMutatingRightsAvoidReadOnlyCompositeOverlap(t *testing.T) {
	const registryReadKey int64 = 131097
	const registryWriteKey int64 = 131078
	const registryFullControl int64 = 983103
	if HasRegistryMutatingRights(registryReadKey) {
		t.Fatal("Registry ReadKey must not be classified as mutating")
	}
	for name, rights := range map[string]int64{
		"set-value":              RegistrySetValue,
		"create-subkey":          RegistryCreateSubKey,
		"create-link":            RegistryCreateLink,
		"delete":                 RegistryDelete,
		"change-permissions":     RegistryChangePermissions,
		"take-ownership":         RegistryTakeOwnership,
		"write-key-composite":    registryWriteKey,
		"full-control-composite": registryFullControl,
	} {
		if !HasRegistryMutatingRights(rights) {
			t.Fatalf("%s rights %d were not classified as mutating", name, rights)
		}
	}
}

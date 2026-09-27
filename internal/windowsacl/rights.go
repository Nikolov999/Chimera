package windowsacl

// FileSystemRights atomic flag values from System.Security.AccessControl.FileSystemRights.
// Do not build write tests from composite values such as Write, Modify, or FullControl:
// those composites contain read/execute/synchronize bits and can turn a harmless ACE into
// a false write grant when used as the right-hand side of a bitwise intersection.
const (
	WriteData                    int64 = 2 // CreateFiles for directories
	AppendData                   int64 = 4 // CreateDirectories for directories
	WriteExtendedAttributes      int64 = 16
	DeleteSubdirectoriesAndFiles int64 = 64
	WriteAttributes              int64 = 256
	Delete                       int64 = 65536
	ChangePermissions            int64 = 262144
	TakeOwnership                int64 = 524288
)

const MutatingMask int64 = WriteData | AppendData | WriteExtendedAttributes | DeleteSubdirectoriesAndFiles | WriteAttributes | Delete | ChangePermissions | TakeOwnership
const CreateMask int64 = WriteData | AppendData | WriteExtendedAttributes | WriteAttributes
const ControlMask int64 = DeleteSubdirectoriesAndFiles | Delete | ChangePermissions | TakeOwnership

// PowerShell expressions intentionally contain only atomic FileSystemRights values.
const PowerShellMutatingMaskExpression = `[int64]([System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership)`
const PowerShellCreateMaskExpression = `[int64]([System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes)`
const PowerShellControlMaskExpression = `[int64]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership)`

func HasMutatingRights(rights int64) bool { return rights&MutatingMask != 0 }

// RegistryRights atomic flag values from System.Security.AccessControl.RegistryRights.
// As with FileSystemRights, composite values such as WriteKey and FullControl must
// not be used as a mask because they also contain read/control bits.
const (
	RegistrySetValue          int64 = 2
	RegistryCreateSubKey      int64 = 4
	RegistryCreateLink        int64 = 32
	RegistryDelete            int64 = 65536
	RegistryChangePermissions int64 = 262144
	RegistryTakeOwnership     int64 = 524288
)

const RegistryMutatingMask int64 = RegistrySetValue | RegistryCreateSubKey | RegistryCreateLink | RegistryDelete | RegistryChangePermissions | RegistryTakeOwnership

const PowerShellRegistryMutatingMaskExpression = `[int64]([System.Security.AccessControl.RegistryRights]::SetValue -bor [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor [System.Security.AccessControl.RegistryRights]::CreateLink -bor [System.Security.AccessControl.RegistryRights]::Delete -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::TakeOwnership)`

func HasRegistryMutatingRights(rights int64) bool { return rights&RegistryMutatingMask != 0 }

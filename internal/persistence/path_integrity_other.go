//go:build !linux && !darwin && !windows

package persistence

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func assessPlatformPathIntegrity(_ context.Context, inv *Inventory) {
	for i := range inv.Entries {
		privileged, basis := privilegedContext(inv.Entries[i].PrivilegeContext)
		inv.Entries[i].PathIntegrity = normalizePathIntegrity(PathIntegrity{
			State: evidence.StateUnsupported, Privileged: privileged, PrivilegeBasis: basis,
			Executable: unsupportedPosture(inv.Entries[i].ExecutablePath), ExecutableDirectory: unsupportedPosture(""),
			ReferencedScript: unsupportedPosture(inv.Entries[i].ReferencedScriptPath), ReferencedScriptDirectory: unsupportedPosture(""),
			Definition: unsupportedPosture(inv.Entries[i].DefinitionPath), DefinitionDirectory: unsupportedPosture(""),
		})
	}
	addSource(inv, "persistence-path-integrity", evidence.StateUnsupported, "platform persistence path permission provider", 0, "persistence path-integrity assessment is unsupported on this platform")
}
func unsupportedPosture(path string) PathPosture {
	return PathPosture{Path: path, State: evidence.StateUnsupported, CollectionSource: "platform persistence path permission provider", Confidence: evidence.ConfidenceExact, Reason: "unsupported platform"}
}

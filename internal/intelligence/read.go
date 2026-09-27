package intelligence

import "github.com/Nikolov999/chimera/internal/reliability"

func readStablePointer(path string) ([]byte, error) {
	return reliability.StableReadFile(path, reliability.MaxIntelligencePointerBytes)
}

func readStableManifest(path string) ([]byte, error) {
	return reliability.StableReadFile(path, reliability.MaxIntelligenceManifestBytes)
}

func readStableAux(path string) ([]byte, error) {
	return reliability.StableReadFile(path, reliability.MaxIntelligenceAuxBytes)
}

//go:build !linux && !darwin && !windows

package secrets

func platformCandidates() []candidate { return nil }

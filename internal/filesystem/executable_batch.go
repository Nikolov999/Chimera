package filesystem

// executableBatchRange is a half-open candidate range [Start, End). Keeping the
// batching plan platform-neutral lets ordinary unit tests exercise the Windows
// executable-DACL scheduling contract without requiring a Windows runtime.
type executableBatchRange struct {
	Start int
	End   int
}

const windowsExecutableCandidateBatchSize = 4

func planWindowsExecutableBatches(total, batchSize int) []executableBatchRange {
	if total <= 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = windowsExecutableCandidateBatchSize
	}
	out := make([]executableBatchRange, 0, (total+batchSize-1)/batchSize)
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		out = append(out, executableBatchRange{Start: start, End: end})
	}
	return out
}

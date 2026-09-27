package filesystem

import "testing"

func TestFix54ExecutableBatchPlanPreservesEveryCandidate(t *testing.T) {
	batches := planWindowsExecutableBatches(11, 4)
	want := []executableBatchRange{{0, 4}, {4, 8}, {8, 11}}
	if len(batches) != len(want) {
		t.Fatalf("batch count=%d want=%d: %#v", len(batches), len(want), batches)
	}
	for i := range want {
		if batches[i] != want[i] {
			t.Fatalf("batch[%d]=%#v want=%#v", i, batches[i], want[i])
		}
	}
}

func TestFix54ExecutableBatchPlanUsesSafeDefault(t *testing.T) {
	batches := planWindowsExecutableBatches(9, 0)
	if len(batches) != 3 || batches[0] != (executableBatchRange{0, 4}) || batches[2] != (executableBatchRange{8, 9}) {
		t.Fatalf("unexpected default batching: %#v", batches)
	}
}

func TestFix54ExecutableBatchPlanHandlesEmptyInput(t *testing.T) {
	if got := planWindowsExecutableBatches(0, 4); len(got) != 0 {
		t.Fatalf("empty input produced batches: %#v", got)
	}
}

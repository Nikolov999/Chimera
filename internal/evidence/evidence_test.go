package evidence

import (
	"testing"
	"time"
)

func TestObservedContractValidates(t *testing.T) {
	o := NewObserved("host.hostname", "chimera-lab", "os.Hostname", time.Now(), ConfidenceExact)
	if err := o.Validate(); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
}

func TestUnavailableRequiresReason(t *testing.T) {
	o := NewState("host.memory.total_bytes", StateUnavailable, "platform", time.Now(), ConfidenceHigh, "")
	if err := o.Validate(); err == nil {
		t.Fatal("expected missing degradation reason to fail validation")
	}
}

func TestObservedRequiresValue(t *testing.T) {
	o := NewObserved("host.kernel", nil, "platform", time.Now(), ConfidenceHigh)
	if err := o.Validate(); err == nil {
		t.Fatal("expected nil observed value to fail validation")
	}
}

func TestValidateAllRejectsDuplicateKeys(t *testing.T) {
	at := time.Now()
	obs := []Observation{
		NewObserved("host.kernel", "a", "test", at, ConfidenceExact),
		NewObserved("host.kernel", "b", "test", at, ConfidenceExact),
	}
	if err := ValidateAll(obs); err == nil {
		t.Fatal("expected duplicate evidence key to fail validation")
	}
}

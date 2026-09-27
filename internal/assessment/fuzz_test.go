package assessment

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func FuzzDeclarativePredicateValidationNeverPanics(f *testing.F) {
	f.Add("kernel.secure_boot", "EXISTS", "OBSERVED", "true")
	f.Add("", "STRING_IN", "DENIED", "")
	f.Fuzz(func(t *testing.T, key, operator, state, value string) {
		p := Predicate{
			Key:      key,
			Operator: PredicateOperator(operator),
			State:    evidence.State(state),
			Value:    value,
			Values:   []string{value},
		}
		_ = p.Validate()
		_ = PredicateCondition(p).Validate()
	})
}

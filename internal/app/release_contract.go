package app

import (
	"sort"

	"github.com/Nikolov999/chimera/internal/releasecontract"
)

func validateV1CommandRegistry(registry map[string]Command) error {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	descriptors := make([]releasecontract.CommandDescriptor, 0, len(names))
	for _, name := range names {
		c := registry[name]
		descriptors = append(descriptors, releasecontract.CommandDescriptor{
			Name: c.Name, Lane: c.Lane, Purpose: c.Help.Purpose, Usage: c.Help.Usage,
			ExampleCount: len(c.Help.Examples), Output: c.Help.Output, Safety: c.Help.Safety,
			Requirements: c.Help.Requirements, NextSteps: c.Help.NextSteps,
		})
	}
	return releasecontract.ValidateCommandRegistry(descriptors)
}

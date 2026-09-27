package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/profile"
)

func ProfileHeaderHuman(w io.Writer, p profile.Descriptor, decisions []profile.RuleDecision) {
	applicable, notApplicable, changed := decisionCounts(decisions)
	fmt.Fprintln(w, "ASSESSMENT PROFILE")
	fmt.Fprintf(w, "  Name               %s\n", p.Name)
	fmt.Fprintf(w, "  Type               %s\n", profileType(p))
	if p.Custom {
		fmt.Fprintf(w, "  Extends            %s\n", p.Extends)
		fmt.Fprintf(w, "  Behavior profile   %s\n", p.BehaviorProfile)
		fmt.Fprintf(w, "  Policy version     %s\n", p.PolicyVersion)
	}
	fmt.Fprintf(w, "  Description        %s\n", p.Description)
	fmt.Fprintf(w, "  Rules applicable   %d\n", applicable)
	fmt.Fprintf(w, "  Rules N/A          %d\n", notApplicable)
	fmt.Fprintf(w, "  Severity changed   %d\n", changed)
	if p.Custom {
		fmt.Fprintf(w, "  Expected services  %d\n", len(p.ExpectedServices))
		fmt.Fprintf(w, "  Expected ports     %d\n", len(p.ExpectedPorts))
		fmt.Fprintf(w, "  Allowed exceptions %d\n", len(p.AllowedExceptions))
	}
}

func ProfilesHuman(w io.Writer, active profile.Descriptor, catalog []profile.Descriptor, decisions []profile.RuleDecision) {
	fmt.Fprintln(w, "ASSESSMENT PROFILES")
	fmt.Fprintf(w, "  Active             %s\n", active.Name)
	fmt.Fprintf(w, "  Schema             %s\n", profile.SchemaVersion)

	items := append([]profile.Descriptor(nil), catalog...)
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	fmt.Fprintln(w, "\nCATALOG")
	for _, p := range items {
		marker := " "
		if p.Name == active.Name {
			marker = "*"
		}
		fmt.Fprintf(w, "  %s %-18s [%s] %s\n", marker, p.Name, profileType(p), p.Description)
		if p.Custom {
			fmt.Fprintf(w, "      extends: %s; behavior profile: %s; policy: %s\n", p.Extends, p.BehaviorProfile, p.PolicyVersion)
		}
		fmt.Fprintf(w, "      default-applicable: %t\n", p.DefaultApplicable)
		if len(p.EnabledCategories) > 0 {
			fmt.Fprintf(w, "      enabled categories: %s\n", strings.Join(p.EnabledCategories, ", "))
		}
		if len(p.DisabledCategories) > 0 {
			fmt.Fprintf(w, "      disabled categories: %s\n", strings.Join(p.DisabledCategories, ", "))
		}
		if len(p.EnabledRules) > 0 {
			fmt.Fprintf(w, "      enabled rules: %s\n", strings.Join(p.EnabledRules, ", "))
		}
		if len(p.DisabledRules) > 0 {
			fmt.Fprintf(w, "      disabled rules: %s\n", strings.Join(p.DisabledRules, ", "))
		}
		if len(p.SeverityFloors) > 0 {
			fmt.Fprintf(w, "      severity floors: %s\n", severityMap(p.SeverityFloors))
		}
		if len(p.SeverityOverrides) > 0 {
			fmt.Fprintf(w, "      severity overrides: %s\n", severityMap(p.SeverityOverrides))
		}
		if len(p.Environment) > 0 {
			keys := make([]string, 0, len(p.Environment))
			for k := range p.Environment {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, k+"="+p.Environment[k])
			}
			fmt.Fprintf(w, "      environment: %s\n", strings.Join(parts, ", "))
		}
		if p.ServicePolicyMode != "" || len(p.ExpectedServices) > 0 {
			mode := p.ServicePolicyMode
			if mode == "" {
				mode = profile.ServiceModeRequired
			}
			fmt.Fprintf(w, "      service policy: mode=%s expected=%d\n", mode, len(p.ExpectedServices))
		}
		if p.PortPolicyMode != "" || len(p.ExpectedPorts) > 0 {
			mode := p.PortPolicyMode
			if mode == "" {
				mode = profile.PortModeRequired
			}
			fmt.Fprintf(w, "      port policy: mode=%s expected=%d\n", mode, len(p.ExpectedPorts))
		}
		if len(p.AllowedExceptions) > 0 {
			fmt.Fprintf(w, "      allowed policy exceptions: %d\n", len(p.AllowedExceptions))
		}
	}

	fmt.Fprintln(w, "\nACTIVE RULE POLICY")
	for _, d := range decisions {
		state := "APPLICABLE"
		if !d.Applicable {
			state = "NOT_APPLICABLE"
		}
		sev := string(d.EffectiveSeverity)
		if d.BaseSeverity != d.EffectiveSeverity {
			sev = fmt.Sprintf("%s (base %s)", d.EffectiveSeverity, d.BaseSeverity)
		}
		fmt.Fprintf(w, "  %-14s %-18s %-18s severity=%s\n", d.RuleID, d.Category, state, sev)
	}
}

func decisionCounts(decisions []profile.RuleDecision) (applicable, notApplicable, changed int) {
	for _, d := range decisions {
		if d.Applicable {
			applicable++
		} else {
			notApplicable++
		}
		if d.BaseSeverity != d.EffectiveSeverity {
			changed++
		}
	}
	return
}

func profileType(p profile.Descriptor) string {
	if p.Custom {
		return "custom"
	}
	return "built-in"
}

func severityMap(values map[string]assessment.Severity) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, values[k]))
	}
	return strings.Join(parts, ", ")
}

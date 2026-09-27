package accounts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxSudoFiles      = 256
	maxSudoGrants     = 8192
	maxSudoEnvIssues  = 2048
	maxSudoPathIssues = 4096
)

// SudoConfigPath captures ownership/permission metadata for sudoers files and
// include directories. Content is never copied into findings or evidence.
type SudoConfigPath struct {
	ID            string              `json:"id"`
	Path          string              `json:"path"`
	Kind          string              `json:"kind"`
	State         evidence.State      `json:"state"`
	Mode          string              `json:"mode,omitempty"`
	UID           uint32              `json:"uid,omitempty"`
	GID           uint32              `json:"gid,omitempty"`
	Symlink       bool                `json:"symlink"`
	Parsed        bool                `json:"parsed"`
	Insecure      bool                `json:"insecure"`
	InsecureBasis []string            `json:"insecure_basis,omitempty"`
	Source        string              `json:"source"`
	Confidence    evidence.Confidence `json:"confidence"`
	Reason        string              `json:"reason,omitempty"`
}

// SudoCommand describes a normalized command specification from a sudoers
// user specification. It intentionally keeps authorization metadata only.
type SudoCommand struct {
	Spec         string `json:"spec"`
	Path         string `json:"path,omitempty"`
	ScriptPath   string `json:"script_path,omitempty"`
	Negated      bool   `json:"negated"`
	NOPASSWD     bool   `json:"nopasswd"`
	SetEnv       bool   `json:"setenv"`
	Unrestricted bool   `json:"unrestricted"`
	Wildcard     bool   `json:"wildcard"`
	Alias        string `json:"alias,omitempty"`
}

// SudoGrant is a bounded, normalized sudoers authorization statement.
type SudoGrant struct {
	ID       string        `json:"id"`
	Subjects string        `json:"subjects"`
	Hosts    string        `json:"hosts"`
	RunAs    string        `json:"run_as,omitempty"`
	Commands []SudoCommand `json:"commands"`
	Source   string        `json:"source"`
	Line     int           `json:"line"`
}

// SudoEnvironmentIssue records a configuration construct that weakens sudo's
// environment boundary. Values contains variable names only, never values.
type SudoEnvironmentIssue struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Scope  string   `json:"scope,omitempty"`
	Values []string `json:"values,omitempty"`
	Source string   `json:"source"`
	Line   int      `json:"line"`
	Detail string   `json:"detail"`
}

// SudoPathIssue records a sudo-authorized executable/script path whose local
// ownership or mode makes it modifiable through an untrusted boundary.
type SudoPathIssue struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
	Source string `json:"source"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

type SudoSummary struct {
	ParsedFiles            int `json:"parsed_files"`
	ConfigPaths            int `json:"config_paths"`
	Grants                 int `json:"grants"`
	NOPASSWDCommands       int `json:"nopasswd_commands"`
	BroadNOPASSWDCommands  int `json:"broad_nopasswd_commands"`
	UnrestrictedCommands   int `json:"unrestricted_commands"`
	ExplicitSetEnvCommands int `json:"explicit_setenv_commands"`
	UnsafeEnvironment      int `json:"unsafe_environment"`
	WritableReferences     int `json:"writable_references"`
	InsecureConfigPaths    int `json:"insecure_config_paths"`
	UnresolvedAliases      int `json:"unresolved_aliases"`
}

// SudoPosture is the Linux sudo/sudoers posture surface. It contains
// authorization and permission metadata only; it never contains credentials,
// authentication tokens, or secret environment values.
type SudoPosture struct {
	State             evidence.State         `json:"state"`
	Source            string                 `json:"source"`
	Reason            string                 `json:"reason,omitempty"`
	ConfigPaths       []SudoConfigPath       `json:"config_paths,omitempty"`
	Grants            []SudoGrant            `json:"grants,omitempty"`
	EnvironmentIssues []SudoEnvironmentIssue `json:"environment_issues,omitempty"`
	PathIssues        []SudoPathIssue        `json:"path_issues,omitempty"`
	Summary           SudoSummary            `json:"summary"`
}

func stableSudoID(prefix string, parts ...string) string {
	basis := strings.Join(parts, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return prefix + "-" + hex.EncodeToString(sum[:10])
}

func normalizeSudoPosture(platform string, p SudoPosture) SudoPosture {
	p.Source = strings.TrimSpace(p.Source)
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Source == "" {
		p.Source = "Linux sudoers posture provider"
	}
	if p.State == "" {
		if strings.EqualFold(platform, "linux") {
			p.State = evidence.StateUnavailable
			p.Reason = fallback(p.Reason, "Linux sudoers posture provider returned no state")
		} else {
			p.State = evidence.StateNotApplicable
			p.Reason = fallback(p.Reason, "Linux sudo/sudoers assessment is not applicable on this platform")
		}
	}

	seenPaths := map[string]struct{}{}
	paths := make([]SudoConfigPath, 0, len(p.ConfigPaths))
	for _, item := range p.ConfigPaths {
		item.Path = strings.TrimSpace(item.Path)
		item.Kind = strings.ToUpper(strings.TrimSpace(item.Kind))
		item.Source = strings.TrimSpace(item.Source)
		item.Reason = strings.TrimSpace(item.Reason)
		item.InsecureBasis = uniqueSorted(item.InsecureBasis)
		if item.ID == "" && item.Path != "" {
			item.ID = stableSudoID("sudo-config", item.Path, item.Kind)
		}
		if item.ID == "" || item.Path == "" || item.Kind == "" {
			continue
		}
		if item.State == "" {
			item.State = evidence.StateUnavailable
		}
		if item.Source == "" {
			item.Source = item.Path
		}
		if item.Confidence == "" {
			item.Confidence = evidence.ConfidenceHigh
		}
		if item.State != evidence.StateObserved && item.Reason == "" {
			item.Reason = "sudo configuration path metadata was not observable"
		}
		if _, ok := seenPaths[item.ID]; ok {
			continue
		}
		seenPaths[item.ID] = struct{}{}
		paths = append(paths, item)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Path != paths[j].Path {
			return paths[i].Path < paths[j].Path
		}
		return paths[i].ID < paths[j].ID
	})
	p.ConfigPaths = paths

	seenGrants := map[string]struct{}{}
	grants := make([]SudoGrant, 0, len(p.Grants))
	for _, grant := range p.Grants {
		grant.Subjects = strings.TrimSpace(grant.Subjects)
		grant.Hosts = strings.TrimSpace(grant.Hosts)
		grant.RunAs = strings.TrimSpace(grant.RunAs)
		grant.Source = strings.TrimSpace(grant.Source)
		if grant.ID == "" {
			grant.ID = stableSudoID("sudo-grant", grant.Source, fmt.Sprint(grant.Line), grant.Subjects, grant.Hosts, grant.RunAs)
		}
		if grant.ID == "" || grant.Subjects == "" || grant.Hosts == "" || grant.Source == "" || grant.Line <= 0 {
			continue
		}
		commands := make([]SudoCommand, 0, len(grant.Commands))
		for _, cmd := range grant.Commands {
			cmd.Spec = strings.TrimSpace(cmd.Spec)
			cmd.Path = strings.TrimSpace(cmd.Path)
			cmd.ScriptPath = strings.TrimSpace(cmd.ScriptPath)
			cmd.Alias = strings.TrimSpace(cmd.Alias)
			if cmd.Spec == "" {
				continue
			}
			commands = append(commands, cmd)
		}
		if len(commands) == 0 {
			continue
		}
		grant.Commands = commands
		if _, ok := seenGrants[grant.ID]; ok {
			continue
		}
		seenGrants[grant.ID] = struct{}{}
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Source != grants[j].Source {
			return grants[i].Source < grants[j].Source
		}
		if grants[i].Line != grants[j].Line {
			return grants[i].Line < grants[j].Line
		}
		return grants[i].ID < grants[j].ID
	})
	p.Grants = grants

	seenEnv := map[string]struct{}{}
	envIssues := make([]SudoEnvironmentIssue, 0, len(p.EnvironmentIssues))
	for _, issue := range p.EnvironmentIssues {
		issue.Kind = strings.ToUpper(strings.TrimSpace(issue.Kind))
		issue.Scope = strings.TrimSpace(issue.Scope)
		issue.Source = strings.TrimSpace(issue.Source)
		issue.Detail = strings.TrimSpace(issue.Detail)
		issue.Values = uniqueSorted(issue.Values)
		if issue.ID == "" {
			issue.ID = stableSudoID("sudo-env", issue.Source, fmt.Sprint(issue.Line), issue.Kind, issue.Scope, strings.Join(issue.Values, ","))
		}
		if issue.ID == "" || issue.Kind == "" || issue.Source == "" || issue.Line <= 0 || issue.Detail == "" {
			continue
		}
		if _, ok := seenEnv[issue.ID]; ok {
			continue
		}
		seenEnv[issue.ID] = struct{}{}
		envIssues = append(envIssues, issue)
	}
	sort.Slice(envIssues, func(i, j int) bool {
		if envIssues[i].Source != envIssues[j].Source {
			return envIssues[i].Source < envIssues[j].Source
		}
		if envIssues[i].Line != envIssues[j].Line {
			return envIssues[i].Line < envIssues[j].Line
		}
		return envIssues[i].ID < envIssues[j].ID
	})
	p.EnvironmentIssues = envIssues

	seenPathIssues := map[string]struct{}{}
	pathIssues := make([]SudoPathIssue, 0, len(p.PathIssues))
	for _, issue := range p.PathIssues {
		issue.Kind = strings.ToUpper(strings.TrimSpace(issue.Kind))
		issue.Path = strings.TrimSpace(issue.Path)
		issue.Source = strings.TrimSpace(issue.Source)
		issue.Reason = strings.TrimSpace(issue.Reason)
		if issue.ID == "" {
			issue.ID = stableSudoID("sudo-path", issue.Source, fmt.Sprint(issue.Line), issue.Kind, issue.Path, issue.Reason)
		}
		if issue.ID == "" || issue.Kind == "" || issue.Path == "" || issue.Source == "" || issue.Line <= 0 || issue.Reason == "" {
			continue
		}
		if _, ok := seenPathIssues[issue.ID]; ok {
			continue
		}
		seenPathIssues[issue.ID] = struct{}{}
		pathIssues = append(pathIssues, issue)
	}
	sort.Slice(pathIssues, func(i, j int) bool {
		if pathIssues[i].Path != pathIssues[j].Path {
			return pathIssues[i].Path < pathIssues[j].Path
		}
		if pathIssues[i].Source != pathIssues[j].Source {
			return pathIssues[i].Source < pathIssues[j].Source
		}
		return pathIssues[i].Line < pathIssues[j].Line
	})
	p.PathIssues = pathIssues

	p.Summary = summarizeSudoPosture(p)
	return p
}

func summarizeSudoPosture(p SudoPosture) SudoSummary {
	s := SudoSummary{ConfigPaths: len(p.ConfigPaths), Grants: len(p.Grants), UnsafeEnvironment: len(p.EnvironmentIssues), WritableReferences: len(p.PathIssues)}
	for _, cfg := range p.ConfigPaths {
		if cfg.Insecure {
			s.InsecureConfigPaths++
		}
		if cfg.State == evidence.StateObserved && cfg.Kind == "FILE" && cfg.Parsed {
			s.ParsedFiles++
		}
	}
	for _, grant := range p.Grants {
		for _, cmd := range grant.Commands {
			if cmd.NOPASSWD && !cmd.Negated {
				s.NOPASSWDCommands++
				if cmd.Unrestricted || cmd.Wildcard {
					s.BroadNOPASSWDCommands++
				}
			}
			if cmd.Unrestricted && !cmd.Negated {
				s.UnrestrictedCommands++
			}
			if cmd.SetEnv && !cmd.Negated {
				s.ExplicitSetEnvCommands++
			}
			if cmd.Alias != "" && cmd.Path == "" && !cmd.Unrestricted {
				s.UnresolvedAliases++
			}
		}
	}
	return s
}

func validateSudoPosture(platform string, p SudoPosture) error {
	if p.State == "" || strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("sudo posture state/source is incomplete")
	}
	if !strings.EqualFold(platform, "linux") && p.State != evidence.StateNotApplicable {
		return fmt.Errorf("non-Linux sudo posture must be NOT_APPLICABLE")
	}
	if p.State != evidence.StateObserved && p.State != evidence.StateDegraded && strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("non-observed sudo posture requires a reason")
	}
	if len(p.ConfigPaths) > maxSudoFiles || len(p.Grants) > maxSudoGrants || len(p.EnvironmentIssues) > maxSudoEnvIssues || len(p.PathIssues) > maxSudoPathIssues {
		return fmt.Errorf("sudo posture exceeds bounded record limits")
	}
	last := ""
	seen := map[string]struct{}{}
	for i, item := range p.ConfigPaths {
		if item.ID == "" || item.Path == "" || item.Kind == "" || item.State == "" || item.Source == "" || item.Confidence == "" {
			return fmt.Errorf("sudo config path %d is incomplete", i)
		}
		if item.State != evidence.StateObserved && item.Reason == "" {
			return fmt.Errorf("sudo config path %q non-observed without reason", item.ID)
		}
		if _, ok := seen[item.ID]; ok {
			return fmt.Errorf("duplicate sudo config path id %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		key := item.Path + "\x00" + item.ID
		if last != "" && key < last {
			return fmt.Errorf("sudo config paths are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, grant := range p.Grants {
		if grant.ID == "" || grant.Subjects == "" || grant.Hosts == "" || grant.Source == "" || grant.Line <= 0 || len(grant.Commands) == 0 {
			return fmt.Errorf("sudo grant %d is incomplete", i)
		}
		if _, ok := seen[grant.ID]; ok {
			return fmt.Errorf("duplicate sudo grant id %q", grant.ID)
		}
		seen[grant.ID] = struct{}{}
		key := grant.Source + "\x00" + fmt.Sprintf("%09d", grant.Line) + "\x00" + grant.ID
		if last != "" && key < last {
			return fmt.Errorf("sudo grants are not deterministically ordered")
		}
		last = key
	}
	if p.Summary != summarizeSudoPosture(p) {
		return fmt.Errorf("sudo posture summary does not match records")
	}
	return nil
}

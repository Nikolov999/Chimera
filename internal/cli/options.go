package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/reliability"
)

type Options struct {
	JSON                bool          `json:"json"`
	Plain               bool          `json:"plain"`
	NoColor             bool          `json:"no_color"`
	Quiet               bool          `json:"quiet"`
	Verbose             bool          `json:"verbose"`
	Timeout             time.Duration `json:"-"`
	Profile             string        `json:"profile"`
	Severity            string        `json:"severity"`
	Category            string        `json:"category"`
	Include             []string      `json:"include,omitempty"`
	Exclude             []string      `json:"exclude,omitempty"`
	Output              string        `json:"output,omitempty"`
	ConfigPath          string        `json:"config_path,omitempty"`
	Offline             bool          `json:"offline"`
	RefreshIntelligence bool          `json:"refresh_intelligence"`
	MaxWorkers          int           `json:"max_workers"`
	Help                bool          `json:"-"`
	Version             bool          `json:"-"`
}

type Parsed struct {
	Options Options
	Command string
	Args    []string
}

func Parse(args []string, base Options) (Parsed, error) {
	out := Parsed{Options: base}
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			if out.Command == "" && i+1 < len(args) {
				out.Command = args[i+1]
				out.Args = append(out.Args, args[i+2:]...)
			} else {
				out.Args = append(out.Args, args[i+1:]...)
			}
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			if out.Command == "" {
				out.Command = token
			} else {
				out.Args = append(out.Args, token)
			}
			continue
		}

		name, value, hasValue := splitFlag(token)
		switch name {
		case "-h", "--help":
			out.Options.Help = true
		case "-V", "--version":
			out.Options.Version = true
		case "--json":
			out.Options.JSON = true
		case "--plain":
			out.Options.Plain = true
		case "--no-color":
			out.Options.NoColor = true
		case "--quiet":
			out.Options.Quiet = true
		case "--verbose":
			out.Options.Verbose = true
		case "--offline":
			out.Options.Offline = true
		case "--refresh-intelligence":
			out.Options.RefreshIntelligence = true
		case "--timeout", "--profile", "--severity", "--category", "--include", "--exclude", "--output", "--config", "--max-workers":
			if !hasValue {
				i++
				if i >= len(args) {
					return Parsed{}, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			if err := applyValue(&out.Options, name, value); err != nil {
				return Parsed{}, err
			}
		default:
			return Parsed{}, fmt.Errorf("unknown option %q", name)
		}
	}

	if out.Options.JSON {
		out.Options.Plain = true
		out.Options.NoColor = true
	}
	if out.Options.Quiet && out.Options.Verbose {
		return Parsed{}, fmt.Errorf("--quiet and --verbose cannot be used together")
	}
	if out.Options.Offline && out.Options.RefreshIntelligence {
		return Parsed{}, fmt.Errorf("--offline and --refresh-intelligence cannot be used together")
	}
	if out.Options.Timeout <= 0 {
		return Parsed{}, fmt.Errorf("--timeout must be greater than zero")
	}
	if out.Options.MaxWorkers < 1 {
		return Parsed{}, fmt.Errorf("--max-workers must be at least 1")
	}
	if out.Options.MaxWorkers > reliability.MaxWorkers {
		return Parsed{}, fmt.Errorf("--max-workers must not exceed %d", reliability.MaxWorkers)
	}
	return out, nil
}

func splitFlag(token string) (name, value string, hasValue bool) {
	if strings.HasPrefix(token, "--") {
		if idx := strings.IndexByte(token, '='); idx >= 0 {
			return token[:idx], token[idx+1:], true
		}
	}
	return token, "", false
}

func applyValue(opts *Options, name, value string) error {
	switch name {
	case "--timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid --timeout %q: %w", value, err)
		}
		opts.Timeout = d
	case "--profile":
		opts.Profile = strings.TrimSpace(value)
	case "--severity":
		s := strings.ToUpper(strings.TrimSpace(value))
		switch s {
		case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
			opts.Severity = s
		default:
			return fmt.Errorf("invalid --severity %q", value)
		}
	case "--category":
		opts.Category = strings.TrimSpace(value)
	case "--include":
		opts.Include = append(opts.Include, value)
	case "--exclude":
		opts.Exclude = append(opts.Exclude, value)
	case "--output":
		opts.Output = value
	case "--config":
		opts.ConfigPath = value
	case "--max-workers":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > reliability.MaxWorkers {
			return fmt.Errorf("invalid --max-workers %q (allowed 1-%d)", value, reliability.MaxWorkers)
		}
		opts.MaxWorkers = n
	}
	return nil
}

func FindConfigPath(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		token := args[i]
		if strings.HasPrefix(token, "--config=") {
			return strings.TrimPrefix(token, "--config="), nil
		}
		if token == "--config" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--config requires a value")
			}
			return args[i+1], nil
		}
	}
	return "", nil
}

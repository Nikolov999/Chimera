package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cli"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/suppression"
)

type File struct {
	JSON                *bool                    `json:"json"`
	Plain               *bool                    `json:"plain"`
	NoColor             *bool                    `json:"no_color"`
	Quiet               *bool                    `json:"quiet"`
	Verbose             *bool                    `json:"verbose"`
	Timeout             string                   `json:"timeout"`
	Profile             string                   `json:"profile"`
	Severity            string                   `json:"severity"`
	Category            string                   `json:"category"`
	Include             []string                 `json:"include"`
	Exclude             []string                 `json:"exclude"`
	Output              string                   `json:"output"`
	Offline             *bool                    `json:"offline"`
	RefreshIntelligence *bool                    `json:"refresh_intelligence"`
	MaxWorkers          *int                     `json:"max_workers"`
	CustomProfiles      []profile.Definition     `json:"custom_profiles,omitempty"`
	Suppressions        []suppression.Definition `json:"suppressions,omitempty"`
}

type Result struct {
	Options      cli.Options
	Sources      []string
	Profiles     []profile.Definition
	Suppressions []suppression.Definition
}

func defaultTimeoutForGOOS(goos string) time.Duration {
	// Post-117 Fix57: repeated real Windows 11 release gates proved that the
	// historical 60s command ceiling could leave otherwise healthy late providers
	// with sub-second parent budgets. Windows therefore uses a realistic bounded
	// enterprise-assessment budget while provider-specific ceilings remain tight.
	// Linux/macOS retain the established 30s default.
	if strings.EqualFold(strings.TrimSpace(goos), "windows") {
		return reliability.WindowsNormalAssessmentTimeout
	}
	return 30 * time.Second
}

func Defaults() cli.Options {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}
	timeout := defaultTimeoutForGOOS(runtime.GOOS)
	return cli.Options{
		Timeout:    timeout,
		Profile:    "default",
		Severity:   "INFO",
		MaxWorkers: workers,
	}
}

func Load(explicit string) (Result, error) {
	result := Result{Options: Defaults()}
	candidates := defaultPaths()
	if explicit != "" {
		candidates = append(candidates, explicit)
	}

	seen := map[string]bool{}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			p = abs
		}
		if seen[p] {
			continue
		}
		seen[p] = true

		data, err := reliability.StableReadFile(p, reliability.MaxConfigBytes)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && p != explicit && absOrOriginal(explicit) != p {
				continue
			}
			if errors.Is(err, os.ErrNotExist) && explicit != "" && absOrOriginal(explicit) == p {
				return Result{}, fmt.Errorf("explicit config %q does not exist", explicit)
			}
			return Result{}, fmt.Errorf("read config %q: %w", p, err)
		}
		var f File
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return Result{}, fmt.Errorf("parse config %q: %w", p, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			if err == nil {
				return Result{}, fmt.Errorf("parse config %q: multiple JSON values are not allowed", p)
			}
			return Result{}, fmt.Errorf("parse config %q: trailing content: %w", p, err)
		}
		if err := merge(&result.Options, f); err != nil {
			return Result{}, fmt.Errorf("config %q: %w", p, err)
		}
		result.Profiles = append(result.Profiles, f.CustomProfiles...)
		for _, raw := range f.Suppressions {
			raw.Source = p
			result.Suppressions = append(result.Suppressions, raw)
		}
		result.Sources = append(result.Sources, p)
	}
	if _, err := profile.NewRegistry(result.Profiles, assessment.ImplementedRules()); err != nil {
		return Result{}, fmt.Errorf("custom profile configuration: %w", err)
	}
	if normalized, err := suppression.NormalizeAndValidate(result.Suppressions, assessment.ImplementedRules()); err != nil {
		return Result{}, fmt.Errorf("suppression configuration: %w", err)
	} else {
		result.Suppressions = normalized
	}
	if explicit != "" {
		result.Options.ConfigPath = explicit
	}
	return result, nil
}

func defaultPaths() []string {
	var paths []string
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("ProgramData"); v != "" {
			paths = append(paths, filepath.Join(v, "Chimera", "config.json"))
		}
		if v := os.Getenv("AppData"); v != "" {
			paths = append(paths, filepath.Join(v, "Chimera", "config.json"))
		}
	case "darwin":
		paths = append(paths, "/Library/Application Support/Chimera/config.json")
		if home != "" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", "Chimera", "config.json"))
		}
	default:
		paths = append(paths, "/etc/chimera/config.json")
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			paths = append(paths, filepath.Join(xdg, "chimera", "config.json"))
		} else if home != "" {
			paths = append(paths, filepath.Join(home, ".config", "chimera", "config.json"))
		}
	}
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, "chimera.json"))
	}
	return paths
}

func merge(o *cli.Options, f File) error {
	if f.JSON != nil {
		o.JSON = *f.JSON
	}
	if f.Plain != nil {
		o.Plain = *f.Plain
	}
	if f.NoColor != nil {
		o.NoColor = *f.NoColor
	}
	if f.Quiet != nil {
		o.Quiet = *f.Quiet
	}
	if f.Verbose != nil {
		o.Verbose = *f.Verbose
	}
	if f.Timeout != "" {
		d, err := time.ParseDuration(f.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid timeout %q", f.Timeout)
		}
		o.Timeout = d
	}
	if f.Profile != "" {
		o.Profile = f.Profile
	}
	if f.Severity != "" {
		s := strings.ToUpper(f.Severity)
		switch s {
		case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
			o.Severity = s
		default:
			return fmt.Errorf("invalid severity %q", f.Severity)
		}
	}
	if f.Category != "" {
		o.Category = f.Category
	}
	if f.Include != nil {
		o.Include = append([]string(nil), f.Include...)
	}
	if f.Exclude != nil {
		o.Exclude = append([]string(nil), f.Exclude...)
	}
	if f.Output != "" {
		o.Output = f.Output
	}
	if f.Offline != nil {
		o.Offline = *f.Offline
	}
	if f.RefreshIntelligence != nil {
		if *f.RefreshIntelligence {
			return fmt.Errorf("refresh_intelligence cannot be enabled from configuration; request refresh explicitly on the command line")
		}
		o.RefreshIntelligence = false
	}
	if f.MaxWorkers != nil {
		if *f.MaxWorkers < 1 || *f.MaxWorkers > reliability.MaxWorkers {
			return fmt.Errorf("max_workers must be between 1 and %d", reliability.MaxWorkers)
		}
		o.MaxWorkers = *f.MaxWorkers
	}
	return nil
}

func absOrOriginal(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

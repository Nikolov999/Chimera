package updateposture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func run(ctx context.Context, name string, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(b))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%w: %s", err, text)
		}
		return "", err
	}
	return text, nil
}
func commandAvailable(name string) bool { _, err := exec.LookPath(name); return err == nil }
func stateForError(ctx context.Context, err error) evidence.State {
	if ctx.Err() != nil {
		return evidence.StateDegraded
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "permission denied") || strings.Contains(s, "access denied") || strings.Contains(s, "unauthorized") || strings.Contains(s, "requires elevation") {
		return evidence.StateDenied
	}
	return evidence.StateDegraded
}
func addProvider(r *Result, id string, state evidence.State, source string, count, security int, meta time.Time, fresh Freshness, reason string) {
	r.Providers = append(r.Providers, Provider{ID: id, State: state, Source: source, ItemCount: count, SecurityCount: security, MetadataTime: meta, Freshness: fresh, Reason: strings.TrimSpace(reason)})
}

func newestMTime(roots ...string) time.Time {
	var newest time.Time
	visited := 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			visited++
			if visited > 50000 {
				return errors.New("limit")
			}
			if d.IsDir() {
				return nil
			}
			info, e := d.Info()
			if e == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
			return nil
		})
	}
	return newest.UTC()
}

const metadataFreshnessWindow = 14 * 24 * time.Hour

func freshness(t, now time.Time) Freshness {
	if t.IsZero() {
		return FreshnessUnknown
	}
	if now.Sub(t) > metadataFreshnessWindow {
		return FreshnessStale
	}
	return FreshnessFresh
}

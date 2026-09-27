package intelligence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	ActiveSchemaVersion     = "chimera.intelligence-active/v1"
	ProvenanceSchemaVersion = "chimera.intelligence-refresh-provenance/v1"
	ActiveFilename          = "active.json"
	ManifestFilename        = "manifest.json"
)

type RefreshProvenance struct {
	Schema             string    `json:"schema"`
	BundleSchema       string    `json:"bundle_schema"`
	SourceURL          string    `json:"source_url"`
	KeyID              string    `json:"key_id"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Signature          string    `json:"signature"`
	ManifestVersion    string    `json:"manifest_version"`
	ManifestDigest     string    `json:"manifest_digest"`
	BundleCreatedAt    time.Time `json:"bundle_created_at"`
	VerifiedAt         time.Time `json:"verified_at"`
}

type SnapshotRef struct {
	Version         string             `json:"version"`
	DigestAlgorithm string             `json:"digest_algorithm"`
	Digest          string             `json:"digest"`
	Manifest        string             `json:"manifest"`
	Provenance      *RefreshProvenance `json:"provenance,omitempty"`
}

type ActivePointer struct {
	Schema      string       `json:"schema"`
	ActivatedAt time.Time    `json:"activated_at"`
	Current     SnapshotRef  `json:"current"`
	Previous    *SnapshotRef `json:"previous,omitempty"`
}

func loadConfiguredDirectory(dir string) (Loaded, error) {
	abs, err := filepath.Abs(dir)
	if err == nil {
		dir = abs
	}
	activePath := filepath.Join(dir, ActiveFilename)
	if raw, err := readStablePointer(activePath); err == nil {
		pointer, err := decodeActivePointer(raw)
		if err != nil {
			return Loaded{}, fmt.Errorf("validate active intelligence pointer %q: %w", activePath, err)
		}
		return loadSnapshotRef(dir, pointer.Current, "PINNED_LOCAL")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Loaded{}, fmt.Errorf("read active intelligence pointer %q: %w", activePath, err)
	}

	path := filepath.Join(dir, ManifestFilename)
	raw, err := readStableManifest(path)
	if err != nil {
		return Loaded{}, fmt.Errorf("read configured intelligence manifest %q: %w", path, err)
	}
	return decode(raw, path, "PINNED_LOCAL")
}

func decodeActivePointer(raw []byte) (ActivePointer, error) {
	var p ActivePointer
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return ActivePointer{}, fmt.Errorf("decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return ActivePointer{}, errors.New("multiple JSON values are not allowed")
		}
		return ActivePointer{}, fmt.Errorf("trailing content: %w", err)
	}
	if err := p.Validate(); err != nil {
		return ActivePointer{}, err
	}
	return p, nil
}

func (p ActivePointer) Validate() error {
	if p.Schema != ActiveSchemaVersion {
		return fmt.Errorf("unexpected schema %q", p.Schema)
	}
	if p.ActivatedAt.IsZero() {
		return errors.New("activated_at is required")
	}
	if err := p.Current.Validate(); err != nil {
		return fmt.Errorf("current snapshot: %w", err)
	}
	if p.Previous != nil {
		if err := p.Previous.Validate(); err != nil {
			return fmt.Errorf("previous snapshot: %w", err)
		}
		if p.Previous.Digest == p.Current.Digest {
			return errors.New("previous snapshot cannot equal current snapshot")
		}
	}
	return nil
}

func (r SnapshotRef) Validate() error {
	if strings.TrimSpace(r.Version) == "" {
		return errors.New("version is required")
	}
	if strings.ToLower(strings.TrimSpace(r.DigestAlgorithm)) != "sha256" {
		return fmt.Errorf("unsupported digest algorithm %q", r.DigestAlgorithm)
	}
	if !validSHA256(r.Digest) {
		return errors.New("digest must be a 64-character SHA-256 hex value")
	}
	if err := validateSnapshotRelativePath(r.Manifest, r.Digest); err != nil {
		return err
	}
	if r.Provenance != nil {
		if err := r.Provenance.Validate(); err != nil {
			return fmt.Errorf("provenance: %w", err)
		}
		if r.Provenance.ManifestVersion != r.Version || r.Provenance.ManifestDigest != strings.ToLower(r.Digest) {
			return errors.New("provenance manifest identity does not match snapshot reference")
		}
	}
	return nil
}

func (p RefreshProvenance) Validate() error {
	if p.Schema != ProvenanceSchemaVersion {
		return fmt.Errorf("unexpected provenance schema %q", p.Schema)
	}
	if p.BundleSchema != RefreshSchemaVersion {
		return fmt.Errorf("unexpected refresh bundle schema %q", p.BundleSchema)
	}
	if strings.TrimSpace(p.SourceURL) == "" || strings.TrimSpace(p.KeyID) == "" || strings.TrimSpace(p.ManifestVersion) == "" {
		return errors.New("source_url, key_id, and manifest_version are required")
	}
	if !validSHA256(p.ManifestDigest) {
		return errors.New("manifest_digest must be a SHA-256 hex value")
	}
	if strings.ToLower(strings.TrimSpace(p.SignatureAlgorithm)) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", p.SignatureAlgorithm)
	}
	if strings.TrimSpace(p.Signature) == "" || p.BundleCreatedAt.IsZero() || p.VerifiedAt.IsZero() {
		return errors.New("signature, bundle_created_at, and verified_at are required")
	}
	return nil
}

func loadSnapshotRef(dir string, ref SnapshotRef, state string) (Loaded, error) {
	if err := ref.Validate(); err != nil {
		return Loaded{}, err
	}
	path, err := resolveSnapshotPath(dir, ref.Manifest)
	if err != nil {
		return Loaded{}, err
	}
	raw, err := readStableManifest(path)
	if err != nil {
		return Loaded{}, fmt.Errorf("read active intelligence snapshot %q: %w", path, err)
	}
	loaded, err := decode(raw, path, state)
	if err != nil {
		return Loaded{}, err
	}
	if loaded.Metadata.Version != ref.Version {
		return Loaded{}, fmt.Errorf("active snapshot version mismatch: pointer=%q manifest=%q", ref.Version, loaded.Metadata.Version)
	}
	if loaded.Metadata.Digest != strings.ToLower(ref.Digest) {
		return Loaded{}, fmt.Errorf("active snapshot digest mismatch: pointer=%s manifest=%s", ref.Digest, loaded.Metadata.Digest)
	}
	return loaded, nil
}

func validateSnapshotRelativePath(rel, digest string) error {
	rel = strings.TrimSpace(rel)
	if rel == "" || strings.Contains(rel, "\\") {
		return fmt.Errorf("unsafe snapshot manifest path %q", rel)
	}
	clean := path.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean != rel {
		return fmt.Errorf("unsafe snapshot manifest path %q", rel)
	}
	expected := path.Join("snapshots", strings.ToLower(digest), ManifestFilename)
	if rel != expected {
		return fmt.Errorf("snapshot manifest path %q does not match digest-addressed path %q", rel, expected)
	}
	return nil
}

func resolveSnapshotPath(dir, rel string) (string, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	rel = strings.TrimSpace(rel)
	clean := path.Clean(rel)
	if rel == "" || strings.Contains(rel, "\\") || clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe snapshot path %q", rel)
	}
	resolved, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	prefix := root + string(filepath.Separator)
	if resolved != root && !strings.HasPrefix(resolved, prefix) {
		return "", fmt.Errorf("snapshot path escapes intelligence directory: %q", rel)
	}
	return resolved, nil
}

func snapshotRefForLoaded(dir string, loaded Loaded, provenance *RefreshProvenance) (SnapshotRef, error) {
	if !validSHA256(loaded.Metadata.Digest) {
		return SnapshotRef{}, errors.New("loaded intelligence digest is invalid")
	}
	rel := path.Join("snapshots", loaded.Metadata.Digest, ManifestFilename)
	if err := ensureSnapshotFile(dir, loaded, rel); err != nil {
		return SnapshotRef{}, err
	}
	return SnapshotRef{
		Version: loaded.Metadata.Version, DigestAlgorithm: "sha256", Digest: loaded.Metadata.Digest,
		Manifest: rel, Provenance: provenance,
	}, nil
}

func ensureSnapshotFile(dir string, loaded Loaded, rel string) error {
	path, err := resolveSnapshotPath(dir, rel)
	if err != nil {
		return err
	}
	if raw, err := readStableManifest(path); err == nil {
		existing, err := decode(raw, path, "PINNED_LOCAL")
		if err != nil {
			return fmt.Errorf("existing digest-addressed snapshot is invalid: %w", err)
		}
		if existing.Metadata.Digest != loaded.Metadata.Digest || existing.Metadata.Version != loaded.Metadata.Version {
			return errors.New("existing digest-addressed snapshot does not match requested snapshot")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	raw, err := json.MarshalIndent(loaded.Store, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	raw = append(raw, '\n')
	if err := atomicWrite(path, raw, 0o600); err != nil {
		return fmt.Errorf("persist snapshot: %w", err)
	}
	verified, err := decode(raw, path, "PINNED_LOCAL")
	if err != nil {
		return fmt.Errorf("verify persisted snapshot: %w", err)
	}
	if verified.Metadata.Digest != loaded.Metadata.Digest {
		return errors.New("persisted snapshot digest changed after write")
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".chimera-atomic-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func validSHA256(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

package intelligence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	RefreshSchemaVersion = "chimera.intelligence-refresh/v1"
	RefreshResultSchema  = "chimera.intelligence-refresh-result/v1"
	RollbackResultSchema = "chimera.intelligence-rollback-result/v1"

	EnvRefreshURL     = "CHIMERA_INTELLIGENCE_REFRESH_URL"
	EnvTrustedKey     = "CHIMERA_INTELLIGENCE_TRUSTED_KEY"
	EnvTrustedKeyFile = "CHIMERA_INTELLIGENCE_TRUSTED_KEY_FILE"

	maxRefreshBytes = 16 << 20
)

type SignedBundle struct {
	Schema         string    `json:"schema"`
	KeyID          string    `json:"key_id"`
	Version        string    `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	ManifestDigest string    `json:"manifest_digest"`
	Manifest       Store     `json:"manifest"`
	Signature      string    `json:"signature"`
}

type RefreshOptions struct {
	URL               string
	Directory         string
	TrustedPublicKey  ed25519.PublicKey
	Client            *http.Client
	Now               time.Time
	AllowInsecureHTTP bool
}

type RefreshResult struct {
	Schema             string             `json:"schema"`
	State              string             `json:"state"`
	SourceURL          string             `json:"source_url"`
	Directory          string             `json:"directory"`
	KeyID              string             `json:"key_id"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	VerifiedAt         time.Time          `json:"verified_at"`
	AtomicActivation   bool               `json:"atomic_activation"`
	NetworkAccess      bool               `json:"network_access"`
	Previous           *Metadata          `json:"previous,omitempty"`
	Current            Metadata           `json:"current"`
	PreviousAvailable  bool               `json:"previous_available"`
	Provenance         *RefreshProvenance `json:"provenance,omitempty"`
}

type RollbackResult struct {
	Schema           string    `json:"schema"`
	State            string    `json:"state"`
	Directory        string    `json:"directory"`
	RolledBackAt     time.Time `json:"rolled_back_at"`
	AtomicActivation bool      `json:"atomic_activation"`
	NetworkAccess    bool      `json:"network_access"`
	From             Metadata  `json:"from"`
	To               Metadata  `json:"to"`
}

// RefreshFromEnvironment performs the only networked intelligence
// action. It requires an explicit configured destination, endpoint, and trusted
// Ed25519 public key. Ordinary scans never call this function.
func RefreshFromEnvironment(ctx context.Context) (RefreshResult, error) {
	key, err := trustedKeyFromEnvironment()
	if err != nil {
		return RefreshResult{}, err
	}
	return Refresh(ctx, RefreshOptions{
		URL:              strings.TrimSpace(os.Getenv(EnvRefreshURL)),
		Directory:        strings.TrimSpace(os.Getenv(EnvDirectory)),
		TrustedPublicKey: key,
	})
}

func Refresh(ctx context.Context, opts RefreshOptions) (RefreshResult, error) {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dir := strings.TrimSpace(opts.Directory)
	if dir == "" {
		return RefreshResult{}, fmt.Errorf("%s must name a writable local intelligence directory before refresh", EnvDirectory)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("resolve intelligence directory: %w", err)
	}
	dir = abs
	endpoint := strings.TrimSpace(opts.URL)
	if endpoint == "" {
		return RefreshResult{}, fmt.Errorf("%s is required for explicit refresh", EnvRefreshURL)
	}
	if err := validateRefreshURL(endpoint, opts.AllowInsecureHTTP); err != nil {
		return RefreshResult{}, err
	}
	if len(opts.TrustedPublicKey) != ed25519.PublicKeySize {
		return RefreshResult{}, errors.New("trusted Ed25519 public key must be exactly 32 bytes")
	}

	client := opts.Client
	if client == nil {
		client = secureRefreshClient(opts.AllowInsecureHTTP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("create intelligence refresh request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IRONCLAD-Chimera/phase032")
	resp, err := client.Do(req)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("retrieve signed intelligence bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return RefreshResult{}, fmt.Errorf("retrieve signed intelligence bundle: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRefreshBytes+1))
	if err != nil {
		return RefreshResult{}, fmt.Errorf("read signed intelligence bundle: %w", err)
	}
	if len(raw) > maxRefreshBytes {
		return RefreshResult{}, fmt.Errorf("signed intelligence bundle exceeds %d-byte safety limit", maxRefreshBytes)
	}
	bundle, candidate, provenance, err := verifySignedBundle(raw, opts.TrustedPublicKey, endpoint, now)
	if err != nil {
		return RefreshResult{}, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return RefreshResult{}, fmt.Errorf("create intelligence directory: %w", err)
	}
	localState, err := currentLocalSnapshot(dir)
	if err != nil {
		return RefreshResult{}, err
	}
	current := localState.Loaded
	currentRef := localState.CurrentRef
	var previousRef *SnapshotRef
	if localState.Active != nil {
		previousRef = localState.Active.Previous
	}
	hadCurrent := localState.HadCurrent
	if hadCurrent {
		if current.Metadata.Digest == candidate.Metadata.Digest {
			// Even when content is unchanged, an explicit successful signed refresh
			// persists the verified provenance and migrates a legacy flat store into
			// the atomic digest-addressed active-pointer layout.
			signedRef, err := snapshotRefForLoaded(dir, candidate, &provenance)
			if err != nil {
				return RefreshResult{}, fmt.Errorf("persist unchanged verified snapshot: %w", err)
			}
			if err := writeSnapshotProvenance(dir, signedRef, provenance); err != nil {
				return RefreshResult{}, err
			}
			if err := activatePointer(dir, ActivePointer{Schema: ActiveSchemaVersion, ActivatedAt: now, Current: signedRef, Previous: previousRef}); err != nil {
				return RefreshResult{}, fmt.Errorf("activate unchanged verified snapshot: %w", err)
			}
			activated, err := loadConfiguredDirectory(dir)
			if err != nil || activated.Metadata.Digest != candidate.Metadata.Digest {
				if err == nil {
					err = errors.New("unchanged verified snapshot digest mismatch after activation")
				}
				return RefreshResult{}, fmt.Errorf("validate unchanged verified snapshot: %w", err)
			}
			return RefreshResult{
				Schema: RefreshResultSchema, State: "UNCHANGED", SourceURL: endpoint, Directory: dir,
				KeyID: bundle.KeyID, SignatureAlgorithm: "ed25519", VerifiedAt: now,
				AtomicActivation: true, NetworkAccess: true, Previous: metadataPtr(current.Metadata), Current: activated.Metadata,
				PreviousAvailable: previousRef != nil, Provenance: &provenance,
			}, nil
		}
		if candidate.Metadata.Version == current.Metadata.Version {
			return RefreshResult{}, fmt.Errorf("signed refresh reuses current version %q with a different digest", candidate.Metadata.Version)
		}
		if !candidate.Metadata.RetrievedAt.After(current.Metadata.RetrievedAt) {
			return RefreshResult{}, fmt.Errorf("signed refresh would roll intelligence backward: current retrieved_at=%s candidate=%s", current.Metadata.RetrievedAt.UTC().Format(time.RFC3339), candidate.Metadata.RetrievedAt.UTC().Format(time.RFC3339))
		}
	}

	newRef, err := snapshotRefForLoaded(dir, candidate, &provenance)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("stage signed intelligence snapshot: %w", err)
	}
	if err := writeSnapshotProvenance(dir, newRef, provenance); err != nil {
		return RefreshResult{}, err
	}

	var previous *SnapshotRef
	if hadCurrent {
		if currentRef != nil {
			copyRef := *currentRef
			previous = &copyRef
		} else {
			legacyRef, err := snapshotRefForLoaded(dir, current, nil)
			if err != nil {
				return RefreshResult{}, fmt.Errorf("preserve current snapshot for rollback: %w", err)
			}
			previous = &legacyRef
		}
	}
	pointer := ActivePointer{Schema: ActiveSchemaVersion, ActivatedAt: now, Current: newRef, Previous: previous}
	if err := activatePointer(dir, pointer); err != nil {
		return RefreshResult{}, fmt.Errorf("activate signed intelligence snapshot: %w", err)
	}
	activated, err := loadConfiguredDirectory(dir)
	if err != nil || activated.Metadata.Digest != candidate.Metadata.Digest {
		rollbackErr := restoreLocalState(dir, localState.Active)
		if err == nil {
			err = errors.New("activated intelligence digest does not match verified candidate")
		}
		if rollbackErr != nil {
			return RefreshResult{}, fmt.Errorf("post-activation validation failed: %v; automatic rollback also failed: %w", err, rollbackErr)
		}
		return RefreshResult{}, fmt.Errorf("post-activation validation failed and previous local state was restored: %w", err)
	}

	result := RefreshResult{
		Schema: RefreshResultSchema, State: "APPLIED", SourceURL: endpoint, Directory: dir,
		KeyID: bundle.KeyID, SignatureAlgorithm: "ed25519", VerifiedAt: now,
		AtomicActivation: true, NetworkAccess: true, Current: activated.Metadata,
		PreviousAvailable: previous != nil, Provenance: &provenance,
	}
	if hadCurrent {
		result.Previous = metadataPtr(current.Metadata)
	}
	return result, nil
}

func Rollback(dir string, now time.Time) (RollbackResult, error) {
	if strings.TrimSpace(dir) == "" {
		return RollbackResult{}, fmt.Errorf("%s must name a local intelligence directory", EnvDirectory)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return RollbackResult{}, err
	}
	dir = abs
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	raw, err := readStablePointer(filepath.Join(dir, ActiveFilename))
	if err != nil {
		return RollbackResult{}, fmt.Errorf("read active intelligence pointer: %w", err)
	}
	pointer, err := decodeActivePointer(raw)
	if err != nil {
		return RollbackResult{}, err
	}
	if pointer.Previous == nil {
		return RollbackResult{}, errors.New("no previous validated intelligence snapshot is available for rollback")
	}
	from, err := loadSnapshotRef(dir, pointer.Current, "PINNED_LOCAL")
	if err != nil {
		return RollbackResult{}, fmt.Errorf("validate current snapshot before rollback: %w", err)
	}
	to, err := loadSnapshotRef(dir, *pointer.Previous, "PINNED_LOCAL")
	if err != nil {
		return RollbackResult{}, fmt.Errorf("validate rollback snapshot: %w", err)
	}
	oldCurrent := pointer.Current
	newPointer := ActivePointer{Schema: ActiveSchemaVersion, ActivatedAt: now, Current: *pointer.Previous, Previous: &oldCurrent}
	if err := activatePointer(dir, newPointer); err != nil {
		return RollbackResult{}, fmt.Errorf("activate rollback snapshot: %w", err)
	}
	verified, err := loadConfiguredDirectory(dir)
	if err != nil || verified.Metadata.Digest != to.Metadata.Digest {
		_ = activatePointer(dir, pointer)
		if err == nil {
			err = errors.New("rollback activation digest mismatch")
		}
		return RollbackResult{}, fmt.Errorf("rollback validation failed; original pointer restored: %w", err)
	}
	return RollbackResult{
		Schema: RollbackResultSchema, State: "ROLLED_BACK", Directory: dir, RolledBackAt: now,
		AtomicActivation: true, NetworkAccess: false, From: from.Metadata, To: verified.Metadata,
	}, nil
}

func verifySignedBundle(raw []byte, publicKey ed25519.PublicKey, sourceURL string, now time.Time) (SignedBundle, Loaded, RefreshProvenance, error) {
	var bundle SignedBundle
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("decode signed intelligence bundle: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("decode signed intelligence bundle: multiple JSON values are not allowed")
		}
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("decode signed intelligence bundle: trailing content: %w", err)
	}
	bundle.Schema = strings.TrimSpace(bundle.Schema)
	bundle.KeyID = strings.TrimSpace(bundle.KeyID)
	bundle.Version = strings.TrimSpace(bundle.Version)
	bundle.ManifestDigest = strings.ToLower(strings.TrimSpace(bundle.ManifestDigest))
	bundle.Signature = strings.TrimSpace(bundle.Signature)
	if bundle.Schema != RefreshSchemaVersion {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("unexpected refresh bundle schema %q", bundle.Schema)
	}
	if bundle.CreatedAt.IsZero() || bundle.Version == "" || !validSHA256(bundle.ManifestDigest) || bundle.Signature == "" {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("signed refresh bundle is incomplete")
	}
	expectedKeyID := KeyID(publicKey)
	if bundle.KeyID != expectedKeyID {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("refresh bundle key_id %q does not match trusted key %q", bundle.KeyID, expectedKeyID)
	}
	if bundle.CreatedAt.After(now.Add(5 * time.Minute)) {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("refresh bundle created_at is implausibly in the future")
	}
	manifestRaw, err := json.Marshal(bundle.Manifest)
	if err != nil {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("encode candidate manifest: %w", err)
	}
	candidate, err := decode(manifestRaw, "verified-refresh://candidate", "VERIFIED_CANDIDATE")
	if err != nil {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("validate candidate intelligence manifest: %w", err)
	}
	if candidate.Metadata.Version != bundle.Version {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("bundle version %q does not match manifest version %q", bundle.Version, candidate.Metadata.Version)
	}
	if candidate.Metadata.Digest != bundle.ManifestDigest {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, fmt.Errorf("bundle manifest digest %s does not match canonical manifest digest %s", bundle.ManifestDigest, candidate.Metadata.Digest)
	}
	if candidate.Metadata.RetrievedAt.After(now.Add(5 * time.Minute)) {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("candidate manifest retrieved_at is implausibly in the future")
	}
	if bundle.CreatedAt.Before(candidate.Metadata.RetrievedAt.Add(-5 * time.Minute)) {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("refresh bundle created_at predates the candidate retrieval timestamp")
	}
	sig, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("refresh bundle signature is not valid base64 Ed25519 signature data")
	}
	if !ed25519.Verify(publicKey, SignaturePayload(bundle), sig) {
		return SignedBundle{}, Loaded{}, RefreshProvenance{}, errors.New("refresh bundle Ed25519 signature verification failed")
	}
	provenance := RefreshProvenance{
		Schema: ProvenanceSchemaVersion, BundleSchema: bundle.Schema, SourceURL: sourceURL, KeyID: bundle.KeyID,
		SignatureAlgorithm: "ed25519", Signature: bundle.Signature, ManifestVersion: candidate.Metadata.Version, ManifestDigest: candidate.Metadata.Digest,
		BundleCreatedAt: bundle.CreatedAt.UTC(), VerifiedAt: now.UTC(),
	}
	return bundle, candidate, provenance, nil
}

func SignaturePayload(bundle SignedBundle) []byte {
	return []byte(strings.Join([]string{
		RefreshSchemaVersion,
		"key_id=" + strings.TrimSpace(bundle.KeyID),
		"version=" + strings.TrimSpace(bundle.Version),
		"manifest_digest=sha256:" + strings.ToLower(strings.TrimSpace(bundle.ManifestDigest)),
		"created_at=" + bundle.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "\n") + "\n")
}

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "ed25519-sha256:" + hex.EncodeToString(sum[:])
}

func trustedKeyFromEnvironment() (ed25519.PublicKey, error) {
	inline := strings.TrimSpace(os.Getenv(EnvTrustedKey))
	path := strings.TrimSpace(os.Getenv(EnvTrustedKeyFile))
	if inline != "" && path != "" {
		return nil, fmt.Errorf("set only one of %s or %s", EnvTrustedKey, EnvTrustedKeyFile)
	}
	var raw []byte
	if path != "" {
		b, err := readStableAux(path)
		if err != nil {
			return nil, fmt.Errorf("read trusted intelligence public key %q: %w", path, err)
		}
		if len(b) > 64<<10 {
			return nil, errors.New("trusted intelligence public key file exceeds 64 KiB safety limit")
		}
		raw = b
	} else if inline != "" {
		raw = []byte(inline)
	} else {
		return nil, fmt.Errorf("%s or %s is required for signed refresh", EnvTrustedKey, EnvTrustedKeyFile)
	}
	return ParseTrustedPublicKey(raw)
}

func ParseTrustedPublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), raw...)), nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM public key: %w", err)
		}
		ed, ok := pub.(ed25519.PublicKey)
		if !ok || len(ed) != ed25519.PublicKeySize {
			return nil, errors.New("PEM public key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), ed...), nil
	}
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	if b, err := hex.DecodeString(trimmed); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	return nil, errors.New("trusted public key must be Ed25519 PEM, 32-byte base64, or 64-character hex")
}

func validateRefreshURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid intelligence refresh URL %q", raw)
	}
	if u.User != nil {
		return errors.New("intelligence refresh URL must not embed credentials")
	}
	if u.Scheme == "https" {
		return nil
	}
	if allowHTTP && u.Scheme == "http" {
		return nil
	}
	return errors.New("intelligence refresh URL must use HTTPS")
}

func secureRefreshClient(allowHTTP bool) *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many intelligence refresh redirects")
			}
			if err := validateRefreshURL(req.URL.String(), allowHTTP); err != nil {
				return err
			}
			return nil
		},
	}
}

type localSnapshotState struct {
	Loaded     Loaded
	CurrentRef *SnapshotRef
	Active     *ActivePointer
	HadCurrent bool
}

func currentLocalSnapshot(dir string) (localSnapshotState, error) {
	activePath := filepath.Join(dir, ActiveFilename)
	if raw, err := readStablePointer(activePath); err == nil {
		p, err := decodeActivePointer(raw)
		if err != nil {
			return localSnapshotState{}, fmt.Errorf("current active intelligence pointer is invalid: %w", err)
		}
		loaded, err := loadSnapshotRef(dir, p.Current, "PINNED_LOCAL")
		if err != nil {
			return localSnapshotState{}, fmt.Errorf("current active intelligence snapshot is invalid: %w", err)
		}
		ref := p.Current
		active := p
		return localSnapshotState{Loaded: loaded, CurrentRef: &ref, Active: &active, HadCurrent: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return localSnapshotState{}, err
	}
	manifestPath := filepath.Join(dir, ManifestFilename)
	if raw, err := readStableManifest(manifestPath); err == nil {
		loaded, err := decode(raw, manifestPath, "PINNED_LOCAL")
		if err != nil {
			return localSnapshotState{}, fmt.Errorf("current legacy intelligence manifest is invalid: %w", err)
		}
		return localSnapshotState{Loaded: loaded, HadCurrent: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return localSnapshotState{}, err
	}
	return localSnapshotState{}, nil
}

func activatePointer(dir string, pointer ActivePointer) error {
	if err := pointer.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWrite(filepath.Join(dir, ActiveFilename), raw, 0o600)
}

func restoreLocalState(dir string, active *ActivePointer) error {
	if active == nil {
		path := filepath.Join(dir, ActiveFilename)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return activatePointer(dir, *active)
}

func writeSnapshotProvenance(dir string, ref SnapshotRef, provenance RefreshProvenance) error {
	if err := provenance.Validate(); err != nil {
		return err
	}
	manifestPath, err := resolveSnapshotPath(dir, ref.Manifest)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWrite(filepath.Join(filepath.Dir(manifestPath), "refresh-provenance.json"), raw, 0o600)
}

func metadataPtr(m Metadata) *Metadata {
	copy := m
	return &copy
}

// SortedSnapshotDigests is intentionally small and read-only; it is useful for
// diagnostics and tests without turning the refresh store into a mutable DB.
func SortedSnapshotDigests(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && validSHA256(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

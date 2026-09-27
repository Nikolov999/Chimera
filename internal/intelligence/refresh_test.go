package intelligence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedTestBundle(t *testing.T, store Store, pub ed25519.PublicKey, priv ed25519.PrivateKey, created time.Time) []byte {
	t.Helper()
	store.Normalize()
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := decode(raw, "test://candidate", "TEST")
	if err != nil {
		t.Fatal(err)
	}
	bundle := SignedBundle{
		Schema: RefreshSchemaVersion, KeyID: KeyID(pub), Version: loaded.Metadata.Version,
		CreatedAt: created.UTC(), ManifestDigest: loaded.Metadata.Digest, Manifest: loaded.Store,
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SignaturePayload(bundle)))
	out, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func candidateStore(t *testing.T, version string, retrieved time.Time) Store {
	t.Helper()
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	store := builtin.Store
	store.Version = version
	store.RetrievedAt = retrieved.UTC()
	for i := range store.Sources {
		store.Sources[i].RetrievedAt = retrieved.UTC()
	}
	return store
}

func serveBundle(raw []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
}

func TestPhase032SignedRefreshAtomicActivationAndRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)

	firstRaw := signedTestBundle(t, candidateStore(t, "2026.08-phase032-test1", now.Add(-2*time.Hour)), pub, priv, now.Add(-90*time.Minute))
	firstServer := serveBundle(firstRaw)
	defer firstServer.Close()
	first, err := Refresh(context.Background(), RefreshOptions{URL: firstServer.URL, Directory: dir, TrustedPublicKey: pub, Now: now, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.State != "APPLIED" || !first.AtomicActivation || !first.NetworkAccess || first.PreviousAvailable {
		t.Fatalf("unexpected first refresh result: %#v", first)
	}
	if _, err := os.Stat(filepath.Join(dir, ActiveFilename)); err != nil {
		t.Fatalf("active pointer missing: %v", err)
	}

	secondNow := now.Add(time.Hour)
	secondRaw := signedTestBundle(t, candidateStore(t, "2026.08-phase032-test2", now.Add(30*time.Minute)), pub, priv, now.Add(35*time.Minute))
	secondServer := serveBundle(secondRaw)
	defer secondServer.Close()
	second, err := Refresh(context.Background(), RefreshOptions{URL: secondServer.URL, Directory: dir, TrustedPublicKey: pub, Now: secondNow, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.State != "APPLIED" || !second.PreviousAvailable || second.Previous == nil || second.Previous.Version != first.Current.Version {
		t.Fatalf("refresh did not preserve rollback snapshot: %#v", second)
	}

	t.Setenv(EnvDirectory, dir)
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.Version != "2026.08-phase032-test2" || loaded.Metadata.Digest != second.Current.Digest {
		t.Fatalf("active store is not second signed snapshot: %#v", loaded.Metadata)
	}

	rb, err := Rollback(dir, secondNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rb.State != "ROLLED_BACK" || rb.NetworkAccess || rb.To.Version != "2026.08-phase032-test1" {
		t.Fatalf("unexpected rollback result: %#v", rb)
	}
	loaded, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.Version != "2026.08-phase032-test1" {
		t.Fatalf("rollback did not activate prior snapshot: %#v", loaded.Metadata)
	}
}

func TestPhase032RejectsInvalidSignatureWithoutActivation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	raw := signedTestBundle(t, candidateStore(t, "2026.08-phase032-badsig", now.Add(-time.Hour)), pub, priv, now.Add(-30*time.Minute))
	server := serveBundle(raw)
	defer server.Close()
	dir := t.TempDir()
	if _, err := Refresh(context.Background(), RefreshOptions{URL: server.URL, Directory: dir, TrustedPublicKey: otherPub, Now: now, AllowInsecureHTTP: true}); err == nil {
		t.Fatal("expected untrusted bundle to be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, ActiveFilename)); !os.IsNotExist(err) {
		t.Fatalf("failed signature unexpectedly activated intelligence: %v", err)
	}
}

func TestPhase032RejectsSignedRollbackDuringRefresh(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	newerRaw := signedTestBundle(t, candidateStore(t, "newer", now.Add(-time.Hour)), pub, priv, now.Add(-30*time.Minute))
	newerServer := serveBundle(newerRaw)
	defer newerServer.Close()
	if _, err := Refresh(context.Background(), RefreshOptions{URL: newerServer.URL, Directory: dir, TrustedPublicKey: pub, Now: now, AllowInsecureHTTP: true}); err != nil {
		t.Fatal(err)
	}
	olderRaw := signedTestBundle(t, candidateStore(t, "older", now.Add(-2*time.Hour)), pub, priv, now.Add(-20*time.Minute))
	olderServer := serveBundle(olderRaw)
	defer olderServer.Close()
	if _, err := Refresh(context.Background(), RefreshOptions{URL: olderServer.URL, Directory: dir, TrustedPublicKey: pub, Now: now, AllowInsecureHTTP: true}); err == nil {
		t.Fatal("expected signed downgrade to be rejected")
	}
	t.Setenv(EnvDirectory, dir)
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.Version != "newer" {
		t.Fatalf("downgrade altered active snapshot: %#v", loaded.Metadata)
	}
}

func TestPhase032TrustedKeyParsing(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	parsed, err := ParseTrustedPublicKey([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(parsed) != KeyID(pub) {
		t.Fatal("parsed key identity changed")
	}
}

func TestPhase032UnchangedSignedRefreshPersistsProvenanceAndActivePointer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	store := candidateStore(t, "same-version", now.Add(-time.Hour))
	store.Normalize()
	rawManifest, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ManifestFilename), rawManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := signedTestBundle(t, store, pub, priv, now.Add(-30*time.Minute))
	server := serveBundle(bundle)
	defer server.Close()
	result, err := Refresh(context.Background(), RefreshOptions{URL: server.URL, Directory: dir, TrustedPublicKey: pub, Now: now, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "UNCHANGED" {
		t.Fatalf("unexpected state: %#v", result)
	}
	activeRaw, err := os.ReadFile(filepath.Join(dir, ActiveFilename))
	if err != nil {
		t.Fatal(err)
	}
	active, err := decodeActivePointer(activeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if active.Current.Provenance == nil || active.Current.Provenance.ManifestDigest != result.Current.Digest {
		t.Fatalf("signed provenance was not persisted: %#v", active.Current)
	}
}

func TestPhase032StrictBundleRejectsTrailingContent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	raw := append(signedTestBundle(t, candidateStore(t, "trailing", now.Add(-time.Hour)), pub, priv, now.Add(-30*time.Minute)), []byte(" trailing")...)
	server := serveBundle(raw)
	defer server.Close()
	if _, err := Refresh(context.Background(), RefreshOptions{URL: server.URL, Directory: t.TempDir(), TrustedPublicKey: pub, Now: now, AllowInsecureHTTP: true}); err == nil {
		t.Fatal("expected trailing bundle content to fail closed")
	}
}

func TestPhase032ActivePointerRejectsTraversal(t *testing.T) {
	p := ActivePointer{
		Schema:      ActiveSchemaVersion,
		ActivatedAt: time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC),
		Current:     SnapshotRef{Version: "x", DigestAlgorithm: "sha256", Digest: strings.Repeat("a", 64), Manifest: "../manifest.json"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected unsafe active pointer path to be rejected")
	}
}

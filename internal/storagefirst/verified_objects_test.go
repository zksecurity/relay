package storagefirst

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func TestVerifiedObjectsRoundTripAndFailSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verified-objects.json")
	missing := LoadVerifiedObjects(path)
	if _, ok := missing.Verified("blob/sha256/aa"); ok {
		t.Fatal("missing memo reported a verified object")
	}
	v := LoadVerifiedObjects(path)
	v.Record("blob/sha256/aa", store.ObjectVersion{ETag: "e1", VersionID: "v1", Size: 3})
	// Versions without an ETag or version id must not be pinned.
	v.Record("blob/sha256/bb", store.ObjectVersion{Size: 9})
	v.Record("blob/sha256/cc", store.ObjectVersion{ETag: "invalid\n", Size: 9})
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := LoadVerifiedObjects(path)
	version, ok := reloaded.Verified("blob/sha256/aa")
	if !ok || version != (store.ObjectVersion{ETag: "e1", VersionID: "v1", Size: 3}) {
		t.Fatalf("memo did not survive save/load: %v %v", version, ok)
	}
	if _, ok := reloaded.Verified("blob/sha256/bb"); ok {
		t.Fatal("unpinned version was remembered")
	}
	if _, ok := reloaded.Verified("blob/sha256/cc"); ok {
		t.Fatal("invalid version was remembered")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := LoadVerifiedObjects(path)
	if _, ok := corrupt.Verified("blob/sha256/aa"); ok {
		t.Fatal("corrupt memo reported a verified object")
	}
}

func TestSameVersionRequiresIdentity(t *testing.T) {
	pinned := store.ObjectVersion{ETag: "e1", Size: 3}
	if sameVersion(pinned, store.ObjectVersion{ETag: "e1", Size: 3}) != true {
		t.Fatal("identical versions did not match")
	}
	for _, other := range []store.ObjectVersion{
		{ETag: "e2", Size: 3},
		{ETag: "e1", Size: 4},
		{ETag: "e1", VersionID: "v9", Size: 3},
		{Size: 3},
		{ETag: "e1\n", Size: 3},
		{ETag: "e1", VersionID: "v1\r", Size: 3},
		{ETag: "e1", Size: -1},
	} {
		if sameVersion(pinned, other) {
			t.Fatalf("different version matched: %v", other)
		}
	}
	if sameVersion(store.ObjectVersion{Size: 3}, store.ObjectVersion{Size: 3}) {
		t.Fatal("size-only versions matched")
	}
}

func TestSameVersionTreatsProviderTokensAsOpaque(t *testing.T) {
	for _, version := range []store.ObjectVersion{
		{ETag: `"0123456789abcdef-17"`, Size: 1 << 30},
		{ETag: `"0123456789abcdef-17"`, VersionID: "null", Size: 1 << 30},
	} {
		if !sameVersion(version, version) {
			t.Fatalf("identical opaque provider version did not match: %+v", version)
		}
	}
	withNull := store.ObjectVersion{ETag: `"0123456789abcdef-17"`, VersionID: "null", Size: 1 << 30}
	withoutVersion := store.ObjectVersion{ETag: withNull.ETag, Size: withNull.Size}
	if sameVersion(withNull, withoutVersion) {
		t.Fatal("different opaque version-ID responses matched")
	}
}

// publishingFake is an in-memory PublishingStore. Uploads overlap for the
// configured delay so concurrency is observable, and tamper simulates an
// object replaced under an existing content-addressed key.
type publishingFake struct {
	mu          sync.Mutex
	stored      map[string][]byte
	version     map[string]store.ObjectVersion
	sequence    int
	putFail     map[string]error
	headFail    bool
	putDelay    time.Duration
	heads       int
	gets        int
	attempts    int
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
}

func newPublishingFake() *publishingFake {
	return &publishingFake{stored: map[string][]byte{}, version: map[string]store.ObjectVersion{}, putFail: map[string]error{}}
}

func (f *publishingFake) PutIfAbsent(key, local string) (store.ObjectVersion, error) {
	raw, err := os.ReadFile(local)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	f.mu.Lock()
	f.attempts++
	if fail, ok := f.putFail[key]; ok {
		f.mu.Unlock()
		return store.ObjectVersion{}, fail
	}
	_, exists := f.stored[key]
	f.mu.Unlock()
	if exists {
		return store.ObjectVersion{}, store.ErrExists
	}
	// Simulated upload window outside the lock so parallel publications and
	// the in-flight byte accounting are observable.
	now := f.inFlight.Add(int64(len(raw)))
	for {
		observed := f.maxInFlight.Load()
		if now <= observed || f.maxInFlight.CompareAndSwap(observed, now) {
			break
		}
	}
	if f.putDelay > 0 {
		time.Sleep(f.putDelay)
	}
	f.inFlight.Add(-int64(len(raw)))
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.stored[key]; ok {
		return store.ObjectVersion{}, store.ErrExists
	}
	f.sequence++
	version := store.ObjectVersion{ETag: fmt.Sprintf("etag-%d", f.sequence), VersionID: fmt.Sprintf("version-%d", f.sequence), Size: int64(len(raw))}
	f.stored[key] = raw
	f.version[key] = version
	return version, nil
}

func (f *publishingFake) HeadVersion(key string) (store.ObjectVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heads++
	if f.headFail {
		return store.ObjectVersion{}, errors.New("head unavailable")
	}
	version, ok := f.version[key]
	if !ok {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	return version, nil
}

func (f *publishingFake) GetVersionedAtMost(key, local string, maximum int64) (store.ObjectVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	raw, ok := f.stored[key]
	if !ok {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("too large")
	}
	if err := os.WriteFile(local, raw, 0o600); err != nil {
		return store.ObjectVersion{}, err
	}
	return f.version[key], nil
}

// tamper replaces the bytes and version stored under key, as a rewritten or
// corrupted object at a content-addressed key would appear.
func (f *publishingFake) tamper(key string, raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sequence++
	f.stored[key] = raw
	f.version[key] = store.ObjectVersion{ETag: fmt.Sprintf("etag-%d", f.sequence), VersionID: fmt.Sprintf("version-%d", f.sequence), Size: int64(len(raw))}
}

// reset empties the store so a benchmark iteration publishes freshly.
func (f *publishingFake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = map[string][]byte{}
	f.version = map[string]store.ObjectVersion{}
}

func writeArtifact(t testing.TB, dir, name string, raw []byte) (string, state.ContentRef) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, state.ContentRef{Name: name, SHA256: digestBytes(raw), Size: int64(len(raw))}
}

func TestPublishImmutableMemoSkipsUnchangedExistingVersion(t *testing.T) {
	dir := t.TempDir()
	path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	if fake.gets != 0 {
		t.Fatalf("unchanged version was re-downloaded: gets=%d", fake.gets)
	}
	if fake.heads != 1 {
		t.Fatalf("existing object was not checked by metadata: heads=%d", fake.heads)
	}
	if fake.attempts != 1 {
		t.Fatalf("unchanged version was retransmitted: attempts=%d", fake.attempts)
	}
}

func TestPublishImmutableMemoCatchesRewrittenObject(t *testing.T) {
	dir := t.TempDir()
	path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	fake.tamper(store.Key(ref.SHA256), []byte("replaced bytes"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err == nil {
		t.Fatal("rewritten object at a verified key was accepted")
	}
	if fake.gets != 1 {
		t.Fatalf("changed version did not fall back to a full fetch: gets=%d", fake.gets)
	}
	if fake.attempts != 2 {
		t.Fatalf("changed version skipped conditional create: attempts=%d", fake.attempts)
	}
}

func TestPublishImmutableMemoFallsBackWhenHeadUnavailable(t *testing.T) {
	dir := t.TempDir()
	path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	fake.headFail = true
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	if fake.gets != 1 {
		t.Fatalf("unavailable metadata did not fall back to a full fetch: gets=%d", fake.gets)
	}
	if fake.attempts != 2 {
		t.Fatalf("unavailable metadata skipped conditional create: attempts=%d", fake.attempts)
	}
}

func TestPublishImmutableMemoDoesNotHeadUnknownObject(t *testing.T) {
	dir := t.TempDir()
	path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	if fake.heads != 0 || fake.attempts != 1 {
		t.Fatalf("unknown object used preflight metadata: heads=%d attempts=%d", fake.heads, fake.attempts)
	}
}

func TestPublishImmutableMemoMismatchRetainsConditionalAndFetch(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(store.ObjectVersion) store.ObjectVersion
	}{
		{"etag", func(v store.ObjectVersion) store.ObjectVersion { v.ETag = "changed"; return v }},
		{"version-id", func(v store.ObjectVersion) store.ObjectVersion { v.VersionID = "changed"; return v }},
		{"size", func(v store.ObjectVersion) store.ObjectVersion { v.Size++; return v }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
			fake := newPublishingFake()
			memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
			if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
				t.Fatal(err)
			}
			key := store.Key(ref.SHA256)
			fake.mu.Lock()
			fake.version[key] = test.change(fake.version[key])
			fake.mu.Unlock()
			err := PublishImmutable(fake, ref, path, dir, memo)
			if test.name == "size" && err == nil {
				t.Fatal("provider size mismatch was accepted")
			}
			if test.name != "size" && err != nil {
				t.Fatal(err)
			}
			if fake.attempts != 2 || fake.gets != 1 {
				t.Fatalf("mismatch bypassed fallback: attempts=%d gets=%d", fake.attempts, fake.gets)
			}
		})
	}
}

type cancellingHeadStore struct {
	*publishingFake
	cancel context.CancelFunc
}

func (s cancellingHeadStore) HeadVersion(key string) (store.ObjectVersion, error) {
	version, err := s.publishingFake.HeadVersion(key)
	s.cancel()
	return version, err
}

func TestPublishImmutableMemoCancellationAfterHeadDoesNotUpload(t *testing.T) {
	dir := t.TempDir()
	path, ref := writeArtifact(t, dir, "artifacts/a.bin", []byte("payload-a"))
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := PublishImmutableContext(ctx, cancellingHeadStore{publishingFake: fake, cancel: cancel}, ref, path, dir, memo)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after HEAD = %v", err)
	}
	if fake.attempts != 1 {
		t.Fatalf("cancellation fell through to upload: attempts=%d", fake.attempts)
	}
}

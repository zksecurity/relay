package storagefirst

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func artifactRefs(t testing.TB, root string, names ...string) []state.ContentRef {
	t.Helper()
	refs := make([]state.ContentRef, 0, len(names))
	for _, name := range names {
		raw := []byte("payload-" + name)
		_, ref := writeArtifact(t, root, name, raw)
		refs = append(refs, ref)
	}
	return refs
}

func TestPublishArtifactsPublishesAllAndMemoSkipsReverifiedObjects(t *testing.T) {
	root := t.TempDir()
	fake := newPublishingFake()
	memoPath := filepath.Join(root, "verified-objects.json")
	memo := LoadVerifiedObjects(memoPath)
	refs := artifactRefs(t, root, "a.bin", "b.bin", "c.bin", "d.bin", "e.bin")
	if err := PublishArtifacts(fake, refs, root, root, memo, PublishLimits{InFlightBytes: 1 << 20, Workers: 4}); err != nil {
		t.Fatal(err)
	}
	if fake.attempts != len(refs) {
		t.Fatalf("uploads attempted=%d want %d", fake.attempts, len(refs))
	}
	if err := memo.Save(); err != nil {
		t.Fatal(err)
	}
	// The next checkpoint carries the same cumulative inventory plus one new
	// artifact: existing objects must be confirmed by metadata only.
	reloaded := LoadVerifiedObjects(memoPath)
	next := append(artifactRefs(t, root, "f.bin"), refs...)
	if err := PublishArtifacts(fake, next, root, root, reloaded, PublishLimits{InFlightBytes: 1 << 20, Workers: 4}); err != nil {
		t.Fatal(err)
	}
	if fake.gets != 0 {
		t.Fatalf("already-verified objects were re-downloaded: gets=%d", fake.gets)
	}
	if fake.heads != len(refs) {
		t.Fatalf("existing objects not confirmed by metadata: heads=%d want %d", fake.heads, len(refs))
	}
	for _, ref := range next {
		if _, ok := fake.version[store.Key(ref.SHA256)]; !ok {
			t.Fatalf("artifact %q was not stored", ref.Name)
		}
	}
}

func TestPublishArtifactsConflictingRemoteObjectFails(t *testing.T) {
	root := t.TempDir()
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(root, "verified-objects.json"))
	refs := artifactRefs(t, root, "a.bin", "b.bin")
	if err := PublishArtifacts(fake, refs, root, root, memo, PublishLimits{InFlightBytes: 1 << 20, Workers: 2}); err != nil {
		t.Fatal(err)
	}
	if err := memo.Save(); err != nil {
		t.Fatal(err)
	}
	fake.tamper(store.Key(refs[0].SHA256), []byte("conflicting bytes"))
	err := PublishArtifacts(fake, refs, root, root, LoadVerifiedObjects(memo.path), PublishLimits{InFlightBytes: 1 << 20, Workers: 2})
	if err == nil || !strings.Contains(err.Error(), "a.bin") {
		t.Fatalf("conflicting remote object was not reported against its artifact: %v", err)
	}
	if fake.gets != 1 {
		t.Fatalf("changed version must trigger exactly one full fetch: gets=%d", fake.gets)
	}
}

func TestPublishArtifactsReportsDeterministicFirstError(t *testing.T) {
	root := t.TempDir()
	fake := newPublishingFake()
	fake.putDelay = time.Millisecond
	// "z-fast" fails during upload almost immediately; "a-slow" fails later,
	// after hashing a large wrong-digest file. The reported failure must be
	// the first in logical-name order regardless of which failed first.
	slow := make([]byte, 48<<20)
	if err := os.WriteFile(filepath.Join(root, "a-slow.bin"), slow, 0o600); err != nil {
		t.Fatal(err)
	}
	refs := []state.ContentRef{{Name: "a-slow.bin", SHA256: digestBytes([]byte("wrong digest")), Size: int64(len(slow))}}
	_, fastRef := writeArtifact(t, root, "z-fast.bin", []byte("payload-z"))
	fake.putFail[store.Key(fastRef.SHA256)] = errors.New("injected upload failure")
	refs = append(refs, fastRef)
	err := PublishArtifacts(fake, refs, root, root, nil, PublishLimits{InFlightBytes: 1 << 30, Workers: 2})
	if err == nil || !strings.Contains(err.Error(), "a-slow.bin") {
		t.Fatalf("error was not the first artifact in name order: %v", err)
	}
}

func TestPublishArtifactsStopsUnstartedArtifactsAfterFailure(t *testing.T) {
	root := t.TempDir()
	fake := newPublishingFake()
	refs := artifactRefs(t, root, "a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin")
	fake.putFail[store.Key(refs[0].SHA256)] = errors.New("injected upload failure")
	err := PublishArtifacts(fake, refs, root, root, nil, PublishLimits{InFlightBytes: 1 << 20, Workers: 1})
	if err == nil || !strings.Contains(err.Error(), "a.bin") {
		t.Fatalf("expected failure on the first artifact: %v", err)
	}
	if fake.attempts != 1 {
		t.Fatalf("artifacts were started after a failure: attempts=%d", fake.attempts)
	}
}

func TestPublishArtifactsRetriesIdempotentlyAfterPartialFailure(t *testing.T) {
	root := t.TempDir()
	fake := newPublishingFake()
	refs := artifactRefs(t, root, "a.bin", "b.bin", "c.bin")
	fake.putFail[store.Key(refs[1].SHA256)] = errors.New("injected upload failure")
	if err := PublishArtifacts(fake, refs, root, root, nil, PublishLimits{InFlightBytes: 1 << 20, Workers: 1}); err == nil {
		t.Fatal("partial failure was not reported")
	}
	delete(fake.putFail, store.Key(refs[1].SHA256))
	if err := PublishArtifacts(fake, refs, root, root, nil, PublishLimits{InFlightBytes: 1 << 20, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if _, ok := fake.version[store.Key(ref.SHA256)]; !ok {
			t.Fatalf("artifact %q missing after retry", ref.Name)
		}
	}
}

func TestPublishArtifactsBoundsInFlightBytes(t *testing.T) {
	root := t.TempDir()
	names := []string{"a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin"}
	refs := make([]state.ContentRef, 0, len(names))
	for index, name := range names {
		raw := make([]byte, 100)
		raw[0] = byte(index)
		_, ref := writeArtifact(t, root, name, raw)
		refs = append(refs, ref)
	}
	// A cap that admits every artifact at once: the upload windows overlap,
	// so the accounting must observe more than a single artifact in flight.
	wide := newPublishingFake()
	wide.putDelay = 10 * time.Millisecond
	if err := PublishArtifacts(wide, refs, root, root, nil, PublishLimits{InFlightBytes: 1000, Workers: 6}); err != nil {
		t.Fatal(err)
	}
	if observed := wide.maxInFlight.Load(); observed <= 100 {
		t.Fatalf("wide cap showed no overlap: max in-flight bytes=%d", observed)
	}
	// A cap of 150 bytes with 100-byte artifacts admits one at a time, so the
	// observed in-flight bytes can never exceed the cap.
	narrow := newPublishingFake()
	narrow.putDelay = 10 * time.Millisecond
	if err := PublishArtifacts(narrow, refs, root, root, nil, PublishLimits{InFlightBytes: 150, Workers: 6}); err != nil {
		t.Fatal(err)
	}
	if observed := narrow.maxInFlight.Load(); observed > 150 {
		t.Fatalf("in-flight bytes exceeded the cap: %d > 150", observed)
	}
}

func benchRefs(b *testing.B, root string, count int) []state.ContentRef {
	b.Helper()
	refs := make([]state.ContentRef, 0, count)
	for index := 0; index < count; index++ {
		raw := make([]byte, 64<<10)
		raw[0] = byte(index)
		_, ref := writeArtifact(b, root, fmt.Sprintf("bench-%03d.bin", index), raw)
		refs = append(refs, ref)
	}
	return refs
}

// BenchmarkPublishArtifactsFresh* records fresh-publication wall-clock for 64
// artifacts with a 2ms upload window per object, single-worker versus the
// default bounded parallelism.
func BenchmarkPublishArtifactsFreshSequential(b *testing.B) {
	dir := b.TempDir()
	refs := benchRefs(b, dir, 64)
	fake := newPublishingFake()
	fake.putDelay = 2 * time.Millisecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fake.reset()
		if err := PublishArtifacts(fake, refs, dir, dir, nil, PublishLimits{InFlightBytes: 1 << 30, Workers: 1}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPublishArtifactsFreshParallel(b *testing.B) {
	dir := b.TempDir()
	refs := benchRefs(b, dir, 64)
	fake := newPublishingFake()
	fake.putDelay = 2 * time.Millisecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fake.reset()
		if err := PublishArtifacts(fake, refs, dir, dir, nil, DefaultPublishLimits()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPublishArtifactsRepublishMemo records the cumulative-inventory
// case: re-publishing 64 already-verified artifacts confirms each one by a
// metadata request instead of re-downloading it.
func BenchmarkPublishArtifactsRepublishMemo(b *testing.B) {
	dir := b.TempDir()
	refs := benchRefs(b, dir, 64)
	fake := newPublishingFake()
	memo := LoadVerifiedObjects(filepath.Join(dir, "verified-objects.json"))
	if err := PublishArtifacts(fake, refs, dir, dir, memo, DefaultPublishLimits()); err != nil {
		b.Fatal(err)
	}
	if err := memo.Save(); err != nil {
		b.Fatal(err)
	}
	reloaded := LoadVerifiedObjects(memo.path)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := PublishArtifacts(fake, refs, dir, dir, reloaded, DefaultPublishLimits()); err != nil {
			b.Fatal(err)
		}
	}
}

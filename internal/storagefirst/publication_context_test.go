package storagefirst

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type cancellationStore struct {
	ctx     context.Context
	entered chan struct{}
	drain   chan struct{}
	calls   atomic.Int32
}

func (s *cancellationStore) PutIfAbsent(_, _ string) (store.ObjectVersion, error) {
	s.calls.Add(1)
	s.entered <- struct{}{}
	<-s.ctx.Done()
	<-s.drain
	return store.ObjectVersion{}, s.ctx.Err()
}
func (s *cancellationStore) GetVersionedAtMost(_, _ string, _ int64) (store.ObjectVersion, error) {
	return store.ObjectVersion{}, errors.New("unexpected fetch")
}

func TestPublishArtifactsCancellationDrainsWorkers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits PublishLimits
	}{
		{"worker-slot", PublishLimits{Workers: 1, InFlightBytes: 1024}},
		{"byte-budget", PublishLimits{Workers: 2, InFlightBytes: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			refs := artifactRefs(t, dir, "a.bin", "b.bin", "c.bin")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			objects := &cancellationStore{ctx: ctx, entered: make(chan struct{}, 3), drain: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- PublishArtifactsContext(ctx, objects, refs, dir, dir, nil, tc.limits) }()
			select {
			case <-objects.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("provider not entered")
			}
			cancel()
			select {
			case err := <-done:
				t.Fatalf("returned before provider drained: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(objects.drain)
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled dispatcher did not return")
			}
			if objects.calls.Load() != 1 {
				t.Fatalf("admitted later uploads: %d", objects.calls.Load())
			}
			leftovers, _ := filepath.Glob(filepath.Join(dir, "relay-immutable-upload-*"))
			if len(leftovers) != 0 {
				t.Fatal("staging not cleaned", leftovers)
			}
		})
	}
}

func TestPublishArtifactsPreCancelledAndEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	objects := newPublishingFake()
	for _, refs := range [][]state.ContentRef{nil, artifactRefs(t, dir, "a.bin")} {
		if err := PublishArtifactsContext(ctx, objects, refs, dir, dir, nil, DefaultPublishLimits()); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled batch returned %v", err)
		}
	}
	if objects.attempts != 0 {
		t.Fatal("cancelled batch contacted provider")
	}
	if err := PublishArtifactsContext(context.Background(), objects, nil, dir, dir, nil, DefaultPublishLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestByteSemaphoreCancelledWaitDoesNotConsumeCapacity(t *testing.T) {
	s := newByteSemaphore(1)
	if err := s.acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.acquire(ctx, 1) }()
	cancel()
	// The held token is deliberately not released until cancellation wakes the waiter.
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled capacity waiter stuck")
	}
	s.release(1)
	if err := s.acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}

type cancelledFallbackStore struct {
	cancel  context.CancelFunc
	raw     []byte
	created bool
}

func (s cancelledFallbackStore) PutIfAbsent(_, _ string) (store.ObjectVersion, error) {
	if s.created {
		s.cancel()
		return store.ObjectVersion{ETag: "created", Size: int64(len(s.raw))}, nil
	}
	return store.ObjectVersion{}, store.ErrExists
}
func (s cancelledFallbackStore) GetVersionedAtMost(_, local string, _ int64) (store.ObjectVersion, error) {
	if err := os.WriteFile(local, s.raw, 0600); err != nil {
		return store.ObjectVersion{}, err
	}
	s.cancel() // Simulate cancellation racing a successful download response.
	return store.ObjectVersion{ETag: "existing", Size: int64(len(s.raw))}, nil
}
func TestPublishImmutableCancellationAfterProviderSuccess(t *testing.T) {
	for _, created := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback-read", true: "upload"}[created], func(t *testing.T) {
			dir := t.TempDir()
			raw := []byte("public artifact")
			path, ref := writeArtifact(t, dir, "a.bin", raw)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			memo := LoadVerifiedObjects(filepath.Join(dir, "memo.json"))
			err := PublishImmutableContext(ctx, cancelledFallbackStore{cancel: cancel, raw: raw, created: created}, ref, path, dir, memo)
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation became success", err)
			}
			if _, ok := memo.Verified(store.Key(ref.SHA256)); ok {
				t.Fatal("cancelled operation recorded memo success")
			}
			leftovers, _ := filepath.Glob(filepath.Join(dir, "relay-immutable-upload-*"))
			if len(leftovers) != 0 {
				t.Fatal("cancelled upload retained staging")
			}
		})
	}
}

type cancelOnRead struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (r cancelOnRead) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}
func TestPublicationHashReaderStopsBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := bytes.Repeat([]byte("x"), 128<<10)
	n, err := io.Copy(io.Discard, contextReader{ctx: ctx, reader: cancelOnRead{reader: bytes.NewReader(raw), cancel: cancel}})
	if !errors.Is(err, context.Canceled) || n == 0 || n >= int64(len(raw)) {
		t.Fatalf("hash/copy ignored mid-read cancellation: %d %v", n, err)
	}
}

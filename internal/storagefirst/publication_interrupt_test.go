package storagefirst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

// A subprocess receives a real SIGINT while PublishArtifacts has staged bytes
// and is waiting on a provider. Disk-backed fake storage survives that process.
// This tests the publication layer, not live AWS/R2 or signed RootCommit.
type interruptionStore struct {
	root, blockKey string
	ctx            context.Context
}

func (s interruptionStore) PutIfAbsent(key, local string) (store.ObjectVersion, error) {
	raw, err := os.ReadFile(local)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	if key == s.blockKey {
		if err := os.WriteFile(filepath.Join(s.root, "upload-started"), []byte(local), 0600); err != nil {
			return store.ObjectVersion{}, err
		}
		<-s.ctx.Done()
		return store.ObjectVersion{}, s.ctx.Err()
	}
	path := filepath.Join(s.root, "objects", filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return store.ObjectVersion{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return store.ObjectVersion{}, store.ErrExists
	}
	if err != nil {
		return store.ObjectVersion{}, err
	}
	_, writeErr := f.Write(raw)
	closeErr := f.Close()
	return store.ObjectVersion{ETag: key, Size: int64(len(raw))}, errors.Join(writeErr, closeErr)
}
func (s interruptionStore) GetVersionedAtMost(key, local string, maximum int64) (store.ObjectVersion, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, "objects", filepath.FromSlash(key)))
	if err != nil {
		return store.ObjectVersion{}, err
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("oversized object")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
		return store.ObjectVersion{}, err
	}
	if err := os.WriteFile(local, raw, 0600); err != nil {
		return store.ObjectVersion{}, err
	}
	if err := os.WriteFile(filepath.Join(s.root, "reverified-"+filepath.Base(key)), nil, 0600); err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{ETag: key, Size: int64(len(raw))}, nil
}

func TestPublicationInterruptHelper(t *testing.T) {
	root := os.Getenv("RELAY_TEST_PUBLICATION_INTERRUPT_ROOT")
	if root == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(filepath.Join(root, "refs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var refs []state.ContentRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	objects := interruptionStore{root: root, ctx: ctx}
	if os.Getenv("RELAY_TEST_PUBLICATION_INTERRUPT_BLOCK") == "1" {
		objects.blockKey = store.Key(refs[1].SHA256)
	}
	if err := PublishArtifactsContext(ctx, objects, refs, filepath.Join(root, "source"), filepath.Join(root, "staging"), nil, PublishLimits{Workers: 2, InFlightBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	// Same sequencing as commit-v4: no checkpoint/root publication may follow
	// until the entire batch returns successfully. This marker is not a signed root.
	if err := os.WriteFile(filepath.Join(root, "batch-complete"), []byte("complete"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPublishArtifactsSignals(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) { testPublishArtifactsSignal(t, sig) })
	}
}

func testPublishArtifactsSignal(t *testing.T, sig os.Signal) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix interrupt signals")
	}
	root := t.TempDir()
	source, staging := filepath.Join(root, "source"), filepath.Join(root, "staging")
	for _, p := range []string{source, staging} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(staging, "relay-immutable-upload-preexisting")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(unrelated, "preserve")
	if err := os.WriteFile(marker, []byte("unrelated retained work"), 0600); err != nil {
		t.Fatal(err)
	}
	refs := artifactRefs(t, source, "a.bin", "b.bin", "c.bin")
	raw, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "refs.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	child := func(block bool) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPublicationInterruptHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "RELAY_TEST_PUBLICATION_INTERRUPT_ROOT="+root, "RELAY_TEST_PUBLICATION_INTERRUPT_BLOCK=0")
		if block {
			cmd.Env[len(cmd.Env)-1] = "RELAY_TEST_PUBLICATION_INTERRUPT_BLOCK=1"
		}
		return cmd
	}
	cmd := child(true)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, started := os.Stat(filepath.Join(root, "upload-started"))
		_, uploaded := os.Stat(filepath.Join(root, "objects", filepath.FromSlash(store.Key(refs[0].SHA256))))
		if started == nil && uploaded == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("child exited before interruption: %v\n%s", err, output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for in-flight upload")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("interrupted publication returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not stop after SIGINT")
	}
	if !bytes.Contains(output.Bytes(), []byte("context canceled")) {
		t.Fatalf("child did not drain through cancellation: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(root, "batch-complete")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial batch reported complete", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(staging, "relay-immutable-upload-*"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Signal stopped active upload; batch-complete marker absent; retained staging directories (including unrelated sentinel): %d", len(leftovers))
	t.Run("safe-retry", func(t *testing.T) {
		if output, err := child(false).CombinedOutput(); err != nil {
			t.Fatalf("retry failed: %v\n%s", err, output)
		}
		if _, err := os.Stat(filepath.Join(root, "reverified-"+filepath.Base(store.Key(refs[0].SHA256)))); err != nil {
			t.Fatal("retry did not reread the previously uploaded object", err)
		}
		for _, ref := range refs {
			got, err := os.ReadFile(filepath.Join(root, "objects", filepath.FromSlash(store.Key(ref.SHA256))))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(source, ref.Name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("object differs after retry: %s", ref.Name)
			}
		}
		if _, err := os.Stat(filepath.Join(root, "batch-complete")); err != nil {
			t.Fatal("retry never completed", err)
		}
	})
	t.Run("clean-staging", func(t *testing.T) {
		remaining, err := filepath.Glob(filepath.Join(staging, "relay-immutable-upload-*"))
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(marker)
		if err != nil || string(contents) != "unrelated retained work" {
			t.Fatal("unrelated directory changed", err)
		}
		if len(remaining) != 1 || remaining[0] != unrelated {
			t.Fatalf("cancellation left unexpected staging directories (%d total)", len(remaining))
		}
	})
}

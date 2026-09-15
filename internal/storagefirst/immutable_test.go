package storagefirst

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type immutableFake struct {
	existing []byte
	putErr   error
	puts     int
}

func (f *immutableFake) PutIfAbsent(_ string, _ string) (store.ObjectVersion, error) {
	f.puts++
	return store.ObjectVersion{}, f.putErr
}
func (f *immutableFake) GetVersionedAtMost(_ string, local string, maximum int64) (store.ObjectVersion, error) {
	if int64(len(f.existing)) > maximum {
		return store.ObjectVersion{}, errors.New("too large")
	}
	if err := os.WriteFile(local, f.existing, 0o600); err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{ETag: "existing", Size: int64(len(f.existing))}, nil
}

func TestPublishImmutableVerifiesExistingBytesOnRetry(t *testing.T) {
	raw := []byte("checkpoint")
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ref := state.ContentRef{Name: "checkpoints/0.json", SHA256: digestBytes(raw), Size: int64(len(raw))}
	storeFake := &immutableFake{existing: raw, putErr: store.ErrExists}
	if err := PublishImmutable(storeFake, ref, path, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	storeFake.existing = []byte("other bytes")
	if err := PublishImmutable(storeFake, ref, path, t.TempDir()); err == nil {
		t.Fatal("pre-existing different bytes accepted")
	}
}

func TestPublishImmutableRejectsWrongLocalBytesBeforeUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	storeFake := &immutableFake{}
	err := PublishImmutable(storeFake, state.ContentRef{Name: "x", SHA256: digestBytes([]byte("right")), Size: 5}, path, t.TempDir())
	if err == nil || storeFake.puts != 0 {
		t.Fatalf("err=%v puts=%d", err, storeFake.puts)
	}
}

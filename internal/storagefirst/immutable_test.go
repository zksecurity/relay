package storagefirst

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func TestVerifyLocalRefStreamsLargeArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contribution.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const size = 32 << 20
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	file.Close()
	ref := state.ContentRef{Name: "contribution.bin", SHA256: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Size: size}
	if err := verifyLocalRef(ref, path); err != nil {
		t.Fatal(err)
	}
	for _, delta := range []int64{-1, 1} {
		changed := ref
		changed.Size += delta
		if err := verifyLocalRef(changed, path); err == nil {
			t.Fatal("wrong size accepted")
		}
	}
	ref.SHA256 = digestBytes([]byte("wrong"))
	if err := verifyLocalRef(ref, path); err == nil {
		t.Fatal("wrong digest accepted")
	}
}

func TestVerifyLocalRefRejectsSymlinkAndInvalidReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload")
	if err := os.WriteFile(path, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	ref := state.ContentRef{Name: "payload", SHA256: digestBytes([]byte("ok")), Size: 2}
	if err := verifyLocalRef(ref, link); err == nil {
		t.Fatal("symlink accepted")
	}
	ref.SHA256 = "invalid"
	if err := verifyLocalRef(ref, path); err == nil {
		t.Fatal("invalid reference accepted")
	}
}

type immutableFake struct {
	existing []byte
	putErr   error
	puts     int
}

type replacingUploadStore struct {
	original string
	uploaded []byte
}

func (s *replacingUploadStore) PutIfAbsent(_ string, source string) (store.ObjectVersion, error) {
	if err := os.WriteFile(s.original, []byte("changed"), 0600); err != nil {
		return store.ObjectVersion{}, err
	}
	var err error
	s.uploaded, err = os.ReadFile(source)
	return store.ObjectVersion{}, err
}

func (s *replacingUploadStore) GetVersionedAtMost(_, _ string, _ int64) (store.ObjectVersion, error) {
	return store.ObjectVersion{}, errors.New("unexpected fetch")
}

func TestPublishImmutableStagesVerifiedBytesBeforeProviderReopensSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original")
	raw := []byte("correct")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s := &replacingUploadStore{original: path}
	ref := state.ContentRef{Name: "payload", SHA256: digestBytes(raw), Size: int64(len(raw))}
	if err := PublishImmutable(s, ref, path, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	if string(s.uploaded) != string(raw) {
		t.Fatalf("uploaded replaced source: %q", s.uploaded)
	}
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
	if err := PublishImmutable(storeFake, ref, path, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	storeFake.existing = []byte("other bytes")
	if err := PublishImmutable(storeFake, ref, path, t.TempDir(), nil); err == nil {
		t.Fatal("pre-existing different bytes accepted")
	}
}

func TestPublishImmutableRejectsWrongLocalBytesBeforeUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	storeFake := &immutableFake{}
	err := PublishImmutable(storeFake, state.ContentRef{Name: "x", SHA256: digestBytes([]byte("right")), Size: 5}, path, t.TempDir(), nil)
	if err == nil || storeFake.puts != 0 {
		t.Fatalf("err=%v puts=%d", err, storeFake.puts)
	}
}

// fallbackSpaceStore observes disk usage at the boundary between upload and
// download, where retaining the upload would double the reservation.
type fallbackSpaceStore struct {
	*publishingFake
	fetched bool
}

func (s *fallbackSpaceStore) GetVersionedAtMost(key, local string, maximum int64) (store.ObjectVersion, error) {
	if _, err := os.Lstat(filepath.Join(filepath.Dir(local), "payload")); !errors.Is(err, os.ErrNotExist) {
		return store.ObjectVersion{}, errors.New("upload copy still occupies disk space before fallback download")
	}
	s.fetched = true
	return s.publishingFake.GetVersionedAtMost(key, local, maximum)
}

func TestPublishImmutableReleasesUploadSpaceBeforeFallback(t *testing.T) {
	for _, useMemo := range []bool{false, true} {
		name := "without-memo"
		if useMemo {
			name = "empty-memo"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path, ref := writeArtifact(t, dir, "artifact.bin", []byte("retained artifact"))
			fake := &fallbackSpaceStore{publishingFake: newPublishingFake()}
			if err := PublishImmutable(fake, ref, path, dir, nil); err != nil {
				t.Fatal(err)
			}
			var memo *VerifiedObjects
			if useMemo {
				memo = LoadVerifiedObjects(filepath.Join(dir, "memo.json"))
			}
			if err := PublishImmutable(fake, ref, path, dir, memo); err != nil {
				t.Fatal(err)
			}
			if !fake.fetched {
				t.Fatal("expected fallback download")
			}
		})
	}
}

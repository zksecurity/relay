package storagefirst

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type ImmutableStore interface {
	GetVersionedAtMost(key, localPath string, maximum int64) (store.ObjectVersion, error)
	PutIfAbsent(key, localPath string) (store.ObjectVersion, error)
}

// PublishImmutable creates a content-addressed object. If the key already
// exists, it downloads and hashes those bytes before treating the operation as
// an idempotent retry. Mere existence is not proof of identical content.
func PublishImmutable(objects ImmutableStore, ref state.ContentRef, localPath, tempParent string) error {
	if objects == nil {
		return errors.New("immutable object store is required")
	}
	if err := verifyLocalRef(ref, localPath); err != nil {
		return err
	}
	_, err := objects.PutIfAbsent(store.Key(ref.SHA256), localPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrExists) {
		return err
	}
	temp, tempErr := os.MkdirTemp(tempParent, "relay-existing-object-")
	if tempErr != nil {
		return tempErr
	}
	defer os.RemoveAll(temp)
	return fetchExact(objects, ref, filepath.Join(temp, "object"))
}

func verifyLocalRef(ref state.ContentRef, localPath string) error {
	info, err := os.Lstat(localPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("immutable upload source must be a regular non-symlink file")
	}
	if info.Size() != ref.Size {
		return fmt.Errorf("immutable upload source size %d, want %d", info.Size(), ref.Size)
	}
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if digestBytes(raw) != ref.SHA256 {
		return errors.New("immutable upload source digest does not match its reference")
	}
	return nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

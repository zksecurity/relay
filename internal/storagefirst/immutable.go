package storagefirst

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	// The provider reopens its source path. Stage an independently verified
	// private copy so a replacement of the caller's file cannot change what is
	// uploaded after verification.
	temp, err := os.MkdirTemp(tempParent, "relay-immutable-upload-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	staged := filepath.Join(temp, "payload")
	if err := stageDeliveryFile(localPath, staged, deliveryFile{SHA256: ref.SHA256, Size: ref.Size}); err != nil {
		return err
	}
	_, err = objects.PutIfAbsent(store.Key(ref.SHA256), staged)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrExists) {
		return err
	}
	return fetchExact(objects, ref, filepath.Join(temp, "object"))
}

func verifyLocalRef(ref state.ContentRef, localPath string) error {
	if ref.Size <= 0 || !validDigest(ref.SHA256) {
		return errors.New("immutable reference requires a positive size and valid SHA-256")
	}
	info, err := os.Lstat(localPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("immutable upload source must be a regular non-symlink file")
	}
	if info.Size() != ref.Size {
		return fmt.Errorf("immutable upload source size %d, want %d", info.Size(), ref.Size)
	}
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != ref.Size {
		return errors.New("immutable source changed while opening")
	}
	hash := sha256.New()
	// Hash only the declared bytes, then check for growth without size+1 overflow.
	n, err := io.Copy(hash, io.LimitReader(file, ref.Size))
	if err != nil {
		return err
	}
	var extra [1]byte
	more, readErr := file.Read(extra[:])
	if n != ref.Size || more != 0 || readErr != io.EOF {
		return errors.New("immutable source size changed while hashing")
	}
	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return errors.New("immutable source changed while hashing")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
		return errors.New("immutable upload source digest does not match its reference")
	}
	return nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

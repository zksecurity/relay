package storagefirst

import (
	"context"
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

// PublishingStore is an ImmutableStore that can also report an object's
// current version metadata without downloading it.
type PublishingStore interface {
	ImmutableStore
	HeadVersion(key string) (store.ObjectVersion, error)
}

// PublishImmutable creates a content-addressed object. If the key already
// exists, the stored bytes are confirmed before the operation is treated as
// an idempotent retry: with a memo, one metadata request shows the stored
// version is the exact one this workspace digest-verified earlier; without
// one, the object is downloaded and hashed. Mere existence is not proof of
// identical content, and a nil memo keeps the always-fetch behavior.
func PublishImmutable(objects ImmutableStore, ref state.ContentRef, localPath, tempParent string, memo *VerifiedObjects) error {
	return PublishImmutableContext(context.Background(), objects, ref, localPath, tempParent, memo)
}

// PublishImmutableContext makes staging and verification cancellable. Provider
// calls must also be bound to ctx by the caller; cleanup waits for them to return.
func PublishImmutableContext(ctx context.Context, objects ImmutableStore, ref state.ContentRef, localPath, tempParent string, memo *VerifiedObjects) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if objects == nil {
		return errors.New("immutable object store is required")
	}
	if ref.Size <= 0 || !validDigest(ref.SHA256) {
		return errors.New("immutable reference requires a positive size and valid SHA-256")
	}
	// The provider reopens its source path. Stage a private copy that is
	// hashed while it is copied, so a replacement of the caller's file cannot
	// change what is uploaded, and the digest covers exactly the uploaded
	// bytes. One read of the source verifies both.
	temp, err := os.MkdirTemp(tempParent, "relay-immutable-upload-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temp); err != nil {
			result = errors.Join(result, fmt.Errorf("clean staged upload: %w", err))
		}
	}()
	staged := filepath.Join(temp, "payload")
	if err := stageDeliveryFileContext(ctx, localPath, staged, deliveryFile{SHA256: ref.SHA256, Size: ref.Size}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := store.Key(ref.SHA256)
	created, err := objects.PutIfAbsent(key, staged)
	if cancelErr := ctx.Err(); cancelErr != nil {
		return cancelErr
	}
	if err == nil {
		memo.Record(key, created)
		return ctx.Err()
	}
	if !errors.Is(err, store.ErrExists) {
		return err
	}
	// The upload is finished. Release its disk space before a fallback read
	// creates another full copy of the artifact.
	if err := os.Remove(staged); err != nil {
		return fmt.Errorf("remove staged upload before verification: %w", err)
	}
	if memo != nil {
		if publishing, ok := objects.(PublishingStore); ok {
			return memo.confirmExistingContext(ctx, publishing, key, ref, filepath.Join(temp, "object"))
		}
	}
	_, err = fetchExactVersionContext(ctx, objects, ref, filepath.Join(temp, "object"))
	return err
}

func verifyLocalRef(ref state.ContentRef, localPath string) error {
	return verifyLocalRefContext(context.Background(), ref, localPath)
}

func verifyLocalRefContext(ctx context.Context, ref state.ContentRef, localPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, reader: file}, ref.Size))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
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
	return ctx.Err()
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

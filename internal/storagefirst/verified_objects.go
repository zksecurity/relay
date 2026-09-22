package storagefirst

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

const verifiedObjectsSchema = "relay-verified-objects-v1"

// VerifiedObjects remembers, per content-addressed key, the exact object
// version whose bytes this workspace has already digest-verified in storage.
// It lets a re-publication of an already-present artifact confirm "still the
// version I verified" with one metadata request instead of downloading and
// re-hashing the object. Trust is pinned to a verified version, never to mere
// existence: an unknown, changed, or unpinnable version always falls back to
// a full fetch-and-hash. A missing or unreadable memo is treated as empty, so
// losing it only costs verification work, never verification strength.
type VerifiedObjects struct {
	mu      sync.Mutex
	path    string
	objects map[string]store.ObjectVersion
}

type verifiedObjectsFile struct {
	Schema  string                         `json:"schema"`
	Objects map[string]store.ObjectVersion `json:"objects"`
}

// LoadVerifiedObjects reads the memo at path. A missing or corrupt file
// yields an empty memo; the verification work is simply redone.
func LoadVerifiedObjects(path string) *VerifiedObjects {
	v := &VerifiedObjects{path: path, objects: map[string]store.ObjectVersion{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return v
	}
	var file verifiedObjectsFile
	if json.Unmarshal(raw, &file) != nil || file.Schema != verifiedObjectsSchema || file.Objects == nil {
		return v
	}
	v.objects = file.Objects
	return v
}

// Verified reports the remembered version for key, if any. A nil memo knows
// nothing, which keeps every publication fully verified.
func (v *VerifiedObjects) Verified(key string) (store.ObjectVersion, bool) {
	if v == nil {
		return store.ObjectVersion{}, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	version, ok := v.objects[key]
	return version, ok
}

// Record remembers that the bytes at key were digest-verified at version.
// Versions without an ETag or version id are ignored: a size alone is not
// strong enough to pin exact bytes.
func (v *VerifiedObjects) Record(key string, version store.ObjectVersion) {
	if v == nil || !pinnedVersion(version) {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.objects == nil {
		v.objects = map[string]store.ObjectVersion{}
	}
	v.objects[key] = version
}

// Save persists the memo as workspace-private state, writing a fresh file
// beside the old one and renaming it into place. The map is snapshotted under
// the lock so a Save racing a Record never marshals a mutating map.
func (v *VerifiedObjects) Save() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	objects := make(map[string]store.ObjectVersion, len(v.objects))
	for key, version := range v.objects {
		objects[key] = version
	}
	v.mu.Unlock()
	file := verifiedObjectsFile{Schema: verifiedObjectsSchema, Objects: objects}
	raw, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	staged := v.path + ".staging"
	if err := os.WriteFile(staged, raw, 0o600); err != nil {
		return fmt.Errorf("stage verified-objects memo: %w", err)
	}
	if err := os.Rename(staged, v.path); err != nil {
		return fmt.Errorf("replace verified-objects memo: %w", err)
	}
	return nil
}

// confirmExisting settles an already-present key for a memo-aware publisher.
// The current stored version is fetched by metadata only; when it is the
// exact version this workspace digest-verified before, the stored bytes are
// already known good. Anything else — unknown version, changed version, or
// metadata unavailable — falls back to a full download-and-hash, which is the
// corruption check the always-fetch path performs.
func (v *VerifiedObjects) confirmExisting(objects PublishingStore, key string, ref state.ContentRef, fetchPath string) error {
	return v.confirmExistingContext(context.Background(), objects, key, ref, fetchPath)
}

func (v *VerifiedObjects) confirmExistingContext(ctx context.Context, objects PublishingStore, key string, ref state.ContentRef, fetchPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, err := objects.HeadVersion(key); err == nil {
		if remembered, ok := v.Verified(key); ok && sameVersion(remembered, current) {
			return ctx.Err()
		}
	}
	observed, err := fetchExactVersionContext(ctx, objects, ref, fetchPath)
	if err != nil {
		return err
	}
	v.Record(key, observed)
	return ctx.Err()
}

// matchesCurrentContext reports whether authoritative current provider
// metadata is the exact object version this workspace previously downloaded or
// created and digest-verified. It deliberately avoids a metadata request when
// the memo has no pinned entry: callers must then keep the conditional-create
// and full verification path. Operational metadata failures also fall back to
// that path, while cancellation stops the operation immediately.
//
// PublishingStore implementations must return strongly consistent current
// metadata from HeadVersion. The equality check inherits the provider's object
// identity guarantees; it never treats existence or size alone as proof.
func (v *VerifiedObjects) matchesCurrentContext(ctx context.Context, objects PublishingStore, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	remembered, ok := v.Verified(key)
	if !ok || !pinnedVersion(remembered) {
		return false, nil
	}
	current, err := objects.HeadVersion(key)
	if cancelErr := ctx.Err(); cancelErr != nil {
		return false, cancelErr
	}
	if err != nil || !pinnedVersion(current) {
		return false, nil
	}
	return sameVersion(remembered, current), nil
}

// pinnedVersion reports whether a version identifies exact bytes strongly
// enough to skip a re-download: an ETag or a version id, never size alone.
func pinnedVersion(version store.ObjectVersion) bool {
	if version.Size < 0 || len(version.ETag) > 1024 || len(version.VersionID) > 1024 ||
		strings.ContainsAny(version.ETag, "\x00\r\n") || strings.ContainsAny(version.VersionID, "\x00\r\n") {
		return false
	}
	return version.ETag != "" || version.VersionID != ""
}

// sameVersion reports whether two metadata responses describe the identical
// stored object. Versions without identifying fields never match.
func sameVersion(a, b store.ObjectVersion) bool {
	if !pinnedVersion(a) || !pinnedVersion(b) {
		return false
	}
	return a == b
}

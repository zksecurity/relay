package storagefirst

// This is the transport-only lane for the revised workflow. It does not change
// the released envelope-based lane in submission.go and cannot authenticate or
// accept a ceremony contribution. Callers must verify payloads with proof-tool.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

const deliverySchema = "relay-submission-transport-v1"
const maxDeliveryManifestBytes = 1 << 20

// DeliveryScope comes from the active protocol slot, not from the manifest.
// The provider prefix is derived here in Relay and never passed to proof-tool.
type DeliveryScope struct {
	CeremonyID string
	AttemptID  string
	Kind       string
}

func (s DeliveryScope) validate() error {
	if !validDigest(s.CeremonyID) || !validAttempt(s.AttemptID) {
		return errors.New("delivery requires an exact ceremony and allocated attempt")
	}
	if s.Kind != "receipt" && s.Kind != "candidate" && s.Kind != "enrollment" && s.Kind != "release" {
		return errors.New("unsupported delivery kind")
	}
	return nil
}

func (s DeliveryScope) Prefix() (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	return "submissions/" + strings.TrimPrefix(s.CeremonyID, "sha256:") + "/" + s.AttemptID, nil
}

type deliveryManifest struct {
	Schema     string         `json:"schema"`
	CeremonyID string         `json:"ceremony_id"`
	AttemptID  string         `json:"attempt_id"`
	Kind       string         `json:"kind"`
	Files      []deliveryFile `json:"files"`
}

type deliveryFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// DeliveryInventory is supplied by the workflow, never by uploaded metadata.
// Each value is an independently selected maximum byte count. The candidate
// contribution bound must come from the expected circuit/runtime, not a remote
// manifest's claimed size. This layer does not choose required ceremony records.
type DeliveryInventory map[string]int64

// FetchedDelivery is the exact transport package that FetchDeliveryVerified
// placed in its fresh private directory. It is transport evidence only: a
// caller must still ask proof-tool to authenticate the ceremony records.
// Manifest and Files contain no credentials and are ordered as the verified
// transport manifest was ordered.
type FetchedDelivery struct {
	Dir      string
	Manifest state.ContentRef
	Files    []state.ContentRef
}

func (i DeliveryInventory) validate() error {
	if len(i) == 0 || len(i) > 2048 {
		return errors.New("invalid delivery inventory count")
	}
	for name, limit := range i {
		// A release package legitimately contains its signed manifest.json. It
		// is stored below files/ and remains distinct from this transport
		// layer's own prefix-level manifest.json.
		if !validDeliveryName(name) || strings.ContainsAny(name, ":\x00\r\n\t") || limit <= 0 || limit > 16<<30 {
			return errors.New("delivery inventory requires safe relative file names and positive bounded sizes")
		}
		for _, r := range name {
			if r < 32 || r > 126 {
				return errors.New("delivery file names must be printable ASCII")
			}
		}
	}
	return nil
}

func validDeliveryName(name string) bool {
	if name == "" || len(name) > 512 || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || filepath.Clean(name) != name {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if !validComponent(component) {
			return false
		}
	}
	return true
}

func (i DeliveryInventory) validateKind(kind string) error {
	if err := i.validate(); err != nil {
		return err
	}
	if kind == "release" {
		names := make([]string, 0, len(i))
		for name := range i {
			names = append(names, name)
		}
		slices.Sort(names)
		for index, name := range names {
			if index > 0 && strings.HasPrefix(name, names[index-1]+"/") {
				return errors.New("release delivery paths overlap as a file and directory")
			}
		}
		return nil
	}
	want := []string{"receipt.json", "receipt.sig"}
	if kind == "candidate" {
		want = []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"}
	} else if kind == "enrollment" {
		want = []string{"enrollment.json", "disclosure.txt", "enrollment.sig"}
	} else if kind != "receipt" {
		return errors.New("unsupported delivery kind")
	}
	if len(i) != len(want) {
		return errors.New("unexpected files for delivery kind")
	}
	for _, name := range want {
		limit, exists := i[name]
		if !exists {
			return errors.New("missing required delivery file")
		}
		if strings.HasSuffix(name, ".sig") && limit > 4096 {
			return errors.New("delivery signature bound exceeds 4096 bytes")
		}
		if strings.HasSuffix(name, ".json") && limit > 16<<20 {
			return errors.New("delivery record bound exceeds 16 MiB")
		}
	}
	return nil
}

func decodeDelivery(raw []byte, scope DeliveryScope, inventory DeliveryInventory) (deliveryManifest, error) {
	var m deliveryManifest
	if err := scope.validate(); err != nil {
		return m, err
	}
	if err := inventory.validateKind(scope.Kind); err != nil {
		return m, err
	}
	if len(raw) > maxDeliveryManifestBytes {
		return m, errors.New("delivery manifest exceeds size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, err
	}
	// Exact encoding rejects duplicate fields, trailing data and alternate JSON
	// spellings. This is transport framing, not a new signed canonical format.
	encoded, err := json.Marshal(m)
	if err != nil || !bytes.Equal(raw, encoded) {
		return m, errors.New("delivery manifest is not in its exact wire format")
	}
	if m.Schema != deliverySchema || m.CeremonyID != scope.CeremonyID || m.AttemptID != scope.AttemptID || m.Kind != scope.Kind {
		return m, errors.New("delivery manifest does not match the allocated scope")
	}
	if len(m.Files) != len(inventory) {
		return m, errors.New("delivery inventory mismatch")
	}
	previous := ""
	for _, file := range m.Files {
		limit, expected := inventory[file.Name]
		if !expected || file.Name <= previous || file.Size <= 0 || file.Size > limit || !validDigest(file.SHA256) {
			return m, errors.New("delivery contains unknown, duplicate, unordered or invalid files")
		}
		previous = file.Name
	}
	return m, nil
}

// UploadDelivery uploads only the exact supplied inventory, staging verified
// private copies before any provider writes. Repeating identical bytes is safe;
// different existing bytes fail. A successful return means uploaded, not accepted.
func UploadDelivery(objects ImmutableStore, scope DeliveryScope, inventory DeliveryInventory, sources map[string]state.ContentRef, paths map[string]string, tempParent string) error {
	if objects == nil {
		return errors.New("delivery store required")
	}
	prefix, err := scope.Prefix()
	if err != nil {
		return err
	}
	if err := inventory.validateKind(scope.Kind); err != nil {
		return err
	}
	if len(sources) != len(inventory) || len(paths) != len(inventory) {
		return errors.New("delivery sources do not match inventory")
	}
	names := make([]string, 0, len(inventory))
	for name := range inventory {
		names = append(names, name)
	}
	slices.Sort(names)
	m := deliveryManifest{Schema: deliverySchema, CeremonyID: scope.CeremonyID, AttemptID: scope.AttemptID, Kind: scope.Kind}
	for _, name := range names {
		ref, ok := sources[name]
		if !ok || paths[name] == "" || ref.Size <= 0 || ref.Size > inventory[name] || !validDigest(ref.SHA256) {
			return errors.New("delivery source is missing or exceeds its independent bound")
		}
		m.Files = append(m.Files, deliveryFile{Name: name, SHA256: ref.SHA256, Size: ref.Size})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := decodeDelivery(raw, scope, inventory); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(tempParent, "relay-delivery-upload-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, file := range m.Files {
		if err := stageDeliveryFile(paths[file.Name], filepath.Join(tmp, file.Name), file); err != nil {
			return err
		}
	}
	// Keep transport framing outside the staged payload namespace. A signed
	// release package legitimately has its own files/manifest.json.
	manifestPath := filepath.Join(tmp, ".relay-transport-manifest")
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		return err
	}
	for _, file := range m.Files {
		if err := putExactDelivery(objects, prefix+"/files/"+file.Name, filepath.Join(tmp, file.Name), file, tmp); err != nil {
			return err
		}
	}
	return putExactDelivery(objects, prefix+"/manifest.json", manifestPath, deliveryFile{Name: "manifest.json", SHA256: digestBytes(raw), Size: int64(len(raw))}, tmp)
}

func putExactDelivery(objects ImmutableStore, key, local string, file deliveryFile, temp string) error {
	_, err := objects.PutIfAbsent(key, local)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrExists) {
		return err
	}
	comparison, err := os.MkdirTemp(temp, "existing-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(comparison)
	existing := filepath.Join(comparison, "object")
	version, err := objects.GetVersionedAtMost(key, existing, file.Size)
	if err != nil {
		return err
	}
	if version.Size != file.Size {
		return errors.New("existing delivery size differs")
	}
	return verifyLocalRef(state.ContentRef{SHA256: file.SHA256, Size: file.Size}, existing)
}

func stageDeliveryFile(source, destination string, expected deliveryFile) error {
	return stageDeliveryFileContext(context.Background(), source, destination, expected)
}

func stageDeliveryFileContext(ctx context.Context, source, destination string, expected deliveryFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() != expected.Size {
		return errors.New("delivery source must be a regular file of the expected size")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != expected.Size {
		return errors.New("delivery source changed while opening")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	// Hash the bytes while they are copied so the source is read once. The
	// staged copy is what the provider uploads, so its digest is the one that
	// must match: a truncated copy, a swapped source, or wrong source bytes
	// all fail this single comparison.
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(contextReader{ctx: ctx, reader: input}, expected.Size))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var extra [1]byte
	more, readErr := input.Read(extra[:])
	if n != expected.Size || more != 0 || readErr != io.EOF {
		return errors.New("delivery source size changed during staging")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("staged delivery bytes do not match the expected digest")
	}
	return ctx.Err()
}

// FetchDelivery returns a private staging directory only after every listed
// byte has been checked. The caller owns cleanup and must ask proof-tool to
// authenticate the records before importing or accepting them. No role folder
// or completed-operation marker is modified here.
func FetchDelivery(objects ObjectStore, scope DeliveryScope, inventory DeliveryInventory, tempParent string) (string, error) {
	fetched, err := FetchDeliveryVerified(objects, scope, inventory, tempParent)
	if err != nil {
		return "", err
	}
	return fetched.Dir, nil
}

// FetchDeliveryVerified returns both the fresh private staging directory and
// the exact manifest/file references that were checked before it is returned.
// This lets a caller retain a small private receipt and revalidate the bytes
// before a later consequential decision without retaining transport framing in
// a fixed protocol directory.
func FetchDeliveryVerified(objects ObjectStore, scope DeliveryScope, inventory DeliveryInventory, tempParent string) (result FetchedDelivery, err error) {
	if objects == nil {
		return result, errors.New("delivery store required")
	}
	prefix, err := scope.Prefix()
	if err != nil {
		return result, err
	}
	if err := inventory.validateKind(scope.Kind); err != nil {
		return result, err
	}
	result.Dir, err = os.MkdirTemp(tempParent, "relay-delivery-received-")
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(result.Dir)
			result.Dir = ""
		}
	}()
	manifestPath := filepath.Join(result.Dir, "manifest.json")
	if _, err = objects.GetVersionedAtMost(prefix+"/manifest.json", manifestPath, maxDeliveryManifestBytes); err != nil {
		return result, err
	}
	manifest, err := os.Open(manifestPath)
	if err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(manifest, maxDeliveryManifestBytes+1))
	manifest.Close()
	if err != nil {
		return result, err
	}
	m, err := decodeDelivery(raw, scope, inventory)
	if err != nil {
		return result, err
	}
	result.Manifest = state.ContentRef{Name: "manifest.json", SHA256: digestBytes(raw), Size: int64(len(raw))}
	// Transport framing must not be forwarded as candidate/evidence content.
	if err = os.Remove(manifestPath); err != nil {
		return result, err
	}
	for _, file := range m.Files {
		local := filepath.Join(result.Dir, file.Name)
		if err = os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			return result, err
		}
		version, fetchErr := objects.GetVersionedAtMost(prefix+"/files/"+file.Name, local, file.Size)
		if fetchErr != nil {
			return result, fetchErr
		}
		if version.Size != file.Size {
			return result, errors.New("delivery download size differs")
		}
		if err = verifyLocalRef(state.ContentRef{SHA256: file.SHA256, Size: file.Size}, local); err != nil {
			return result, fmt.Errorf("delivery payload: %w", err)
		}
		result.Files = append(result.Files, state.ContentRef{Name: file.Name, SHA256: file.SHA256, Size: file.Size})
	}
	return result, nil
}

// FetchReleaseDelivery discovers a release package inventory from the trusted
// delivery service's immutable manifest, then verifies every downloaded byte.
// The caller must still ask proof-tool to authenticate the closed package; the
// transport manifest is not release approval.
func FetchReleaseDelivery(objects ObjectStore, scope DeliveryScope, tempParent string) (dir string, inventory DeliveryInventory, err error) {
	if objects == nil || scope.Kind != "release" {
		return "", nil, errors.New("release delivery store and release scope required")
	}
	prefix, err := scope.Prefix()
	if err != nil {
		return "", nil, err
	}
	dir, err = os.MkdirTemp(tempParent, "relay-release-received-")
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
			dir = ""
		}
	}()
	manifestPath := filepath.Join(dir, "manifest.json")
	if _, err = objects.GetVersionedAtMost(prefix+"/manifest.json", manifestPath, maxDeliveryManifestBytes); err != nil {
		return dir, nil, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return dir, nil, err
	}
	var wire deliveryManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&wire); err != nil {
		return dir, nil, err
	}
	exact, marshalErr := json.Marshal(wire)
	if marshalErr != nil || !bytes.Equal(raw, exact) || wire.Schema != deliverySchema || wire.CeremonyID != scope.CeremonyID || wire.AttemptID != scope.AttemptID || wire.Kind != scope.Kind {
		return dir, nil, errors.New("release delivery manifest is not exact or does not match its allocated scope")
	}
	inventory = DeliveryInventory{}
	previous := ""
	for _, file := range wire.Files {
		if file.Name <= previous || file.Size <= 0 || file.Size > 16<<30 || !validDigest(file.SHA256) {
			return dir, nil, errors.New("release delivery manifest has invalid, duplicate or unordered files")
		}
		previous = file.Name
		inventory[file.Name] = file.Size
	}
	if err = inventory.validateKind(scope.Kind); err != nil {
		return dir, nil, err
	}
	if _, err = decodeDelivery(raw, scope, inventory); err != nil {
		return dir, nil, err
	}
	if err = os.Remove(manifestPath); err != nil {
		return dir, nil, err
	}
	for _, file := range wire.Files {
		local := filepath.Join(dir, filepath.FromSlash(file.Name))
		if err = os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			return dir, nil, err
		}
		version, fetchErr := objects.GetVersionedAtMost(prefix+"/files/"+file.Name, local, file.Size)
		if fetchErr != nil {
			return dir, nil, fetchErr
		}
		if version.Size != file.Size {
			return dir, nil, errors.New("release delivery download size differs")
		}
		if err = verifyLocalRef(state.ContentRef{SHA256: file.SHA256, Size: file.Size}, local); err != nil {
			return dir, nil, fmt.Errorf("release delivery payload: %w", err)
		}
	}
	return dir, inventory, nil
}

package storagefirst

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type deliveryStore struct {
	objects      map[string][]byte
	writes       []string
	failKey      string
	lostResponse bool
}

func (s *deliveryStore) PutIfAbsent(key, path string) (store.ObjectVersion, error) {
	if _, exists := s.objects[key]; exists {
		return store.ObjectVersion{}, store.ErrExists
	}
	if key == s.failKey && !s.lostResponse {
		return store.ObjectVersion{}, errors.New("interrupted upload")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	s.objects[key] = raw
	s.writes = append(s.writes, key)
	if key == s.failKey {
		return store.ObjectVersion{}, errors.New("response lost after write")
	}
	return store.ObjectVersion{Size: int64(len(raw))}, nil
}

func (s *deliveryStore) GetVersionedAtMost(key, path string, maximum int64) (store.ObjectVersion, error) {
	raw, exists := s.objects[key]
	if !exists {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("object exceeds bound")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	_, err = file.Write(raw)
	closeErr := file.Close()
	if err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{Size: int64(len(raw))}, closeErr
}

func deliveryFixture(t *testing.T) (*deliveryStore, DeliveryScope, DeliveryInventory, map[string]state.ContentRef, map[string]string) {
	t.Helper()
	s := &deliveryStore{objects: make(map[string][]byte)}
	scope := DeliveryScope{CeremonyID: digestBytes([]byte("test ceremony")), AttemptID: strings.Repeat("a", 32), Kind: "receipt"}
	inventory := DeliveryInventory{"receipt.json": 1024, "receipt.sig": 4096}
	refs := make(map[string]state.ContentRef)
	paths := make(map[string]string)
	dir := t.TempDir()
	for name := range inventory {
		raw := []byte("synthetic bytes for " + name)
		paths[name] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[name], raw, 0600); err != nil {
			t.Fatal(err)
		}
		refs[name] = state.ContentRef{Name: "logical/" + name, SHA256: digestBytes(raw), Size: int64(len(raw))}
	}
	return s, scope, inventory, refs, paths
}

func TestDeliveryManifestLastAndExactRetry(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	prefix, _ := scope.Prefix()
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := s.writes[len(s.writes)-1]; got != prefix+"/manifest.json" {
		t.Fatalf("last write = %s", got)
	}
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 3 {
		t.Fatal("retry wrote duplicate objects")
	}
	dir, err := FetchDelivery(s, scope, inventory, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(inventory) {
		t.Fatalf("transport metadata leaked into payload directory: %v %v", entries, err)
	}
	for name, ref := range refs {
		if err := verifyLocalRef(ref, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Plain synthetic files pass transport checks: they are deliberately NOT
	// treated as authenticated receipts or completed ceremony operations.
}

func TestDeliveryInterruptedUploadAndLostResponse(t *testing.T) {
	for _, lost := range []bool{false, true} {
		for _, target := range []string{"files/receipt.sig", "manifest.json"} {
			t.Run(target+map[bool]string{false: "/before", true: "/after"}[lost], func(t *testing.T) {
				s, scope, inventory, refs, paths := deliveryFixture(t)
				prefix, _ := scope.Prefix()
				s.failKey, s.lostResponse = prefix+"/"+target, lost
				if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err == nil {
					t.Fatal("interruption hidden")
				}
				if target != "manifest.json" || !lost {
					if _, exists := s.objects[prefix+"/manifest.json"]; exists {
						t.Fatal("premature manifest")
					}
				}
				s.failKey = ""
				if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
					t.Fatal(err)
				}
				if len(s.writes) != 3 {
					t.Fatal("retry did not preserve exact upload")
				}
			})
		}
	}
}

func TestDeliveryConflictingExistingPayloadNeverCompletes(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	prefix, _ := scope.Prefix()
	s.objects[prefix+"/files/receipt.json"] = []byte("different")
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err == nil {
		t.Fatal("conflict accepted")
	}
	if _, ok := s.objects[prefix+"/manifest.json"]; ok {
		t.Fatal("manifest published on conflict")
	}
}

func TestDeliveryRejectsChangedSourceBeforeAnyUpload(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	if err := os.WriteFile(paths["receipt.sig"], []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err == nil || len(s.writes) != 0 {
		t.Fatalf("err=%v writes=%v", err, s.writes)
	}
}

func TestDeliveryRejectsManifestScopeAndInventoryChanges(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	prefix, _ := scope.Prefix()
	raw := s.objects[prefix+"/manifest.json"]
	cases := map[string]func(*deliveryManifest){
		"ceremony":  func(m *deliveryManifest) { m.CeremonyID = digestBytes([]byte("other")) },
		"attempt":   func(m *deliveryManifest) { m.AttemptID = strings.Repeat("b", 32) },
		"kind":      func(m *deliveryManifest) { m.Kind = "candidate" },
		"missing":   func(m *deliveryManifest) { m.Files = m.Files[:1] },
		"duplicate": func(m *deliveryManifest) { m.Files[1] = m.Files[0] },
		"path":      func(m *deliveryManifest) { m.Files[0].Name = "../receipt.json" },
		"large":     func(m *deliveryManifest) { m.Files[0].Size = 1 << 60 },
		"zero":      func(m *deliveryManifest) { m.Files[0].Size = 0 },
		"hash":      func(m *deliveryManifest) { m.Files[0].SHA256 = "no" },
		"order":     func(m *deliveryManifest) { m.Files[0], m.Files[1] = m.Files[1], m.Files[0] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var m deliveryManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			mutate(&m)
			bad, _ := json.Marshal(m)
			if _, err := decodeDelivery(bad, scope, inventory); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), []byte("{}")...), bytes.Replace(raw, []byte(`"schema":`), []byte(`"unexpected":1,"schema":`), 1), bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"ignored","schema":`), 1)} {
		if _, err := decodeDelivery(bad, scope, inventory); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestDeliveryIncompleteFetchLeavesNoReturnedFolder(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	prefix, _ := scope.Prefix()
	delete(s.objects, prefix+"/files/receipt.sig")
	parent := t.TempDir()
	if dir, err := FetchDelivery(s, scope, inventory, parent); err == nil || dir != "" {
		t.Fatalf("dir=%q err=%v", dir, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial files retained: %v %v", entries, err)
	}
}

func TestDeliveryRejectsPrivateAndIncompleteInventories(t *testing.T) {
	for _, inventory := range []DeliveryInventory{
		{"signing.hex": 1024, "receipt.sig": 4096},
		{"receipt.json": 1024, "receipt.sig": 8192},
		{"receipt.json": 32 << 20, "receipt.sig": 4096},
		{"receipt.json": 1024},
	} {
		if err := inventory.validateKind("receipt"); err == nil {
			t.Fatalf("unsafe inventory accepted: %v", inventory)
		}
	}
	i := DeliveryInventory{"attestation.json": 1024, "attestation.sig": 4096, "erasure.json": 1024, "erasure.sig": 4096, "contribution.bin": 1 << 30}
	if err := i.validateKind("candidate"); err != nil {
		t.Fatal(err)
	}
	i["return-handoff.sig"] = 4096
	if err := i.validateKind("candidate"); err == nil {
		t.Fatal("unpaired return evidence accepted")
	}
	i["return-handoff.json"] = 1024
	if err := i.validateKind("candidate"); err == nil {
		t.Fatal("obsolete return-custody files accepted")
	}
}

func TestDeliveryRedeliveryUsesNewAttemptWithoutChangingPayloads(t *testing.T) {
	s, scope, inventory, refs, paths := deliveryFixture(t)
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	first, _ := scope.Prefix()
	scope.AttemptID = strings.Repeat("b", 32)
	if err := UploadDelivery(s, scope, inventory, refs, paths, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	second, _ := scope.Prefix()
	for name := range inventory {
		if !bytes.Equal(s.objects[first+"/files/"+name], s.objects[second+"/files/"+name]) {
			t.Fatal("redelivery changed payload")
		}
	}
	// Allocation/retirement and rejected candidate policy are protocol checks,
	// outside this transport. This proves only that no extra participant
	// signature is required to carry identical records to another attempt.
}

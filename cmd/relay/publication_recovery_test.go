package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type publicationStoreFake struct {
	objects map[string][]byte
	putErr  error
	puts    int
	putHook func(string, []byte) error
}

func (f *publicationStoreFake) Head(key string) (bool, error) {
	_, ok := f.objects[key]
	return ok, nil
}
func (f *publicationStoreFake) Size(key string) (int64, error) {
	raw, ok := f.objects[key]
	if !ok {
		return 0, errors.New("not found")
	}
	return int64(len(raw)), nil
}
func (f *publicationStoreFake) Get(key, path string) error {
	raw, ok := f.objects[key]
	if !ok {
		return errors.New("not found")
	}
	return os.WriteFile(path, raw, 0o600)
}
func (f *publicationStoreFake) PutNoReplace(key, path string) error {
	f.puts++
	if _, ok := f.objects[key]; ok {
		return store.ErrExists
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if f.putHook != nil {
		return f.putHook(key, raw)
	}
	f.objects[key] = raw
	return f.putErr
}

func TestReconcilePublicationObject(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "genesis.bin")
	if err := os.WriteFile(source, []byte("retained genesis"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		initial  []byte
		putErr   error
		wantErr  string
		wantPuts int
	}{
		{name: "missing", wantPuts: 1},
		{name: "matching", initial: []byte("retained genesis")},
		{name: "conflict", initial: []byte("different"), wantErr: "integrity conflict"},
		{name: "ambiguous write after effect", putErr: errors.New("expired response"), wantPuts: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &publicationStoreFake{objects: map[string][]byte{}, putErr: test.putErr}
			if test.initial != nil {
				fake.objects["blob"] = test.initial
			}
			err := reconcilePublicationObject(fake, "blob", source, "phase1/genesis.bin")
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error=%v, want substring %q", err, test.wantErr)
			}
			if fake.puts != test.wantPuts {
				t.Fatalf("puts=%d, want %d", fake.puts, test.wantPuts)
			}
		})
	}
}

func TestEquivalentInitialPointerIgnoresOnlyTimestamp(t *testing.T) {
	ref := state.Ref{Name: "phase1/chain-0000.json", SHA256: "sha256:" + strings.Repeat("a", 64)}
	sig := state.Ref{Name: "phase1/chain-0000.sig", SHA256: "sha256:" + strings.Repeat("b", 64)}
	want := state.Pointer{Schema: state.Schema, CeremonyID: "sha256:" + strings.Repeat("c", 64), Phase: "phase1", Index: 0, Chain: ref, ChainSignature: sig, UpdatedAt: "2026-01-01T00:00:00Z", Files: []state.Ref{ref, sig}}
	got := want
	got.UpdatedAt = "2026-01-01T00:00:01Z"
	if !equivalentInitialPointer(got, want) {
		t.Fatal("timestamp-only difference should reconcile")
	}
	got.Index = 1
	if equivalentInitialPointer(got, want) {
		t.Fatal("advanced head must not reconcile")
	}
}

func TestReconcileInitialPointerHeadRace(t *testing.T) {
	ref := state.Ref{Name: "phase1/chain-0000.json", SHA256: "sha256:" + strings.Repeat("a", 64)}
	sig := state.Ref{Name: "phase1/chain-0000.sig", SHA256: "sha256:" + strings.Repeat("b", 64)}
	want := state.Pointer{Schema: state.Schema, CeremonyID: "sha256:" + strings.Repeat("c", 64), Phase: "phase1", Index: 0, Chain: ref, ChainSignature: sig, UpdatedAt: "2026-01-01T00:00:00Z", Files: []state.Ref{ref, sig}}
	raw, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "head.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		mutate  func(*state.Pointer)
		wantErr string
	}{
		{name: "equivalent", mutate: func(pointer *state.Pointer) { pointer.UpdatedAt = "2026-01-01T00:00:01Z" }},
		{name: "conflicting", mutate: func(pointer *state.Pointer) { pointer.Index = 1 }, wantErr: "not the exact retained"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &publicationStoreFake{objects: map[string][]byte{}}
			fake.putHook = func(key string, _ []byte) error {
				competing := want
				test.mutate(&competing)
				encoded, encodeErr := competing.Encode()
				if encodeErr != nil {
					return encodeErr
				}
				fake.objects[key] = encoded
				return store.ErrExists
			}
			err := reconcileInitialPointer(fake, "state/head.json", path, want, false)
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error=%v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestDecodeRecoveryPointerRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"schema":"relay-state-v1","ceremony_id":"sha256:` + strings.Repeat("c", 64) + `","phase":"phase1","index":0,"chain":{"name":"chain","sha256":"sha256:` + strings.Repeat("a", 64) + `"},"chain_signature":{"name":"sig","sha256":"sha256:` + strings.Repeat("b", 64) + `"},"updated_at":"2026-01-01T00:00:00Z","closed":false,"files":[],"surprise":true}`)
	if _, err := decodeRecoveryPointer(raw); err == nil {
		t.Fatal("unknown pointer fields must not be accepted during recovery")
	}
}

func TestUnresolvedLegacyPublicationIsExact(t *testing.T) {
	command := []string{"relay", "coordinator", "publish", "--verify", "--storage", "/work/ceremony/config/relay-storage.json", "--chain", "/work/ceremony/public/phase1/chain-0000.json", "--chain-signature", "/work/ceremony/public/phase1/chain-0000.sig"}
	publication := flowAttempt{ID: "flow-" + strings.Repeat("a", 32), Task: "publish", Stage: "storage", Status: "failed", OperationSchema: flowOperationSchema, RecoveryClass: recoveryPublication, Command: command, InputBindings: map[string]string{command[5]: "hash-storage", command[7]: "hash-chain", command[9]: "hash-signature"}}
	got, err := unresolvedLegacyPublication(roleFlowState{Attempts: []flowAttempt{publication}})
	if err != nil || got.ID != publication.ID {
		t.Fatalf("got=%v err=%v", got, err)
	}
	publication.Command = append(publication.Command, "--closed")
	if _, err := unresolvedLegacyPublication(roleFlowState{Attempts: []flowAttempt{publication}}); err == nil {
		t.Fatal("modified publication recipe must not use initial recovery")
	}
}

func TestUnresolvedLegacyPublicationUsesLatestScopedAttempt(t *testing.T) {
	command := []string{"relay", "coordinator", "publish", "--verify", "--storage", "/work/ceremony/config/relay-storage.json", "--chain", "/work/ceremony/public/phase1/chain-0000.json", "--chain-signature", "/work/ceremony/public/phase1/chain-0000.sig"}
	bindings := map[string]string{command[5]: "hash-storage", command[7]: "hash-chain", command[9]: "hash-signature"}
	old := flowAttempt{ID: "flow-" + strings.Repeat("a", 32), Task: "inspect", Stage: "enrollments", Status: "failed", RecoveryClass: recoveryReadOnly}
	target := flowAttempt{ID: "flow-" + strings.Repeat("b", 32), Task: "publish", Stage: "storage", Status: "failed", OperationSchema: flowOperationSchema, RecoveryClass: recoveryPublication, Command: command, InputBindings: bindings}
	if got, err := unresolvedLegacyPublication(roleFlowState{Attempts: []flowAttempt{old, target}}); err != nil || got.ID != target.ID {
		t.Fatalf("got=%v err=%v", got, err)
	}
	succeeded := target
	succeeded.Status = "succeeded"
	if _, err := unresolvedLegacyPublication(roleFlowState{Attempts: []flowAttempt{target, succeeded}}); err == nil {
		t.Fatal("a later successful storage publication must supersede the old failure")
	}
}

func TestCopyRecoverySnapshotIsIndependent(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "snapshot", "object")
	if err := os.WriteFile(source, []byte("authenticated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoverySnapshot(source, destination); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("changed later"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(destination)
	if err != nil || string(raw) != "authenticated" {
		t.Fatalf("snapshot=%q err=%v", raw, err)
	}
}

func TestAWSStorageRecoveryAllowsOnlyCredentialChange(t *testing.T) {
	work := t.TempDir()
	settings := storageSettingsFixture()
	config, err := settings.infrastructure()
	if err != nil {
		t.Fatal(err)
	}
	config.Schema = access.StorageConfigSchema
	config.CeremonyID = "sha256:" + strings.Repeat("c", 64)
	config.CeremonyPath = "/work/ceremony/public/ceremony.json"
	config.CeremonySignature = "/work/ceremony/public/ceremony.sig"
	config.CoordinatorPublicKey = "/trust/coordinator-public-key.hex"
	config.CeremonyBinary = "mpc-ceremony"
	path := filepath.Join(work, "relay-storage.json")
	if err := writeJSONNoReplace(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	draft := coordinatorDraft{Storage: settings.Settings}
	f := roleFlow{state: roleFlowState{Profile: guidedProfile{Work: work}}}
	if err := awsStorageUnchanged("/work/relay-storage.json", draft, f); err != nil {
		t.Fatal(err)
	}
	draft.Storage = map[string]string{}
	for key, value := range settings.Settings {
		draft.Storage[key] = value
	}
	draft.Storage["published-bucket"] = "different-public-fixture"
	if err := awsStorageUnchanged("/work/relay-storage.json", draft, f); err == nil {
		t.Fatal("changed publication bucket must be refused")
	}
}

func TestValidateRecoveryFileRequiresSignedR1CS(t *testing.T) {
	r1cs := transcript.ArtifactRef{Name: "ownership-destination.ccs", Digest: transcript.Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 12}}
	file := transcript.File{Name: r1cs.Name}
	if _, err := validateRecoveryFile(file, r1cs, "sha256:"+strings.Repeat("b", 64), 12); err == nil {
		t.Fatal("changed R1CS must be rejected even though TranscriptFiles has no digest on the root file")
	}
	matched, err := validateRecoveryFile(file, r1cs, r1cs.Digest.SHA256, r1cs.Digest.Size)
	if err != nil || !matched {
		t.Fatalf("matched=%v err=%v", matched, err)
	}
}

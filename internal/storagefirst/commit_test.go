package storagefirst

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type rootWriterFake struct {
	current  []byte
	version  store.ObjectVersion
	objects  map[string][]byte
	create   int
	replace  int
	conflict bool
	// afterWrite simulates an unreliable provider after it reports a successful
	// conditional write: "prior" restores the old root, "missing" makes the
	// root unreadable, and "different" exposes unrelated bytes/version.
	afterWrite       string
	lastWriteVersion store.ObjectVersion
}

func (f *rootWriterFake) GetVersionedAtMost(key string, local string, maximum int64) (store.ObjectVersion, error) {
	raw := f.current
	version := f.version
	if strings.HasPrefix(key, "state/") && raw == nil {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	if !strings.HasPrefix(key, "state/") {
		var ok bool
		raw, ok = f.objects[key]
		if !ok {
			return store.ObjectVersion{}, os.ErrNotExist
		}
		version = store.ObjectVersion{ETag: "immutable", Size: int64(len(raw))}
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("too large")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return store.ObjectVersion{}, err
	}
	if err := os.WriteFile(local, raw, 0o600); err != nil {
		return store.ObjectVersion{}, err
	}
	return version, nil
}
func (f *rootWriterFake) PutIfAbsent(_ string, local string) (store.ObjectVersion, error) {
	f.create++
	if f.conflict {
		return store.ObjectVersion{}, store.ErrExists
	}
	prior, priorVersion := append([]byte(nil), f.current...), f.version
	f.current, _ = os.ReadFile(local)
	f.version = store.ObjectVersion{ETag: "created", Size: int64(len(f.current))}
	committed := f.version
	f.lastWriteVersion = committed
	f.applyAfterWrite(prior, priorVersion)
	return committed, nil
}
func (f *rootWriterFake) PutIfMatch(_ string, local string, expected store.ObjectVersion) (store.ObjectVersion, error) {
	f.replace++
	if f.conflict || expected.ETag != f.version.ETag {
		return store.ObjectVersion{}, store.ErrVersionConflict
	}
	prior, priorVersion := append([]byte(nil), f.current...), f.version
	f.current, _ = os.ReadFile(local)
	f.version = store.ObjectVersion{ETag: "replaced", Size: int64(len(f.current))}
	committed := f.version
	f.lastWriteVersion = committed
	f.applyAfterWrite(prior, priorVersion)
	return committed, nil
}

func (f *rootWriterFake) applyAfterWrite(prior []byte, priorVersion store.ObjectVersion) {
	switch f.afterWrite {
	case "prior":
		f.current, f.version = prior, priorVersion
	case "missing":
		f.current, f.version = nil, store.ObjectVersion{}
	case "different":
		f.current = []byte(`{"schema":"relay-state-root-v2","ceremony_id":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","checkpoint":{"name":"checkpoints/other.json","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"checkpoint_signature":{"name":"checkpoints/other.sig","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1}}`)
		f.version = store.ObjectVersion{ETag: "different", Size: int64(len(f.current))}
	}
}

func TestCommitRootCreatesThenConditionallyAdvances(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	first, firstSig, child0 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-0"), []byte("signature-0"), nil, 0)
	created, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child0}, t.TempDir())
	if err != nil || w.create != 1 || w.replace != 0 {
		t.Fatalf("created=%+v err=%v calls=%d/%d", created, err, w.create, w.replace)
	}
	previous, err := state.DecodeRoot(w.current)
	if err != nil {
		t.Fatal(err)
	}
	_, _, child1 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-1"), []byte("signature-1"), &SignedRef{Checkpoint: first, Signature: firstSig}, 1)
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child1, Previous: &previous, PreviousVersion: &created}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if w.replace != 1 {
		t.Fatal("root was not conditionally replaced")
	}
}

func TestCommitRootDoesNotReturnCommittedUntilExactReread(t *testing.T) {
	for _, behavior := range []string{"missing", "different"} {
		t.Run(behavior, func(t *testing.T) {
			ceremonyID := digestOfTest("1")
			w := &rootWriterFake{objects: make(map[string][]byte), afterWrite: behavior}
			verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
			_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint"), []byte("signature"), nil, 0)
			if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child}, t.TempDir()); !errors.Is(err, ErrRootCommitUnconfirmed) {
				t.Fatalf("post-write %s error = %v", behavior, err)
			}
		})
	}
}

func TestCommitRootClassifiesPriorRootAfterReportedReplacement(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	first, firstSig, child0 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-0"), []byte("signature-0"), nil, 0)
	created, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child0}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous, err := state.DecodeRoot(w.current)
	if err != nil {
		t.Fatal(err)
	}
	_, _, child1 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-1"), []byte("signature-1"), &SignedRef{Checkpoint: first, Signature: firstSig}, 1)
	commit := RootCommit{CeremonyID: ceremonyID, Child: child1, Previous: &previous, PreviousVersion: &created}
	w.afterWrite = "prior"
	if _, err := CommitRoot(w, commit, t.TempDir()); !errors.Is(err, ErrRootCommitUnconfirmed) {
		t.Fatalf("prior-root error = %v", err)
	}
	status, _, err := ReconcileRootCommit(w, commit, w.lastWriteVersion, t.TempDir())
	if err != nil || status != RootCommitStillPrior {
		t.Fatalf("reconcile status=%s err=%v", status, err)
	}
}

func TestReconcileRootCommitDistinguishesUnexpectedRoot(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint"), []byte("signature"), nil, 0)
	commit := RootCommit{CeremonyID: ceremonyID, Child: child}
	w.current = []byte(`{"schema":"relay-state-root-v2","ceremony_id":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","checkpoint":{"name":"checkpoints/other.json","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"checkpoint_signature":{"name":"checkpoints/other.sig","sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1}}`)
	w.version = store.ObjectVersion{ETag: "different", Size: int64(len(w.current))}
	status, _, err := ReconcileRootCommit(w, commit, store.ObjectVersion{ETag: "created", Size: 1}, t.TempDir())
	if err != nil || status != RootCommitUnexpected {
		t.Fatalf("reconcile status=%s err=%v", status, err)
	}
}

func TestCommitRootPreservesConflict(t *testing.T) {
	w := &rootWriterFake{conflict: true, objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	ceremonyID := digestOfTest("1")
	_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint"), []byte("signature"), nil, 0)
	_, err := CommitRoot(w, RootCommit{
		CeremonyID: ceremonyID,
		Child:      child,
	}, t.TempDir())
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestRootStillNamesDetectsChangedVersionOrBytes(t *testing.T) {
	w := &rootWriterFake{objects: make(map[string][]byte)}
	ceremonyID := digestOfTest("1")
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint"), []byte("signature"), nil, 0)
	version, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, _ := state.DecodeRoot(w.current)
	if err := RootStillNames(w, root, version, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	w.version.ETag = "other"
	if !errors.Is(RootStillNames(w, root, version, t.TempDir()), store.ErrVersionConflict) {
		t.Fatal("changed root version accepted")
	}
}

func TestCommitRootRejectsUnrelatedForkWithCorrectETag(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	first, firstSig, child0 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-0"), []byte("signature-0"), nil, 0)
	created, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child0}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous, _ := state.DecodeRoot(w.current)
	unrelated := SignedRef{
		Checkpoint: state.ContentRef{Name: "checkpoints/unrelated.json", SHA256: digestOfTest("a"), Size: 1},
		Signature:  state.ContentRef{Name: "checkpoints/unrelated.sig", SHA256: digestOfTest("b"), Size: 1},
	}
	_, _, fork := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("fork"), []byte("fork-signature"), &unrelated, 1)
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: fork, Previous: &previous, PreviousVersion: &created}, t.TempDir()); err == nil {
		t.Fatal("unrelated authenticated child replaced the root")
	}
	if w.replace != 0 || previous.Checkpoint != first || previous.CheckpointSignature != firstSig {
		t.Fatal("rejected fork changed the root")
	}
}

func TestCommitRootRequiresExactParentSignatureAndRootVersionPair(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	first, firstSig, child0 := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-0"), []byte("signature-0"), nil, 0)
	created, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child0}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous, _ := state.DecodeRoot(w.current)
	wrongSignature := firstSig
	wrongSignature.SHA256 = digestOfTest("e")
	_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-1"), []byte("signature-1"), &SignedRef{Checkpoint: first, Signature: wrongSignature}, 1)
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child, Previous: &previous, PreviousVersion: &created}, t.TempDir()); err == nil {
		t.Fatal("child naming a different parent signature replaced the root")
	}

	_, _, correctChild := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint-2"), []byte("signature-2"), &SignedRef{Checkpoint: first, Signature: firstSig}, 1)
	wrongVersion := created
	wrongVersion.ETag = "not-the-version-of-previous"
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: correctChild, Previous: &previous, PreviousVersion: &wrongVersion}, t.TempDir()); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("mismatched previous root/version pair error=%v", err)
	}
}

func TestCommitRootRequiresExactImmutableChildBytesBeforeCAS(t *testing.T) {
	ceremonyID := digestOfTest("1")
	w := &rootWriterFake{objects: make(map[string][]byte)}
	verifier := &verifierFake{byDigest: make(map[string]Checkpoint)}
	_, _, child := authenticatedCommitChild(t, w, verifier, ceremonyID, []byte("checkpoint"), []byte("signature"), nil, 0)
	delete(w.objects, store.Key(child.signatureRef.SHA256))
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child}, t.TempDir()); err == nil {
		t.Fatal("root committed before its immutable signature existed")
	}
	if w.create != 0 {
		t.Fatal("root create was attempted before immutable verification")
	}
	w.objects[store.Key(child.signatureRef.SHA256)] = []byte("wrong-signature")
	if _, err := CommitRoot(w, RootCommit{CeremonyID: ceremonyID, Child: child}, t.TempDir()); err == nil {
		t.Fatal("root committed with wrong immutable signature bytes")
	}
}

func TestAuthenticateRootChildRejectsReferenceOrVerifierMismatch(t *testing.T) {
	dir := t.TempDir()
	cpPath, sigPath := filepath.Join(dir, "checkpoint.json"), filepath.Join(dir, "checkpoint.sig")
	if err := os.WriteFile(cpPath, []byte("checkpoint"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte("signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	cpRef, sigRef := ref("checkpoints/0.json", []byte("checkpoint")), ref("checkpoints/0.sig", []byte("signature"))
	verifier := &verifierFake{byDigest: map[string]Checkpoint{cpRef.SHA256: {CeremonyID: digestOfTest("1"), Position: state.CheckpointPosition{Sequence: 0, Digest: digestOfTest("f")}}}}
	if _, err := AuthenticateRootChild(verifier, cpRef, sigRef, dir, cpPath, sigPath); err == nil {
		t.Fatal("proof-tool digest mismatch accepted")
	}
	cpRef.Size++
	if _, err := AuthenticateRootChild(verifier, cpRef, sigRef, dir, cpPath, sigPath); err == nil {
		t.Fatal("local checkpoint reference mismatch accepted")
	}
}

func TestAuthenticateRootChildRejectsShallowCheckpointOnly(t *testing.T) {
	dir := t.TempDir()
	cpBytes, sigBytes := []byte("checkpoint"), []byte("signature")
	cpPath, sigPath := filepath.Join(dir, "checkpoint.json"), filepath.Join(dir, "checkpoint.sig")
	if err := os.WriteFile(cpPath, cpBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sigBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cpRef, sigRef := ref("checkpoints/0.json", cpBytes), ref("checkpoints/0.sig", sigBytes)
	ceremonyID := digestOfTest("1")
	verifier := &verifierFake{byDigest: map[string]Checkpoint{
		cpRef.SHA256: {CeremonyID: ceremonyID, Position: state.CheckpointPosition{Digest: cpRef.SHA256}, Transition: "initial"},
	}, rejectEvidence: true}
	if _, err := AuthenticateRootChild(verifier, cpRef, sigRef, dir, cpPath, sigPath); err == nil || !strings.Contains(err.Error(), "bad stored evidence") {
		t.Fatalf("err=%v", err)
	}
}

func authenticatedCommitChild(t *testing.T, w *rootWriterFake, verifier *verifierFake, ceremonyID string, checkpointBytes, signatureBytes []byte, previous *SignedRef, sequence uint64) (state.ContentRef, state.ContentRef, AuthenticatedRootChild) {
	t.Helper()
	cpRef := ref("checkpoints/child.json", checkpointBytes)
	sigRef := ref("checkpoints/child.sig", signatureBytes)
	w.objects[store.Key(cpRef.SHA256)] = append([]byte(nil), checkpointBytes...)
	w.objects[store.Key(sigRef.SHA256)] = append([]byte(nil), signatureBytes...)
	position := state.CheckpointPosition{Sequence: sequence, Digest: cpRef.SHA256}
	if previous != nil {
		position.PreviousDigest = previous.Checkpoint.SHA256
	}
	transition := "initial"
	if sequence > 0 {
		transition = "phase1-outbound-published"
	}
	verifier.byDigest[cpRef.SHA256] = Checkpoint{CeremonyID: ceremonyID, Position: position, Previous: previous, Transition: transition}
	dir := t.TempDir()
	cpPath, sigPath := filepath.Join(dir, "checkpoint.json"), filepath.Join(dir, "checkpoint.sig")
	if err := os.WriteFile(cpPath, checkpointBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, signatureBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier.evidence = EvidenceVerification{CeremonyID: ceremonyID, Sequence: sequence, Digest: cpRef.SHA256, TransitionKind: transition, FullyVerified: true}
	child, err := AuthenticateRootChild(verifier, cpRef, sigRef, dir, cpPath, sigPath)
	if err != nil {
		t.Fatal(err)
	}
	return cpRef, sigRef, child
}

func digestOfTest(c string) string { return "sha256:" + string(makeHex(c, 64)) }
func makeHex(c string, n int) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = c[0]
	}
	return result
}

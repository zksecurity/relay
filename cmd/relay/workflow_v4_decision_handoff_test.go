package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func testHandoffDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func testDecisionHandoff(t *testing.T) workflowV4DecisionHandoff {
	t.Helper()
	dir, _ := offlineFixture(t)
	raw, err := os.ReadFile(filepath.Join(dir, offlineSnapshotFile))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot workflowV4PublicSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	decision := testHandoffDigest("decision")
	prefix, err := workflowV4HandoffPrefix(snapshot.Root.CeremonyID, decision)
	if err != nil {
		t.Fatal(err)
	}
	signature := testHandoffDigest("coordinator-signature")
	decisionKey, _ := workflowV4HandoffObjectKey(prefix, decision)
	signatureKey, _ := workflowV4HandoffObjectKey(prefix, signature)
	return workflowV4DecisionHandoff{
		Schema:           workflowV4DecisionHandoffSchema,
		CeremonyID:       snapshot.Root.CeremonyID,
		CandidateID:      testHandoffDigest("candidate"),
		CheckpointSHA256: snapshot.Root.Checkpoint.SHA256,
		DecisionSHA256:   decision,
		SignerID:         "release-signer-1",
		PublishedBaseURL: "https://example.test",
		Snapshot:         snapshot,
		Files: []workflowV4DecisionHandoffFile{
			{Name: "decision/decision.json", Key: decisionKey, SHA256: decision, Size: 8},
			{Name: "decision/coordinator.sig", Key: signatureKey, SHA256: signature, Size: 21},
		},
	}
}

func TestDecisionHandoffRejectsChangedBindingsAndUnsafeInventory(t *testing.T) {
	valid := testDecisionHandoff(t)
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*workflowV4DecisionHandoff){
		"wrong ceremony":    func(m *workflowV4DecisionHandoff) { m.CeremonyID = testHandoffDigest("other") },
		"missing candidate": func(m *workflowV4DecisionHandoff) { m.CandidateID = "" },
		"wrong decision":    func(m *workflowV4DecisionHandoff) { m.DecisionSHA256 = testHandoffDigest("other") },
		"wrong object key":  func(m *workflowV4DecisionHandoff) { m.Files[0].Key = "handoff/elsewhere" },
		"path traversal":    func(m *workflowV4DecisionHandoff) { m.Files[1].Name = "decision/../signing.hex" },
		"duplicate path":    func(m *workflowV4DecisionHandoff) { m.Files[1].Name = m.Files[0].Name },
		"missing signature": func(m *workflowV4DecisionHandoff) { m.Files = m.Files[:1] },
		"oversized file":    func(m *workflowV4DecisionHandoff) { m.Files[1].Size = 16<<20 + 1 },
		"invalid signer":    func(m *workflowV4DecisionHandoff) { m.SignerID = "../other" },
		"snapshot traversal": func(m *workflowV4DecisionHandoff) {
			m.Snapshot.Files = append([]state.ContentRef(nil), m.Snapshot.Files...)
			m.Snapshot.Files[0].Name = "../signing.hex"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Files = append([]workflowV4DecisionHandoffFile(nil), valid.Files...)
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("unsafe handoff accepted")
			}
		})
	}
}

func TestDecisionHandoffRejectsDuplicateAndUnknownJSON(t *testing.T) {
	valid := testDecisionHandoff(t)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflowV4DecodeHandoff(raw); err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{
		[]byte(strings.Replace(string(raw), `"schema":`, `"schema":"other","schema":`, 1)),
		[]byte(strings.Replace(string(raw), `"schema":`, `"unexpected":true,"schema":`, 1)),
		append(append([]byte(nil), raw...), []byte(" true")...),
	} {
		if _, err := workflowV4DecodeHandoff(corrupt); err == nil {
			t.Fatal("invalid handoff JSON accepted")
		}
	}
}

func TestDecisionHandoffAWSCreateOnlyReadbackAndConflict(t *testing.T) {
	if os.Getenv("CI_WINDOWS") != "" {
		t.Skip("the fake AWS executable uses a POSIX shell")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	fake := `#!/bin/sh
exec python3 - "$@" <<'PY'
import hashlib, json, os, pathlib, sys
a = sys.argv[1:]
a = a[a.index('s3api')+1:]
op = a[0]
def arg(name):
    return a[a.index(name)+1]
path = pathlib.Path(os.environ['AWS_FAKE_ROOT']) / arg('--bucket') / arg('--key')
if op == 'put-object':
    if path.exists():
        sys.stderr.write('PreconditionFailed')
        sys.exit(1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pathlib.Path(arg('--body')).read_bytes())
    print('{}')
elif op == 'head-object':
    if not path.is_file():
        sys.exit(1)
    raw = path.read_bytes()
    print(json.dumps({'ETag': hashlib.sha256(raw).hexdigest(), 'ContentLength': len(raw)}))
elif op == 'get-object':
    if not path.is_file():
        sys.exit(1)
    raw = path.read_bytes()
    if arg('--if-match') != hashlib.sha256(raw).hexdigest():
        sys.exit(1)
    pathlib.Path(a[-1]).write_bytes(raw)
    print(json.dumps({'ETag': hashlib.sha256(raw).hexdigest()}))
else:
    sys.exit(2)
PY
`
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AWS_FAKE_ROOT", filepath.Join(root, "objects"))
	source := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(source, []byte(`{"schema":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	client := store.Client{Bucket: "test-inbox", Region: "test-region", Profile: "test-profile"}
	key := "handoff/decision/test/manifest.json"
	if err := workflowV4HandoffPut(client, key, source, root, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4HandoffPut(client, key, source, root, 1<<20); err != nil {
		t.Fatalf("identical create-only retry: %v", err)
	}
	if err := os.WriteFile(source, []byte(`{"schema":"changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4HandoffPut(client, key, source, root, 1<<20); err == nil {
		t.Fatal("conflicting existing AWS bytes were accepted")
	}
}

func TestDecisionHandoffRejectsWrongReleaseBinding(t *testing.T) {
	m := testDecisionHandoff(t)
	path := filepath.Join(t.TempDir(), "decision.json")
	release := transcript.SignedArtifactRefs{
		Record:    transcript.ArtifactRef{Name: m.Snapshot.Root.Checkpoint.Name, Digest: transcript.Digest{SHA256: m.CheckpointSHA256, Size: m.Snapshot.Root.Checkpoint.Size}},
		Signature: transcript.ArtifactRef{Name: m.Snapshot.Root.CheckpointSignature.Name, Digest: transcript.Digest{SHA256: m.Snapshot.Root.CheckpointSignature.SHA256, Size: m.Snapshot.Root.CheckpointSignature.Size}},
	}
	write := func(candidate string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"release": map[string]any{"candidate_id": candidate, "final_release_checkpoint": release}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(m.CandidateID)
	if err := workflowV4HandoffDecisionRelease(path, m.CandidateID, m.CheckpointSHA256, m.Snapshot.Root); err != nil {
		t.Fatal(err)
	}
	write(testHandoffDigest("other-candidate"))
	if err := workflowV4HandoffDecisionRelease(path, m.CandidateID, m.CheckpointSHA256, m.Snapshot.Root); err == nil {
		t.Fatal("wrong candidate accepted")
	}
	write(m.CandidateID)
	if err := workflowV4HandoffDecisionRelease(path, m.CandidateID, testHandoffDigest("other-checkpoint"), m.Snapshot.Root); err == nil {
		t.Fatal("wrong final checkpoint accepted")
	}
}

func TestFetchedSignatureIsNotPromotedBeforeVerification(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "fetched.sig")
	destination := filepath.Join(dir, "release-signer.sig")
	if err := os.WriteFile(source, []byte("invalid signature"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4PromoteVerifiedDecisionSignature(source, destination, func(string) error {
		return os.ErrInvalid
	}); err == nil {
		t.Fatal("invalid signature passed verification")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("invalid signature occupied the canonical path")
	}
	if err := os.WriteFile(source, []byte("valid replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4PromoteVerifiedDecisionSignature(source, destination, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(destination)
	if err != nil || string(retained) != "valid replacement" {
		t.Fatal("validated replacement was not retained exactly")
	}
}

func TestRetainedSignerDownloadCanBeReusedAndDetectsLostSnapshot(t *testing.T) {
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := testDecisionHandoff(t)
	stage := filepath.Join(work, "incoming-decision-test")
	snapshotDir := filepath.Join(stage, "snapshot")
	if err := os.MkdirAll(filepath.Join(snapshotDir, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(stage, "handoff-manifest.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0600); err != nil {
		t.Fatal(err)
	}
	snapshotRaw, err := json.MarshalIndent(m.Snapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, offlineSnapshotFile), snapshotRaw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range m.Snapshot.Files {
		object := filepath.Join(snapshotDir, "objects", strings.TrimPrefix(ref.SHA256, "sha256:"))
		if err := os.WriteFile(object, []byte("public checkpoint"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	decisionDir := filepath.Join(work, "ceremony", "public", "decision")
	if err := os.MkdirAll(decisionDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"decision.json": "decision", "coordinator.sig": "coordinator-signature"} {
		if err := os.WriteFile(filepath.Join(decisionDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	prefix, _ := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	manifestHash, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	transport := workflowV4SignerHandoffTransport{Schema: "relay-signer-decision-transport-v1", CeremonyID: m.CeremonyID, CandidateID: m.CandidateID, CheckpointSHA256: m.CheckpointSHA256, DecisionSHA256: m.DecisionSHA256, SignerID: m.SignerID, Region: "us-east-1", Bucket: "private-inbox", ManifestKey: prefix + "/manifest.json", ManifestSHA256: manifestHash, SignatureKey: prefix + "/signatures/" + m.SignerID + ".sig", SnapshotPath: snapshotDir}
	if err := workflowV4ValidateRetainedDecisionDownload(work, m.SignerID, transport); err != nil {
		t.Fatalf("exact completed download could not be reused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(decisionDir, "unexpected.tmp"), []byte("sidecar"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4ValidateRetainedDecisionDownload(work, m.SignerID, transport); err == nil {
		t.Fatal("unexpected retained decision sidecar was ignored")
	}
	if err := os.Remove(filepath.Join(decisionDir, "unexpected.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(snapshotDir); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4ValidateRetainedDecisionDownload(work, m.SignerID, transport); err == nil {
		t.Fatal("lost snapshot was treated as a reusable download")
	}
	canonical := filepath.Join(decisionDir, "decision.json")
	if err := os.WriteFile(canonical, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := setupWriteBytesNewOrExact(canonical, []byte("decision"), 0600); err == nil {
		t.Fatal("retry silently replaced conflicting canonical decision bytes")
	}
}

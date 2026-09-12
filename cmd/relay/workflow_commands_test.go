package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func TestCollectEvidenceRejectsSymlinksAndSecrets(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "audit.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.sig")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := collectEvidence(nil, dir); err == nil {
		t.Fatal("evidence symlink accepted")
	}
	if _, err := collectEvidence([]string{"release-signing-key.hex"}, ""); err == nil {
		t.Fatal("possible signing key accepted")
	}
}

func TestParticipateV2ProfileRequiresTurnGrant(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "participant.json")
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, Phase: "phase1", Root: filepath.Join(dir, "ceremony"),
		Ceremony: filepath.Join(dir, "ceremony.json"), CeremonySignature: filepath.Join(dir, "ceremony.sig"),
		CoordinatorKey: filepath.Join(dir, "coordinator.hex"), CeremonyBinary: "mpc-ceremony",
		SigningKey: filepath.Join(dir, "participant.hex"), Environment: filepath.Join(dir, "environment.json"),
		CandidateParentDir: filepath.Join(dir, "candidates"), PublishedBaseURL: "https://ceremony.example",
		PublishedBucket: "published", ExecutionMode: nativeExecutionMode,
	}
	if err := writeJSONNoReplace(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runParticipate([]string{"--config", configPath})
	if err == nil || !strings.Contains(err.Error(), "temporary upload grant") {
		t.Fatalf("missing grant error = %v", err)
	}
}

func TestManifestKeysOnlyReturnsSafeCompletedSubmissions(t *testing.T) {
	objects := []store.Object{
		{Key: "candidates/id/person/phase1/0001/attempt/contribution.bin"},
		{Key: "candidates/id/person/phase1/0001/attempt/manifest.json"},
		{Key: "../manifest.json"},
	}
	got := manifestKeys(objects)
	if len(got) != 1 || got[0] != objects[1].Key {
		t.Fatalf("manifest keys = %q", got)
	}
}

type candidateStoreFake struct {
	objects map[string][]byte
	puts    []string
	failKey string
}

func (f *candidateStoreFake) PutNoReplace(key, localPath string) error {
	if key == f.failKey {
		return errors.New("temporary upload failure")
	}
	if _, exists := f.objects[key]; exists {
		return store.ErrExists
	}
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	f.objects[key] = append([]byte(nil), raw...)
	f.puts = append(f.puts, key)
	return nil
}

func (f *candidateStoreFake) Get(key, localPath string) error {
	raw, exists := f.objects[key]
	if !exists {
		return os.ErrNotExist
	}
	return os.WriteFile(localPath, raw, 0o600)
}

func candidateFixture(t *testing.T) (string, string, access.CandidateManifest) {
	t.Helper()
	dir := t.TempDir()
	manifest := access.CandidateManifest{
		Schema: access.CandidateManifestSchema, CeremonyID: "sha256:" + strings.Repeat("a", 64),
		Phase: "phase1", Index: 3, ParticipantID: "participant-03",
		ParentChainSHA256: "sha256:" + strings.Repeat("b", 64),
		AttemptID:         strings.Repeat("c", 32), CompletedAt: "2026-08-29T12:00:00Z",
	}
	for _, name := range candidateFileNames {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("contents of "+name), 0o600); err != nil {
			t.Fatal(err)
		}
		ref, err := regularFileRef(filepath.Join(dir, name), name)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, ref)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, localCandidateManifestName)
	if err := writeJSONNoReplace(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, manifestPath, manifest
}

func TestUploadCandidateResumesMatchingPartialUpload(t *testing.T) {
	dir, manifestPath, manifest := candidateFixture(t)
	grantPrefix, err := access.Prefix(manifest.CeremonyID, access.RoleParticipant, manifest.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := grantPrefix + "phase1/0003/" + manifest.AttemptID + "/"
	fake := &candidateStoreFake{objects: make(map[string][]byte), failKey: prefix + "attestation.sig"}

	if _, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest); err == nil {
		t.Fatal("interrupted upload succeeded")
	}
	if len(fake.objects) != 2 {
		t.Fatalf("partial object count = %d, want 2", len(fake.objects))
	}

	fake.failKey = ""
	manifestKey, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if manifestKey != prefix+"manifest.json" {
		t.Fatalf("manifest key = %q", manifestKey)
	}
	if len(fake.objects) != len(candidateFileNames)+1 {
		t.Fatalf("completed object count = %d", len(fake.objects))
	}
	if got := fake.puts[len(fake.puts)-1]; got != manifestKey {
		t.Fatalf("last created object = %q, want manifest %q", got, manifestKey)
	}
	created := len(fake.puts)
	if got, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest); err != nil || got != manifestKey {
		t.Fatalf("completed retry = %q, %v", got, err)
	}
	if len(fake.puts) != created {
		t.Fatalf("completed retry created %d extra objects", len(fake.puts)-created)
	}
}

func TestUploadCandidateRejectsConflictingExistingObject(t *testing.T) {
	dir, manifestPath, manifest := candidateFixture(t)
	grantPrefix, err := access.Prefix(manifest.CeremonyID, access.RoleParticipant, manifest.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := grantPrefix + "phase1/0003/" + manifest.AttemptID + "/"
	fake := &candidateStoreFake{objects: map[string][]byte{
		prefix + candidateFileNames[0]: []byte("different bytes"),
	}}

	_, err = uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest)
	if err == nil || !strings.Contains(err.Error(), "conflicts with the saved candidate") {
		t.Fatalf("conflicting upload error = %v", err)
	}
}

func TestUploadJSONLastOrVerifyIsIdempotent(t *testing.T) {
	fake := &candidateStoreFake{objects: make(map[string][]byte)}
	value := map[string]string{"schema": "example-v1", "attempt_id": strings.Repeat("a", 32)}
	if err := uploadJSONLastOrVerify(fake, "evidence/manifest.json", value); err != nil {
		t.Fatal(err)
	}
	created := len(fake.puts)
	if err := uploadJSONLastOrVerify(fake, "evidence/manifest.json", value); err != nil {
		t.Fatal(err)
	}
	if len(fake.puts) != created {
		t.Fatal("matching manifest retry created another object")
	}
	if err := uploadJSONLastOrVerify(fake, "evidence/manifest.json", map[string]string{"schema": "different"}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting manifest retry error = %v", err)
	}
}

func TestVerifyLocalCandidateRejectsChangedFile(t *testing.T) {
	dir, _, manifest := candidateFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "erasure.json"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalCandidate(dir, manifest); err == nil || !strings.Contains(err.Error(), "recorded digest") {
		t.Fatalf("changed candidate error = %v", err)
	}
}

func TestFinishResumableCandidateMetadataKeepsExistingContribution(t *testing.T) {
	parent := t.TempDir()
	attempt := strings.Repeat("d", 32)
	dir := filepath.Join(parent, "phase1-0003-"+attempt)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range candidateFileNames {
		contents := []byte("retained " + name)
		if name == "erasure.json" {
			contents = []byte(`{"destroyed_at":"2026-09-12T01:02:03Z"}`)
		}
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	grant := access.Grant{CeremonyID: "sha256:" + strings.Repeat("a", 64), IdentityID: "participant-03"}
	config := access.ParticipantConfig{Phase: "phase1", ExecutionMode: nativeExecutionMode}
	pos := position{nextIndex: 3, pointer: state.Pointer{Chain: state.Ref{SHA256: "sha256:" + strings.Repeat("b", 64)}}}
	if err := finishResumableCandidateMetadata(config, grant, pos, dir, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, localCandidateManifestName))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := access.Decode(raw, access.CandidateManifest.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.AttemptID != attempt || manifest.Index != 3 || manifest.ParentChainSHA256 != pos.pointer.Chain.SHA256 {
		t.Fatalf("recovered manifest = %#v", manifest)
	}
	if manifest.CompletedAt != "2026-09-12T01:02:03Z" {
		t.Fatalf("recovered manifest did not reuse cleanup time: %s", manifest.CompletedAt)
	}
}

func TestPersistDockerErasureIntentIsStable(t *testing.T) {
	dir := t.TempDir()
	receipt, driver := verifiedDockerLifecycleFixture()
	path := filepath.Join(dir, dockerLifecycleLogName)
	if err := writeJSONNoReplace(path, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	o := roleOpts{outDir: dir, docker: driver}
	want := time.Date(2026, 9, 12, 0, 0, 1, 0, time.UTC)
	if err := persistDockerErasureIntent(o, want); err != nil {
		t.Fatal(err)
	}
	got, confirmed, err := dockerErasureIntent(o)
	if err != nil || !confirmed || !got.Equal(want) {
		t.Fatalf("saved erasure intent = %v, %v, %v", got, confirmed, err)
	}
	if err := persistDockerErasureIntent(o, want.Add(time.Second)); err == nil {
		t.Fatal("changed persisted erasure time")
	}
}

func verifiedDockerLifecycleFixture() (dockerLifecycleReceipt, *dockerDriver) {
	image := "sha256:" + strings.Repeat("a", 64)
	status := dockerLinuxSwapDisabled
	if runtime.GOOS == "darwin" {
		status = dockerMacSwapUnassessed
	}
	receipt := dockerLifecycleReceipt{
		Schema: dockerLifecycleSchema, Image: image, Platform: "linux/arm64", RemovalVerified: true,
		ParticipantConfirmation: "CLEANUP PRECAUTIONS CONFIRMED", ConfirmedAt: "2026-09-12T00:00:00Z", HostSwapStatus: status,
		Daemon:   dockerDaemonFacts{Context: "default", Endpoint: "unix:///var/run/docker.sock", ID: "daemon", Name: "docker", ServerVersion: "1", OperatingSystem: "Linux", OSType: "linux", Architecture: "arm64", LocalUnixEndpoint: true},
		Security: dockerSecurityFacts{NetworkNone: true, ReadOnlyRoot: true, NonRoot: true, CapabilitiesOff: true, NoNewPrivileges: true, CoreDumpsOff: true, LogDriverOff: true, PrivatePID: true, PrivateIPC: true, UserNamespaceMode: "private", BoundedTmpfs: true, MountsVerified: true},
	}
	return receipt, &dockerDriver{image: image, platform: "linux/arm64"}
}

func TestFinishResumableCandidateMetadataBlocksPartialLegacyErasure(t *testing.T) {
	parent := t.TempDir()
	attempt := strings.Repeat("e", 32)
	dir := filepath.Join(parent, "phase1-0001-"+attempt)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range candidateFileNames[:len(candidateFileNames)-1] {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("retained "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	receipt, driver := verifiedDockerLifecycleFixture()
	if err := writeJSONNoReplace(filepath.Join(dir, dockerLifecycleLogName), receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	config := access.ParticipantConfig{Phase: "phase1", ExecutionMode: dockerExecutionMode}
	grant := access.Grant{CeremonyID: "sha256:" + strings.Repeat("a", 64), IdentityID: "participant-01"}
	pos := position{nextIndex: 1, pointer: state.Pointer{Chain: state.Ref{SHA256: "sha256:" + strings.Repeat("b", 64)}}}
	err := finishResumableCandidateMetadata(config, grant, pos, dir, driver)
	if err == nil || !strings.Contains(err.Error(), "partial legacy erasure") {
		t.Fatalf("partial legacy erasure error = %v", err)
	}
}

func TestCandidateDestroyedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "erasure.json")
	if err := os.WriteFile(path, []byte(`{"destroyed_at":"2026-09-04T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := candidateDestroyedAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-09-04T12:00:00Z" {
		t.Fatalf("destroyed_at = %q", got)
	}

	if err := os.WriteFile(path, []byte(`{"destroyed_at":"not-a-time"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateDestroyedAt(dir); err == nil {
		t.Fatal("invalid destroyed_at accepted")
	}
}

func TestValidateResumableCandidateRejectsAdvancedHead(t *testing.T) {
	_, _, manifest := candidateFixture(t)
	config := access.ParticipantConfig{Phase: manifest.Phase}
	grant := access.Grant{
		CeremonyID: manifest.CeremonyID, IdentityID: manifest.ParticipantID,
	}
	pos := position{
		nextID: manifest.ParticipantID, nextIndex: manifest.Index + 1,
		pointer: state.Pointer{Chain: state.Ref{SHA256: "sha256:" + strings.Repeat("d", 64)}},
	}
	if err := validateResumableCandidate(manifest, config, grant, pos); err == nil || !strings.Contains(err.Error(), "different ceremony head") {
		t.Fatalf("advanced-head error = %v", err)
	}
}

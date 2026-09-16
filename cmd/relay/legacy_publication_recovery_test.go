package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
)

func writeRecoveryFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFrozen1828GoldenContextRemainsCompatible(t *testing.T) {
	root := filepath.Join("testdata", "frozen-1828-recovery")
	var profile guidedProfile
	if err := setupReadJSON(filepath.Join(root, "profile.json"), &profile); err != nil {
		t.Fatal(err)
	}
	var workflow roleFlowState
	if err := setupReadJSON(filepath.Join(root, "state.json"), &workflow); err != nil {
		t.Fatal(err)
	}
	var draft coordinatorDraft
	if err := setupReadJSON(filepath.Join(root, "draft.json"), &draft); err != nil {
		t.Fatal(err)
	}
	attempt, err := validateFrozenRecoveryState(profile, workflow)
	if err != nil || attempt.ID != "flow-"+strings.Repeat("b", 32) {
		t.Fatalf("1828 golden workflow rejected: attempt=%v err=%v", attempt, err)
	}
	if err := validateFrozenRecoveryDraft(profile, draft, false); err != nil {
		t.Fatalf("1828 golden preparation rejected: %v", err)
	}
}

func frozen1828RecoveryFixture(t *testing.T) (string, string, guidedProfile, coordinatorDraft, string) {
	t.Helper()
	root := t.TempDir()
	settingsRoot := filepath.Join(root, "settings")
	work, trust, keys := filepath.Join(root, "work"), filepath.Join(root, "trust"), filepath.Join(root, "keys")
	for _, dir := range []string{settingsRoot, work, trust, keys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldCredentials, newCredentials := filepath.Join(root, "old.aws"), filepath.Join(root, "new.aws")
	writeRecoveryFixtureFile(t, oldCredentials, "[default]\naws_access_key_id=old\naws_secret_access_key=old\n")
	writeRecoveryFixtureFile(t, newCredentials, "[default]\naws_access_key_id=new\naws_secret_access_key=new\n")
	name := "frozen-1828-fixture"
	p := guidedProfile{Schema: guidedSchema, Name: name, Role: "coordinator", ReleaseCommit: expiredAWSRecoveryRelease,
		Image: "sha256:" + strings.Repeat("a", 64), Platform: "linux/arm64", Work: work, Trust: trust, Keys: keys, Credentials: oldCredentials}
	dir, err := guidedDirectory(settingsRoot, name, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "workflow"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveJSONAtomic(filepath.Join(dir, "profile.json"), p); err != nil {
		t.Fatal(err)
	}
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
	storagePath := filepath.Join(work, "ceremony", "config", "relay-storage.json")
	if err := os.MkdirAll(filepath.Dir(storagePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(storagePath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(work, "ceremony", "public", "phase1", "chain-0000.json")
	signaturePath := filepath.Join(work, "ceremony", "public", "phase1", "chain-0000.sig")
	writeRecoveryFixtureFile(t, chainPath, "retained-chain")
	writeRecoveryFixtureFile(t, signaturePath, "retained-signature")
	command := []string{"relay", "coordinator", "publish", "--verify", "--storage", "/work/ceremony/config/relay-storage.json", "--chain", "/work/ceremony/public/phase1/chain-0000.json", "--chain-signature", "/work/ceremony/public/phase1/chain-0000.sig"}
	bindings := map[string]string{}
	for index, hostPath := range []string{storagePath, chainPath, signaturePath} {
		digest, err := setupFileHash(hostPath)
		if err != nil {
			t.Fatal(err)
		}
		bindings[command[5+index*2]] = digest
	}
	attempt := flowAttempt{ID: "flow-" + strings.Repeat("b", 32), Task: "publish", Stage: "storage", Status: "failed",
		OperationSchema: flowOperationSchema, RecoveryClass: recoveryPublication, ImageDigest: p.Image, Platform: p.Platform,
		Command: command, Mounts: map[string]string{"/work": work, "/trust": trust, "/keys": keys}, InputBindings: bindings}
	workflow := roleFlowState{Schema: roleFlowSchema, Name: name, Role: "coordinator", Profile: p, Attempts: []flowAttempt{attempt}, Values: map[string]string{}}
	if err := saveJSONAtomic(filepath.Join(dir, "workflow", "state.json"), workflow); err != nil {
		t.Fatal(err)
	}
	draft := coordinatorDraft{Name: name, Release: "role-images-" + expiredAWSRecoveryRelease, Work: work, Trust: trust, Keys: keys,
		Credentials: newCredentials, Storage: settings.Settings}
	draftPath := filepath.Join(work, "coordinator-setup", "draft.json")
	if err := os.MkdirAll(filepath.Dir(draftPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveJSONAtomic(draftPath, draft); err != nil {
		t.Fatal(err)
	}
	return settingsRoot, name, p, draft, attempt.ID
}

func TestFrozen1828RecoveryPathAndIdempotentRerun(t *testing.T) {
	settingsRoot, name, oldProfile, draft, attemptID := frozen1828RecoveryFixture(t)
	oldCommit, oldInput, oldOutput, oldRemote, oldHook, oldSave := legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote, legacyRecoveryAfterCredentialRefresh, legacyRecoverySave
	defer func() {
		legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote = oldCommit, oldInput, oldOutput, oldRemote
		legacyRecoveryAfterCredentialRefresh, legacyRecoverySave = oldHook, oldSave
	}()
	commit := strings.Repeat("d", 40)
	legacyRecoveryLauncherCommit = func() string { return commit }
	legacyRecoveryInput = strings.NewReader("UPDATE CREDENTIAL REFERENCES\n")
	var output bytes.Buffer
	legacyRecoveryOutput = &output
	remoteCalls := 0
	legacyRecoveryRemote = func(p guidedProfile, gotDraft coordinatorDraft, dir string, attempt *flowAttempt, gotCommit string) error {
		remoteCalls++
		if p.ReleaseCommit != expiredAWSRecoveryRelease || p.Image != oldProfile.Image || p.Credentials != draft.Credentials ||
			!reflect.DeepEqual(gotDraft, draft) || attempt.ID != attemptID || gotCommit != commit {
			t.Fatal("remote recovery did not receive the fully revalidated frozen context")
		}
		return nil
	}
	args := []string{name, "--settings-root", settingsRoot}
	if err := runLegacyPublicationRecovery(args); err != nil {
		t.Fatal(err)
	}
	if remoteCalls != 1 {
		t.Fatalf("remote calls=%d, want 1", remoteCalls)
	}
	dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
	var state roleFlowState
	if err := setupReadJSON(filepath.Join(dir, "workflow", "state.json"), &state); err != nil {
		t.Fatal(err)
	}
	attempt, err := validateFrozenRecoveryState(state.Profile, state)
	if err != nil || !legacyRecoveryCompleted(state, attempt) {
		t.Fatalf("completion not retained: attempt=%v err=%v", attempt, err)
	}
	legacyRecoveryLauncherCommit = func() string { return strings.Repeat("f", 40) }
	legacyRecoveryInput = strings.NewReader("")
	legacyRecoveryRemote = func(guidedProfile, coordinatorDraft, string, *flowAttempt, string) error {
		t.Fatal("durably completed recovery must not rerun the remote operation")
		return nil
	}
	if err := runLegacyPublicationRecovery(args); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryContextMountIsInternalAndReadOnly(t *testing.T) {
	o := roleTestOptions(t)
	o.recoveryContext = privateRoleTestDir(t)
	args, err := dockerRoleArgs(o, []string{"relay", "coordinator", "recover-initial-1828", "--attempt-id", "flow-" + strings.Repeat("a", 32)}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "src="+o.recoveryContext+",dst=/recovery,readonly") {
		t.Fatalf("recovery context is not mounted read-only: %s", joined)
	}
	o.recoveryContext = ""
	args, err = dockerRoleArgs(o, []string{"relay", "coordinator", "publish"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "dst=/recovery") {
		t.Fatal("ordinary role invocation unexpectedly received recovery context")
	}
}

func TestPostRotationMutationsStopBeforeRemoteRecovery(t *testing.T) {
	mutations := map[string]func(t *testing.T, settingsRoot, name string, draft coordinatorDraft){
		"profile": func(t *testing.T, settingsRoot, name string, _ coordinatorDraft) {
			dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
			path := filepath.Join(dir, "profile.json")
			var p guidedProfile
			if err := setupReadJSON(path, &p); err != nil {
				t.Fatal(err)
			}
			p.Image = "sha256:" + strings.Repeat("9", 64)
			if err := saveJSONAtomic(path, p); err != nil {
				t.Fatal(err)
			}
		},
		"workflow command": func(t *testing.T, settingsRoot, name string, _ coordinatorDraft) {
			dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
			path := filepath.Join(dir, "workflow", "state.json")
			var s roleFlowState
			if err := setupReadJSON(path, &s); err != nil {
				t.Fatal(err)
			}
			s.Attempts[0].Command[3] = "--closed"
			if err := saveJSONAtomic(path, s); err != nil {
				t.Fatal(err)
			}
		},
		"draft storage": func(t *testing.T, _ string, _ string, draft coordinatorDraft) {
			draft.Storage["published-bucket"] = "changed-bucket"
			if err := saveJSONAtomic(filepath.Join(draft.Work, "coordinator-setup", "draft.json"), draft); err != nil {
				t.Fatal(err)
			}
		},
		"attempt status": func(t *testing.T, settingsRoot, name string, _ coordinatorDraft) {
			dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
			path := filepath.Join(dir, "workflow", "state.json")
			var s roleFlowState
			if err := setupReadJSON(path, &s); err != nil {
				t.Fatal(err)
			}
			s.Attempts[0].Status = "succeeded"
			if err := saveJSONAtomic(path, s); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			settingsRoot, ceremony, _, draft, _ := frozen1828RecoveryFixture(t)
			oldCommit, oldInput, oldOutput, oldRemote, oldHook := legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote, legacyRecoveryAfterCredentialRefresh
			defer func() {
				legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote, legacyRecoveryAfterCredentialRefresh = oldCommit, oldInput, oldOutput, oldRemote, oldHook
			}()
			legacyRecoveryLauncherCommit = func() string { return strings.Repeat("d", 40) }
			legacyRecoveryInput = strings.NewReader("UPDATE CREDENTIAL REFERENCES\n")
			legacyRecoveryOutput = &bytes.Buffer{}
			legacyRecoveryAfterCredentialRefresh = func() error { mutate(t, settingsRoot, ceremony, draft); return nil }
			legacyRecoveryRemote = func(guidedProfile, coordinatorDraft, string, *flowAttempt, string) error {
				t.Fatal("mutation reached remote recovery")
				return nil
			}
			if err := runLegacyPublicationRecovery([]string{ceremony, "--settings-root", settingsRoot}); err == nil {
				t.Fatal("post-rotation mutation was accepted")
			}
		})
	}
}

func TestRemoteSuccessCheckpointNotLandedRerunsCreateOnly(t *testing.T) {
	settingsRoot, name, _, _, _ := frozen1828RecoveryFixture(t)
	oldCommit, oldInput, oldOutput, oldRemote, oldSave := legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote, legacyRecoverySave
	defer func() {
		legacyRecoveryLauncherCommit, legacyRecoveryInput, legacyRecoveryOutput, legacyRecoveryRemote, legacyRecoverySave = oldCommit, oldInput, oldOutput, oldRemote, oldSave
	}()
	commit := strings.Repeat("d", 40)
	legacyRecoveryLauncherCommit = func() string { return commit }
	legacyRecoveryInput = strings.NewReader("UPDATE CREDENTIAL REFERENCES\n")
	legacyRecoveryOutput = &bytes.Buffer{}
	source := filepath.Join(t.TempDir(), "blob")
	writeRecoveryFixtureFile(t, source, "exact retained bytes")
	ref := state.Ref{Name: "phase1/chain-0000.json", SHA256: "sha256:" + strings.Repeat("a", 64)}
	sig := state.Ref{Name: "phase1/chain-0000.sig", SHA256: "sha256:" + strings.Repeat("b", 64)}
	pointer := state.Pointer{Schema: state.Schema, CeremonyID: "sha256:" + strings.Repeat("c", 64), Phase: "phase1", Index: 0, Chain: ref, ChainSignature: sig, UpdatedAt: "2026-01-01T00:00:00Z", Files: []state.Ref{ref, sig}}
	raw, _ := pointer.Encode()
	pointerPath := filepath.Join(t.TempDir(), "head.json")
	writeRecoveryFixtureFile(t, pointerPath, string(raw))
	store := &publicationStoreFake{objects: map[string][]byte{}}
	remoteCalls := 0
	legacyRecoveryRemote = func(guidedProfile, coordinatorDraft, string, *flowAttempt, string) error {
		remoteCalls++
		if err := reconcilePublicationObject(store, "blob", source, "blob"); err != nil {
			return err
		}
		present, _ := store.Head("head")
		return reconcileInitialPointer(store, "head", pointerPath, pointer, present)
	}
	legacyRecoverySave = func(string, any) error { return errors.New("checkpoint did not land") }
	args := []string{name, "--settings-root", settingsRoot}
	if err := runLegacyPublicationRecovery(args); err == nil {
		t.Fatal("missing checkpoint should remain an error")
	}
	putsAfterFirst := store.puts
	legacyRecoveryInput = strings.NewReader("")
	legacyRecoverySave = saveJSONAtomic
	if err := runLegacyPublicationRecovery(args); err != nil {
		t.Fatal(err)
	}
	if remoteCalls != 2 || store.puts != putsAfterFirst {
		t.Fatalf("remoteCalls=%d puts=%d firstPuts=%d", remoteCalls, store.puts, putsAfterFirst)
	}
}

func TestAmbiguousRecoveryCheckpointIsReconciled(t *testing.T) {
	settingsRoot, name, _, _, attemptID := frozen1828RecoveryFixture(t)
	dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
	statePath := filepath.Join(dir, "workflow", "state.json")
	var state roleFlowState
	if err := setupReadJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("e", 40)
	if err := markLegacyRecoveryComplete(&state, attemptID, commit, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	ambiguous := errors.New("ambiguous fsync result")
	err := persistLegacyRecoveryCompletion(statePath, state, state.Profile, attemptID, func(path string, value any) error {
		if err := saveJSONAtomic(path, value); err != nil {
			return err
		}
		return ambiguous
	})
	if err != nil {
		t.Fatalf("landed checkpoint must reconcile despite ambiguous return: %v", err)
	}
}

func TestGenericPublishHasNoRecoverySwitch(t *testing.T) {
	if err := runPublish([]string{"--recover-initial"}); err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("direct recovery switch unexpectedly accepted: %v", err)
	}
	if err := runRecoverInitial1828([]string{"--attempt-id", "flow-" + strings.Repeat("a", 32)}); err == nil || !strings.Contains(err.Error(), "locked recovery profile") {
		t.Fatalf("internal recovery ran without the locked 1828 context: %v", err)
	}
}

func TestFrozen1828InternalRecoveryReconcilesExactObjects(t *testing.T) {
	settingsRoot, name, profile, _, attemptID := frozen1828RecoveryFixture(t)
	dir, _ := guidedDirectory(settingsRoot, name, "coordinator")
	public := filepath.Join(profile.Work, "ceremony", "public")
	for path, contents := range map[string]string{
		filepath.Join(public, "ceremony.json"):                     "signed-definition",
		filepath.Join(public, "ceremony.sig"):                      "definition-signature",
		filepath.Join(public, "ownership-destination.ccs"):         "signed-r1cs",
		filepath.Join(public, "phase1", "genesis.bin"):             "signed-genesis",
		filepath.Join(profile.Trust, "coordinator-public-key.hex"): strings.Repeat("1", 64),
	} {
		writeRecoveryFixtureFile(t, path, contents)
	}
	r1csPath := filepath.Join(public, "ownership-destination.ccs")
	genesisPath := filepath.Join(public, "phase1", "genesis.bin")
	r1csHash, _ := setupFileHash(r1csPath)
	genesisHash, _ := setupFileHash(genesisPath)
	r1csHash, genesisHash = "sha256:"+r1csHash, "sha256:"+genesisHash
	r1csInfo, _ := os.Stat(r1csPath)
	genesisInfo, _ := os.Stat(genesisPath)
	ceremonyID := "sha256:" + strings.Repeat("c", 64)
	blake := "blake2b256:" + strings.Repeat("0", 64)
	definitionResult := fmt.Sprintf(`{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect definition","definition_inspection":{"schema":"proof-tool-mpc-definition-inspection-v1","ceremony_id":"%s","mode":"rehearsal","phase1_participants":["participant-1"],"phase2_participants":["participant-1"],"r1cs":{"name":"ownership-destination.ccs","digest":{"sha256":"%s","blake2b256":"%s","size":%d}}}}`, ceremonyID, r1csHash, blake, r1csInfo.Size())
	chainResult := fmt.Sprintf(`{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect chain","chain_inspection":{"schema":"proof-tool-mpc-chain-inspection-v1","ceremony_id":"%s","phase":"phase1","accepted_count":0,"artifacts":[{"name":"phase1/genesis.bin","digest":{"sha256":"%s","blake2b256":"%s","size":%d}}],"records":[]}}`, ceremonyID, genesisHash, blake, genesisInfo.Size())
	tool := filepath.Join(t.TempDir(), "mpc-ceremony")
	script := "#!/bin/sh\ncase \"$3 $4\" in\n  'inspect definition') printf '%s\\n' '" + definitionResult + "' ;;\n  'inspect chain') printf '%s\\n' '" + chainResult + "' ;;\n  *) exit 2 ;;\nesac\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	storagePath := filepath.Join(profile.Work, "ceremony", "config", "relay-storage.json")
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	config.CeremonyBinary = tool
	if err := saveJSONAtomic(storagePath, config); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "workflow", "state.json")
	var workflow roleFlowState
	if err := setupReadJSON(statePath, &workflow); err != nil {
		t.Fatal(err)
	}
	storageHash, _ := setupFileHash(storagePath)
	workflow.Attempts[0].InputBindings[workflow.Attempts[0].Command[5]] = storageHash
	if err := saveJSONAtomic(statePath, workflow); err != nil {
		t.Fatal(err)
	}
	fake := &publicationStoreFake{objects: map[string][]byte{}}
	oldContext, oldWork, oldTrust, oldStore := legacyRecoveryContextRoot, legacyRecoveryWorkRoot, legacyRecoveryTrustRoot, legacyRecoveryStore
	defer func() {
		legacyRecoveryContextRoot, legacyRecoveryWorkRoot, legacyRecoveryTrustRoot, legacyRecoveryStore = oldContext, oldWork, oldTrust, oldStore
	}()
	legacyRecoveryContextRoot, legacyRecoveryWorkRoot, legacyRecoveryTrustRoot = dir, profile.Work, profile.Trust
	legacyRecoveryStore = func(access.StorageConfig) publicationStore { return fake }
	args := []string{"--attempt-id", attemptID}
	if err := runRecoverInitial1828(args); err != nil {
		t.Fatal(err)
	}
	firstPuts := fake.puts
	if firstPuts == 0 {
		t.Fatal("integrated recovery created no objects")
	}
	if err := runRecoverInitial1828(args); err != nil {
		t.Fatal(err)
	}
	if fake.puts != firstPuts {
		t.Fatalf("idempotent internal rerun added writes: first=%d after=%d", firstPuts, fake.puts)
	}
}

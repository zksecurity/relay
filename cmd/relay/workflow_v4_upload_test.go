package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type workflowV4UploadStore struct {
	objects map[string][]byte
	writes  []string
	fail    string
}

func (s *workflowV4UploadStore) PutIfAbsent(key, path string) (store.ObjectVersion, error) {
	if _, ok := s.objects[key]; ok {
		return store.ObjectVersion{}, store.ErrExists
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	s.objects[key] = raw
	s.writes = append(s.writes, key)
	if key == s.fail {
		return store.ObjectVersion{}, errors.New("lost upload response")
	}
	return store.ObjectVersion{Size: int64(len(raw))}, nil
}

func (s *workflowV4UploadStore) GetVersionedAtMost(key, path string, maximum int64) (store.ObjectVersion, error) {
	raw, ok := s.objects[key]
	if !ok {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("object exceeds bound")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{Size: int64(len(raw))}, nil
}

func workflowV4UploadFixture(t *testing.T) (*workflowV4Journal, workflowV4OperationPlan, transcript.ContributionInventoryFactsV4) {
	t.Helper()
	protocol, binding := workflowV4TestBinding(t)
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	contribution := workflowV4TestPlan(t, binding)
	candidate := contribution.Outputs[0]
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	files := make([]transcript.ArtifactRef, 0, 5)
	inputs := append([]workflowV4Input(nil), contribution.Inputs...)
	for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", dockerLifecycleLogName} {
		raw := "public " + name
		if err := os.WriteFile(filepath.Join(candidate, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		ref := workflowV4TestRef(name, raw)
		inputs = append(inputs, workflowV4Input{Path: filepath.Join(candidate, name), Ref: ref})
		if name != dockerLifecycleLogName {
			files = append(files, ref)
		}
	}
	id := strings.Repeat("3", 32)
	root, err := workflowV4ContainerPath(binding.Runtimes["signer"], candidate)
	if err != nil {
		t.Fatal(err)
	}
	definition, _ := workflowV4ContainerPath(binding.Runtimes["signer"], contribution.Inputs[4].Path)
	definitionSignature, _ := workflowV4ContainerPath(binding.Runtimes["signer"], contribution.Inputs[5].Path)
	coordinatorKey, _ := workflowV4ContainerPath(binding.Runtimes["signer"], contribution.Inputs[6].Path)
	cleanup := workflowV4OperationPlan{
		ID: id, Kind: "attest-erasure", Scope: contribution.Scope, Predecessor: contribution.Predecessor,
		AttemptID: contribution.AttemptID, Runtime: binding.Runtimes["signer"], Inputs: inputs,
		Command: []string{"mpc-ceremony", "phase1", "attest-erasure", "--ceremony", definition, "--ceremony-signature", definitionSignature, "--coordinator-public-key-file", coordinatorKey, "--participant-id", contribution.Scope.ParticipantID, "--participant-signing-key", "/keys/signing.hex", "--candidate-dir", root, "--destroyed-at", "2026-09-16T00:00:00Z"},
		Outputs: []string{filepath.Join(candidate, "erasure.json"), filepath.Join(candidate, "erasure.sig")},
	}
	if err := j.prepare(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(cleanup.ID, func(workflowV4OperationPlan) error {
		for _, name := range []string{"erasure.json", "erasure.sig"} {
			raw := "public " + name
			if err := os.WriteFile(filepath.Join(candidate, name), []byte(raw), 0600); err != nil {
				return err
			}
			files = append(files, workflowV4TestRef(name, raw))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(cleanup.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	resultID := "sha256:" + strings.Repeat("9", 64)
	complete := transcript.CandidateInventoryV4{Schema: "proof-tool-mpc-candidate-inventory-v1", Scope: contribution.Scope, Files: files}
	inventory := transcript.ContributionInventoryFactsV4{Scope: contribution.Scope, Predecessor: contribution.Predecessor, Computed: complete, Complete: &complete, ComputedCandidateID: resultID, CandidateResultID: resultID}
	return j, cleanup, inventory
}

func TestWorkflowV4UploadUsesActiveReplacementAttemptAndCanBePrepared(t *testing.T) {
	j, cleanup, inventory := workflowV4UploadFixture(t)
	defer j.close()
	replacement := strings.Repeat("b", 32)
	plan, err := j.prepareWorkflowV4Upload(cleanup.ID, replacement, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if plan.AttemptID != replacement || plan.AttemptID == cleanup.AttemptID {
		t.Fatalf("upload attempt = %q", plan.AttemptID)
	}
	if err := j.prepare(plan); err != nil {
		t.Fatalf("prepared upload plan was not executable: %v", err)
	}
}

func TestWorkflowV4UploadExactResumePublishesManifestLast(t *testing.T) {
	j, cleanup, inventory := workflowV4UploadFixture(t)
	defer j.close()
	attempt := strings.Repeat("b", 32)
	plan, err := j.prepareWorkflowV4Upload(cleanup.ID, attempt, inventory)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := workflowV4CandidateDir(plan)
	if err != nil {
		t.Fatal(err)
	}
	sources, paths, err := workflowV4CandidateFiles(candidate, inventory)
	if err != nil {
		t.Fatal(err)
	}
	scope := storagefirst.DeliveryScope{CeremonyID: plan.Scope.CeremonyID, AttemptID: attempt, Kind: "candidate"}
	prefix, _ := scope.Prefix()
	objects := &workflowV4UploadStore{objects: make(map[string][]byte), fail: prefix + "/files/contribution.bin"}
	temporary := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "temporary")
	if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, temporary); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 16, 0, 30, 0, 0, time.UTC)
	err = j.uploadCandidatePlan(plan, objects, scope, sources, paths, inventory.CandidateResultID, prefix+"/manifest.json", temporary, now)
	if err == nil {
		t.Fatal("lost response was hidden")
	}
	objects.fail = ""
	if err := j.uploadCandidatePlan(plan, objects, scope, sources, paths, inventory.CandidateResultID, prefix+"/manifest.json", temporary, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := objects.writes[len(objects.writes)-1]; got != prefix+"/manifest.json" {
		t.Fatalf("last upload = %s", got)
	}
	if err := j.uploadCandidatePlan(plan, objects, scope, sources, paths, inventory.CandidateResultID, prefix+"/manifest.json", temporary, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("exact repeated upload failed: %v", err)
	}
	var record workflowV4UploadRecord
	if err := readWorkflowV4JSON(plan.Outputs[0], &record); err != nil || record.CandidateResultID != inventory.CandidateResultID {
		t.Fatalf("retained result = %+v, %v", record, err)
	}
}

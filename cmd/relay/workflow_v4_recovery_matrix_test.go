package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
)

// These cases restart the durable participant journal at distinct operation
// boundaries. The candidate bytes and remote store are synthetic; this tests
// recovery behavior, not proof-tool signatures or a published image pair.
func TestWorkflowV4ParticipantRecoveryMatrix(t *testing.T) {
	reopen := func(t *testing.T, j *workflowV4Journal) *workflowV4Journal {
		t.Helper()
		binding := j.state.Marker.Binding
		protocol, _ := workflowV4TestBinding(t)
		protocol.Definition.CeremonyID = binding.CeremonyID
		protocol.DefinitionRefs = binding.Definition
		if err := j.close(); err != nil {
			t.Fatal(err)
		}
		resumed, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
		if err != nil {
			t.Fatal(err)
		}
		return resumed
	}

	t.Run("prepared-unstarted", func(t *testing.T) {
		protocol, binding := workflowV4TestBinding(t)
		j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
		if err != nil {
			t.Fatal(err)
		}
		plan := workflowV4TestPlan(t, binding)
		if err := j.prepare(plan); err != nil {
			t.Fatal(err)
		}
		j = reopen(t, j)
		defer j.close()
		pending, err := j.pending()
		if err != nil || pending == nil || pending.Status != "prepared" || pending.Plan.ID != plan.ID {
			t.Fatalf("saved unstarted operation = %+v, %v", pending, err)
		}
		if err := j.abandonPrepared(plan.ID); err != nil {
			t.Fatalf("safe unstarted abandon: %v", err)
		}
	})

	t.Run("entropy-before-output", func(t *testing.T) {
		protocol, binding := workflowV4TestBinding(t)
		j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
		if err != nil {
			t.Fatal(err)
		}
		plan := workflowV4TestPlan(t, binding)
		if err := j.prepare(plan); err != nil {
			t.Fatal(err)
		}
		if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error {
			return errors.New("synthetic interruption after computation started")
		}); err == nil {
			t.Fatal("lost interrupted computation")
		}
		j = reopen(t, j)
		defer j.close()
		if _, err := os.Lstat(plan.Outputs[0]); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected output: %v", err)
		}
		called := false
		if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { called = true; return nil }); err == nil || called {
			t.Fatal("restarted a possibly entropy-consuming computation")
		}
		if err := j.abandonPrepared(plan.ID); err == nil {
			t.Fatal("abandoned uncertain computation")
		}
	})

	t.Run("generated-before-cleanup", func(t *testing.T) {
		protocol, binding := workflowV4TestBinding(t)
		j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
		if err != nil {
			t.Fatal(err)
		}
		plan := workflowV4TestPlan(t, binding)
		if err := j.prepare(plan); err != nil {
			t.Fatal(err)
		}
		if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error {
			if err := os.Mkdir(plan.Outputs[0], 0700); err != nil {
				return err
			}
			return errors.New("synthetic interruption with retained output")
		}); err == nil {
			t.Fatal("lost interrupted computation")
		}
		j = reopen(t, j)
		defer j.close()
		if info, err := os.Stat(plan.Outputs[0]); err != nil || !info.IsDir() {
			t.Fatalf("generated output not retained: %v", err)
		}
		if err := j.prepare(workflowV4TestPlan(t, binding)); err == nil {
			t.Fatal("started another operation while output needs verification")
		}
		if err := j.reconcile(plan.ID, func(workflowV4OperationPlan) error {
			return errors.New("synthetic output lacks authenticated proof-tool evidence")
		}); err == nil {
			t.Fatal("accepted unverified generated output")
		}
	})

	t.Run("cleaned-before-upload", func(t *testing.T) {
		j, cleanup, inventory := workflowV4UploadFixture(t)
		j = reopen(t, j)
		defer j.close()
		plan, err := j.prepareWorkflowV4Upload(cleanup.ID, cleanup.AttemptID, inventory)
		if err != nil {
			t.Fatalf("verified candidate could not proceed to upload: %v", err)
		}
		if err := j.prepare(plan); err != nil {
			t.Fatal(err)
		}
		pending, err := j.pending()
		if err != nil || pending == nil || pending.Plan.AttemptID != cleanup.AttemptID || pending.Status != "prepared" {
			t.Fatalf("retained upload identity = %+v, %v", pending, err)
		}
	})

	t.Run("interrupted-publication", func(t *testing.T) {
		j, cleanup, inventory := workflowV4UploadFixture(t)
		plan, err := j.prepareWorkflowV4Upload(cleanup.ID, cleanup.AttemptID, inventory)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.prepare(plan); err != nil {
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
		scope := storagefirst.DeliveryScope{CeremonyID: plan.Scope.CeremonyID, AttemptID: plan.AttemptID, Kind: "candidate"}
		prefix, err := scope.Prefix()
		if err != nil {
			t.Fatal(err)
		}
		objects := &workflowV4UploadStore{objects: map[string][]byte{}, fail: prefix + "/files/contribution.bin"}
		temporary := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "temporary")
		if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, temporary); err != nil {
			t.Fatal(err)
		}
		manifest := prefix + "/manifest.json"
		now := time.Date(2026, 9, 16, 0, 30, 0, 0, time.UTC)
		if err := j.runPrepared(plan.ID, func(p workflowV4OperationPlan) error {
			return j.uploadCandidatePlan(p, objects, scope, sources, paths, inventory.CandidateResultID, manifest, temporary, now)
		}); err == nil {
			t.Fatal("lost upload response was hidden")
		}
		j = reopen(t, j)
		defer j.close()
		pending, err := j.pending()
		if err != nil || pending == nil || pending.Status != "running" || pending.Plan.ID != plan.ID {
			t.Fatalf("interrupted upload identity = %+v, %v", pending, err)
		}
		if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { t.Fatal("restarted upload as fresh operation"); return nil }); err == nil {
			t.Fatal("fresh execution accepted for running upload")
		}
		writesBefore := len(objects.writes)
		objects.fail = ""
		if err := j.uploadCandidatePlan(pending.Plan, objects, scope, sources, paths, inventory.CandidateResultID, manifest, temporary, now.Add(time.Minute)); err != nil {
			t.Fatalf("exact immutable resume: %v", err)
		}
		if len(objects.writes) <= writesBefore || objects.writes[len(objects.writes)-1] != manifest {
			t.Fatalf("manifest was not published last: %v", objects.writes)
		}
		for _, key := range objects.writes[writesBefore:] {
			if strings.HasSuffix(key, "/files/contribution.bin") {
				t.Fatal("replaced an already uploaded contribution")
			}
		}
		if err := j.transition(plan.ID, "returned-needs-verification"); err != nil {
			t.Fatal(err)
		}
		if err := j.reconcileCandidateUpload(plan.ID, objects, inventory); err != nil {
			t.Fatalf("exact upload reconciliation: %v", err)
		}
	})
}

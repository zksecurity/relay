package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func workflowV4TestRef(name, contents string) transcript.ArtifactRef {
	hash := sha256.Sum256([]byte(contents))
	return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: "sha256:" + hex.EncodeToString(hash[:]), Blake2b256: "blake2b256:" + strings.Repeat("b", 64), Size: int64(len(contents))}}
}

func workflowV4TestBinding(t *testing.T) (transcript.DefinitionProtocol, workflowV4Binding) {
	t.Helper()
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	b := workflowV4Binding{CeremonyID: "sha256:" + strings.Repeat("a", 64), Definition: transcript.SignedArtifactRefs{Record: workflowV4TestRef("ceremony.json", "definition"), Signature: workflowV4TestRef("ceremony.sig", "signature")}, Name: "test", Role: "participant", IdentityID: "participant-test", Work: work}
	b.Runtimes = make(map[string]workflowV4Runtime)
	trust, keys := t.TempDir(), t.TempDir()
	for _, class := range []string{"online", "signer", "contributor"} {
		b.Runtimes[class] = workflowV4Runtime{Image: "example.test/role@sha256:" + strings.Repeat("d", 64), Platform: "linux/arm64", Mounts: map[string]string{"/work": work, "/trust": trust, "/keys": keys}}
	}
	p := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v4", StorageWorkflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1"}
	p.Definition.CeremonyID = b.CeremonyID
	p.DefinitionRefs = b.Definition
	p.Definition.Journey = &transcript.DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v2", ObserverRequirementSource: "signed-policy"}
	for _, role := range []string{"coordinator", "release-signer", "participant"} {
		p.Definition.Journey.RequiredEnrollments = append(p.Definition.Journey.RequiredEnrollments, transcript.ExpectedEnrollment{Role: role, RoleIndex: 1, Identity: transcript.PublicIdentity{ID: role + "-test", KeyID: "test-key-" + role, PublicKeyFingerprint: "test-fingerprint-" + role}})
	}
	return p, b
}

func workflowV4TestPlan(t *testing.T, b workflowV4Binding) workflowV4OperationPlan {
	t.Helper()
	id := strings.Repeat("1", 32)
	record := workflowV4TestRef("phase1/chain.json", "chain")
	signature := workflowV4TestRef("phase1/chain.sig", "signature")
	p := workflowV4OperationPlan{ID: id, Kind: "contribute", Scope: transcript.ContributionScopeV4{CeremonyID: b.CeremonyID, Phase: "phase1", Index: 1, ParticipantID: b.IdentityID, ParentHeadID: "sha256:" + strings.Repeat("c", 64)}, Predecessor: transcript.SignedArtifactRefs{Record: record, Signature: signature}, Runtime: workflowV4Runtime{Image: "example.test/role@sha256:" + strings.Repeat("d", 64), Platform: "linux/arm64", Mounts: map[string]string{"/work": b.Work}}, Command: []string{"mpc-ceremony", "contribute"}, Outputs: []string{filepath.Join(b.Work, "candidate")}}
	for destination, source := range b.Runtimes["contributor"].Mounts {
		p.Runtime.Mounts[destination] = source
	}
	for n, ref := range []transcript.ArtifactRef{record, signature} {
		path := filepath.Join(b.Work, "workflow-v4", "inputs", id, filepath.FromSlash(ref.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte([]string{"chain", "signature"}[n]), 0600); err != nil {
			t.Fatal(err)
		}
		p.Inputs = append(p.Inputs, workflowV4Input{Path: path, Ref: ref})
	}
	root := filepath.Join(b.Work, "workflow-v4", "inputs", id)
	for _, item := range []struct {
		ref            transcript.ArtifactRef
		contents, path string
	}{
		{b.Definition.Record, "definition", filepath.Join(root, "ceremony.json")},
		{b.Definition.Signature, "signature", filepath.Join(root, "ceremony.sig")},
		{workflowV4TestRef("coordinator.hex", "public-key"), "public-key", filepath.Join(p.Runtime.Mounts["/trust"], "coordinator.hex")},
		{workflowV4TestRef("environment.json", "environment"), "environment", filepath.Join(root, "environment.json")},
	} {
		if err := os.WriteFile(item.path, []byte(item.contents), 0600); err != nil {
			t.Fatal(err)
		}
		p.Inputs = append(p.Inputs, workflowV4Input{Path: item.path, Ref: item.ref})
	}
	containerRoot := "/work/workflow-v4/inputs/" + id
	p.Command = []string{"mpc-ceremony", "phase1", "contribute", "--ceremony", containerRoot + "/ceremony.json", "--ceremony-signature", containerRoot + "/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator.hex", "--transcript-dir", containerRoot, "--chain", containerRoot + "/phase1/chain.json", "--chain-signature", containerRoot + "/phase1/chain.sig", "--participant-id", b.IdentityID, "--participant-signing-key", "/keys/signing.hex", "--environment", containerRoot + "/environment.json", "--contributed-at", "2026-01-01T00:00:00Z", "--out-dir", "/work/candidate"}
	return p
}

func TestWorkflowV4JournalRestartDoesNotReplay(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	// Changing caller-owned data cannot change the durable operation.
	plan.Command[0] = "changed"
	plan.Runtime.Mounts["/work"] = "/wrong"
	op, err := j.pending()
	if err != nil || op.Plan.Command[0] != "mpc-ceremony" || op.Plan.Runtime.Mounts["/work"] != binding.Work {
		t.Fatal("plan alias", err)
	}
	if err := j.runPrepared(plan.ID, func(p workflowV4OperationPlan) error { return errors.New("interrupted") }); err == nil {
		t.Fatal("lost child error")
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	j, err = openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	op, err = j.pending()
	if err != nil || op.Status != "running" {
		t.Fatal("lost uncertain state", err)
	}
	called := false
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { called = true; return nil }); err == nil || called {
		t.Fatal("replayed uncertain child")
	}
	if err := j.abandonPrepared(plan.ID); err == nil {
		t.Fatal("abandoned uncertain child")
	}
	if err := j.reconcile(plan.ID, func(workflowV4OperationPlan) error { return errors.New("incomplete outputs") }); err == nil {
		t.Fatal("ignored verification failure")
	}
	if err := j.reconcile(plan.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if op, err := j.pending(); err != nil || op != nil {
		t.Fatal("did not reconcile", err)
	}
	next := workflowV4TestPlan(t, binding)
	next.ID = strings.Repeat("2", 32)
	oldRoot := filepath.Join(binding.Work, "workflow-v4", "inputs", plan.ID)
	newRoot := filepath.Join(binding.Work, "workflow-v4", "inputs", next.ID)
	for n := range next.Inputs {
		if !strings.HasPrefix(next.Inputs[n].Path, oldRoot+string(filepath.Separator)) {
			continue
		}
		original := next.Inputs[n].Path
		next.Inputs[n].Path = strings.Replace(original, oldRoot, newRoot, 1)
		if err := os.MkdirAll(filepath.Dir(next.Inputs[n].Path), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(next.Inputs[n].Path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for n := range next.Command {
		next.Command[n] = strings.ReplaceAll(next.Command[n], plan.ID, next.ID)
	}
	// Even removing outputs cannot cause a second computation of this turn.
	if err := j.prepare(next); err == nil || !strings.Contains(err.Error(), "already has a computation") {
		t.Fatal("allowed recomputation")
	}
}

func TestWorkflowV4JournalPreparedAndSuccessfulBoundaries(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.Outputs[0], []byte("unexpected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.abandonPrepared(plan.ID); err == nil {
		t.Fatal("abandoned existing output")
	}
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { t.Fatal("launched over output"); return nil }); err == nil {
		t.Fatal("accepted existing output")
	}
	if err := os.Remove(plan.Outputs[0]); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error {
		var disk workflowV4State
		if err := readWorkflowV4JSON(j.path, &disk); err != nil {
			t.Fatal(err)
		}
		if disk.Operations[0].Status != "running" {
			t.Fatal("launched without durable intent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	op, err := j.pending()
	if err != nil || op.Status != "returned-needs-verification" {
		t.Fatal("child exit overclaims success", err)
	}
	if err := j.reconcile(plan.ID, nil); err == nil {
		t.Fatal("reconciled without verification")
	}
}

func TestWorkflowV4JournalFailedSaveStopsSameProcess(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-rename", true: "after-rename"}[afterRename], func(t *testing.T) {
			protocol, binding := workflowV4TestBinding(t)
			j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			plan := workflowV4TestPlan(t, binding)
			if err := j.prepare(plan); err != nil {
				t.Fatal(err)
			}
			j.save = func(path string, value any, maximum int) error {
				if afterRename {
					if err := saveJSONAtomicWithLimit(path, value, maximum); err != nil {
						return err
					}
				}
				return errors.New("injected save failure")
			}
			called := false
			run := func(workflowV4OperationPlan) error { called = true; return nil }
			if err := j.runPrepared(plan.ID, run); err == nil || called {
				t.Fatal("launched after failed save")
			}
			j.save = saveJSONAtomicWithLimit
			if err := j.runPrepared(plan.ID, run); err == nil || called {
				t.Fatal("reused stale memory after failed save")
			}
			if err := j.close(); err != nil {
				t.Fatal(err)
			}
			j, err = openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			op, err := j.pending()
			if err != nil {
				t.Fatal(err)
			}
			want := "prepared"
			if afterRename {
				want = "running"
			}
			if op.Status != want {
				t.Fatalf("durable status %s, want %s", op.Status, want)
			}
			if !afterRename {
				if err := j.abandonPrepared(plan.ID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWorkflowV4JournalBindingsLockAndLegacyIsolation(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	legacy := filepath.Join(binding.Work, "workflow", "state.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("legacy untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	old := protocol
	old.DefinitionSchema = "proof-tool-mpc-ceremony-definition-v3"
	if _, err := openWorkflowV4Journal(old, binding.Definition, binding); err == nil {
		t.Fatal("opened legacy as V4")
	}
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openWorkflowV4Journal(protocol, binding.Definition, binding); err == nil {
		second.close()
		t.Fatal("opened concurrent journal")
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.Name = "other"
	if _, err := openWorkflowV4Journal(protocol, binding.Definition, wrong); err == nil {
		t.Fatal("accepted wrong binding")
	}
	if raw, err := os.ReadFile(legacy); err != nil || string(raw) != "legacy untouched" {
		t.Fatal("changed legacy state", err)
	}
	if err := os.Remove(j.path); err != nil {
		t.Fatal(err)
	}
	if _, err := openWorkflowV4Journal(protocol, binding.Definition, binding); err == nil {
		t.Fatal("recreated lost journal")
	}
}

func TestWorkflowV4JournalRejectsInvalidPlansAndChangedInputs(t *testing.T) {
	for _, kind := range []string{"unknown", "missing-attempt", "unexpected-attempt", "mutable-runtime", "outside-output", "overlap", "changed-input", "symlink-parent", "mutable-predecessor"} {
		t.Run(kind, func(t *testing.T) {
			protocol, binding := workflowV4TestBinding(t)
			j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			plan := workflowV4TestPlan(t, binding)
			switch kind {
			case "unknown":
				plan.Kind = "anything"
			case "missing-attempt":
				plan.Kind = "upload-candidate"
			case "unexpected-attempt":
				plan.AttemptID = strings.Repeat("3", 32)
			case "mutable-runtime":
				plan.Runtime.Image = "example.test/role:latest"
			case "outside-output":
				plan.Outputs[0] = filepath.Join(t.TempDir(), "outside")
			case "overlap":
				plan.Outputs[0] = plan.Inputs[0].Path
			case "changed-input":
				if err := os.WriteFile(plan.Inputs[0].Path, []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				link := filepath.Join(binding.Work, "link")
				if err := os.Symlink(t.TempDir(), link); err != nil {
					t.Fatal(err)
				}
				plan.Outputs[0] = filepath.Join(link, "output")
			case "mutable-predecessor":
				plan.Inputs[0].Path = filepath.Join(binding.Work, "chain-current.json")
			}
			if err := j.prepare(plan); err == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
}

func TestWorkflowV4JournalInitializationRecovery(t *testing.T) {
	for _, markerPresent := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-marker", true: "after-marker"}[markerPresent], func(t *testing.T) {
			protocol, binding := workflowV4TestBinding(t)
			j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			state := j.state
			state.Status = "initializing"
			if err := j.close(); err != nil {
				t.Fatal(err)
			}
			if err := saveJSONAtomicWithLimit(j.path, state, workflowV4MaximumBytes); err != nil {
				t.Fatal(err)
			}
			if !markerPresent {
				if err := os.Remove(filepath.Join(binding.Work, ".relay-workspace-v4.json")); err != nil {
					t.Fatal(err)
				}
			}
			resumed, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer resumed.close()
			if resumed.state.Status != "ready" || !reflect.DeepEqual(resumed.state.Marker, state.Marker) {
				t.Fatal("did not retain initialization binding")
			}
		})
	}
}

func TestWorkflowV4JournalRejectsCorruptLoadedState(t *testing.T) {
	for _, mutation := range []string{"duplicate-id", "unknown-kind", "unknown-status", "attempt", "missing-time", "wrong-state-path", "too-many-operations", "missing-marker"} {
		t.Run(mutation, func(t *testing.T) {
			protocol, binding := workflowV4TestBinding(t)
			j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.prepare(workflowV4TestPlan(t, binding)); err != nil {
				t.Fatal(err)
			}
			s := j.state
			if err := j.close(); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "duplicate-id":
				s.Operations = append(s.Operations, s.Operations[0])
			case "unknown-kind":
				s.Operations[0].Plan.Kind = "arbitrary-command"
			case "unknown-status":
				s.Operations[0].Status = "done"
			case "attempt":
				s.Operations[0].Plan.AttemptID = strings.Repeat("1", 32)
			case "missing-time":
				s.Operations[0].Status = "running"
			case "wrong-state-path":
				s.Marker.StatePath = filepath.Join(binding.Work, "elsewhere")
			case "too-many-operations":
				s.Operations = make([]workflowV4Operation, workflowV4MaximumOperations+1)
			case "missing-marker":
				if err := os.Remove(filepath.Join(binding.Work, ".relay-workspace-v4.json")); err != nil {
					t.Fatal(err)
				}
			}
			if err := saveJSONAtomicWithLimit(j.path, s, workflowV4MaximumBytes); err != nil {
				t.Fatal(err)
			}
			if bad, err := openWorkflowV4Journal(protocol, binding.Definition, binding); err == nil {
				bad.close()
				t.Fatal("accepted corrupt journal")
			}
		})
	}
}

func TestWorkflowV4JournalFailedReturnedSaveRetainsUncertainty(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error {
		j.save = func(string, any, int) error { return errors.New("return-status save failed") }
		return nil
	}); err == nil {
		t.Fatal("ignored failed return-status save")
	}
	verified := false
	if err := j.reconcile(plan.ID, func(workflowV4OperationPlan) error { verified = true; return nil }); err == nil || verified {
		t.Fatal("continued after failed save")
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	j, err = openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	op, err := j.pending()
	if err != nil || op.Status != "running" {
		t.Fatal("lost pending child", err)
	}
}

func TestWorkflowV4JournalCoordinatorNeedsExactCommittedPublication(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	binding.Role = "coordinator"
	binding.IdentityID = "coordinator-test"
	binding.CeremonyID = commitDigest("1")
	protocol.Definition.CeremonyID = binding.CeremonyID
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	plan.Kind, plan.AttemptID = "commit-outbound", strings.Repeat("2", 32)
	plan.Command = []string{"relay-internal", "commit-outbound"}
	commitPlan := testCoordinatorCommitPlan(filepath.Join(binding.Work, "publication"))
	plan.CommitPlan = &commitPlan
	plan.Outputs = append([]string(nil), commitPlan.InnerOutputPaths...)
	plan.CommitJournalPath = filepath.Join(binding.Work, "workflow-v4", "commits", plan.ID+".json")
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	verify := func(workflowV4OperationPlan) error { return nil } // synthetic verification result, not ceremony evidence
	if err := j.reconcile(plan.ID, verify); err == nil {
		t.Fatal("accepted missing publication journal")
	}
	commit, err := openOrCreateCoordinatorCommitJournal(plan.CommitJournalPath, commitPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(plan.ID, verify); err == nil {
		t.Fatal("child return treated as publication")
	}
	root := filepath.Dir(commitPlan.InnerOutputPaths[0])
	if err := commit.recordInnerSigned([]coordinatorCommitOutput{commitOutput(commitPlan.InnerOutputPaths[0], "3"), commitOutput(commitPlan.InnerOutputPaths[1], "4")}); err != nil {
		t.Fatal(err)
	}
	checkpoint := testCheckpointIntent(root)
	if err := commit.checkpointSigningIntent(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := commit.recordCheckpointSigned(commitOutput(checkpoint.CheckpointOutputPath, "5"), commitOutput(checkpoint.CheckpointSignatureOutputPath, "6")); err != nil {
		t.Fatal(err)
	}
	if err := commit.recordAuthenticatedChild(testAuthenticatedChild(root, commitPlan)); err != nil {
		t.Fatal(err)
	}
	intent := testRootIntent(root)
	if err := commit.rootCASIntent(intent, commitOutput(intent.RootPayloadOutputPath, "7")); err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(plan.ID, verify); err == nil {
		t.Fatal("publication intent treated as committed")
	}
	if err := commit.recordRootCASCommitted(committedRootVersion()); err != nil {
		t.Fatal(err)
	}
	// A committed status for another predecessor version is insufficient.
	exact := commit.record
	changed := exact
	changed.Plan = cloneCoordinatorCommitPlan(exact.Plan)
	changed.Plan.PreviousRootVersion.VersionID = "different-version"
	if err := saveJSONAtomic(plan.CommitJournalPath, changed); err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(plan.ID, verify); err == nil {
		t.Fatal("accepted different commit plan")
	}
	if err := saveJSONAtomic(plan.CommitJournalPath, exact); err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(plan.ID, verify); err != nil {
		t.Fatal(err)
	}
}

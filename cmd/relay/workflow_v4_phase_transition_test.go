package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// These fixtures stub the approved-tool boundary, not its cryptography. The
// guide receives immutable snapshots through the real SyncV4 implementation.
type guidePhaseObjects map[string][]byte

func (m guidePhaseObjects) GetVersionedAtMost(key, local string, maximum int64) (store.ObjectVersion, error) {
	raw, ok := m[key]
	if !ok || int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("missing or oversized test object")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{ETag: "fixture", Size: int64(len(raw))}, os.WriteFile(local, raw, 0600)
}

type guidePhaseVerifier struct {
	discovery  transcript.CheckpointDiscoveryV4
	inspection transcript.CheckpointInspectionV4
	metadata   transcript.EnrollmentMetadataInspectionV4
}

func (v guidePhaseVerifier) DiscoverCheckpointV4(_, _, _ string) (transcript.CheckpointDiscoveryV4, error) {
	return v.discovery, nil
}
func (v guidePhaseVerifier) CheckpointGuidanceV4(_, _, _ string) (transcript.CheckpointInspectionV4, transcript.EnrollmentMetadataInspectionV4, error) {
	return v.inspection, v.metadata, nil
}

func guidePhaseSnapshot(t *testing.T, protocol transcript.DefinitionProtocol, b workflowV4Binding, phase string) storagefirst.SnapshotV4 {
	t.Helper()
	objects := guidePhaseObjects{}
	ref := func(name, contents string) transcript.ArtifactRef {
		r := workflowV4TestRef(name, contents)
		objects[store.Key(r.Digest.SHA256)] = []byte(contents)
		return r
	}
	pair := func(name string) transcript.SignedArtifactRefs {
		return transcript.SignedArtifactRefs{Record: ref(name+".json", name+" record"), Signature: ref(name+".sig", name+" signature")}
	}
	ref("ceremony.json", "definition")
	ref("ceremony.sig", "signature")
	head := pair("checkpoints/" + phase)
	c := transcript.CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: b.CeremonyID, Definition: b.Definition, AcceptedArtifacts: []transcript.ArtifactRef{}, Deliveries: []transcript.DeliverySlotV4{}}
	phaseState := func(p string) transcript.CheckpointPhaseState {
		return transcript.CheckpointPhaseState{Phase: p, Chain: pair(p + "/chain-0000"), HeadRecordID: workflowV4TestRef("head", p).Digest.SHA256, HeadPayload: ref(p+"/genesis.bin", p+" payload")}
	}
	c.Progress.Phase1 = phaseState("phase1")
	current := c.Progress.Phase1
	if phase == "phase2" {
		p2 := phaseState("phase2")
		c.Progress.Phase2 = &p2
		closure, beacon, seal := pair("phase1/closure"), pair("phase1/beacon"), pair("phase1/seal")
		c.Progress.Phase1Closure, c.Progress.Phase1Beacon, c.Progress.Phase1Seal = &closure, &beacon, &seal
		current = p2
	}
	scope := transcript.ContributionScopeV4{CeremonyID: b.CeremonyID, Phase: phase, Index: 1, ParticipantID: b.IdentityID, ParentHeadID: current.HeadRecordID}
	c.Deliveries = []transcript.DeliverySlotV4{{Kind: "candidate", Scope: scope, AttemptID: strings.Repeat("a", 32), Status: "allocated"}}
	enrollment := pair("enrollments/participant")
	v := guidePhaseVerifier{
		discovery:  transcript.CheckpointDiscoveryV4{Schema: "proof-tool-mpc-checkpoint-discovery-v4", Depth: "signed-checkpoint-discovery", CheckpointRefs: head},
		inspection: transcript.CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", CheckpointRefs: head, Checkpoint: c, Commitments: transcript.CheckpointCommitmentsV4{Enrollments: []transcript.SignedArtifactRefs{enrollment}, Turns: []transcript.TurnCommitmentV4{}}},
		metadata:   transcript.EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", EnrollmentSignaturesVerified: true, Metadata: transcript.EnrollmentMetadataV4{CeremonyID: b.CeremonyID, Checkpoint: head}},
	}
	v.discovery.Discovery.CeremonyID = b.CeremonyID
	v.discovery.Discovery.VerificationDependencies = []transcript.ArtifactRef{}
	v.discovery.Discovery.Enrollment = &enrollment
	for _, e := range protocol.Definition.Journey.RequiredEnrollments {
		if e.Identity.ID == b.IdentityID {
			v.metadata.Metadata.Enrollments = []transcript.CommittedEnrollmentMetadataV4{{Refs: enrollment, Enrollment: transcript.EnrollmentInspection{Role: e.Role, RoleIndex: e.RoleIndex, Identity: e.Identity}}}
		}
	}
	content := func(r transcript.ArtifactRef) state.ContentRef {
		return state.ContentRef{Name: r.Name, SHA256: r.Digest.SHA256, Size: r.Digest.Size}
	}
	root := state.Root{Schema: state.RootSchema, CeremonyID: b.CeremonyID, Checkpoint: content(head.Record), CheckpointSignature: content(head.Signature)}
	raw, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	objects[state.RootKey(b.CeremonyID)] = raw
	h, err := state.OpenWorkspaceHighWater(t.TempDir(), b.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagefirst.SyncV4Retained(objects, v, h, b.CeremonyID, t.TempDir(), filepath.Join(b.Work, "ceremony", "public"))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func guidePhaseProfile(t *testing.T, b workflowV4Binding) (guidedProfile, access.RoleConfig) {
	t.Helper()
	r := b.Runtimes["contributor"]
	p := guidedProfile{Name: b.Name, Role: "participant", Work: b.Work, Trust: r.Mounts["/trust"], Keys: r.Mounts["/keys"], Image: r.Image, Platform: r.Platform, Config: filepath.Join(b.Work, "ceremony/config/participant-phase1.json")}
	root := filepath.Join(p.Work, "ceremony/public")
	c := access.RoleConfig{Schema: access.RoleConfigSchema, Role: "participant", IdentityID: b.IdentityID, Phase: "phase1", CeremonyID: b.CeremonyID, CeremonyHome: filepath.Dir(root), Root: root, Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"), CoordinatorKey: filepath.Join(p.Trust, "coordinator.hex"), CeremonyBinary: dockerCeremonyBinary, SigningKey: filepath.Join(p.Keys, "signing.hex"), Environment: filepath.Join(p.Work, "environment.json"), RunRoot: filepath.Join(p.Work, "runs"), StorageConfig: filepath.Join(p.Work, "storage.json"), PublishedBaseURL: "https://public.example.test", PublishedBucket: "published", ExecutionMode: "docker", DockerImage: p.Image, DockerPlatform: p.Platform, DockerCLI: "docker"}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p.Config), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	storage := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: "aws", CeremonyID: b.CeremonyID, PublishedBucket: c.PublishedBucket, PublishedBaseURL: c.PublishedBaseURL, InboxBucket: "private", CoordinatorProfile: "test", Region: "us-east-1", IssuerProfile: "test", GrantRoleARN: "test", GrantRoleMaxTTL: "2h", CeremonyPath: c.Ceremony, CeremonySignature: c.CeremonySignature, CoordinatorPublicKey: c.CoordinatorKey, CeremonyBinary: c.CeremonyBinary}
	if err := saveJSONAtomic(c.StorageConfig, storage); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRoleConfig(p.Config, "participant")
	if err != nil {
		t.Fatal(err)
	}
	return p, loaded
}

func TestWorkflowV4GuidePhaseTransition(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	protocol.Definition.Phase1Participants = []string{b.IdentityID}
	protocol.Definition.Phase2Participants = []string{b.IdentityID}
	p, saved := guidePhaseProfile(t, b)
	before, err := os.ReadFile(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	phase1 := guidePhaseSnapshot(t, protocol, b, "phase1")
	phase2 := guidePhaseSnapshot(t, protocol, b, "phase2")
	for _, tc := range []struct {
		name, input string
		snapshots   []storagefirst.SnapshotV4
		failure     bool
		want        []string
	}{
		{"refresh", "R\nQ\n", []storagefirst.SnapshotV4{phase1, phase2}, false, []string{"phase1 turn 1", "phase2 turn 1", "Verify the signed allocation and contribute"}},
		{"restart", "1\nCANCEL\nQ\n", []storagefirst.SnapshotV4{phase2, phase2}, false, []string{"phase2 turn 1", "Proof-tool will verify this exact allocation"}},
		{"failed-refresh", "R\n1\nQ\n", []storagefirst.SnapshotV4{phase1, phase2, phase2}, true, []string{"Storage synchronization failed", "No role action is available"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, err := openWorkflowV4Journal(protocol, b.Definition, b)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			loaded, err := loadRoleConfig(p.Config, "participant")
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader(tc.input)), output: &out}
			calls := 0
			err = runWorkflowV4GuideLoop(t.TempDir(), p, guidedProfile{}, setupIdentity{ID: b.IdentityID}, protocol, j, access.StorageConfig{}, transcript.Inspector{}, "/unused/docker", &loaded, &ui, func() (storagefirst.SnapshotV4, error) {
				if calls >= len(tc.snapshots) {
					t.Fatal("unexpected refresh")
				}
				snapshot := tc.snapshots[calls]
				calls++
				if tc.failure && calls > 1 {
					return snapshot, errors.New("fixture authentication failed")
				}
				return snapshot, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q:\n%s", want, out.String())
				}
			}
			if tc.failure && strings.Contains(out.String(), "phase2 turn") {
				t.Fatal("failed sync authorized phase2")
			}
			if !reflect.DeepEqual(loaded, saved) {
				t.Fatal("guide modified saved participant")
			}
			after, _ := os.ReadFile(p.Config)
			if !bytes.Equal(after, before) {
				t.Fatal("profile file changed")
			}
		})
	}
}

func TestWorkflowV4GuidePhaseOnlyRosters(t *testing.T) {
	for _, assigned := range []string{"phase1", "phase2"} {
		t.Run(assigned, func(t *testing.T) {
			protocol, b := workflowV4TestBinding(t)
			protocol.Definition.Phase1Participants = []string{"other-participant"}
			protocol.Definition.Phase2Participants = []string{"other-participant"}
			if assigned == "phase1" {
				protocol.Definition.Phase1Participants = []string{b.IdentityID}
			} else {
				protocol.Definition.Phase2Participants = []string{b.IdentityID}
			}
			p, saved := guidePhaseProfile(t, b)
			for _, phase := range []string{"phase1", "phase2"} {
				snapshot := guidePhaseSnapshot(t, protocol, b, phase)
				j, err := openWorkflowV4Journal(protocol, b.Definition, b)
				if err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("Q\n")), output: &out}
				err = runWorkflowV4GuideLoop(t.TempDir(), p, guidedProfile{}, setupIdentity{ID: b.IdentityID}, protocol, j, access.StorageConfig{}, transcript.Inspector{}, "/unused/docker", &saved, &ui, func() (storagefirst.SnapshotV4, error) { return snapshot, nil })
				j.close()
				if err != nil {
					t.Fatal(err)
				}
				hasAction := strings.Contains(out.String(), "1) ")
				if hasAction != (assigned == phase) {
					t.Fatalf("assignment %s at %s: %s", assigned, phase, out.String())
				}
			}
		})
	}
}

func TestWorkflowV4GuidePreservesEarlierPhasePendingWork(t *testing.T) {
	for _, kind := range []string{"contribute", "attest-erasure", "upload-candidate"} {
		t.Run(kind, func(t *testing.T) {
			protocol, b := workflowV4TestBinding(t)
			protocol.Definition.Phase1Participants = []string{b.IdentityID}
			protocol.Definition.Phase2Participants = []string{b.IdentityID}
			p, saved := guidePhaseProfile(t, b)
			snapshot := guidePhaseSnapshot(t, protocol, b, "phase2")
			j, err := openWorkflowV4Journal(protocol, b.Definition, b)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			plan := workflowV4TestPlan(t, b)
			plan.Kind = kind
			// Model a retained operation without executing a container or forging a
			// successful journal transition. The guard must run before any action.
			j.state.Operations = []workflowV4Operation{{Plan: plan, Status: "prepared"}}
			before, _ := json.Marshal(j.state)
			var out bytes.Buffer
			ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("1\nQ\n")), output: &out}
			err = runWorkflowV4GuideLoop(t.TempDir(), p, guidedProfile{}, setupIdentity{ID: b.IdentityID}, protocol, j, access.StorageConfig{}, transcript.Inspector{}, "/unused/docker", &saved, &ui, func() (storagefirst.SnapshotV4, error) { return snapshot, nil })
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "work belongs to phase1; the ceremony is now in phase2") || strings.Contains(out.String(), "1) ") {
				t.Fatal(out.String())
			}
			active := saved
			active.Phase = "phase2"
			view, err := snapshot.TurnV4(protocol, "phase2", b.IdentityID)
			if err != nil {
				t.Fatal(err)
			}
			err = runWorkflowV4ParticipantAction(&ui, j, snapshot, protocol, active, access.StorageConfig{}, transcript.Inspector{}, "/unused/docker", view, workflowV4ParticipantProgress{}, nil)
			if err == nil || !strings.Contains(err.Error(), "another participant turn") {
				t.Fatalf("pending action dispatched: %v", err)
			}
			after, _ := json.Marshal(j.state)
			if !bytes.Equal(before, after) {
				t.Fatal("retained work changed")
			}
		})
	}
}

func TestWorkflowV4Phase2PlanIncludesAuthenticatedSeal(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	protocol.Definition.Phase1Participants = []string{b.IdentityID}
	protocol.Definition.Phase2Participants = []string{b.IdentityID}
	_, participant := guidePhaseProfile(t, b)
	snapshot := guidePhaseSnapshot(t, protocol, b, "phase2")
	for path, raw := range map[string]string{participant.CoordinatorKey: "public-key", participant.Environment: "environment"} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	participant.Phase = "phase2"
	plan, _, err := prepareWorkflowV4Contribution(snapshot, protocol, b, participant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, _ := snapshot.State()
	if plan.Scope.Phase != "phase2" || plan.Predecessor != c.Progress.Phase2.Chain || plan.Allocation != snapshot.Head() {
		t.Fatal("wrong phase2 plan")
	}
	for flag, ref := range map[string]transcript.ArtifactRef{"phase1-seal": c.Progress.Phase1Seal.Record, "phase1-seal-signature": c.Progress.Phase1Seal.Signature, "checkpoint": snapshot.Head().Record} {
		got := commandValue(plan.Command, flag)
		if !strings.HasSuffix(got, "/"+ref.Name) {
			t.Fatalf("%s: %s", flag, got)
		}
	}
}

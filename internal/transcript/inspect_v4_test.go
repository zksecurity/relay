package transcript

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDefinitionProtocolV4ExactDispatch(t *testing.T) {
	for version := 1; version <= 5; version++ {
		p := DefinitionProtocol{Schema: "proof-tool-mpc-definition-protocol-inspection-v1", DefinitionSchema: fmt.Sprintf("proof-tool-mpc-ceremony-definition-v%d", version), StorageWorkflow: "storage-first-v1", Definition: testDefinition()}
		p.Definition.CeremonyID = "sha256:" + hex64
		p.Definition.Mode = "rehearsal"
		p.Definition.Journey = &DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v2", ObserverRequirementSource: "signed ceremony assurance_policy"}
		for _, role := range []string{"coordinator", "release-signer", "participant"} {
			p.Definition.Journey.RequiredEnrollments = append(p.Definition.Journey.RequiredEnrollments, ExpectedEnrollment{Role: role, RoleIndex: 1, Identity: PublicIdentity{ID: role, KeyID: "key-" + role, PublicKeyFingerprint: "fingerprint-" + role}})
		}
		if version >= 4 {
			p.StorageWorkflow, p.ReleaseVerification = "storage-first-v2", "coordinator-full-replay-v1"
			p.DefinitionRefs = SignedArtifactRefs{Record: inspectionTestRef("ceremony.json"), Signature: inspectionTestRef("ceremony.sig")}
		}
		check := func(p DefinitionProtocol) (DefinitionProtocol, error) {
			i := testInspector()
			i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect definition-protocol", DefinitionProtocolInspection: &p}, "inspect definition-protocol")
			return i.DefinitionProtocol()
		}
		got, err := check(p)
		if err != nil || !reflect.DeepEqual(got, p) || got.UsesV4() != (version >= 4) {
			t.Fatalf("version %d: %+v %v", version, got, err)
		}
		if version >= 4 {
			for _, refs := range []SignedArtifactRefs{{}, {Record: inspectionTestRef("other.json"), Signature: p.DefinitionRefs.Signature}} {
				bad := p
				bad.DefinitionRefs = refs
				if _, err := check(bad); err == nil {
					t.Fatal("invalid definition binding accepted")
				}
			}
		}
		bad := p
		bad.ReleaseVerification = "skip-replay"
		if _, err := check(bad); err == nil {
			t.Fatal("unsupported policy accepted")
		}
		bad = p
		bad.StorageWorkflow = "storage-first-v99"
		if _, err := check(bad); err == nil {
			t.Fatal("unsupported workflow accepted")
		}
	}
	i := testInspector()
	calls := 0
	i.run = func(string, ...string) ([]byte, []byte, error) {
		calls++
		return nil, nil, errors.New("unsupported command")
	}
	if _, err := i.DefinitionProtocol(); err == nil || calls != 1 {
		t.Fatal("inspection failure triggered fallback")
	}
}

func TestStoredCheckpointV4RejectsMalformedProgress(t *testing.T) {
	pair := SignedArtifactRefs{Record: inspectionTestRef("record.json"), Signature: inspectionTestRef("record.sig")}
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: pair, AcceptedArtifacts: []ArtifactRef{}, Deliveries: []DeliverySlotV4{{Scope: ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + hex64}, Kind: "candidate", Status: "allocated", AttemptID: strings.Repeat("ab", 16)}}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("payload.bin"), Chain: pair}
	check := func(c CheckpointStateV4) error {
		i := testInspector()
		p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: pair, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}}}
		i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint verify-stored-v4", CheckpointInspectionV4: &p}, "checkpoint verify-stored-v4")
		_, err := i.StoredCheckpointV4("/stage", "/stage/record.json", "/stage/record.sig")
		return err
	}
	if err := check(c); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CheckpointStateV4){
		"phase":         func(c *CheckpointStateV4) { c.Progress.Phase1.Phase = "phase2" },
		"count":         func(c *CheckpointStateV4) { c.Progress.Phase1.AcceptedCount = 21 },
		"head":          func(c *CheckpointStateV4) { c.Progress.Phase1.HeadRecordID = "missing" },
		"pair":          func(c *CheckpointStateV4) { c.Progress.Phase1.Chain.Signature.Digest.Size = 4097 },
		"optional pair": func(c *CheckpointStateV4) { c.Progress.FinalRelease = &SignedArtifactRefs{} },
		"scope":         func(c *CheckpointStateV4) { c.Deliveries[0].Scope.CeremonyID = "other" },
		"turn":          func(c *CheckpointStateV4) { c.Deliveries[0].Scope.Index = 0 },
		"kind":          func(c *CheckpointStateV4) { c.Deliveries[0].Kind = "anything" },
		"status":        func(c *CheckpointStateV4) { c.Deliveries[0].Status = "done" },
		"attempt":       func(c *CheckpointStateV4) { c.Deliveries[0].AttemptID = "z" },
		"duplicate":     func(c *CheckpointStateV4) { c.Deliveries = append(c.Deliveries, c.Deliveries[0]) },
		"result":        func(c *CheckpointStateV4) { c.Deliveries[0].Status = "accepted" },
	} {
		raw, _ := json.Marshal(c)
		var bad CheckpointStateV4
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		change(&bad)
		if err := check(bad); err == nil {
			t.Errorf("accepted malformed %s", name)
		}
	}
}

func TestAuthenticateCheckpointForPublicationV4UsesSignedStoredVerificationOnly(t *testing.T) {
	pair := SignedArtifactRefs{Record: inspectionTestRef("record.json"), Signature: inspectionTestRef("record.sig")}
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: pair, AcceptedArtifacts: []ArtifactRef{}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("payload.bin"), Chain: pair}
	want := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: pair, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}}}
	i := testInspector()
	i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint verify-stored-v4", CheckpointInspectionV4: &want}, "checkpoint verify-stored-v4")
	got, err := i.AuthenticateCheckpointForPublicationV4("/stage", "/stage/record.json", "/stage/record.sig")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inspection = %+v, want %+v", got, want)
	}
}

func TestCheckpointGuidanceV4UsesStrictReleasedFinalInventoryFallback(t *testing.T) {
	pair := SignedArtifactRefs{Record: inspectionTestRef("checkpoints/final.json"), Signature: inspectionTestRef("checkpoints/final.sig")}
	definition := SignedArtifactRefs{Record: inspectionTestRef("ceremony.json"), Signature: inspectionTestRef("ceremony.sig")}
	release := SignedArtifactRefs{Record: inspectionTestRef("final/release/manifest.json"), Signature: inspectionTestRef("final/release/manifest.sig")}
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: definition, AcceptedArtifacts: []ArtifactRef{}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("phase1/genesis.bin"), Chain: definition}
	c.Progress.FinalRelease = &release
	empty := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: pair, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}, FinalReleaseArtifacts: []ArtifactRef{}}}
	full := empty
	full.Commitments.FinalReleaseArtifacts = []ArtifactRef{inspectionTestRef("final/release/setup-transcript.json")}
	metadata := EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", Metadata: EnrollmentMetadataV4{CeremonyID: c.CeremonyID, Checkpoint: pair, Enrollments: []CommittedEnrollmentMetadataV4{}}, EnrollmentSignaturesVerified: true}
	i := testInspector()
	calls := 0
	i.run = func(executable string, args ...string) ([]byte, []byte, error) {
		calls++
		var result inspectionResult
		if strings.Contains(strings.Join(args, " "), "inspect-enrollments-v4") {
			result = inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint inspect-enrollments-v4", CheckpointInspectionV4: &empty, EnrollmentMetadataV4: &metadata}
		} else {
			result = inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint verify-stored-v4", CheckpointInspectionV4: &full}
		}
		raw, err := json.Marshal(result)
		return raw, nil, err
	}
	got, _, err := i.CheckpointGuidanceV4("/stage", "/stage/final.json", "/stage/final.sig")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !reflect.DeepEqual(got.Commitments.FinalReleaseArtifacts, full.Commitments.FinalReleaseArtifacts) {
		t.Fatalf("released-runtime fallback calls=%d inventory=%+v", calls, got.Commitments.FinalReleaseArtifacts)
	}
}

func TestRequiredPublicArtifactsV4ReleaseReviewOmitsHistoricalReplayPayloads(t *testing.T) {
	pair := func(base string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: inspectionTestRef(base + ".json"), Signature: inspectionTestRef(base + ".sig")}
	}
	definition := pair("ceremony")
	chain := pair("phase1/chain-0001")
	review := pair("operational/evidence-bundle")
	checkpoint := pair("checkpoints/0012/checkpoint")
	contribution := inspectionTestRef("phase1/contributions/0001/contribution.bin")
	genesis := inspectionTestRef("phase1/genesis.bin")
	key := inspectionTestRef("final/candidate/ownership.pk")
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: definition, AcceptedArtifacts: []ArtifactRef{key, review.Record, review.Signature, contribution, genesis}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: contribution, Chain: chain}
	c.Progress.ReleaseReview = &review
	p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: checkpoint, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}}}
	refs, err := RequiredPublicArtifactsV4(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, ref := range refs {
		names[ref.Name] = true
	}
	for _, want := range []string{"ceremony.json", "operational/evidence-bundle.json", "operational/evidence-bundle.sig", "final/candidate/ownership.pk"} {
		if !names[want] {
			t.Fatalf("missing release dependency %s", want)
		}
	}
	for _, unwanted := range []string{contribution.Name, genesis.Name} {
		if names[unwanted] {
			t.Fatalf("historical replay payload scheduled for release-signer download: %s", unwanted)
		}
	}
}

func TestRequiredPublicArtifactsV4PublishesEnrollmentEvidenceBeforeReview(t *testing.T) {
	pair := func(base string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: inspectionTestRef(base + ".json"), Signature: inspectionTestRef(base + ".sig")}
	}
	definition := pair("ceremony")
	chain := pair("phase1/chain-0000")
	checkpoint := pair("checkpoints/enrollment/checkpoint")
	enrollment := pair("enrollments/participant-01/enrollment")
	disclosure := inspectionTestRef("enrollments/participant-01/disclosure.txt")
	genesis := inspectionTestRef("phase1/genesis.bin")
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: definition, AcceptedArtifacts: []ArtifactRef{disclosure, enrollment.Record, enrollment.Signature, genesis}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: genesis, Chain: chain}
	p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: checkpoint, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{enrollment}, Turns: []TurnCommitmentV4{}}}
	refs, err := RequiredPublicArtifactsV4(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, ref := range refs {
		names[ref.Name] = true
	}
	for _, want := range []string{enrollment.Record.Name, enrollment.Signature.Name, disclosure.Name, genesis.Name} {
		if !names[want] {
			t.Fatalf("missing pre-review public dependency %s", want)
		}
	}
}

func TestRequiredPublicArtifactsV4IncludesPhase1ReplayForPhase2(t *testing.T) {
	pair := func(base string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: inspectionTestRef(base + ".json"), Signature: inspectionTestRef(base + ".sig")}
	}
	definition := pair("ceremony")
	phase1Chain := pair("phase1/chain-0001")
	phase2Chain := pair("phase2/chain-0000")
	checkpoint := pair("checkpoints/phase2/allocate/checkpoint")
	phase1Genesis := inspectionTestRef("phase1/genesis.bin")
	phase1Contribution := inspectionTestRef("phase1/contributions/0001/contribution.bin")
	phase2Genesis := inspectionTestRef("phase2/genesis.bin")
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: definition, AcceptedArtifacts: []ArtifactRef{phase1Contribution, phase1Genesis, phase2Genesis}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: phase1Contribution, Chain: phase1Chain}
	c.Progress.Phase2 = &CheckpointPhaseState{Phase: "phase2", HeadRecordID: "sha256:" + hex64, HeadPayload: phase2Genesis, Chain: phase2Chain}
	p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: checkpoint, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}}}
	refs, err := RequiredPublicArtifactsV4(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, ref := range refs {
		names[ref.Name] = true
	}
	for _, want := range []string{phase1Genesis.Name, phase1Contribution.Name, phase2Genesis.Name} {
		if !names[want] {
			t.Fatalf("missing Phase 2 replay dependency %s", want)
		}
	}
}

func TestRequiredPublicArtifactsV4IncludesClosedFinalReleaseInventory(t *testing.T) {
	pair := func(base string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: inspectionTestRef(base + ".json"), Signature: inspectionTestRef(base + ".sig")}
	}
	definition := pair("ceremony")
	chain := pair("phase1/chain-0001")
	finalRelease := pair("final/release/release")
	checkpoint := pair("checkpoints/0013/checkpoint")
	bundle := inspectionTestRef("final/release/key-bundle.json")
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: definition, AcceptedArtifacts: []ArtifactRef{}, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("phase1/genesis.bin"), Chain: chain}
	c.Progress.FinalRelease = &finalRelease
	p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: checkpoint, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}, FinalReleaseArtifacts: []ArtifactRef{bundle, finalRelease.Record, finalRelease.Signature}}}
	refs, err := RequiredPublicArtifactsV4(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, ref := range refs {
		names[ref.Name] = true
	}
	for _, want := range []string{bundle.Name, finalRelease.Record.Name, finalRelease.Signature.Name} {
		if !names[want] {
			t.Fatalf("missing final release member %s", want)
		}
	}
	bad := p
	bad.Commitments.FinalReleaseArtifacts = []ArtifactRef{inspectionTestRef("outside-release.json")}
	if _, err := RequiredPublicArtifactsV4(bad); err == nil {
		t.Fatal("accepted final release inventory outside final/release")
	}
}

func TestCheckpointV4DiscoveryProjectionBoundary(t *testing.T) {
	p := CheckpointDiscoveryV4{Schema: "proof-tool-mpc-checkpoint-discovery-v4", Depth: "signed-checkpoint-discovery", CheckpointRefs: SignedArtifactRefs{Record: inspectionTestRef("checkpoint.json"), Signature: inspectionTestRef("checkpoint.sig")}}
	p.Discovery.CeremonyID = "sha256:" + hex64
	p.Discovery.VerificationDependencies = []ArtifactRef{}
	check := func(p CheckpointDiscoveryV4) (CheckpointDiscoveryV4, error) {
		i := testInspector()
		i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint inspect-signed-v4", CheckpointDiscoveryV4: &p}, "checkpoint inspect-signed-v4")
		return i.DiscoverCheckpointV4("/stage", "/stage/checkpoint.json", "/stage/checkpoint.sig")
	}
	if _, err := check(p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CheckpointDiscoveryV4){
		"ancestry claim":       func(p *CheckpointDiscoveryV4) { p.AncestryVerified = true },
		"artifact claim":       func(p *CheckpointDiscoveryV4) { p.ArtifactsVerified = true },
		"replay claim":         func(p *CheckpointDiscoveryV4) { p.MathematicsReplayed = true },
		"freshness claim":      func(p *CheckpointDiscoveryV4) { p.GlobalFreshnessVerified = true },
		"wrong depth":          func(p *CheckpointDiscoveryV4) { p.Depth = "checkpoint-structure" },
		"missing ancestor":     func(p *CheckpointDiscoveryV4) { p.Discovery.Sequence = 1 },
		"oversize record":      func(p *CheckpointDiscoveryV4) { p.CheckpointRefs.Record.Digest.Size = 16<<20 + 1 },
		"oversize signature":   func(p *CheckpointDiscoveryV4) { p.CheckpointRefs.Signature.Digest.Size = 4097 },
		"same path":            func(p *CheckpointDiscoveryV4) { p.CheckpointRefs.Signature.Name = p.CheckpointRefs.Record.Name },
		"bad path":             func(p *CheckpointDiscoveryV4) { p.CheckpointRefs.Record.Name = "../escape" },
		"missing dependencies": func(p *CheckpointDiscoveryV4) { p.Discovery.VerificationDependencies = nil },
		"excess dependencies": func(p *CheckpointDiscoveryV4) {
			for range 6 {
				p.Discovery.VerificationDependencies = append(p.Discovery.VerificationDependencies, inspectionTestRef("record"))
			}
		},
	} {
		bad := p
		change(&bad)
		if _, err := check(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	previous := SignedArtifactRefs{Record: inspectionTestRef("previous.json"), Signature: inspectionTestRef("previous.sig")}
	p.Discovery.PreviousCheckpoint = &previous
	for _, sequence := range []uint64{1025, MaxCheckpointSequenceV4} {
		p.Discovery.Sequence = sequence
		if _, err := check(p); err != nil {
			t.Fatalf("valid sequence %d rejected: %v", sequence, err)
		}
	}
	p.Discovery.Sequence++
	if _, err := check(p); err == nil {
		t.Fatal("protocol sequence overflow accepted")
	}
}

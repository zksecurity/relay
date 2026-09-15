package transcript

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckpointEnrollmentMetadataBoundaryV4(t *testing.T) {
	pair := SignedArtifactRefs{Record: inspectionTestRef("enrollment.json"), Signature: inspectionTestRef("enrollment.sig")}
	e := EnrollmentInspection{Schema: "proof-tool-mpc-enrollment-record-v1", CeremonyID: "sha256:" + hex64, Role: "participant", RoleIndex: 1, EnrolledAt: "2026-09-01T00:00:00Z", IndependenceDisclosure: inspectionTestRef("disclosure.txt"), Identity: PublicIdentity{ID: "person", DisplayName: "Person", KeyID: "ed25519:" + hex64, Ed25519PublicKeyHex: hex64, PublicKeyFingerprint: "sha256:" + hex64}}
	p := EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", EnrollmentSignaturesVerified: true, Metadata: EnrollmentMetadataV4{CeremonyID: e.CeremonyID, Checkpoint: pair, Enrollments: []CommittedEnrollmentMetadataV4{{Refs: pair, Enrollment: e}}}}
	check := func(p EnrollmentMetadataInspectionV4) error {
		i := testInspector()
		i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint inspect-enrollments-v4", EnrollmentMetadataV4: &p}, "checkpoint inspect-enrollments-v4")
		_, err := i.CheckpointEnrollmentsV4("/stage", "/stage/checkpoint.json", "/stage/checkpoint.sig")
		return err
	}
	if err := check(p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*EnrollmentMetadataInspectionV4){
		"signature unchecked":  func(p *EnrollmentMetadataInspectionV4) { p.EnrollmentSignaturesVerified = false },
		"disclosure overclaim": func(p *EnrollmentMetadataInspectionV4) { p.DisclosureContentsVerified = true },
		"roster overclaim":     func(p *EnrollmentMetadataInspectionV4) { p.CompleteRosterVerified = true },
		"freshness overclaim":  func(p *EnrollmentMetadataInspectionV4) { p.GlobalFreshnessVerified = true },
		"nil set":              func(p *EnrollmentMetadataInspectionV4) { p.Metadata.Enrollments = nil },
		"duplicate": func(p *EnrollmentMetadataInspectionV4) {
			p.Metadata.Enrollments = append(p.Metadata.Enrollments, p.Metadata.Enrollments[0])
		},
		"wrong ceremony":      func(p *EnrollmentMetadataInspectionV4) { p.Metadata.Enrollments[0].Enrollment.CeremonyID = "other" },
		"role":                func(p *EnrollmentMetadataInspectionV4) { p.Metadata.Enrollments[0].Enrollment.Role = "operator" },
		"assignment":          func(p *EnrollmentMetadataInspectionV4) { p.Metadata.Enrollments[0].Enrollment.RoleIndex = 21 },
		"oversized signature": func(p *EnrollmentMetadataInspectionV4) { p.Metadata.Enrollments[0].Refs.Signature.Digest.Size = 4097 },
	} {
		var bad EnrollmentMetadataInspectionV4
		b, _ := json.Marshal(p)
		if err := json.Unmarshal(b, &bad); err != nil {
			t.Fatal(err)
		}
		change(&bad)
		if err := check(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestTurnCommitmentProjectionRetainsHistoricalOutboundsV4(t *testing.T) {
	pair := func(name string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: inspectionTestRef(name + ".json"), Signature: inspectionTestRef(name + ".sig")}
	}
	scope := ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "person", ParentHeadID: "sha256:" + hex64}
	a, b, c := strings.Repeat("ab", 16), strings.Repeat("bc", 16), strings.Repeat("cd", 16)
	state := CheckpointStateV4{CeremonyID: scope.CeremonyID, Sequence: 5, Deliveries: []DeliverySlotV4{{Scope: scope, AttemptID: a, Kind: "receipt", Status: "retired"}, {Scope: scope, AttemptID: b, Kind: "receipt", Status: "accepted"}, {Scope: scope, AttemptID: c, Kind: "candidate", Status: "accepted", ContributionResultID: "sha256:" + hex64}}}
	returnHandoff, returnReceipt := pair("return-handoff"), pair("return-receipt")
	index := CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{{Scope: scope, Outbounds: []OutboundCommitmentV4{{CheckpointSequence: 3, PublishedAttemptID: b, Pair: pair("new")}, {CheckpointSequence: 1, PublishedAttemptID: a, Pair: pair("old")}}, InputReceipt: &AcceptedTurnRecordV4{AttemptID: b, Pair: pair("input-receipt")}, AcceptedChain: &AcceptedChainCommitmentV4{AttemptID: c, ContributionResultID: "sha256:" + hex64, Pair: pair("accepted-chain")}, ReturnHandoff: &returnHandoff, ReturnReceipt: &returnReceipt}}}
	if err := validateCommitmentsV4(state, index); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CheckpointCommitmentsV4){
		"duplicate turn": func(p *CheckpointCommitmentsV4) { p.Turns = append(p.Turns, p.Turns[0]) },
		"reversed history": func(p *CheckpointCommitmentsV4) {
			p.Turns[0].Outbounds[0], p.Turns[0].Outbounds[1] = p.Turns[0].Outbounds[1], p.Turns[0].Outbounds[0]
		},
		"wrong publication attempt": func(p *CheckpointCommitmentsV4) { p.Turns[0].Outbounds[0].PublishedAttemptID = c },
		"wrong result": func(p *CheckpointCommitmentsV4) {
			p.Turns[0].AcceptedChain.ContributionResultID = "sha256:" + strings.Repeat("f", 64)
		},
		"missing return receipt": func(p *CheckpointCommitmentsV4) { p.Turns[0].ReturnReceipt = nil },
		"missing outbounds":      func(p *CheckpointCommitmentsV4) { p.Turns[0].Outbounds = nil },
	} {
		var bad CheckpointCommitmentsV4
		b, _ := json.Marshal(index)
		if err := json.Unmarshal(b, &bad); err != nil {
			t.Fatal(err)
		}
		change(&bad)
		if err := validateCommitmentsV4(state, bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestCheckpointGuidanceV4UsesOneApprovedCommand(t *testing.T) {
	pair := SignedArtifactRefs{Record: inspectionTestRef("checkpoint.json"), Signature: inspectionTestRef("checkpoint.sig")}
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: pair, Deliveries: []DeliverySlotV4{}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("genesis.bin"), Chain: pair}
	structure := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: pair, Commitments: CheckpointCommitmentsV4{Enrollments: []SignedArtifactRefs{}, Turns: []TurnCommitmentV4{}}}
	metadata := EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", EnrollmentSignaturesVerified: true, Metadata: EnrollmentMetadataV4{CeremonyID: c.CeremonyID, Checkpoint: pair, Enrollments: []CommittedEnrollmentMetadataV4{}}}
	r := inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint inspect-enrollments-v4", CheckpointInspectionV4: &structure, EnrollmentMetadataV4: &metadata}
	i := testInspector()
	calls := 0
	i.run = func(_ string, args ...string) ([]byte, []byte, error) {
		calls++
		if strings.Join(args[2:4], " ") != "checkpoint inspect-enrollments-v4" {
			t.Fatalf("unexpected command %v", args)
		}
		b, err := json.Marshal(r)
		return b, nil, err
	}
	if _, _, err := i.CheckpointGuidanceV4("/stage", "/stage/checkpoint.json", "/stage/checkpoint.sig"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("guidance launched more than one ancestry verification")
	}
	metadata.Metadata.Checkpoint.Signature.Name = "different.sig"
	if _, _, err := i.CheckpointGuidanceV4("/stage", "/stage/checkpoint.json", "/stage/checkpoint.sig"); err == nil {
		t.Fatal("different metadata head accepted")
	}
}

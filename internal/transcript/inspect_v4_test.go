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
	for version := 1; version <= 4; version++ {
		p := DefinitionProtocol{Schema: "proof-tool-mpc-definition-protocol-inspection-v1", DefinitionSchema: fmt.Sprintf("proof-tool-mpc-ceremony-definition-v%d", version), StorageWorkflow: "storage-first-v1", Definition: testDefinition()}
		p.Definition.CeremonyID = "sha256:" + hex64
		p.Definition.Mode = "rehearsal"
		p.Definition.Journey = &DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v2", ObserverRequirementSource: "signed ceremony assurance_policy"}
		for _, role := range []string{"coordinator", "release-signer", "participant"} {
			p.Definition.Journey.RequiredEnrollments = append(p.Definition.Journey.RequiredEnrollments, ExpectedEnrollment{Role: role, RoleIndex: 1, Identity: PublicIdentity{ID: role, KeyID: "key-" + role, PublicKeyFingerprint: "fingerprint-" + role}})
		}
		if version == 4 {
			p.StorageWorkflow, p.ReleaseVerification = "storage-first-v2", "coordinator-full-replay-v1"
		}
		check := func(p DefinitionProtocol) (DefinitionProtocol, error) {
			i := testInspector()
			i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect definition-protocol", DefinitionProtocolInspection: &p}, "inspect definition-protocol")
			return i.DefinitionProtocol()
		}
		got, err := check(p)
		if err != nil || !reflect.DeepEqual(got, p) || got.UsesV4() != (version == 4) {
			t.Fatalf("version %d: %+v %v", version, got, err)
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
	c := CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: "sha256:" + hex64, Definition: pair, Deliveries: []DeliverySlotV4{{Scope: ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + hex64}, Kind: "candidate", Status: "allocated", AttemptID: strings.Repeat("ab", 16)}}}
	c.Progress.Phase1 = CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + hex64, HeadPayload: inspectionTestRef("payload.bin"), Chain: pair}
	check := func(c CheckpointStateV4) error {
		i := testInspector()
		p := CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: pair}
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

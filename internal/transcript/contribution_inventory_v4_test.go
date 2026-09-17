package transcript

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestContributionInventoryV4ProjectionBoundary(t *testing.T) {
	scope := ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + hex64}
	pair := SignedArtifactRefs{Record: inspectionTestRef("phase1/chain-0000.json"), Signature: inspectionTestRef("phase1/chain-0000.sig")}
	computed := CandidateInventoryV4{Schema: "proof-tool-mpc-candidate-inventory-v1", Scope: scope, Files: []ArtifactRef{}}
	for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"} {
		computed.Files = append(computed.Files, inspectionTestRef(name))
	}
	complete := computed
	complete.Files = append([]ArtifactRef{}, computed.Files...)
	p := ContributionInventoryInspectionV4{Schema: "proof-tool-mpc-contribution-inventory-inspection-v4", Depth: "candidate-signatures-and-digests", SignaturesVerified: true, PayloadDigestVerified: true, Inventory: ContributionInventoryFactsV4{Scope: scope, Predecessor: pair, Computed: computed, ComputedCandidateID: "sha256:" + hex64, Complete: &complete, CandidateResultID: "sha256:" + hex64}}
	check := func(p ContributionInventoryInspectionV4) error {
		i := testInspector()
		i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect contribution-inventory-v4", ContributionInventoryV4: &p}, "inspect contribution-inventory-v4")
		_, err := i.ContributionInventoryV4("/work/chain.json", "/work/chain.sig", "/work/scope.json", "/work/candidate", scope, pair)
		return err
	}
	if err := check(p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ContributionInventoryInspectionV4){
		"scope":       func(p *ContributionInventoryInspectionV4) { p.Inventory.Scope.Index = 2 },
		"predecessor": func(p *ContributionInventoryInspectionV4) { p.Inventory.Predecessor.Record.Name = "other.json" },
		"math":        func(p *ContributionInventoryInspectionV4) { p.MathematicsReplayed = true },
		"freshness":   func(p *ContributionInventoryInspectionV4) { p.GlobalFreshnessVerified = true },
		"erasure":     func(p *ContributionInventoryInspectionV4) { p.PhysicalErasureVerified = true },
		"unchecked":   func(p *ContributionInventoryInspectionV4) { p.SignaturesVerified = false },
		"partial": func(p *ContributionInventoryInspectionV4) {
			p.Inventory.Complete.Files = p.Inventory.Complete.Files[:4]
		},
		"changed-five": func(p *ContributionInventoryInspectionV4) { p.Inventory.Complete.Files[0].Digest.Size++ },
		"different-id": func(p *ContributionInventoryInspectionV4) {
			p.Inventory.CandidateResultID = "sha256:" + strings.Repeat("b", 64)
		},
		"oversize":         func(p *ContributionInventoryInspectionV4) { p.Inventory.Computed.Files[2].Digest.Size = 16<<30 + 1 },
		"name":             func(p *ContributionInventoryInspectionV4) { p.Inventory.Computed.Files[0].Name = "private.key" },
		"missing-complete": func(p *ContributionInventoryInspectionV4) { p.Inventory.Complete = nil },
	} {
		b, _ := json.Marshal(p)
		var bad ContributionInventoryInspectionV4
		if err := json.Unmarshal(b, &bad); err != nil {
			t.Fatal(err)
		}
		change(&bad)
		if err := check(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	p.Inventory.Complete = nil
	p.Inventory.CandidateResultID = ""
	if err := check(p); err != nil {
		t.Fatal("computed-only inventory rejected", err)
	}
}

func TestContributionInventoryV4DoesNotClassifyOtherCommandFailures(t *testing.T) {
	scope := ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + hex64}
	pair := SignedArtifactRefs{Record: inspectionTestRef("phase1/chain-0000.json"), Signature: inspectionTestRef("phase1/chain-0000.sig")}
	i := testInspector()
	i.run = func(_ string, _ ...string) ([]byte, []byte, error) {
		return []byte(`{"schema":"proof-tool-mpc-command-result-v1","ok":false,"command":"inspect definition","error":{"code":"candidate_invalid","message":"unrelated command failure"}}`), nil, errors.New("exit status 6")
	}
	_, err := i.ContributionInventoryV4("/work/chain.json", "/work/chain.sig", "/work/scope.json", "/work/candidate", scope, pair)
	if err == nil {
		t.Fatal("accepted an unrelated command failure")
	}
	if errors.Is(err, ErrCandidateInvalidV4) {
		t.Fatalf("wrong command became a candidate rejection decision: %v", err)
	}
}

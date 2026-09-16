package transcript

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestComputationOutputV4ProjectionBoundary(t *testing.T) {
	scope := ContributionScopeV4{CeremonyID: "sha256:" + hex64, Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + hex64}
	pair := SignedArtifactRefs{Record: inspectionTestRef("phase1/chain-0000.json"), Signature: inspectionTestRef("phase1/chain-0000.sig")}
	p := ComputationOutputInspectionV4{Schema: "proof-tool-mpc-computation-output-inspection-v4", Depth: "computation-signatures-and-digests", SignaturesVerified: true, PayloadDigestVerified: true, Output: ComputationOutputFactsV4{Scope: scope, Predecessor: pair, Files: []ArtifactRef{inspectionTestRef("attestation.json"), inspectionTestRef("attestation.sig"), inspectionTestRef("contribution.bin")}}}
	check := func(p ComputationOutputInspectionV4) (ComputationOutputFactsV4, error) {
		i := testInspector()
		i.run = inspectionTestRunner(t, inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect computation-output-v4", ComputationOutputV4: &p}, "inspect computation-output-v4")
		return i.ComputationOutputV4("/work/chain.json", "/work/chain.sig", "/work/scope.json", "/work/candidate", scope, pair)
	}
	if got, err := check(p); err != nil || !reflect.DeepEqual(got, p.Output) {
		t.Fatalf("valid output: %v, %v", got, err)
	}
	for name, mutate := range map[string]func(*ComputationOutputInspectionV4){
		"cleanup claim":       func(p *ComputationOutputInspectionV4) { p.CleanupVerified = true },
		"math claim":          func(p *ComputationOutputInspectionV4) { p.MathematicsReplayed = true },
		"freshness claim":     func(p *ComputationOutputInspectionV4) { p.GlobalFreshnessVerified = true },
		"erasure claim":       func(p *ComputationOutputInspectionV4) { p.PhysicalErasureVerified = true },
		"unchecked signature": func(p *ComputationOutputInspectionV4) { p.SignaturesVerified = false },
		"unchecked payload":   func(p *ComputationOutputInspectionV4) { p.PayloadDigestVerified = false },
		"other turn":          func(p *ComputationOutputInspectionV4) { p.Output.Scope.Index++ },
		"other predecessor":   func(p *ComputationOutputInspectionV4) { p.Output.Predecessor.Record.Name = "other.json" },
		"partial":             func(p *ComputationOutputInspectionV4) { p.Output.Files = p.Output.Files[:2] },
		"extra file": func(p *ComputationOutputInspectionV4) {
			p.Output.Files = append(p.Output.Files, inspectionTestRef("erasure.json"))
		},
		"wrong name": func(p *ComputationOutputInspectionV4) { p.Output.Files[0].Name = "signing.hex" },
		"oversize":   func(p *ComputationOutputInspectionV4) { p.Output.Files[2].Digest.Size = 16<<30 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(p)
			var bad ComputationOutputInspectionV4
			if err := json.Unmarshal(encoded, &bad); err != nil {
				t.Fatal(err)
			}
			mutate(&bad)
			got, err := check(bad)
			if err == nil || !reflect.DeepEqual(got, ComputationOutputFactsV4{}) {
				t.Fatalf("invalid output accepted: %v, %v", got, err)
			}
		})
	}
}

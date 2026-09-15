package transcript

import (
	"errors"
	"slices"
)

type CandidateInventoryV4 struct {
	Schema string              `json:"schema"`
	Scope  ContributionScopeV4 `json:"scope"`
	Files  []ArtifactRef       `json:"files"`
}

type ContributionInventoryFactsV4 struct {
	Scope               ContributionScopeV4   `json:"scope"`
	Predecessor         SignedArtifactRefs    `json:"predecessor"`
	Computed            CandidateInventoryV4  `json:"computed"`
	ComputedCandidateID string                `json:"computed_candidate_id"`
	Complete            *CandidateInventoryV4 `json:"complete,omitempty"`
	CandidateResultID   string                `json:"candidate_result_id,omitempty"`
}

type ContributionInventoryInspectionV4 struct {
	Schema                  string                       `json:"schema"`
	Depth                   string                       `json:"depth"`
	Inventory               ContributionInventoryFactsV4 `json:"inventory"`
	SignaturesVerified      bool                         `json:"signatures_verified"`
	PayloadDigestVerified   bool                         `json:"payload_digest_verified"`
	MathematicsReplayed     bool                         `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                         `json:"global_freshness_verified"`
	PhysicalErasureVerified bool                         `json:"physical_erasure_verified"`
}

// ContributionInventoryV4 delegates reconstruction to approved proof-tool. The
// expected scope and exact predecessor come from verified state/retained work,
// not from an arbitrary folder. The scope file is checked by the child too.
func (i Inspector) ContributionInventoryV4(chain, signature, scopeFile, candidateDir string, expected ContributionScopeV4, predecessor SignedArtifactRefs) (ContributionInventoryFactsV4, error) {
	r, err := i.execute("inspect", "contribution-inventory-v4", "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath, "--transcript-root", i.TranscriptRoot, "--chain", chain, "--chain-signature", signature, "--scope", scopeFile, "--candidate-dir", candidateDir)
	if err != nil {
		return ContributionInventoryFactsV4{}, err
	}
	if r.Command != "inspect contribution-inventory-v4" || r.ContributionInventoryV4 == nil {
		return ContributionInventoryFactsV4{}, errors.New("missing contribution inventory inspection")
	}
	p := *r.ContributionInventoryV4
	if p.Schema != "proof-tool-mpc-contribution-inventory-inspection-v4" || p.Depth != "candidate-signatures-and-digests" || !p.SignaturesVerified || !p.PayloadDigestVerified || p.MathematicsReplayed || p.GlobalFreshnessVerified || p.PhysicalErasureVerified {
		return ContributionInventoryFactsV4{}, errors.New("invalid contribution inventory verification boundary")
	}
	f := p.Inventory
	if f.Scope != expected || f.Predecessor != predecessor || !taggedHash(f.ComputedCandidateID, "sha256:") {
		return ContributionInventoryFactsV4{}, errors.New("inventory differs from expected turn or predecessor")
	}
	if err := validatePairV4(f.Predecessor); err != nil {
		return ContributionInventoryFactsV4{}, err
	}
	if err := validateInventoryProjectionV4(f.Computed, expected, 5); err != nil {
		return ContributionInventoryFactsV4{}, err
	}
	if f.Complete == nil {
		if f.CandidateResultID != "" {
			return ContributionInventoryFactsV4{}, errors.New("final candidate identity without complete inventory")
		}
	} else {
		if err := validateInventoryProjectionV4(*f.Complete, expected, 7); err != nil {
			return ContributionInventoryFactsV4{}, err
		}
		if !taggedHash(f.CandidateResultID, "sha256:") || f.CandidateResultID == f.ComputedCandidateID || !slices.Equal(f.Computed.Files, f.Complete.Files[:5]) {
			return ContributionInventoryFactsV4{}, errors.New("complete inventory does not retain exact computed files")
		}
	}
	return f, nil
}

func validateInventoryProjectionV4(i CandidateInventoryV4, expected ContributionScopeV4, count int) error {
	if i.Schema != "proof-tool-mpc-candidate-inventory-v1" || i.Scope != expected || len(i.Files) != count || !taggedHash(expected.CeremonyID, "sha256:") || !taggedHash(expected.ParentHeadID, "sha256:") || (expected.Phase != "phase1" && expected.Phase != "phase2") || expected.Index == 0 || expected.Index > 20 || expected.ParticipantID == "" {
		return errors.New("invalid candidate inventory projection")
	}
	names := []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig", "return-handoff.json", "return-handoff.sig"}
	for n, ref := range i.Files {
		limit := int64(16 << 20)
		if n == 2 {
			limit = 16 << 30 // proof-tool MaxArtifactSize
		} else if n == 1 || n == 4 || n == 6 {
			limit = 4096
		}
		if ref.Name != names[n] {
			return errors.New("unexpected candidate inventory filename")
		}
		if err := validateBoundedRefV4(ref, limit); err != nil {
			return err
		}
	}
	return nil
}

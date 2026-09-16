package transcript

import "errors"

// ComputationOutputFactsV4 describes generated public files before cleanup.
// It is not an upload inventory and intentionally has no candidate result ID.
type ComputationOutputFactsV4 struct {
	Scope       ContributionScopeV4 `json:"scope"`
	Predecessor SignedArtifactRefs  `json:"predecessor"`
	Files       []ArtifactRef       `json:"files"`
}

type ComputationOutputInspectionV4 struct {
	Schema                  string                   `json:"schema"`
	Depth                   string                   `json:"depth"`
	Output                  ComputationOutputFactsV4 `json:"output"`
	SignaturesVerified      bool                     `json:"signatures_verified"`
	PayloadDigestVerified   bool                     `json:"payload_digest_verified"`
	CleanupVerified         bool                     `json:"cleanup_verified"`
	MathematicsReplayed     bool                     `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                     `json:"global_freshness_verified"`
	PhysicalErasureVerified bool                     `json:"physical_erasure_verified"`
}

func (i Inspector) ComputationOutputV4(chain, signature, scopeFile, candidateDir string, expected ContributionScopeV4, predecessor SignedArtifactRefs) (ComputationOutputFactsV4, error) {
	var zero ComputationOutputFactsV4
	r, err := i.execute("inspect", "computation-output-v4", "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath, "--transcript-root", i.TranscriptRoot, "--chain", chain, "--chain-signature", signature, "--scope", scopeFile, "--candidate-dir", candidateDir)
	if err != nil {
		return zero, err
	}
	if r.Command != "inspect computation-output-v4" || r.ComputationOutputV4 == nil {
		return zero, errors.New("missing computation output inspection")
	}
	p := r.ComputationOutputV4
	if p.Schema != "proof-tool-mpc-computation-output-inspection-v4" || p.Depth != "computation-signatures-and-digests" || !p.SignaturesVerified || !p.PayloadDigestVerified || p.CleanupVerified || p.MathematicsReplayed || p.GlobalFreshnessVerified || p.PhysicalErasureVerified {
		return zero, errors.New("invalid computation output verification boundary")
	}
	if p.Output.Scope != expected || p.Output.Predecessor != predecessor {
		return zero, errors.New("generated output differs from expected turn or predecessor")
	}
	if err := validatePairV4(predecessor); err != nil {
		return zero, err
	}
	if err := validateContributionFilesV4(p.Output.Files, expected, 3); err != nil {
		return zero, err
	}
	return p.Output, nil
}

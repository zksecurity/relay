package transcript

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// These constants match proof-tool's V4 protocol, not the legacy sync limits.
const MaxCheckpointSequenceV4 = 16384

type DefinitionProtocol struct {
	Schema              string             `json:"schema"`
	DefinitionSchema    string             `json:"definition_schema"`
	StorageWorkflow     string             `json:"storage_workflow"`
	ReleaseVerification string             `json:"release_verification"`
	Definition          Definition         `json:"definition"`
	DefinitionRefs      SignedArtifactRefs `json:"definition_refs"`
}

func (p DefinitionProtocol) UsesV4() bool {
	return p.DefinitionSchema == "proof-tool-mpc-ceremony-definition-v4" && p.StorageWorkflow == "storage-first-v2" && p.ReleaseVerification == "coordinator-full-replay-v1"
}

// AuthenticateCheckpointForPublicationV4 verifies signed ancestry and asks
// proof-tool to prepare the exact proposal again. prepare-v4 checks the
// transition's evidence and replays contribution mathematics for acceptance
// edges. Relay may publish only when the checked bytes are identical.
func (i Inspector) AuthenticateCheckpointForPublicationV4(root, record, signature string) (CheckpointInspectionV4, error) {
	inspection, err := i.StoredCheckpointV4(root, record, signature)
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	temp, err := os.MkdirTemp(root, ".relay-v4-publication-check-")
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	defer os.RemoveAll(temp)
	checked := filepath.Join(temp, "checkpoint.json")
	result, err := i.execute(
		"checkpoint", "prepare-v4",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--artifact-root", root,
		"--proposal", record,
		"--out", checked,
	)
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	if result.Command != "checkpoint prepare-v4" {
		return CheckpointInspectionV4{}, errors.New("mpc-ceremony returned the wrong V4 checkpoint authentication result")
	}
	original, err := os.ReadFile(record)
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	prepared, err := os.ReadFile(checked)
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	if !bytes.Equal(original, prepared) {
		return CheckpointInspectionV4{}, errors.New("proof-tool checked different V4 checkpoint bytes")
	}
	return inspection, nil
}

// DefinitionProtocol never falls back after a failed inspection. Older pinned
// releases use their existing Definition method, selected before this call.
func (i Inspector) DefinitionProtocol() (DefinitionProtocol, error) {
	r, err := i.execute("inspect", "definition-protocol", "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath)
	if err != nil {
		return DefinitionProtocol{}, err
	}
	if r.Command != "inspect definition-protocol" || r.DefinitionProtocolInspection == nil {
		return DefinitionProtocol{}, errors.New("missing authenticated protocol inspection")
	}
	p := *r.DefinitionProtocolInspection
	if p.Schema != "proof-tool-mpc-definition-protocol-inspection-v1" {
		return DefinitionProtocol{}, errors.New("unsupported protocol inspection schema")
	}
	switch p.DefinitionSchema {
	case "proof-tool-mpc-ceremony-definition-v4":
		if !p.UsesV4() {
			return DefinitionProtocol{}, errors.New("inconsistent V4 protocol selector")
		}
		if err := validatePairV4(p.DefinitionRefs); err != nil {
			return DefinitionProtocol{}, fmt.Errorf("authenticated definition references: %w", err)
		}
		if p.DefinitionRefs.Record.Name != "ceremony.json" || p.DefinitionRefs.Signature.Name != "ceremony.sig" {
			return DefinitionProtocol{}, errors.New("unexpected authenticated definition reference names")
		}
	case "proof-tool-mpc-ceremony-definition-v1", "proof-tool-mpc-ceremony-definition-v2", "proof-tool-mpc-ceremony-definition-v3":
		if p.StorageWorkflow != "storage-first-v1" || p.ReleaseVerification != "" {
			return DefinitionProtocol{}, errors.New("inconsistent legacy protocol selector")
		}
	default:
		return DefinitionProtocol{}, errors.New("unsupported authenticated definition schema")
	}
	d := p.Definition
	if d.Schema != definitionInspectionSchema || !taggedHash(d.CeremonyID, "sha256:") || (d.Mode != "rehearsal" && d.Mode != "production") || len(d.Phase1Participants) == 0 || len(d.Phase2Participants) == 0 || d.Journey == nil {
		return DefinitionProtocol{}, errors.New("incomplete authenticated definition projection")
	}
	if err := validateRef(d.R1CSRef); err != nil {
		return DefinitionProtocol{}, err
	}
	if _, err := d.RequireJourney(); err != nil {
		return DefinitionProtocol{}, err
	}
	return p, nil
}

type CheckpointDiscoveryV4 struct {
	Schema    string `json:"schema"`
	Depth     string `json:"depth"`
	Discovery struct {
		CeremonyID               string              `json:"ceremony_id"`
		Sequence                 uint64              `json:"sequence"`
		PreviousCheckpoint       *SignedArtifactRefs `json:"previous_checkpoint,omitempty"`
		VerificationDependencies []ArtifactRef       `json:"verification_dependencies"`
		Enrollment               *SignedArtifactRefs `json:"enrollment,omitempty"`
	} `json:"discovery"`
	CheckpointRefs          SignedArtifactRefs `json:"checkpoint_refs"`
	AncestryVerified        bool               `json:"ancestry_verified"`
	ArtifactsVerified       bool               `json:"artifacts_verified"`
	MathematicsReplayed     bool               `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool               `json:"global_freshness_verified"`
}

type ContributionScopeV4 struct {
	CeremonyID    string `json:"ceremony_id"`
	Phase         string `json:"phase"`
	Index         uint8  `json:"index"`
	ParticipantID string `json:"participant_id"`
	ParentHeadID  string `json:"parent_head_id"`
}

type DeliverySlotV4 struct {
	Scope                ContributionScopeV4 `json:"scope"`
	Kind                 string              `json:"kind"`
	AttemptID            string              `json:"attempt_id"`
	Status               string              `json:"status"`
	ContributionResultID string              `json:"contribution_result_id,omitempty"`
}

type CheckpointProgressV4 struct {
	Phase1         CheckpointPhaseState  `json:"phase1"`
	Phase1Closure  *SignedArtifactRefs   `json:"phase1_closure,omitempty"`
	Phase1Beacon   *SignedArtifactRefs   `json:"phase1_beacon,omitempty"`
	Phase1Seal     *SignedArtifactRefs   `json:"phase1_seal,omitempty"`
	Phase2         *CheckpointPhaseState `json:"phase2,omitempty"`
	Phase2Closure  *SignedArtifactRefs   `json:"phase2_closure,omitempty"`
	Phase2Beacon   *SignedArtifactRefs   `json:"phase2_beacon,omitempty"`
	FinalCandidate *SignedArtifactRefs   `json:"final_candidate,omitempty"`
	ReleaseReview  *SignedArtifactRefs   `json:"release_review,omitempty"`
	FinalRelease   *SignedArtifactRefs   `json:"final_release,omitempty"`
	Terminal       *struct {
		Kind              string              `json:"kind"`
		Record            SignedArtifactRefs  `json:"record"`
		RestartDefinition *SignedArtifactRefs `json:"restart_definition,omitempty"`
	} `json:"terminal,omitempty"`
}

// This projection is parsed only from successful approved-tool output, never
// directly from a downloaded checkpoint. Fields not needed by Relay are omitted.
type CheckpointStateV4 struct {
	Schema              string              `json:"schema"`
	Workflow            string              `json:"workflow"`
	CeremonyID          string              `json:"ceremony_id"`
	ReleaseVerification string              `json:"release_verification"`
	Sequence            uint64              `json:"sequence"`
	Definition          SignedArtifactRefs  `json:"definition"`
	PreviousCheckpoint  *SignedArtifactRefs `json:"previous_checkpoint,omitempty"`
	Transition          struct {
		Kind string `json:"kind"`
	} `json:"transition"`
	Progress          CheckpointProgressV4 `json:"progress"`
	AcceptedArtifacts []ArtifactRef        `json:"accepted_artifacts"`
	Deliveries        []DeliverySlotV4     `json:"deliveries"`
}

type CheckpointInspectionV4 struct {
	Schema                  string                  `json:"schema"`
	Depth                   string                  `json:"depth"`
	Checkpoint              CheckpointStateV4       `json:"checkpoint"`
	CheckpointRefs          SignedArtifactRefs      `json:"checkpoint_refs"`
	Commitments             CheckpointCommitmentsV4 `json:"commitments"`
	ArtifactsVerified       bool                    `json:"artifacts_verified"`
	MathematicsReplayed     bool                    `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                    `json:"global_freshness_verified"`
}

// RequiredPublicArtifactsV4 returns the exact public files a normal role needs
// in addition to checkpoint ancestry. The set is derived only from an
// approved-tool inspection: callers must never manufacture it by parsing a
// downloaded checkpoint themselves.
//
// Historical contribution payloads are deliberately excluded. A current
// role needs the authenticated definition and current phase inputs, while the
// signed checkpoint ancestry retains the history needed for state guidance.
func RequiredPublicArtifactsV4(p CheckpointInspectionV4) ([]ArtifactRef, error) {
	if _, err := validateStoredInspectionV4(p); err != nil {
		return nil, err
	}
	refs := map[string]ArtifactRef{}
	add := func(ref ArtifactRef, limit int64) error {
		if err := validateBoundedRefV4(ref, limit); err != nil {
			return err
		}
		if previous, ok := refs[ref.Name]; ok && previous != ref {
			return errors.New("authenticated public artifact name has conflicting references")
		}
		refs[ref.Name] = ref
		return nil
	}
	addPair := func(pair *SignedArtifactRefs) error {
		if pair == nil {
			return nil
		}
		if err := add(pair.Record, 16<<20); err != nil {
			return err
		}
		return add(pair.Signature, 4096)
	}
	if err := addPair(&p.Checkpoint.Definition); err != nil {
		return nil, err
	}
	if p.Checkpoint.Progress.ReleaseReview != nil {
		// At review time the authenticated accepted-artifact inventory names
		// every public dependency. Historical replay payloads are deliberately
		// omitted because the release signer verifies the coordinator's bound
		// replay claim instead of repeating contribution mathematics.
		for _, ref := range p.Checkpoint.AcceptedArtifacts {
			if historicalReplayPayloadV4(ref.Name) {
				continue
			}
			if err := add(ref, 16<<30); err != nil {
				return nil, err
			}
		}
	} else {
		phases := []*CheckpointPhaseState{&p.Checkpoint.Progress.Phase1, p.Checkpoint.Progress.Phase2}
		for _, phase := range phases {
			if phase == nil {
				continue
			}
			if err := addPair(&phase.Chain); err != nil {
				return nil, err
			}
			if err := add(phase.HeadPayload, 16<<30); err != nil {
				return nil, err
			}
		}
	}
	for _, pair := range []*SignedArtifactRefs{
		p.Checkpoint.Progress.Phase1Closure,
		p.Checkpoint.Progress.Phase1Beacon,
		p.Checkpoint.Progress.Phase1Seal,
		p.Checkpoint.Progress.Phase2Closure,
		p.Checkpoint.Progress.Phase2Beacon,
		p.Checkpoint.Progress.FinalCandidate,
		p.Checkpoint.Progress.ReleaseReview,
		p.Checkpoint.Progress.FinalRelease,
	} {
		if err := addPair(pair); err != nil {
			return nil, err
		}
	}
	for _, ref := range p.Commitments.FinalReleaseArtifacts {
		if err := add(ref, 16<<30); err != nil {
			return nil, err
		}
	}
	if terminal := p.Checkpoint.Progress.Terminal; terminal != nil {
		if err := addPair(&terminal.Record); err != nil {
			return nil, err
		}
		if err := addPair(terminal.RestartDefinition); err != nil {
			return nil, err
		}
	}
	result := make([]ArtifactRef, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref)
	}
	slices.SortFunc(result, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}

func historicalReplayPayloadV4(name string) bool {
	if name == "phase1/genesis.bin" || name == "phase2/genesis.bin" {
		return true
	}
	return (strings.HasPrefix(name, "phase1/contributions/") || strings.HasPrefix(name, "phase2/contributions/")) && strings.HasSuffix(name, "/contribution.bin")
}

func (i Inspector) checkpointV4(action, root, record, signature string) (inspectionResult, error) {
	return i.execute("checkpoint", action, "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath, "--artifact-root", root, "--checkpoint", record, "--checkpoint-signature", signature)
}

func (i Inspector) DiscoverCheckpointV4(root, record, signature string) (CheckpointDiscoveryV4, error) {
	r, err := i.checkpointV4("inspect-signed-v4", root, record, signature)
	if err != nil {
		return CheckpointDiscoveryV4{}, err
	}
	if r.Command != "checkpoint inspect-signed-v4" || r.CheckpointDiscoveryV4 == nil {
		return CheckpointDiscoveryV4{}, errors.New("missing signed checkpoint discovery")
	}
	p := *r.CheckpointDiscoveryV4
	if p.Schema != "proof-tool-mpc-checkpoint-discovery-v4" || p.Depth != "signed-checkpoint-discovery" || p.AncestryVerified || p.ArtifactsVerified || p.MathematicsReplayed || p.GlobalFreshnessVerified {
		return CheckpointDiscoveryV4{}, errors.New("invalid checkpoint discovery boundary")
	}
	if err := validateCheckpointMetadataV4(p.Discovery.CeremonyID, p.Discovery.Sequence, p.CheckpointRefs, p.Discovery.PreviousCheckpoint); err != nil {
		return CheckpointDiscoveryV4{}, err
	}
	deps := p.Discovery.VerificationDependencies
	if deps == nil || len(deps) > 5 {
		return CheckpointDiscoveryV4{}, errors.New("invalid discovery dependencies")
	}
	for _, ref := range deps {
		if err := validateBoundedRefV4(ref, 16<<20); err != nil {
			return CheckpointDiscoveryV4{}, err
		}
	}
	if p.Discovery.Enrollment != nil {
		if err := validatePairV4(*p.Discovery.Enrollment); err != nil {
			return CheckpointDiscoveryV4{}, err
		}
	}
	return p, nil
}

func (i Inspector) StoredCheckpointV4(root, record, signature string) (CheckpointInspectionV4, error) {
	r, err := i.checkpointV4("verify-stored-v4", root, record, signature)
	if err != nil {
		return CheckpointInspectionV4{}, err
	}
	if r.Command != "checkpoint verify-stored-v4" || r.CheckpointInspectionV4 == nil {
		return CheckpointInspectionV4{}, errors.New("missing verified checkpoint ancestry")
	}
	return validateStoredInspectionV4(*r.CheckpointInspectionV4)
}

func validateStoredInspectionV4(p CheckpointInspectionV4) (CheckpointInspectionV4, error) {
	c := p.Checkpoint
	if p.Schema != "proof-tool-mpc-checkpoint-inspection-v4" || p.Depth != "checkpoint-structure" || p.ArtifactsVerified || p.MathematicsReplayed || p.GlobalFreshnessVerified || c.Schema != "proof-tool-mpc-checkpoint-v4" || c.Workflow != "storage-first-v2" || c.ReleaseVerification != "coordinator-full-replay-v1" {
		return CheckpointInspectionV4{}, errors.New("invalid checkpoint verification boundary")
	}
	if err := validateCheckpointMetadataV4(c.CeremonyID, c.Sequence, p.CheckpointRefs, c.PreviousCheckpoint); err != nil {
		return CheckpointInspectionV4{}, err
	}
	if err := validatePairV4(c.Definition); err != nil {
		return CheckpointInspectionV4{}, err
	}
	if c.Deliveries == nil || len(c.Deliveries) > 4096 {
		return CheckpointInspectionV4{}, errors.New("invalid delivery projection")
	}
	if err := validateProgressV4(c); err != nil {
		return CheckpointInspectionV4{}, err
	}
	if err := validateCommitmentsV4(c, p.Commitments); err != nil {
		return CheckpointInspectionV4{}, err
	}
	return p, nil
}

// These are projection-shape checks, not a second implementation of legal
// ceremony transitions. Proof-tool remains the authority for that validation.
func validateProgressV4(c CheckpointStateV4) error {
	phase := func(p CheckpointPhaseState, want string) error {
		if p.Phase != want || p.AcceptedCount > 20 || !taggedHash(p.HeadRecordID, "sha256:") {
			return errors.New("invalid phase progress projection")
		}
		if err := validatePairV4(p.Chain); err != nil {
			return err
		}
		return validateBoundedRefV4(p.HeadPayload, 16<<30)
	}
	p := c.Progress
	if c.AcceptedArtifacts == nil || len(c.AcceptedArtifacts) > 2048 {
		return errors.New("invalid accepted artifact projection")
	}
	for index, ref := range c.AcceptedArtifacts {
		if err := validateBoundedRefV4(ref, 16<<30); err != nil {
			return err
		}
		if index > 0 && c.AcceptedArtifacts[index-1].Name >= ref.Name {
			return errors.New("accepted artifact projection must be sorted and unique")
		}
	}
	if err := phase(p.Phase1, "phase1"); err != nil {
		return err
	}
	if p.Phase2 != nil {
		if err := phase(*p.Phase2, "phase2"); err != nil {
			return err
		}
	}
	for _, pair := range []*SignedArtifactRefs{p.Phase1Closure, p.Phase1Beacon, p.Phase1Seal, p.Phase2Closure, p.Phase2Beacon, p.FinalCandidate, p.ReleaseReview, p.FinalRelease} {
		if pair != nil {
			if err := validatePairV4(*pair); err != nil {
				return err
			}
		}
	}
	if terminal := p.Terminal; terminal != nil {
		if (terminal.Kind != "abort" && terminal.Kind != "restart") || (terminal.Kind == "restart") != (terminal.RestartDefinition != nil) || p.FinalRelease != nil {
			return errors.New("invalid terminal progress projection")
		}
		if err := validatePairV4(terminal.Record); err != nil {
			return err
		}
		if terminal.RestartDefinition != nil {
			if err := validatePairV4(*terminal.RestartDefinition); err != nil {
				return err
			}
		}
	}
	seen := map[string]bool{}
	for _, slot := range c.Deliveries {
		s := slot.Scope
		if s.CeremonyID != c.CeremonyID || (s.Phase != "phase1" && s.Phase != "phase2") || s.Index == 0 || s.Index > 20 || s.ParticipantID == "" || !taggedHash(s.ParentHeadID, "sha256:") {
			return errors.New("invalid delivery scope projection")
		}
		if len(slot.AttemptID) != 32 || strings.ToLower(slot.AttemptID) != slot.AttemptID {
			return errors.New("invalid delivery attempt projection")
		}
		if _, err := hex.DecodeString(slot.AttemptID); err != nil {
			return err
		}
		if seen[slot.AttemptID] {
			return errors.New("duplicate delivery attempt projection")
		}
		seen[slot.AttemptID] = true
		if slot.Kind != "candidate" {
			return errors.New("invalid delivery kind projection")
		}
		switch slot.Status {
		case "allocated", "retired":
			if slot.ContributionResultID != "" {
				return errors.New("unaccepted delivery claims a candidate result")
			}
		case "accepted", "rejected":
			if !taggedHash(slot.ContributionResultID, "sha256:") {
				return errors.New("missing candidate disposition identity")
			}
		default:
			return errors.New("invalid delivery status projection")
		}
	}
	return nil
}

func taggedHash(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func validateBoundedRefV4(ref ArtifactRef, limit int64) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	if !taggedHash(ref.Digest.SHA256, "sha256:") || !taggedHash(ref.Digest.Blake2b256, "blake2b256:") || ref.Digest.Size <= 0 || ref.Digest.Size > limit {
		return fmt.Errorf("invalid bounded artifact reference %q", ref.Name)
	}
	return nil
}

func validatePairV4(pair SignedArtifactRefs) error {
	if pair.Record.Name == pair.Signature.Name {
		return errors.New("record and signature names coincide")
	}
	if err := validateBoundedRefV4(pair.Record, 16<<20); err != nil {
		return err
	}
	return validateBoundedRefV4(pair.Signature, 4096)
}

func validateCheckpointMetadataV4(id string, sequence uint64, pair SignedArtifactRefs, previous *SignedArtifactRefs) error {
	if !taggedHash(id, "sha256:") || sequence > MaxCheckpointSequenceV4 || (sequence == 0) != (previous == nil) {
		return errors.New("invalid checkpoint identity or ancestry metadata")
	}
	if err := validatePairV4(pair); err != nil {
		return err
	}
	if previous != nil {
		return validatePairV4(*previous)
	}
	return nil
}

package storagefirst

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zksecurity/relay/internal/transcript"
)

// ReceivedOutboundV4 describes SHA-256/size-checked receipt inputs, not a signed
// receipt or a computation-ready transcript. The caller retains Root and passes
// its named files to proof-tool, which checks signatures and both signed digests
// before preparing/signing a receipt. No persistent completion flag is created.
type ReceivedOutboundV4 struct {
	Root        string
	Scope       transcript.ContributionScopeV4
	AttemptID   string
	Predecessor transcript.SignedArtifactRefs
	Handoff     transcript.SignedArtifactRefs
	Files       []transcript.ArtifactRef
}

func (s SnapshotV4) FetchOutboundV4(objects ObjectStore, protocol transcript.DefinitionProtocol, phase, identity, parent string) (result ReceivedOutboundV4, err error) {
	if objects == nil || identity == "" {
		return result, errors.New("participant and public object store required")
	}
	view, err := s.TurnV4(protocol, phase, identity)
	if err != nil {
		return result, err
	}
	if view.Stage != TurnReceiptV4 || view.ReceiptAttempt == nil || view.Commitment == nil || len(view.Commitment.Outbounds) == 0 {
		return result, errors.New("no active input-packet delivery for this participant")
	}
	c, err := s.State()
	if err != nil {
		return result, err
	}
	if c.Definition != protocol.DefinitionRefs {
		return result, errors.New("backend and authenticated definition references differ")
	}
	progress := c.Progress.Phase1
	if phase == "phase2" {
		if c.Progress.Phase2 == nil {
			return result, errors.New("Phase 2 has not started")
		}
		progress = *c.Progress.Phase2
	}
	handoff := view.Commitment.Outbounds[0].Pair
	refs := []transcript.ArtifactRef{c.Definition.Record, c.Definition.Signature, progress.Chain.Record, progress.Chain.Signature, handoff.Record, handoff.Signature, progress.HeadPayload}
	// Validate the entire named set before any fetch. Only the signed current
	// head may use the large-payload bound; metadata remains small.
	seen := map[string]bool{}
	for _, ref := range refs {
		limit := int64(16 << 20)
		if ref == progress.HeadPayload {
			limit = 16 << 30
		} else if ref == c.Definition.Signature || ref == progress.Chain.Signature || ref == handoff.Signature {
			limit = 4096
		}
		if err := transcript.ValidateName(ref.Name); err != nil {
			return result, err
		}
		if seen[ref.Name] || !validDigest(ref.Digest.SHA256) || !strings.HasPrefix(ref.Digest.Blake2b256, "blake2b256:") || !validDigest(strings.Replace(ref.Digest.Blake2b256, "blake2b256:", "sha256:", 1)) || ref.Digest.Size <= 0 || ref.Digest.Size > limit {
			return result, errors.New("invalid, duplicate or oversized outbound input reference")
		}
		seen[ref.Name] = true
	}
	root, err := os.MkdirTemp(parent, "received-turn-")
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()
	names := fetchedNames{}
	for _, ref := range refs {
		if _, err = fetchNamed(objects, root, contentRef(ref), names); err != nil {
			return result, fmt.Errorf("download turn input %s: %w", ref.Name, err)
		}
	}
	return ReceivedOutboundV4{Root: root, Scope: view.Scope, AttemptID: view.ReceiptAttempt.AttemptID, Predecessor: progress.Chain, Handoff: handoff, Files: refs}, nil
}

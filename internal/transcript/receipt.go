package transcript

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// MirrorReceiptDraft is the operator-authored form of the ceremony's
// ImmutableMirrorReceipt, before it is canonicalized and signed.
//
// This is deliberately a draft, not a finished record. The ceremony encodes its
// records as canonical JSON with an exact field order and no trailing newline,
// and reproducing that encoding here would mean maintaining a second
// implementation of a format whose whole purpose is that there is exactly one.
// Instead the draft is handed to the ceremony CLI:
//
//	mpc-ceremony ops export-signing --record-type mirror-receipt --record draft.json ...
//
// which canonicalizes it, and the mirror operator signs the canonical bytes
// offline. Field order below matches the ceremony struct so the draft reads the
// same as the record it becomes.
type MirrorReceiptDraft struct {
	CeremonyID            string        `json:"ceremony_id"`
	Phase                 string        `json:"phase"`
	Index                 uint8         `json:"index"`
	AcceptedHeadID        string        `json:"accepted_head_id"`
	Files                 []ArtifactRef `json:"files"`
	StorageLocationSHA256 string        `json:"storage_location_sha256"`
	StoredAt              string        `json:"stored_at"`
}

// MirrorReceiptFiles returns the exact file set a mirror receipt must list for
// one accepted head.
//
// The ceremony compares this with slices.Equal against its own computed set, so
// a missing, extra or misordered entry fails verification. The composition is
// the accepted contribution evidence, plus the verification record, plus the
// accepted chain prefix and its signature, sorted by logical name.
func MirrorReceiptFiles(record ChainRecordRefs, chainPrefix, chainPrefixSignature ArtifactRef) []ArtifactRef {
	files := []ArtifactRef{
		record.Attestation,
		record.AttestationSignature,
		record.Erasure,
		record.ErasureSignature,
		record.OutputPayload,
		record.Verification,
		chainPrefix,
		chainPrefixSignature,
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files
}

// ChainRecordRefs is the artifact set of one accepted contribution.
type ChainRecordRefs struct {
	OutputPayload        ArtifactRef
	Attestation          ArtifactRef
	AttestationSignature ArtifactRef
	Erasure              ArtifactRef
	ErasureSignature     ArtifactRef
	Verification         ArtifactRef
}

// RecordAt returns the artifact set of the one-based accepted contribution at
// index, along with the head record id the receipt must bind.
func (c Chain) RecordAt(index int) (ChainRecordRefs, string, error) {
	if index < 1 || index > len(c.records) {
		return ChainRecordRefs{}, "", fmt.Errorf("accepted head %d is out of range 1..%d", index, len(c.records))
	}
	r := c.records[index-1]
	return ChainRecordRefs{
		OutputPayload:        r.OutputPayload,
		Attestation:          r.Attestation,
		AttestationSignature: r.AttestationSignature,
		Erasure:              r.Erasure,
		ErasureSignature:     r.ErasureSignature,
		Verification:         r.Verification,
	}, r.RecordID, nil
}

// Encode renders the draft as indented JSON. Indentation is intentional: this
// is a human-reviewable draft, and the ceremony CLI canonicalizes it before
// anyone signs anything.
func (d MirrorReceiptDraft) Encode() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// ChainPrefixRefs returns the accepted chain document and its signature as
// artifact references, digested from the local files.
//
// Nothing inside the transcript names the chain, so unlike every other
// reference in a mirror receipt these digests are computed here rather than
// read from a signed document. The ceremony recomputes them the same way when
// it verifies the receipt.
func ChainPrefixRefs(chain Chain) (ArtifactRef, ArtifactRef, error) {
	root, err := chainRoot(chain)
	if err != nil {
		return ArtifactRef{}, ArtifactRef{}, err
	}
	recordName, err := logicalName(root, chain.ChainPath)
	if err != nil {
		return ArtifactRef{}, ArtifactRef{}, err
	}
	signatureName := strings.TrimSuffix(recordName, ".json") + ".sig"

	refs := make([]ArtifactRef, 0, 2)
	for _, name := range []string{recordName, signatureName} {
		full, err := Resolve(root, name)
		if err != nil {
			return ArtifactRef{}, ArtifactRef{}, err
		}
		sum, size, err := DigestFile(full)
		if err != nil {
			return ArtifactRef{}, ArtifactRef{}, err
		}
		refs = append(refs, ArtifactRef{Name: name, Digest: Digest{SHA256: sum, Size: size}})
	}
	return refs[0], refs[1], nil
}

// chainRoot recovers the transcript root from the chain document's own path.
// A chain always lives at <root>/phase{1,2}/chain-NNNN.json.
func chainRoot(chain Chain) (string, error) {
	dir := filepath.Dir(filepath.Dir(chain.ChainPath))
	if dir == "" || dir == "." {
		return "", fmt.Errorf("cannot derive the transcript root from chain path %q", chain.ChainPath)
	}
	return dir, nil
}

// TaggedSHA256 returns the ceremony's tagged hash form for arbitrary bytes.
func TaggedSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Package transcript reads the artifact references out of an MPC ceremony
// chain document.
//
// This is an intentionally independent reimplementation. It does not import
// anything from the proof-tool module, both because Go forbids importing
// another module's internal packages and because an independent parser is
// better audit evidence: if this tool and the ceremony CLI agree on a digest,
// two implementations agree; if they diverge, that is a finding.
//
// It reads only. It performs no signature verification: authenticity of the
// chain document is established by the ceremony CLI, which holds the
// coordinator public key obtained out of band. This package assumes the caller
// already trusts the chain it was handed, and concerns itself only with which
// artifacts that chain names and what they must hash to.
package transcript

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Digest mirrors the ceremony's artifact digest. Both hashes and the size are
// compared, so a collision in one function alone is not sufficient.
type Digest struct {
	SHA256     string `json:"sha256"`
	Blake2b256 string `json:"blake2b256"`
	Size       int64  `json:"size"`
}

// ArtifactRef is a logical name inside the transcript root plus the digest the
// bytes at that name must have.
type ArtifactRef struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

// chainRecord mirrors the ceremony's full record schema. Every field must be
// declared even though this tool reads only the artifact references, because
// decoding rejects unknown fields: a field the ceremony writes and this struct
// omits would make every real chain unreadable.
type chainRecord struct {
	Schema               string      `json:"schema"`
	RecordID             string      `json:"record_id"`
	CeremonyID           string      `json:"ceremony_id"`
	Phase                string      `json:"phase"`
	PhaseID              string      `json:"phase_id"`
	Index                uint8       `json:"index"`
	ParticipantID        string      `json:"participant_id"`
	PreviousPayload      ArtifactRef `json:"previous_payload"`
	OutputPayload        ArtifactRef `json:"output_payload"`
	AttestationID        string      `json:"attestation_id"`
	Attestation          ArtifactRef `json:"attestation"`
	AttestationSignature ArtifactRef `json:"attestation_signature"`
	ErasureID            string      `json:"erasure_id"`
	Erasure              ArtifactRef `json:"erasure"`
	ErasureSignature     ArtifactRef `json:"erasure_signature"`
	Verification         ArtifactRef `json:"verification"`
	PreviousRecordID     string      `json:"previous_record_id"`
	CoordinatorID        string      `json:"coordinator_id"`
	CoordinatorKeyID     string      `json:"coordinator_key_id"`
	AcceptedAt           string      `json:"accepted_at"`
}

type chain struct {
	Schema     string        `json:"schema"`
	CeremonyID string        `json:"ceremony_id"`
	Phase      string        `json:"phase"`
	PhaseID    string        `json:"phase_id"`
	Genesis    ArtifactRef   `json:"genesis"`
	Records    []chainRecord `json:"records"`
}

// Chain is the parsed view this tool needs: which artifacts exist and what
// they must hash to.
//
// Artifacts covers only what the chain document names. Phase-ending records are
// unreachable from here by design: a closure names the chain head it seals, not
// the reverse, so the reference runs backwards and cannot be followed forwards.
// TranscriptFiles adds them from the known layout.
type Chain struct {
	CeremonyID string
	Phase      string
	ChainPath  string
	Artifacts  []ArtifactRef

	// records is retained so a mirror receipt can be drafted for one accepted
	// head without re-reading and re-parsing the chain.
	records []chainRecord
}

const maxChainBytes = 1 << 20

// LoadChain reads a coordinator-signed chain document and returns every
// artifact it names, in a stable order.
//
// Minimal by design: it covers the genesis payload and each accepted
// contribution's payload, attestation, erasure statement and verification
// record. Closure, beacon and seal records are named in separate documents and
// are not walked yet.
func LoadChain(chainPath string) (Chain, error) {
	raw, err := readRegularBounded(chainPath, maxChainBytes)
	if err != nil {
		return Chain{}, err
	}

	// Reject unknown fields and trailing data. The ceremony writes canonical
	// JSON; anything else did not come from it.
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var parsed chain
	if err := decoder.Decode(&parsed); err != nil {
		return Chain{}, fmt.Errorf("decode chain %s: %w", chainPath, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Chain{}, fmt.Errorf("chain %s has trailing data", chainPath)
	}

	if parsed.CeremonyID == "" || parsed.Phase == "" {
		return Chain{}, fmt.Errorf("chain %s is missing ceremony_id or phase", chainPath)
	}

	result := Chain{CeremonyID: parsed.CeremonyID, Phase: parsed.Phase, ChainPath: chainPath}
	add := func(ref ArtifactRef) error {
		if err := validateRef(ref); err != nil {
			return err
		}
		result.Artifacts = append(result.Artifacts, ref)
		return nil
	}
	if err := add(parsed.Genesis); err != nil {
		return Chain{}, fmt.Errorf("genesis: %w", err)
	}
	for index, record := range parsed.Records {
		for label, ref := range map[string]ArtifactRef{
			"output_payload":        record.OutputPayload,
			"attestation":           record.Attestation,
			"attestation_signature": record.AttestationSignature,
			"erasure":               record.Erasure,
			"erasure_signature":     record.ErasureSignature,
			"verification":          record.Verification,
		} {
			if err := add(ref); err != nil {
				return Chain{}, fmt.Errorf("record %d %s: %w", index+1, label, err)
			}
		}
	}
	result.records = parsed.Records
	return result, nil
}

func validateRef(ref ArtifactRef) error {
	if err := ValidateName(ref.Name); err != nil {
		return err
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(ref.Digest.SHA256, "sha256:")); err != nil {
		return fmt.Errorf("artifact %q sha256 is not hex", ref.Name)
	}
	if len(strings.TrimPrefix(ref.Digest.SHA256, "sha256:")) != 64 {
		return fmt.Errorf("artifact %q sha256 is not 32 bytes", ref.Name)
	}
	if ref.Digest.Size < 0 {
		return fmt.Errorf("artifact %q has negative size", ref.Name)
	}
	return nil
}

// ValidateName enforces the same rule the ceremony does: a clean relative
// logical path. Without this an artifact name could escape the transcript root
// or, on the upload side, be used to write outside the intended key prefix.
func ValidateName(name string) error {
	if name == "" || len(name) > 512 {
		return errors.New("artifact name must be 1 to 512 bytes")
	}
	// path.Clean leaves a leading ".." intact, so it must be rejected
	// explicitly: "../x" is clean and relative but escapes the root.
	if strings.Contains(name, `\`) || strings.HasPrefix(name, "/") ||
		path.Clean(name) != name || name == "." ||
		name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("artifact name %q must be a clean relative logical path", name)
	}
	return nil
}

// Resolve joins a logical artifact name to a local root and confirms the
// result stays inside it.
func Resolve(root, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(name))
	rel, err := filepath.Rel(rootAbs, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact %q escapes the transcript root", name)
	}
	return full, nil
}

// DigestFile returns the tagged SHA-256 and byte length of a local file.
func DigestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

func readRegularBounded(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, over the %d limit", path, info.Size(), max)
	}
	return os.ReadFile(path)
}

// AcceptedCount returns how many contributions the chain has accepted. This is
// counted from the chain itself rather than taken from any pointer or claim.
func (c Chain) AcceptedCount() int { return len(c.records) }

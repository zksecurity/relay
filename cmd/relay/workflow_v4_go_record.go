package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

const workflowV4GoPublicationSchema = "relay-go-publication-v1"
const workflowV4GoPublicationDomain = "relay-go-publication-v1\n"

// The fixed pointer selects at most one approved release for a ceremony.
// The coordinator signs the exact destination and archive bytes. Proof-tool
// continues to verify the underlying GO decision and its required signers.
type workflowV4GoPublication struct {
	Schema           string `json:"schema"`
	CeremonyID       string `json:"ceremony_id"`
	CheckpointSHA256 string `json:"checkpoint_sha256"`
	DecisionSHA256   string `json:"decision_sha256"`
	ReleaseID        string `json:"release_id"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ArchiveKey       string `json:"archive_key"`
	PointerKey       string `json:"pointer_key"`
	PublishedBucket  string `json:"published_bucket"`
	PublishedBaseURL string `json:"published_base_url"`
}

type workflowV4SignedGoPublication struct {
	Record       workflowV4GoPublication `json:"record"`
	SignatureHex string                  `json:"signature_hex"`
}

func workflowV4GoPointerKey(ceremonyID string) string {
	return "approved/" + strings.TrimPrefix(ceremonyID, "sha256:") + "/release.json"
}

func (r workflowV4GoPublication) validate() error {
	if r.Schema != workflowV4GoPublicationSchema || !strings.HasPrefix(r.CeremonyID, "sha256:") || !sha256HexPattern.MatchString(strings.TrimPrefix(r.CeremonyID, "sha256:")) {
		return errors.New("invalid GO publication schema or ceremony")
	}
	for _, value := range []string{r.CheckpointSHA256, r.DecisionSHA256, r.ArchiveSHA256} {
		if !sha256HexPattern.MatchString(value) {
			return errors.New("invalid GO publication digest")
		}
	}
	if !strings.HasPrefix(r.ReleaseID, "sha256:") || !sha256HexPattern.MatchString(strings.TrimPrefix(r.ReleaseID, "sha256:")) || r.PointerKey != workflowV4GoPointerKey(r.CeremonyID) || r.ArchiveKey != path.Join(path.Dir(r.PointerKey), "archives", r.ArchiveSHA256, "ceremony.zip") {
		return errors.New("GO publication does not bind the final release or fixed destination")
	}
	if r.PublishedBucket == "" || len(r.PublishedBucket) > 255 || strings.ContainsAny(r.PublishedBucket, "/\\ \r\n") || validateStorageFirstOrigin("GO publication origin", r.PublishedBaseURL) != nil {
		return errors.New("invalid GO publication storage destination")
	}
	return nil
}

func workflowV4SignGoPublication(record workflowV4GoPublication, seed, trustedKey []byte) ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize || len(trustedKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid coordinator signing key or trust anchor")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer zeroTessera(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), trustedKey) {
		return nil, errors.New("coordinator signing key differs from the authenticated trust anchor")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(private, append([]byte(workflowV4GoPublicationDomain), raw...))
	return json.Marshal(workflowV4SignedGoPublication{Record: record, SignatureHex: hex.EncodeToString(signature)})
}

func workflowV4VerifyGoPublication(raw, trustedKey []byte) (workflowV4GoPublication, error) {
	var signed workflowV4SignedGoPublication
	if len(raw) > 16<<20 || json.Unmarshal(raw, &signed) != nil {
		return workflowV4GoPublication{}, errors.New("invalid GO publication record")
	}
	if err := signed.Record.validate(); err != nil {
		return workflowV4GoPublication{}, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return workflowV4GoPublication{}, errors.New("GO publication record is not canonical")
	}
	signature, err := hex.DecodeString(signed.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || len(trustedKey) != ed25519.PublicKeySize {
		return workflowV4GoPublication{}, errors.New("invalid GO publication signature")
	}
	recordBytes, err := json.Marshal(signed.Record)
	if err != nil {
		return workflowV4GoPublication{}, err
	}
	if !ed25519.Verify(trustedKey, append([]byte(workflowV4GoPublicationDomain), recordBytes...), signature) {
		return workflowV4GoPublication{}, errors.New("GO publication signature does not match the trusted coordinator")
	}
	return signed.Record, nil
}

func workflowV4GoPublicationFor(ceremonyID, checkpointSHA, decisionSHA, releaseID, archiveSHA, bucket, baseURL string) workflowV4GoPublication {
	pointer := workflowV4GoPointerKey(ceremonyID)
	return workflowV4GoPublication{Schema: workflowV4GoPublicationSchema, CeremonyID: ceremonyID, CheckpointSHA256: strings.TrimPrefix(checkpointSHA, "sha256:"), DecisionSHA256: decisionSHA, ReleaseID: releaseID, ArchiveSHA256: archiveSHA, ArchiveKey: path.Join(path.Dir(pointer), "archives", archiveSHA, "ceremony.zip"), PointerKey: pointer, PublishedBucket: bucket, PublishedBaseURL: baseURL}
}

func workflowV4DigestBytes(raw []byte) string {
	h := sha256.Sum256(raw)
	return fmt.Sprintf("%x", h[:])
}

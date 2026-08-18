// Package transcript handles local paths and artifact projections returned by
// the trusted mpc-ceremony inspection commands.
package transcript

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Digest is the transport view emitted by mpc-ceremony inspect.
type Digest struct {
	SHA256     string `json:"sha256"`
	Blake2b256 string `json:"blake2b256"`
	Size       int64  `json:"size"`
}

// ArtifactRef is a validated logical name and digest emitted by mpc-ceremony.
type ArtifactRef struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

type ChainRecord struct {
	Index         uint8         `json:"index"`
	RecordID      string        `json:"record_id"`
	ParticipantID string        `json:"participant_id"`
	Artifacts     []ArtifactRef `json:"artifacts"`
}

// Chain is the parsed view this tool needs: which artifacts exist and what
// they must hash to.
//
// Artifacts covers only what the chain document names. Phase-ending records are
// unreachable from here by design: a closure names the chain head it seals, not
// the reverse, so the reference runs backwards and cannot be followed forwards.
// TranscriptFiles adds them from the known layout.
type Chain struct {
	Schema             string        `json:"schema"`
	CeremonyID         string        `json:"ceremony_id"`
	Phase              string        `json:"phase"`
	ChainPath          string        `json:"-"`
	ChainSignaturePath string        `json:"-"`
	Artifacts          []ArtifactRef `json:"artifacts"`
	Records            []ChainRecord `json:"records"`
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

// AcceptedCount returns how many contributions the chain has accepted. This is
// counted from the chain itself rather than taken from any pointer or claim.
func (c Chain) AcceptedCount() int { return len(c.Records) }

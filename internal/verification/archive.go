// Package verification defines the public, data-only ceremony archive.
package verification

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zksecurity/relay/internal/access"
)

const Schema = "ceremony-verification-v1"
const MaxManifest = 16 << 20
const MaxFiles = 100000

var safeName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]*$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var RequiredInputs = []string{"ceremony", "ceremony-signature", "coordinator-public-key-file", "transcript-root", "phase1-chain", "phase1-chain-signature", "phase1-close", "phase1-close-signature", "phase1-beacon", "phase1-beacon-signature", "phase1-seal", "phase1-seal-signature", "phase2-chain", "phase2-chain-signature", "phase2-close", "phase2-close-signature", "phase2-beacon", "phase2-beacon-signature", "keys-dir", "manifest-public-key-file"}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Decision struct {
	Record       string   `json:"record"`
	Signatures   []string `json:"signatures"`
	EvidenceRoot string   `json:"evidence_root"`
}
type Manifest struct {
	ReleaseKeyID     string            `json:"release_key_id"`
	Schema           string            `json:"schema"`
	CeremonyID       string            `json:"ceremony_id"`
	DefinitionSHA256 string            `json:"definition_sha256"`
	Inputs           map[string]string `json:"inputs"`
	Decision         *Decision         `json:"decision"`
	Files            []File            `json:"files"`
}

func SafePath(name string) bool {
	if len(name) > 512 || !safeName.MatchString(name) || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || strings.HasSuffix(part, ".") {
			return false
		}
	}
	return true
}
func Parse(raw []byte) (Manifest, error) {
	if len(raw) > MaxManifest {
		return Manifest{}, errors.New("verification manifest exceeds 16 MiB")
	}
	if !utf8.Valid(raw) {
		return Manifest{}, errors.New("manifest must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
			if depth > 16 {
				return Manifest{}, errors.New("manifest nesting exceeds 16")
			}
		}
	}
	return access.Decode(raw, func(m Manifest) error { return m.Validate() })
}
func (m Manifest) Validate() error {
	if len(m.ReleaseKeyID) == 0 || len(m.ReleaseKeyID) > 128 {
		return errors.New("invalid release key ID")
	}
	if m.Schema != Schema || !strings.HasPrefix(m.CeremonyID, "sha256:") || !digest.MatchString(strings.TrimPrefix(m.CeremonyID, "sha256:")) || !digest.MatchString(m.DefinitionSHA256) {
		return errors.New("invalid verification schema or ceremony identity")
	}
	if len(m.Files) == 0 || len(m.Files) > MaxFiles {
		return errors.New("invalid file inventory size")
	}
	inventory := map[string]bool{}
	folded := map[string]bool{}
	for _, f := range m.Files {
		lower := strings.ToLower(f.Path)
		if !SafePath(f.Path) || lower == "verification.json" || inventory[f.Path] || folded[lower] || f.Size < 0 || !digest.MatchString(f.SHA256) {
			return fmt.Errorf("invalid or duplicate inventory file %q", f.Path)
		}
		inventory[f.Path] = true
		folded[lower] = true
	}
	for name := range inventory {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if folded[strings.ToLower(parent)] {
				return errors.New("inventory contains file/directory collision")
			}
		}
	}
	check := func(name string, dir bool) error {
		if !SafePath(name) {
			return fmt.Errorf("unsafe input path %q", name)
		}
		if dir {
			for f := range inventory {
				if strings.HasPrefix(f, name+"/") {
					return nil
				}
			}
		} else if inventory[name] {
			return nil
		}
		return fmt.Errorf("missing evidence in inventory: %s", name)
	}
	if len(m.Inputs) != len(RequiredInputs) {
		return errors.New("input map must contain only the required data paths")
	}
	for _, key := range RequiredInputs {
		if err := check(m.Inputs[key], key == "transcript-root" || key == "keys-dir"); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	for _, f := range m.Files {
		if f.Path == m.Inputs["ceremony"] && f.SHA256 != m.DefinitionSHA256 {
			return errors.New("definition digest differs from inventory")
		}
	}
	if m.Decision != nil {
		if err := check(m.Decision.Record, false); err != nil {
			return err
		}
		if err := check(m.Decision.EvidenceRoot, true); err != nil {
			return err
		}
		if len(m.Decision.Signatures) == 0 || len(m.Decision.Signatures) > 64 {
			return errors.New("invalid decision signature count")
		}
		seen := map[string]bool{}
		for _, s := range m.Decision.Signatures {
			if seen[s] {
				return errors.New("duplicate decision signature")
			}
			seen[s] = true
			if err := check(s, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// Extract creates a private temporary tree and never writes into the caller's
// workspace. It checks the complete inventory before any verifier is invoked.
func Extract(archive string, maxBytes int64) (root string, m Manifest, err error) {
	if maxBytes <= 0 || maxBytes > 1<<40 {
		return "", m, errors.New("archive byte limit must be between 1 byte and 1 TiB")
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		return "", m, err
	}
	defer z.Close()
	if len(z.File) > MaxFiles+1 {
		return "", m, errors.New("too many archive entries")
	}
	entries := map[string]*zip.File{}
	var total uint64
	for _, f := range z.File {
		if !SafePath(f.Name) || !f.Mode().IsRegular() || entries[f.Name] != nil {
			return "", m, fmt.Errorf("unsafe or duplicate archive entry %q", f.Name)
		}
		if f.UncompressedSize64 > uint64(maxBytes) || total > uint64(maxBytes)-f.UncompressedSize64 {
			return "", m, errors.New("archive exceeds local expanded-size limit")
		}
		total += f.UncompressedSize64
		entries[f.Name] = f
	}
	index := entries["verification.json"]
	if index == nil {
		return "", m, errors.New("missing verification.json")
	}
	if index.UncompressedSize64 > MaxManifest {
		return "", m, errors.New("verification manifest too large")
	}
	r, err := index.Open()
	if err != nil {
		return "", m, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxManifest+1))
	r.Close()
	if err != nil {
		return "", m, err
	}
	m, err = Parse(raw)
	if err != nil {
		return "", m, err
	}
	if len(entries) != len(m.Files)+1 {
		return "", m, errors.New("archive has missing or unlisted evidence")
	}
	for _, f := range m.Files {
		entry := entries[f.Path]
		if entry == nil || entry.UncompressedSize64 != uint64(f.Size) {
			return "", m, fmt.Errorf("missing evidence or incorrect size: %s", f.Path)
		}
	}
	root, err = os.MkdirTemp("", "relay-verification-")
	if err != nil {
		return "", m, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(root)
			root = ""
		}
	}()
	for _, f := range m.Files {
		dest := filepath.Join(root, filepath.FromSlash(f.Path))
		if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return
		}
		var out *os.File
		out, err = os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		var input io.ReadCloser
		input, err = entries[f.Path].Open()
		if err != nil {
			out.Close()
			return
		}
		hash := sha256.New()
		var n int64
		n, err = io.Copy(io.MultiWriter(out, hash), io.LimitReader(input, f.Size+1))
		input.Close()
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return
		}
		if n != f.Size || hex.EncodeToString(hash.Sum(nil)) != f.SHA256 {
			err = fmt.Errorf("evidence checksum failed: %s", f.Path)
			return
		}
	}
	return
}

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/verification"
)

const workflowV4ArchivePrefix = "ceremony/public/"
const workflowV4ZeroSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

// Trust files and proof-tool public exports may differ by a final newline.
// Compare the decoded key, while rejecting malformed or wrong-length inputs.
func sameCoordinatorPublicKey(a, b []byte) bool {
	decode := func(raw []byte) ([]byte, error) {
		value, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(value) != 32 {
			return nil, errors.New("invalid coordinator public key")
		}
		return value, nil
	}
	first, err := decode(a)
	if err != nil {
		return false
	}
	second, err := decode(b)
	return err == nil && bytes.Equal(first, second)
}

// Only proof-tool-verified decision references are eligible for the archive.
// An extra file in the decision handoff is an error, not an implicit sidecar.
func workflowV4DecisionArchiveFiles(root string) ([]string, []string, error) {
	decisionDir := filepath.Join(root, "decision")
	raw, err := readTesseraRegularFile(filepath.Join(decisionDir, "decision.json"), 16<<20, false)
	if err != nil {
		return nil, nil, err
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, nil, err
	}
	selected := map[string]bool{"decision/decision.json": true}
	var visit func(any) error
	visit = func(value any) error {
		switch v := value.(type) {
		case []any:
			for _, element := range v {
				if err := visit(element); err != nil {
					return err
				}
			}
		case map[string]any:
			name, named := v["name"].(string)
			_, digested := v["digest"].(map[string]any)
			if named && digested && strings.HasPrefix(name, "decision/evidence/") {
				if !verification.SafePath(name) {
					return fmt.Errorf("unsafe signed decision evidence path %q", name)
				}
				selected[name] = true
			}
			for _, element := range v {
				if err := visit(element); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(document); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(decisionDir)
	if err != nil {
		return nil, nil, err
	}
	signatures := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if name == "evidence" && entry.IsDir() {
			continue
		}
		if name == "decision.json" && entry.Type().IsRegular() {
			continue
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".sig") || !verification.SafePath("decision/"+name) {
			return nil, nil, fmt.Errorf("unexpected decision handoff file %q", name)
		}
		signatures = append(signatures, "decision/"+name)
		selected["decision/"+name] = true
	}
	if len(signatures) == 0 || len(signatures) > 64 {
		return nil, nil, errors.New("decision handoff requires accountable signatures")
	}
	slices.Sort(signatures)
	files := make([]string, 0, len(selected))
	for name := range selected {
		files = append(files, name)
	}
	slices.Sort(files)
	// Reject unreferenced evidence as well as symlinks and non-regular files.
	err = filepath.WalkDir(decisionDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == decisionDir {
			return nil
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if entry.IsDir() {
			if name != "decision/evidence" {
				return fmt.Errorf("unexpected decision handoff directory %q", name)
			}
			return nil
		}
		if !entry.Type().IsRegular() || !selected[name] {
			return fmt.Errorf("unreferenced or unsafe decision evidence %q", name)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, name := range files {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
			return nil, nil, fmt.Errorf("missing or oversized decision evidence %q", name)
		}
	}
	return files, signatures, nil
}

func workflowV4ArchiveSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runWorkflowV4PrepareTrialArchive(ui *coordinatorWizard, online guidedProfile, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol) error {
	if online.Role != "coordinator" || protocol.Definition.Mode != "production" || protocol.DefinitionSchema != "proof-tool-mpc-ceremony-definition-v5" {
		return errors.New("a V5 production coordinator must prepare this trial archive")
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	decisionFiles, signatures, err := workflowV4DecisionArchiveFiles(root)
	if err != nil {
		return err
	}
	trustedKey, err := readTesseraRegularFile(filepath.Join(online.Trust, "setup-coordinator.hex"), 4096, false)
	if err != nil {
		return err
	}
	publicKey, err := readTesseraRegularFile(filepath.Join(root, "coordinator-public-key.hex"), 4096, false)
	if err != nil {
		return err
	}
	if !sameCoordinatorPublicKey(trustedKey, publicKey) {
		return errors.New("public archive coordinator key differs from the authenticated local trust anchor")
	}
	// This verifier checks the exact decision, release, evidence and required
	// signature threshold before Relay grants the files publication meaning.
	command := []string{"mpc-ceremony", "decision", "verify", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/setup-coordinator.hex", "--decision", "/work/ceremony/public/decision/decision.json", "--evidence-root", "/work/ceremony/public"}
	for _, name := range signatures {
		command = append(command, "--signature", "/work/ceremony/public/"+name)
	}
	keyless := online
	keyless.Keys = ""
	if err := runWorkflowV4ProfileCommand(keyless, command, false); err != nil {
		return fmt.Errorf("verify exact production decision before trial archive: %w", err)
	}
	raw, err := readTesseraRegularFile(filepath.Join(root, "decision", "decision.json"), 16<<20, false)
	if err != nil {
		return err
	}
	var outcome struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return err
	}
	if outcome.Decision != "NO-GO" && outcome.Decision != "GO" {
		return errors.New("verified production decision has no supported outcome")
	}
	var binding struct {
		Release struct {
			ReleaseID              string                        `json:"release_id"`
			FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		} `json:"release"`
	}
	if err := json.Unmarshal(raw, &binding); err != nil {
		return err
	}
	if outcome.Decision == "GO" && binding.Release.FinalReleaseCheckpoint != snapshot.Head() {
		return errors.New("signed GO decision approves a different final-release checkpoint")
	}
	m, err := workflowV4PublicArchiveManifest(snapshot, protocol, decisionFiles, signatures)
	if err != nil {
		return err
	}
	dir := filepath.Join(online.Work, "workflow-v4", "publication")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := "no-go-trial-ceremony.zip"
	if outcome.Decision == "GO" {
		name = "go-ceremony.zip"
	}
	out := filepath.Join(dir, name)
	if _, err := os.Lstat(out); err == nil {
		return errors.New("a public archive already exists; preserve and inspect it before retrying")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	phrase := "PACK NO-GO TRIAL"
	if outcome.Decision == "GO" {
		phrase = "PACK GO RELEASE"
	}
	if err := ui.confirm("Pack only the authenticated public files and exact signed decision into a public archive", phrase); err != nil {
		return err
	}
	if err := packCeremony(online.Work, out, m); err != nil {
		return err
	}
	digest, err := workflowV4ArchiveSHA256(out)
	if err != nil {
		return err
	}
	if outcome.Decision == "NO-GO" {
		fmt.Fprintf(ui.output, "Signed NO-GO trial archive: %s\nSHA-256: %s\nTransfer this public ZIP to the upload station. It must never be presented as an approved production release.\n", out, digest)
		return nil
	}
	config, err := loadStorageConfig(filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"))
	if err != nil || config.CeremonyID != protocol.Definition.CeremonyID || config.Provider != "aws" {
		return errors.New("GO publication requires matching reviewed AWS storage settings")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	seed, err := readTesseraSeed(filepath.Join(online.Keys, "signing.hex"))
	if err != nil {
		return err
	}
	defer zeroTessera(seed)
	key, err := hex.DecodeString(strings.TrimSpace(string(trustedKey)))
	if err != nil {
		return err
	}
	record := workflowV4GoPublicationFor(protocol.Definition.CeremonyID, snapshot.Head().Record.Digest.SHA256, workflowV4ArchivePrefix+snapshot.Head().Record.Name, workflowV4ArchivePrefix+snapshot.Head().Signature.Name, workflowV4DigestBytes(raw), binding.Release.ReleaseID, digest, config.PublishedBucket, config.PublishedBaseURL)
	signed, err := workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		return err
	}
	pointer := filepath.Join(dir, "go-publication.json")
	if err := writeTesseraFresh(pointer, signed, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Signed GO archive: %s\nSHA-256: %s\nPublication authorization: %s\nTransfer both public files to the upload station. No release has been published yet.\n", out, digest, pointer)
	return nil
}

// The public inventory starts with references returned by the approved
// checkpoint verifier. Accepted historical payloads are added explicitly:
// non-replaying roles may omit those large downloads after release review,
// while the public archive still needs them for independent full replay.
func workflowV4PublicArchiveManifest(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, decisionFiles []string, signatures []string) (verification.Manifest, error) {
	var zero verification.Manifest
	if !protocol.UsesV4() {
		return zero, errors.New("authenticated V4/V5 definition required")
	}
	c, err := snapshot.State()
	if err != nil {
		return zero, err
	}
	if c.CeremonyID != protocol.Definition.CeremonyID || c.Progress.FinalRelease == nil || c.Progress.Phase2 == nil || c.Progress.Phase1Closure == nil || c.Progress.Phase1Beacon == nil || c.Progress.Phase1Seal == nil || c.Progress.Phase2Closure == nil || c.Progress.Phase2Beacon == nil {
		return zero, errors.New("complete authenticated final-release checkpoint required")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		return zero, err
	}
	files := map[string]verification.File{}
	add := func(name, tagged string, size int64) error {
		path := workflowV4ArchivePrefix + name
		if !verification.SafePath(path) || !strings.HasPrefix(tagged, "sha256:") || len(tagged) != len("sha256:")+64 || size <= 0 {
			return fmt.Errorf("invalid authenticated public artifact %q", name)
		}
		item := verification.File{Path: path, Size: size, SHA256: strings.TrimPrefix(tagged, "sha256:")}
		if old, ok := files[path]; ok && old != item {
			return fmt.Errorf("conflicting authenticated public artifact %q", name)
		}
		files[path] = item
		return nil
	}
	for _, ref := range snapshot.Files() {
		if err := add(ref.Name, ref.SHA256, ref.Size); err != nil {
			return zero, err
		}
	}
	for _, ref := range c.AcceptedArtifacts {
		if err := add(ref.Name, ref.Digest.SHA256, ref.Digest.Size); err != nil {
			return zero, err
		}
	}
	if err := add(protocol.Definition.R1CSRef.Name, protocol.Definition.R1CSRef.Digest.SHA256, protocol.Definition.R1CSRef.Digest.Size); err != nil {
		return zero, fmt.Errorf("authenticated circuit constraint system: %w", err)
	}
	// The trusted coordinator key and decision package are outside the signed
	// checkpoint inventory. The caller must verify the exact decision and its
	// signatures with proof-tool before packing these selected public files.
	for _, name := range append([]string{"coordinator-public-key.hex"}, decisionFiles...) {
		path := workflowV4ArchivePrefix + name
		if !verification.SafePath(path) || !strings.HasPrefix(name, "decision/") && name != "coordinator-public-key.hex" {
			return zero, fmt.Errorf("unsafe decision archive path %q", name)
		}
		if _, signed := files[path]; !signed {
			files[path] = verification.File{Path: path, SHA256: workflowV4ZeroSHA256}
		}
	}
	if len(signatures) == 0 {
		return zero, errors.New("verified decision signatures required")
	}
	inputs := map[string]string{
		"ceremony":                    workflowV4ArchivePrefix + protocol.DefinitionRefs.Record.Name,
		"ceremony-signature":          workflowV4ArchivePrefix + protocol.DefinitionRefs.Signature.Name,
		"coordinator-public-key-file": workflowV4ArchivePrefix + "coordinator-public-key.hex",
		"transcript-root":             "ceremony/public",
		"phase1-chain":                workflowV4ArchivePrefix + c.Progress.Phase1.Chain.Record.Name,
		"phase1-chain-signature":      workflowV4ArchivePrefix + c.Progress.Phase1.Chain.Signature.Name,
		"phase1-close":                workflowV4ArchivePrefix + c.Progress.Phase1Closure.Record.Name,
		"phase1-close-signature":      workflowV4ArchivePrefix + c.Progress.Phase1Closure.Signature.Name,
		"phase1-beacon":               workflowV4ArchivePrefix + c.Progress.Phase1Beacon.Record.Name,
		"phase1-beacon-signature":     workflowV4ArchivePrefix + c.Progress.Phase1Beacon.Signature.Name,
		"phase1-seal":                 workflowV4ArchivePrefix + c.Progress.Phase1Seal.Record.Name,
		"phase1-seal-signature":       workflowV4ArchivePrefix + c.Progress.Phase1Seal.Signature.Name,
		"phase2-chain":                workflowV4ArchivePrefix + c.Progress.Phase2.Chain.Record.Name,
		"phase2-chain-signature":      workflowV4ArchivePrefix + c.Progress.Phase2.Chain.Signature.Name,
		"phase2-close":                workflowV4ArchivePrefix + c.Progress.Phase2Closure.Record.Name,
		"phase2-close-signature":      workflowV4ArchivePrefix + c.Progress.Phase2Closure.Signature.Name,
		"phase2-beacon":               workflowV4ArchivePrefix + c.Progress.Phase2Beacon.Record.Name,
		"phase2-beacon-signature":     workflowV4ArchivePrefix + c.Progress.Phase2Beacon.Signature.Name,
		"keys-dir":                    workflowV4ArchivePrefix + "final/release",
		"manifest-public-key-file":    workflowV4ArchivePrefix + "final/release/manifest-public-key.hex",
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	inventory := make([]verification.File, 0, len(paths))
	for _, path := range paths {
		inventory = append(inventory, files[path])
	}
	decisionSignatures := make([]string, 0, len(signatures))
	for _, name := range signatures {
		decisionSignatures = append(decisionSignatures, workflowV4ArchivePrefix+name)
	}
	m := verification.Manifest{Schema: verification.Schema, CeremonyID: c.CeremonyID, DefinitionSHA256: strings.TrimPrefix(protocol.DefinitionRefs.Record.Digest.SHA256, "sha256:"), ReleaseKeyID: expected.Identity.KeyID, Inputs: inputs, Decision: &verification.Decision{Record: workflowV4ArchivePrefix + "decision/decision.json", Signatures: decisionSignatures, EvidenceRoot: "ceremony/public"}, Files: inventory}
	if err := m.Validate(); err != nil {
		return zero, err
	}
	return m, nil
}

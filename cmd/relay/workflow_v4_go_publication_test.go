package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/verification"
)

func syntheticGoDecision(t *testing.T, releaseID string, checkpoint, signature []byte) []byte {
	t.Helper()
	ref := func(name string, raw []byte) map[string]any {
		return map[string]any{"name": name, "digest": map[string]any{"sha256": "sha256:" + workflowV4DigestBytes(raw), "size": len(raw)}}
	}
	raw, err := json.Marshal(map[string]any{"decision": "GO", "release": map[string]any{"release_id": releaseID, "final_release_checkpoint": map[string]any{"record": ref("checkpoints/final/checkpoint.json", checkpoint), "signature": ref("checkpoints/final/checkpoint.sig", signature)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWorkflowV4GoPublicationBindsExactReleaseAndDestination(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	ceremony := "sha256:" + strings.Repeat("a", 64)
	record := workflowV4GoPublicationFor(ceremony, "sha256:"+strings.Repeat("b", 64), "ceremony/public/checkpoints/final/checkpoint.json", "ceremony/public/checkpoints/final/checkpoint.sig", strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("e", 64), "published-bucket", "https://ceremony.example")
	raw, err := workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := workflowV4VerifyGoPublication(raw, key); err != nil || verified != record {
		t.Fatalf("signed publication rejected: %+v %v", verified, err)
	}
	for _, change := range []func(*workflowV4GoPublication){
		func(r *workflowV4GoPublication) { r.ArchiveSHA256 = strings.Repeat("f", 64) },
		func(r *workflowV4GoPublication) { r.DecisionSHA256 = strings.Repeat("f", 64) },
		func(r *workflowV4GoPublication) { r.PublishedBucket = "another-bucket" },
		func(r *workflowV4GoPublication) { r.PublishedBaseURL = "https://another.example" },
		func(r *workflowV4GoPublication) { r.CheckpointSHA256 = strings.Repeat("f", 64) },
		func(r *workflowV4GoPublication) { r.ReleaseID = "sha256:" + strings.Repeat("f", 64) },
	} {
		var signed workflowV4SignedGoPublication
		if err := json.Unmarshal(raw, &signed); err != nil {
			t.Fatal(err)
		}
		change(&signed.Record)
		altered, _ := json.Marshal(signed)
		if _, err := workflowV4VerifyGoPublication(altered, key); err == nil {
			t.Fatalf("altered publication accepted: %s", altered)
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := workflowV4VerifyGoPublication(raw, other); err == nil {
		t.Fatal("wrong coordinator key accepted")
	}
}

func TestGoPublicationSigningRetainsExactAuthorization(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	dir := t.TempDir()
	trust := filepath.Join(t.TempDir(), "coordinator.hex")
	private := filepath.Join(t.TempDir(), "signing.hex")
	if err := os.WriteFile(trust, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}
	record := workflowV4GoPublicationFor("sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "ceremony/public/checkpoints/final/checkpoint.json", "ceremony/public/checkpoints/final/checkpoint.sig", strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("e", 64), "published-bucket", "https://ceremony.example")
	input, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(dir, "go-publication-input.json")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signGoPublicationFiles(dir, trust, private); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "go-publication.json")
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := workflowV4VerifyGoPublication(first, key); err != nil || got != record {
		t.Fatalf("wrong signed record: %+v %v", got, err)
	}
	if err := signGoPublicationFiles(dir, trust, private); err != nil {
		t.Fatalf("exact retry failed: %v", err)
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, first) {
		t.Fatal("exact retry replaced signed bytes")
	}
	changed := record
	changed.PublishedBucket = "other-bucket"
	changedInput, _ := json.Marshal(changed)
	if err := os.WriteFile(inputPath, changedInput, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signGoPublicationFiles(dir, trust, private); err == nil {
		t.Fatal("changed destination replaced retained authorization")
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, first) {
		t.Fatal("failed retry changed signed bytes")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	otherSeed := bytes.Repeat([]byte{8}, ed25519.SeedSize)
	if err := os.WriteFile(private, []byte(hex.EncodeToString(otherSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signGoPublicationFiles(dir, trust, private); err == nil {
		t.Fatal("wrong coordinator key signed publication")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("wrong key created authorization")
	}
}

func TestWorkflowV4OfficialGoReadbackBindsPointerAndArchive(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	archive := filepath.Join(t.TempDir(), "ceremony.zip")
	if err := os.WriteFile(archive, []byte("synthetic public archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveSHA, err := workflowV4ArchiveSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ceremony", "public", "decision"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyName := "ceremony/public/coordinator-public-key.hex"
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(keyName)), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	decisionName := "ceremony/public/decision/decision.json"
	releaseID := "sha256:" + strings.Repeat("d", 64)
	ceremony := "sha256:" + strings.Repeat("a", 64)
	checkpoint := []byte(`{"transition":{"kind":"final-release-recorded"},"progress":{"final_release":{}}}`)
	signature := []byte("synthetic signature")
	checkpointSHA := workflowV4DigestBytes(checkpoint)
	checkpointName := "ceremony/public/checkpoints/final/checkpoint.json"
	signatureName := "ceremony/public/checkpoints/final/checkpoint.sig"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, checkpointName)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, checkpointName), checkpoint, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, signatureName), signature, 0o600); err != nil {
		t.Fatal(err)
	}
	decision := syntheticGoDecision(t, releaseID, checkpoint, signature)
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(decisionName)), decision, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := verification.Manifest{CeremonyID: ceremony, Inputs: map[string]string{"coordinator-public-key-file": keyName, "ceremony": keyName, "ceremony-signature": keyName}, Decision: &verification.Decision{Record: decisionName}, Files: []verification.File{{Path: checkpointName, SHA256: checkpointSHA}, {Path: signatureName}}}
	var pointer []byte
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + workflowV4GoPointerKey(ceremony):
			_, _ = w.Write(pointer)
		case "/" + workflowV4GoPublicationFor(ceremony, checkpointSHA, "ceremony/public/checkpoints/final/checkpoint.json", "ceremony/public/checkpoints/final/checkpoint.sig", workflowV4DigestBytes(decision), releaseID, archiveSHA, "bucket", server.URL).ArchiveKey:
			_, _ = w.Write([]byte("synthetic public archive"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	record := workflowV4GoPublicationFor(ceremony, checkpointSHA, "ceremony/public/checkpoints/final/checkpoint.json", "ceremony/public/checkpoints/final/checkpoint.sig", workflowV4DigestBytes(decision), releaseID, archiveSHA, "bucket", server.URL)
	pointer, err = workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	run := func(args ...string) ([]byte, error) {
		return json.Marshal(map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "checkpoint verify-stored-v4", "ceremony_id": ceremony, "checkpoint_inspection_v4": map[string]any{"schema": "proof-tool-mpc-checkpoint-inspection-v4", "depth": "checkpoint-structure", "checkpoint": map[string]any{"transition": map[string]any{"kind": "final-release-recorded"}, "progress": map[string]any{"final_release": map[string]any{}}}}})
	}
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL, run); err != nil {
		t.Fatal(err)
	}
	var bound struct {
		Release struct {
			FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		} `json:"release"`
	}
	if err := json.Unmarshal(decision, &bound); err != nil {
		t.Fatal(err)
	}
	otherHead := bound.Release.FinalReleaseCheckpoint
	otherHead.Record.Digest.SHA256 = "sha256:" + strings.Repeat("f", 64)
	if err := workflowV4MatchGoDecisionCheckpoint(root, record, otherHead); err == nil {
		t.Fatal("GO for a forked final checkpoint accepted")
	}
	nonfinal := func(args ...string) ([]byte, error) {
		return json.Marshal(map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "checkpoint verify-stored-v4", "ceremony_id": ceremony, "checkpoint_inspection_v4": map[string]any{"schema": "proof-tool-mpc-checkpoint-inspection-v4", "depth": "checkpoint-structure", "checkpoint": map[string]any{"transition": map[string]any{"kind": "phase2-closed"}, "progress": map[string]any{"final_release": map[string]any{}}}}})
	}
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL, nonfinal); err == nil {
		t.Fatal("non-final checkpoint accepted for official GO")
	}
	wrongOrigin := record
	wrongOrigin.PublishedBaseURL = "https://another.example"
	wrongPointer, err := workflowV4SignGoPublication(wrongOrigin, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	pointer = wrongPointer
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL, run); err == nil {
		t.Fatal("pointer for another public origin accepted")
	}
	pointer, err = workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("different archive"))
	if err := os.WriteFile(archive, []byte("different archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL, run); err == nil {
		t.Fatalf("changed archive %x accepted", wrong)
	}
}

func TestWorkflowV4GoPointerRejectsConflictingExistingBytes(t *testing.T) {
	publicBytes := []byte("another signed decision")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(publicBytes) }))
	defer server.Close()
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	if err := workflowV4GoPointerReadback(store.Client{PublicBaseURL: server.URL}, "approved/example/release.json", []byte("intended decision"), t.TempDir()); err == nil {
		t.Fatal("conflicting existing official pointer accepted as a retry")
	}
}

func TestVerifyCeremonyReportsOfficialGoOnlyForMatchingPointer(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	ceremony := "sha256:" + strings.Repeat("a", 64)
	releaseID := "sha256:" + strings.Repeat("d", 64)
	checkpoint := []byte("synthetic final release checkpoint")
	signature := []byte("synthetic checkpoint signature")
	decision := syntheticGoDecision(t, releaseID, checkpoint, signature)
	checkpointSHA := workflowV4DigestBytes(checkpoint)
	root := t.TempDir()
	manifest := verification.Manifest{Schema: verification.Schema, CeremonyID: ceremony, ReleaseKeyID: "release-key", Inputs: map[string]string{}, Decision: &verification.Decision{Record: "decision.json", Signatures: []string{"decision.sig"}, EvidenceRoot: "evidence"}, DefinitionSHA256: workflowV4ZeroSHA256}
	files := map[string][]byte{"decision.json": decision, "decision.sig": []byte("synthetic signature"), "evidence/file": []byte("synthetic evidence"), "ceremony/public/checkpoints/final/checkpoint.json": checkpoint, "ceremony/public/checkpoints/final/checkpoint.sig": signature}
	for _, input := range verification.RequiredInputs {
		name := "data/" + input
		if input == "transcript-root" || input == "keys-dir" {
			name += "/file"
			manifest.Inputs[input] = "data/" + input
		} else {
			manifest.Inputs[input] = name
		}
		files[name] = []byte(input)
	}
	files[manifest.Inputs["coordinator-public-key-file"]] = []byte(hex.EncodeToString(key))
	for name, data := range files {
		location := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(location), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(location, data, 0o600); err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, verification.File{Path: name, SHA256: workflowV4ZeroSHA256})
	}
	archive := filepath.Join(t.TempDir(), "go.zip")
	if err := packCeremony(root, archive, manifest); err != nil {
		t.Fatal(err)
	}
	archiveSHA, err := workflowV4ArchiveSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	extracted, extractedManifest, err := verification.Extract(archive, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(extracted)
	verifier := workflowV4GoVerifierDriver(dockerDriver{}, extracted, extractedManifest)
	checkpointArgs := []string{"--format", "json", "checkpoint", "verify-stored-v4", "--ceremony", filepath.Join(extracted, filepath.FromSlash(extractedManifest.Inputs["ceremony"])), "--ceremony-signature", filepath.Join(extracted, filepath.FromSlash(extractedManifest.Inputs["ceremony-signature"])), "--coordinator-public-key-file", filepath.Join(extracted, filepath.FromSlash(extractedManifest.Inputs["coordinator-public-key-file"])), "--artifact-root", filepath.Join(extracted, "ceremony", "public"), "--checkpoint", filepath.Join(extracted, "ceremony", "public", "checkpoints", "final", "checkpoint.json"), "--checkpoint-signature", filepath.Join(extracted, "ceremony", "public", "checkpoints", "final", "checkpoint.sig")}
	if _, _, err := verifier.rewriteReadOnlyArgs(checkpointArgs); err != nil {
		t.Fatalf("pinned Docker verifier rejects extracted GO archive: %v", err)
	}
	var pointer []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/release.json") {
			_, _ = w.Write(pointer)
		} else if strings.HasSuffix(r.URL.Path, "/ceremony.zip") {
			_, _ = w.Write(archiveBytes)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	record := workflowV4GoPublicationFor(ceremony, checkpointSHA, "ceremony/public/checkpoints/final/checkpoint.json", "ceremony/public/checkpoints/final/checkpoint.sig", workflowV4DigestBytes(decision), releaseID, archiveSHA, "published", server.URL)
	pointer, err = workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	runner := func(args ...string) ([]byte, error) {
		command := args[0]
		if command != "replay" {
			command += " " + args[1]
		}
		result := map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": command, "ceremony_id": ceremony, "release_manifest_sha256": "sha256:" + strings.Repeat("b", 64)}
		if command == "inspect definition" {
			result["definition_inspection"] = map[string]any{"schema": "proof-tool-mpc-definition-inspection-v1", "ceremony_id": ceremony, "mode": "production", "key_version": "rehearsal-k11-v1", "phase1_participants": []string{"a"}, "phase2_participants": []string{"a"}, "r1cs": map[string]any{"name": "circuit.r1cs", "digest": map[string]any{"sha256": strings.Repeat("a", 64), "blake2b256": strings.Repeat("b", 64), "size": 1}}}
		}
		if command == "decision verify" {
			result["decision"] = "GO"
		}
		if command == "checkpoint verify-stored-v4" {
			result["checkpoint_inspection_v4"] = map[string]any{"schema": "proof-tool-mpc-checkpoint-inspection-v4", "depth": "checkpoint-structure", "checkpoint": map[string]any{"transition": map[string]any{"kind": "final-release-recorded"}, "progress": map[string]any{"final_release": map[string]any{}}}}
		}
		return json.Marshal(result)
	}
	report, err := verifyCeremonyArchiveWithPublication(archive, 1<<20, runner, server.URL)
	if err != nil || !report.Passed || len(report.Checks) != 6 || report.Checks[5].Status != "passed" {
		t.Fatalf("official GO was not verified: %+v %v", report, err)
	}
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if report, err := verifyCeremonyArchiveWithPublicationTrusted(archive, 1<<20, runner, server.URL, ceremony, []byte(hex.EncodeToString(wrongKey))); err == nil || report.Passed {
		t.Fatal("untrusted coordinator key accepted for official GO")
	}
	if report, err := verifyCeremonyArchiveWithPublicationTrusted(archive, 1<<20, runner, server.URL, "sha256:"+strings.Repeat("f", 64), []byte(hex.EncodeToString(key))); err == nil || report.Passed {
		t.Fatal("untrusted ceremony ID accepted for official GO")
	}
	pointer = []byte(`{"record":"different"}`)
	report, err = verifyCeremonyArchiveWithPublication(archive, 1<<20, runner, server.URL)
	if err == nil || report.Passed || report.Checks[5].Status != "failed" {
		t.Fatalf("conflicting official pointer passed: %+v %v", report, err)
	}
}

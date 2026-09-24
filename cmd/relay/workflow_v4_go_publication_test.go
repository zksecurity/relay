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
	"github.com/zksecurity/relay/internal/verification"
)

func TestWorkflowV4GoPublicationBindsExactReleaseAndDestination(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	ceremony := "sha256:" + strings.Repeat("a", 64)
	record := workflowV4GoPublicationFor(ceremony, "sha256:"+strings.Repeat("b", 64), strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("e", 64), "published-bucket", "https://ceremony.example")
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
	decision, _ := json.Marshal(map[string]any{"decision": "GO", "release": map[string]any{"release_id": releaseID}})
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(decisionName)), decision, 0o600); err != nil {
		t.Fatal(err)
	}
	ceremony := "sha256:" + strings.Repeat("a", 64)
	checkpointSHA := strings.Repeat("b", 64)
	manifest := verification.Manifest{CeremonyID: ceremony, Inputs: map[string]string{"coordinator-public-key-file": keyName}, Decision: &verification.Decision{Record: decisionName}, Files: []verification.File{{Path: "ceremony/public/checkpoints/final/checkpoint.json", SHA256: checkpointSHA}}}
	var pointer []byte
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + workflowV4GoPointerKey(ceremony):
			_, _ = w.Write(pointer)
		case "/" + workflowV4GoPublicationFor(ceremony, checkpointSHA, workflowV4DigestBytes(decision), releaseID, archiveSHA, "bucket", server.URL).ArchiveKey:
			_, _ = w.Write([]byte("synthetic public archive"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	record := workflowV4GoPublicationFor(ceremony, checkpointSHA, workflowV4DigestBytes(decision), releaseID, archiveSHA, "bucket", server.URL)
	pointer, err = workflowV4SignGoPublication(record, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL); err != nil {
		t.Fatal(err)
	}
	wrongOrigin := record
	wrongOrigin.PublishedBaseURL = "https://another.example"
	wrongPointer, err := workflowV4SignGoPublication(wrongOrigin, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	pointer = wrongPointer
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL); err == nil {
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
	if err := workflowV4VerifyPublishedGo(root, manifest, archive, server.URL); err == nil {
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
	decision, _ := json.Marshal(map[string]any{"decision": "GO", "release": map[string]any{"release_id": releaseID}})
	checkpoint := []byte("synthetic final release checkpoint")
	checkpointSHA := workflowV4DigestBytes(checkpoint)
	root := t.TempDir()
	manifest := verification.Manifest{Schema: verification.Schema, CeremonyID: ceremony, ReleaseKeyID: "release-key", Inputs: map[string]string{}, Decision: &verification.Decision{Record: "decision.json", Signatures: []string{"decision.sig"}, EvidenceRoot: "evidence"}, DefinitionSHA256: workflowV4ZeroSHA256}
	files := map[string][]byte{"decision.json": decision, "decision.sig": []byte("synthetic signature"), "evidence/file": []byte("synthetic evidence"), "ceremony/public/checkpoints/final/checkpoint.json": checkpoint}
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
	record := workflowV4GoPublicationFor(ceremony, checkpointSHA, workflowV4DigestBytes(decision), releaseID, archiveSHA, "published", server.URL)
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
		return json.Marshal(result)
	}
	report, err := verifyCeremonyArchiveWithPublication(archive, 1<<20, runner, server.URL)
	if err != nil || !report.Passed || len(report.Checks) != 6 || report.Checks[5].Status != "passed" {
		t.Fatalf("official GO was not verified: %+v %v", report, err)
	}
	pointer = []byte(`{"record":"different"}`)
	report, err = verifyCeremonyArchiveWithPublication(archive, 1<<20, runner, server.URL)
	if err == nil || report.Passed || report.Checks[5].Status != "failed" {
		t.Fatalf("conflicting official pointer passed: %+v %v", report, err)
	}
}

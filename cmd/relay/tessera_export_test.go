package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
	releaseassets "github.com/zksecurity/relay/release"
)

func tesseraContextForDefinition(d tesseraDefinition) tesseraContext {
	c := tesseraContext{Schema: "tessera-draft-context-v1", CeremonyID: "00000000-0000-4000-8000-000000000001", Revision: 7, Mode: d.Mode, Assignments: []tesseraAssignment{}, Schedules: []tesseraSchedule{}}
	add := func(role string, i setupIdentity) {
		n := len(c.Assignments) + 2
		c.Assignments = append(c.Assignments, tesseraAssignment{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), Person: fmt.Sprintf("00000000-0000-4000-8000-%012d", n+100), Revision: 1, Role: role, Phases: []string{}, Identity: i})
	}
	add("coordinator", d.Coordinator)
	add("release-signer", d.ReleaseSigner)
	for _, i := range d.Auditors {
		add("auditor", i)
	}
	for _, p := range d.Roster {
		add("participant", p.Identity)
	}
	for index, p := range []setupPhase{d.Phase1, d.Phase2} {
		s := tesseraSchedule{Phase: fmt.Sprintf("phase%d", index+1), Minimum: p.Minimum, IDs: []string{}}
		for _, id := range p.Participants {
			for n := range c.Assignments {
				if c.Assignments[n].Identity.ID == id {
					c.Assignments[n].Phases = append(c.Assignments[n].Phases, s.Phase)
					s.IDs = append(s.IDs, c.Assignments[n].ID)
				}
			}
		}
		c.Schedules = append(c.Schedules, s)
	}
	return c
}
func tesseraFixture(t *testing.T) (tesseraContext, tesseraDefinition, transcript.Definition) {
	t.Helper()
	w := setupFixture(t)
	d := tesseraDefinition{Schema: "proof-tool-mpc-ceremony-definition-v2", ProtocolID: "sha256:" + strings.Repeat("a", 64), Mode: "rehearsal", Coordinator: w.d.Identities.Coordinator, ReleaseSigner: w.d.Identities.ReleaseSigner, Auditors: w.d.Identities.Auditors, Roster: w.d.Identities.Roster, Phase1: w.d.Policy.Phase1, Phase2: w.d.Policy.Phase2}
	var inputs struct {
		MPC map[string]struct {
			URL string `json:"url"`
			SHA string `json:"sha256"`
		} `json:"mpc"`
	}
	if err := json.Unmarshal(releaseassets.RoleImageInputs(), &inputs); err != nil {
		t.Fatal(err)
	}
	pin := inputs.MPC["linux_amd64"]
	d.Software.Commit = strings.Split(strings.Split(pin.URL, "mpc-ci-")[1], "/")[0]
	d.Software.OS = "linux"
	d.Software.Arch = "amd64"
	d.Software.Binary.SHA256 = "sha256:" + pin.SHA
	return tesseraContextForDefinition(d), d, transcript.Definition{CeremonyID: d.ProtocolID, Mode: d.Mode, Phase1Participants: d.Phase1.Participants, Phase2Participants: d.Phase2.Participants}
}
func TestTesseraRosterValidationAndImport(t *testing.T) {
	c, _, _ := tesseraFixture(t)
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*tesseraContext){
		"missing coordinator":    func(c *tesseraContext) { c.Assignments = c.Assignments[1:] },
		"duplicate public key":   func(c *tesseraContext) { c.Assignments[1].Identity = c.Assignments[0].Identity },
		"missing schedule entry": func(c *tesseraContext) { c.Schedules[0].IDs = []string{} },
		"wrong phase role":       func(c *tesseraContext) { c.Assignments[0].Phases = []string{"phase1"} },
		"empty phase":            func(c *tesseraContext) { c.Assignments[len(c.Assignments)-1].Phases = []string{} },
		"production minima":      func(c *tesseraContext) { c.Mode = "production" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var changed tesseraContext
			json.Unmarshal(raw, &changed)
			change(&changed)
			if changed.validate() == nil {
				t.Fatal("accepted invalid context")
			}
		})
	}
	raw, _ := json.Marshal(c)
	var parsed tesseraContext
	if tesseraJSON(bytes.Replace(raw, []byte(`"mode":"rehearsal"`), []byte(`"mode":"production","mode":"rehearsal"`), 1), &parsed) == nil {
		t.Fatal("accepted duplicate field")
	}
	if tesseraJSON(bytes.Replace(raw, []byte(`"schema":`), []byte(`"secret":"do not export","schema":`), 1), &parsed) == nil {
		t.Fatal("accepted unknown field")
	}
	w := setupFixture(t)
	path := filepath.Join(t.TempDir(), "roster.json")
	os.WriteFile(path, raw, 0600)
	w.input = bufio.NewReader(strings.NewReader(path + "\nNO\n"))
	if w.importTesseraRoster() == nil || w.d.Tessera != nil {
		t.Fatal("import without consent")
	}
	w.input = bufio.NewReader(strings.NewReader(path + "\nIMPORT ROSTER\n"))
	if err := w.importTesseraRoster(); err != nil {
		t.Fatal(err)
	}
	if err := checkTesseraDraft(w.d); err != nil {
		t.Fatal(err)
	}
	w.d.Policy.Phase1.Minimum = 0
	if checkTesseraDraft(w.d) == nil {
		t.Fatal("accepted local drift")
	}
	w.d.Status = "definition-verified"
	if w.importTesseraRoster() == nil {
		t.Fatal("modified initialized ceremony")
	}
}
func TestTesseraExportPinsExactArtifactsAndRejectsDrift(t *testing.T) {
	c, d, inspected := tesseraFixture(t)
	commit := strings.Repeat("c", 40)
	manifest, err := tesseraManifest(d, "role-images-"+commit, []byte(`{"test_fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	storage := tesseraStorage{"aws", "us-east-1", "https://public.example.test", "published-test", "inbox-test"}
	encoded, err := buildTesseraBundle(c, storage, raw, []byte("unit-test-signature"), []byte(d.Coordinator.PublicKey), manifest, inspected, commit, d.Software.Commit)
	if err != nil {
		t.Fatal(err)
	}
	var b tesseraBundle
	if err := json.Unmarshal(encoded, &b); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range b.Artifacts {
		decoded, err := base64.StdEncoding.DecodeString(artifact.Content)
		if err != nil || len(decoded) != artifact.Length || tesseraDigest(decoded) != artifact.SHA256 {
			t.Fatal("artifact mismatch")
		}
	}
	if !bytes.Equal(raw, mustDecodeTessera(t, b.Artifacts[0].Content)) {
		t.Fatal("rewrote signed bytes")
	}
	output := filepath.Join(t.TempDir(), "setup.json")
	if err := writeTesseraFresh(output, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if writeTesseraFresh(output, encoded, 0600) == nil {
		t.Fatal("overwrote output")
	}
	for name, change := range map[string]func(*tesseraDefinition){
		"identity": func(d *tesseraDefinition) { d.Coordinator.PublicKey = strings.Repeat("0", 64) },
		"minimum":  func(d *tesseraDefinition) { d.Phase1.Minimum++ },
		"protocol": func(d *tesseraDefinition) { d.ProtocolID = "sha256:" + strings.Repeat("b", 64) },
		"mode":     func(d *tesseraDefinition) { d.Mode = "production" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d
			change(&changed)
			raw, _ := json.Marshal(changed)
			if _, err := checkTesseraDefinition(c, raw, inspected); err == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
	d.Software.Binary.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := tesseraManifest(d, "role-images-"+commit, []byte(`{}`)); err == nil {
		t.Fatal("accepted unapproved tool")
	}
	storage.PublicURL = "https://user:secret@example.test"
	if storage.validate() == nil {
		t.Fatal("accepted credentials")
	}
}
func mustDecodeTessera(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Optional real signed rehearsal interoperability check. No cloud writes or
// contribution execution. The supplied executable must match this build's pin.
func TestTesseraRealSignedSetup(t *testing.T) {
	binary := os.Getenv("TESSERA_PROOF_TOOL_BINARY")
	if binary == "" {
		t.Skip("set TESSERA_PROOF_TOOL_BINARY to the approved Linux proof-tool")
	}
	_, approved, _ := tesseraFixture(t)
	hash, err := setupFileHash(binary)
	if err != nil {
		t.Fatal(err)
	}
	if "sha256:"+hash != approved.Software.Binary.SHA256 {
		t.Fatal("test executable differs from embedded release pin")
	}
	root := filepath.Join(t.TempDir(), "rehearsal")
	command := exec.Command(binary, "rehearsal", "init", "--created-at", "2026-09-08T12:00:00Z", "--out-dir", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("init: %v %s", err, output)
	}
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(root, "public", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	definition, signature, key := read("ceremony.json"), read("ceremony.sig"), bytes.TrimSpace(read("coordinator-public-key.hex"))
	inspector := transcript.Inspector{Executable: binary, CeremonyPath: filepath.Join(root, "public/ceremony.json"), CeremonySignaturePath: filepath.Join(root, "public/ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(root, "public/coordinator-public-key.hex")}
	inspected, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	var d tesseraDefinition
	if err := json.Unmarshal(definition, &d); err != nil {
		t.Fatal(err)
	}
	c := tesseraContextForDefinition(d)
	commit := strings.Repeat("c", 40)
	manifest, err := tesseraManifest(d, "role-images-"+commit, []byte(`{"test_fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := buildTesseraBundle(c, tesseraStorage{"aws", "us-east-1", "https://public.example.test", "published-test", "inbox-test"}, definition, signature, key, manifest, inspected, commit, d.Software.Commit)
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("TESSERA_TEST_EXPORT_DIR"); dir != "" {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		context, _ := json.Marshal(c)
		if err = writeTesseraFresh(filepath.Join(dir, "roster.json"), context, 0600); err != nil {
			t.Fatal(err)
		}
		if err = writeTesseraFresh(filepath.Join(dir, "setup.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	changed := bytes.Replace(definition, []byte(`"mode":"rehearsal"`), []byte(`"mode":"production"`), 1)
	if bytes.Equal(changed, definition) {
		changed = append(definition, 'x')
	}
	os.WriteFile(inspector.CeremonyPath, changed, 0600)
	if _, err = inspector.Definition(); err == nil {
		t.Fatal("accepted tampered signed definition")
	}
}

// Called by Tessera's optional cross-repository HTTP round-trip test with the
// exact roster downloaded from its draft. The fixture contains real signatures.
func TestTesseraExportDownloadedRoster(t *testing.T) {
	contextPath := os.Getenv("TESSERA_TEST_CONTEXT")
	if contextPath == "" {
		t.Skip("cross-repository export test")
	}
	raw, err := os.ReadFile(os.Getenv("TESSERA_EXPORT_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	var original tesseraBundle
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	artifacts := map[string][]byte{}
	for _, a := range original.Artifacts {
		artifacts[a.Kind] = mustDecodeTessera(t, a.Content)
	}
	c, err := loadTesseraContext(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for kind, raw := range artifacts {
		if err = os.WriteFile(filepath.Join(dir, kind), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inspector := transcript.Inspector{Executable: os.Getenv("TESSERA_PROOF_TOOL_BINARY"), CeremonyPath: filepath.Join(dir, "definition"), CeremonySignaturePath: filepath.Join(dir, "definition-signature"), CoordinatorPublicKeyPath: filepath.Join(dir, "coordinator-key")}
	inspected, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := buildTesseraBundle(c, original.Storage, artifacts["definition"], artifacts["definition-signature"], artifacts["coordinator-key"], artifacts["software-manifest"], inspected, original.Software.Commit, original.Software.ProofCommit)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTesseraFresh(os.Getenv("TESSERA_TEST_OUTPUT"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

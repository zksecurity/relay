package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	setupv2 "github.com/zksecurity/relay/contracts/setupv2r2"
	"github.com/zksecurity/relay/internal/transcript"
)

func setupTestManifestV2(t *testing.T) []byte {
	t.Helper()
	commit := strings.Repeat("c", 40)
	images := []map[string]string{}
	for target, name := range map[string]string{"online": "relay-role-online", "offline": "relay-role-offline", "contributor": "relay-ceremony-tool"} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			images = append(images, map[string]string{"target": target, "platform": platform, "source_commit": commit, "image": "ghcr.io/zksecurity/relay/" + name + "@sha256:" + strings.Repeat("b", 64)})
		}
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i]["target"]+images[i]["platform"] < images[j]["target"]+images[j]["platform"]
	})
	raw, _ := json.Marshal(map[string]any{"schema": "relay-role-image-release/v1", "approval": "github-attested-ci", "source_commit": commit, "launcher_commit": commit, "images": images})
	m, err := setupManifestV2(commit, raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func setupTestPlanV2(t *testing.T, c tesseraContext, manifest []byte) setupv2.Setup {
	t.Helper()
	var m setupReleaseManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	s := setupv2.Setup{Schema: "ceremony-setup-v2", ID: c.CeremonyID, PlanRevision: c.Revision, Plan: setupv2.Plan{Mode: c.Mode, Ruleset: setupv2.Rules(), Circuit: "rehearsal-tiny-v1", BeaconPolicy: setupv2.Beacon(c.Mode), SoftwareRelease: setupv2.Software{ReleaseTag: m.ReleaseTag, CLICommit: m.CLICommit, ProofToolCommit: m.ProofToolCommit, ManifestSHA256: setupv2.Hash(manifest), WorkflowRecipeSHA256: setupRecipeDigestV2()}, Storage: setupv2.Storage{Provider: "aws", Region: "us-east-1", PublicBaseURL: "https://public.example.test", PublishedBucket: "published-test", InboxBucket: "inbox-test"}}}
	ids := map[string]string{}
	for _, a := range c.Assignments {
		i := a.Identity
		s.Plan.Identities = append(s.Plan.Identities, setupv2.Identity{ID: i.ID, DisplayName: i.DisplayName, KeyID: i.KeyID, PublicKey: i.PublicKey, Fingerprint: i.Fingerprint})
		s.Plan.Roles = append(s.Plan.Roles, setupv2.Role{ID: a.ID, Role: a.Role, IdentityID: i.ID})
		ids[a.ID] = i.ID
	}
	for _, p := range c.Schedules {
		phase := setupv2.Phase{ID: p.Phase, Minimum: p.Minimum}
		for _, id := range p.IDs {
			phase.IdentityIDs = append(phase.IdentityIDs, ids[id])
		}
		s.Plan.Phases = append(s.Plan.Phases, phase)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestSetupV2PlanDrift(t *testing.T) {
	c, _, _ := tesseraFixture(t)
	s := setupTestPlanV2(t, c, setupTestManifestV2(t))
	w := setupFixture(t)
	w.d.TesseraSetup = &s
	w.d.Mode = s.Plan.Mode
	w.d.Circuit = s.Plan.Circuit
	w.d.Release = s.Plan.SoftwareRelease.ReleaseTag
	w.d.Identities, w.d.Policy.Phase1, w.d.Policy.Phase2 = c.setupInputs()
	raw, _ := json.Marshal(s.Plan.BeaconPolicy)
	json.Unmarshal(raw, &w.d.Policy.Beacon)
	p := s.Plan.Storage
	w.d.Storage = map[string]string{"provider": p.Provider, "region": p.Region, "published-base-url": p.PublicBaseURL, "published-bucket": p.PublishedBucket, "inbox-bucket": p.InboxBucket}
	if err := checkTesseraDraft(w.d); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*coordinatorDraft){"circuit": func(d *coordinatorDraft) { d.Circuit = "ownership-destination-v2" }, "beacon": func(d *coordinatorDraft) { d.Policy.Beacon.Lead++ }, "release": func(d *coordinatorDraft) { d.Release = "latest" }, "phase": func(d *coordinatorDraft) { d.Policy.Phase1.Minimum++ }} {
		t.Run(name, func(t *testing.T) {
			d := w.d
			change(&d)
			if checkTesseraDraft(d) == nil {
				t.Fatal("accepted local public-plan drift")
			}
		})
	}
}

func TestSetupV2RealSignedRoundtrip(t *testing.T) {
	binary, fixture := os.Getenv("TESSERA_PROOF_TOOL_BINARY"), os.Getenv("TESSERA_V2_FIXTURE")
	if binary == "" {
		t.Skip("requires pinned proof tool")
	}
	var err error
	artifacts := map[string][]byte{}
	dir := t.TempDir()
	if fixture != "" {
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		old, err := setupv2.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range old.Result.Artifacts {
			artifacts[a.Kind], err = base64.StdEncoding.DecodeString(a.ContentB64)
			if err != nil {
				t.Fatal(err)
			}
		}
	} else {
		root := filepath.Join(dir, "generated")
		cmd := exec.Command(binary, "rehearsal", "init", "--created-at", "2026-09-08T12:00:00Z", "--out-dir", root)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generate rehearsal identities: %v %s", err, output)
		}
		raw, err := os.ReadFile(filepath.Join(root, "config/policy.json"))
		if err != nil {
			t.Fatal(err)
		}
		var policy setupPolicy
		if err = json.Unmarshal(raw, &policy); err != nil {
			t.Fatal(err)
		}
		policy.Beacon.Lead = 180
		raw, _ = json.Marshal(policy)
		os.WriteFile(filepath.Join(dir, "policy.json"), raw, 0600)
		raw, err = os.ReadFile(filepath.Join(root, "config/participants.json"))
		if err != nil {
			t.Fatal(err)
		}
		var roster setupRoster
		if err = json.Unmarshal(raw, &roster); err != nil {
			t.Fatal(err)
		}
		roster.Auditors = roster.Auditors[:1]
		rosterBytes, err := json.Marshal(roster)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "config/participants.json"), rosterBytes, 0600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "signed")
		cmd = exec.Command(binary, "init", "--mode", "rehearsal", "--key-version", "rehearsal-tiny-v1", "--created-at", "2026-09-08T12:00:00Z", "--participants", filepath.Join(root, "config/participants.json"), "--policy", filepath.Join(dir, "policy.json"), "--coordinator-key-id", roster.Coordinator.KeyID, "--coordinator-signing-key", filepath.Join(root, "keys/coordinator.ed25519.private.hex"), "--out-dir", out)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("initialize website profile: %v %s", err, output)
		}
		for kind, name := range map[string]string{"definition": "ceremony.json", "definition-signature": "ceremony.sig", "coordinator-key": "coordinator-public-key.hex"} {
			artifacts[kind], err = os.ReadFile(filepath.Join(out, name))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for kind, b := range artifacts {
		if err = os.WriteFile(filepath.Join(dir, kind), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inspector := transcript.Inspector{Executable: binary, CeremonyPath: filepath.Join(dir, "definition"), CeremonySignaturePath: filepath.Join(dir, "definition-signature"), CoordinatorPublicKeyPath: filepath.Join(dir, "coordinator-key")}
	inspected, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	var d tesseraDefinition
	if err = json.Unmarshal(artifacts["definition"], &d); err != nil {
		t.Fatal(err)
	}
	manifest := setupTestManifestV2(t)
	s := setupTestPlanV2(t, tesseraContextForDefinition(d), manifest)
	if path := os.Getenv("TESSERA_TEST_SETUP_V2"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := setupv2.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		s = *parsed
	}
	if err = checkSetupDefinitionV2(s, artifacts["definition"], artifacts["coordinator-key"], manifest, inspected); err != nil {
		t.Fatal(err)
	}
	before, _ := s.InputDigest()
	s.Result = &setupv2.Result{InputSHA256: before, ProtocolID: inspected.CeremonyID}
	artifacts["software-manifest"] = manifest
	for _, kind := range []string{"definition", "definition-signature", "coordinator-key", "software-manifest"} {
		b := artifacts[kind]
		s.Result.Artifacts = append(s.Result.Artifacts, setupv2.Artifact{Kind: kind, Platform: "none", SHA256: setupv2.Hash(b), ByteLength: len(b), ContentB64: base64.StdEncoding.EncodeToString(b)})
	}
	encoded, _ := json.Marshal(s)
	parsed, err := setupv2.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := parsed.InputDigest()
	if before != after {
		t.Fatal("round trip mutated plan")
	}
	if path := os.Getenv("TESSERA_TEST_OUTPUT_V2"); path != "" {
		if err = writeTesseraFresh(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	originalCircuit := s.Plan.Circuit
	s.Plan.Circuit = "ownership-destination-v2"
	if checkSetupDefinitionV2(s, artifacts["definition"], artifacts["coordinator-key"], manifest, inspected) == nil {
		t.Fatal("accepted signed circuit drift")
	}
	s.Plan.Circuit = originalCircuit
	changed := bytes.Replace(artifacts["definition"], []byte(`"mode":"rehearsal"`), []byte(`"mode":"production"`), 1)
	if bytes.Equal(changed, artifacts["definition"]) {
		changed = append(changed, 'x')
	}
	os.WriteFile(inspector.CeremonyPath, changed, 0600)
	if _, err = inspector.Definition(); err == nil {
		t.Fatal("accepted invalid signature")
	}
}

// Cross-repository test adapter uses the pinned native proof tool in place of
// the release container. It verifies the uploaded bytes, not the source fixture.
func TestSetupV2VerifyUploaded(t *testing.T) {
	path, binary, fixture := os.Getenv("TESSERA_TEST_INPUT_V2"), os.Getenv("TESSERA_PROOF_TOOL_BINARY"), os.Getenv("TESSERA_V2_FIXTURE")
	if path == "" || binary == "" || fixture == "" {
		t.Skip("cross-repository native verifier adapter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupv2.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	original, err := setupv2.Parse(trusted)
	if err != nil {
		t.Fatal(err)
	}
	var manifest []byte
	for _, a := range original.Result.Artifacts {
		if a.Kind == "software-manifest" {
			manifest, _ = base64.StdEncoding.DecodeString(a.ContentB64)
		}
	}
	artifacts := map[string][]byte{}
	dir := t.TempDir()
	for _, a := range s.Result.Artifacts {
		b, _ := base64.StdEncoding.DecodeString(a.ContentB64)
		artifacts[a.Kind] = b
		if err = os.WriteFile(filepath.Join(dir, a.Kind), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(manifest, artifacts["software-manifest"]) {
		t.Fatal("uploaded manifest differs from trusted fixture")
	}
	inspector := transcript.Inspector{Executable: binary, CeremonyPath: filepath.Join(dir, "definition"), CeremonySignaturePath: filepath.Join(dir, "definition-signature"), CoordinatorPublicKeyPath: filepath.Join(dir, "coordinator-key")}
	inspected, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	if err = checkSetupDefinitionV2(*s, artifacts["definition"], artifacts["coordinator-key"], manifest, inspected); err != nil {
		t.Fatal(err)
	}
	if inspected.CeremonyID != s.Result.ProtocolID {
		t.Fatal("uploaded result protocol ID mismatch")
	}
}

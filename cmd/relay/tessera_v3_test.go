package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	setupv3 "github.com/zksecurity/relay/contracts/setupv3"
)

func setupTestManifestV3(t *testing.T) []byte {
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
	m, err := setupManifestV3(commit, raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func setupTestPlanV3(t *testing.T, c tesseraContext, manifest []byte) setupv3.Setup {
	t.Helper()
	var m setupReleaseManifestV3
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	s := setupv3.Setup{Schema: "ceremony-setup-v3", ID: c.CeremonyID, PlanRevision: c.Revision, Plan: setupv3.Plan{
		Mode: c.Mode, Ruleset: setupv3.Rules(), Circuit: "rehearsal-tiny-v1",
		BeaconPolicy:    setupv3.Beacon(c.Mode, 12),
		AssurancePolicy: setupv3.AssurancePolicy{PassingCeremonyAudits: 1},
		SoftwareRelease: setupv3.Software{ReleaseTag: m.ReleaseTag, CLICommit: m.CLICommit, ProofToolCommit: m.ProofToolCommit, ManifestSHA256: setupv3.Hash(manifest), WorkflowRecipeSHA256: setupRecipeDigestV3()},
		Storage:         setupv3.Storage{Provider: "aws", Region: "us-east-1", PublicBaseURL: "https://public.example.test", PublishedBucket: "published-test", InboxBucket: "inbox-test"},
	}}
	ids := map[string]string{}
	for _, a := range c.Assignments {
		i := a.Identity
		s.Plan.Identities = append(s.Plan.Identities, setupv3.Identity{ID: i.ID, DisplayName: i.DisplayName, KeyID: i.KeyID, PublicKey: i.PublicKey, Fingerprint: i.Fingerprint})
		s.Plan.Roles = append(s.Plan.Roles, setupv3.Role{ID: a.ID, Role: a.Role, IdentityID: i.ID})
		ids[a.ID] = i.ID
	}
	for _, p := range c.Schedules {
		phase := setupv3.Phase{ID: p.Phase, Minimum: p.Minimum}
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

func TestSetupV3PlanDrift(t *testing.T) {
	c, _, _ := tesseraFixture(t)
	s := setupTestPlanV3(t, c, setupTestManifestV3(t))
	w := setupFixture(t)
	w.d.TesseraSetupV3 = &s
	w.d.Mode, w.d.Circuit, w.d.Release = s.Plan.Mode, s.Plan.Circuit, s.Plan.SoftwareRelease.ReleaseTag
	w.d.Identities, w.d.Policy.Phase1, w.d.Policy.Phase2 = setupContextV3(s).setupInputs()
	raw, _ := json.Marshal(s.Plan.BeaconPolicy)
	if err := json.Unmarshal(raw, &w.d.Policy.Beacon); err != nil {
		t.Fatal(err)
	}
	w.d.Policy.Assurance = &setupAssurance{PassingCeremonyAudits: 1}
	p := s.Plan.Storage
	w.d.Storage = map[string]string{"provider": p.Provider, "region": p.Region, "published-base-url": p.PublicBaseURL, "published-bucket": p.PublishedBucket, "inbox-bucket": p.InboxBucket}
	if err := checkTesseraDraft(w.d); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*coordinatorDraft){
		"beacon wait": func(d *coordinatorDraft) { d.Policy.Beacon.Lead++ },
		"assurance":   func(d *coordinatorDraft) { d.Policy.Assurance.MirrorsPerAcceptedHead++ },
		"release":     func(d *coordinatorDraft) { d.Release = "latest" },
	} {
		t.Run(name, func(t *testing.T) {
			d := w.d
			a := *d.Policy.Assurance
			d.Policy.Assurance = &a
			change(&d)
			if checkTesseraDraft(d) == nil {
				t.Fatal("accepted local public-plan drift")
			}
		})
	}
}

func TestSetupV3AcceptsAuthenticatedDefinitionV3(t *testing.T) {
	c, definition, inspected := tesseraFixture(t)
	definition.Schema = "proof-tool-mpc-ceremony-definition-v3"
	manifest := setupTestManifestV3(t)
	setup := setupTestPlanV3(t, c, manifest)
	var public map[string]any
	raw, _ := json.Marshal(definition)
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	public["circuit"] = map[string]any{"key_version": setup.Plan.Circuit}
	public["beacon_policy"] = setup.Plan.BeaconPolicy
	public["assurance_policy"] = setup.Plan.AssurancePolicy
	raw, _ = json.Marshal(public)
	if err := checkSetupDefinitionV3(setup, raw, []byte(definition.Coordinator.PublicKey), manifest, inspected); err != nil {
		t.Fatalf("authenticated v3 definition rejected: %v", err)
	}
	public["assurance_policy"] = setupv3.AssurancePolicy{}
	tampered, _ := json.Marshal(public)
	if err := checkSetupDefinitionV3(setup, tampered, []byte(definition.Coordinator.PublicKey), manifest, inspected); err == nil {
		t.Fatal("changed signed assurance policy accepted")
	}
}

func TestRunSetupBySchemaRejectsUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup.json")
	if err := os.WriteFile(path, []byte(`{"schema":"ceremony-setup-v99"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSetupBySchema([]string{"--setup", path}, false); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown setup schema error = %v", err)
	}
}

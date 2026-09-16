package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4ProfileBinding(t *testing.T) {
	protocol, existing := workflowV4TestBinding(t)
	r := existing.Runtimes["online"]
	p := guidedProfile{Name: "coordinator-test", Role: "coordinator", Work: existing.Work, Trust: r.Mounts["/trust"], Keys: r.Mounts["/keys"], Image: r.Image, Platform: r.Platform, ReleaseCommit: strings.Repeat("a", 40)}
	signer := p
	signer.Role, signer.Name = "decision-signer", offlineRoleAlias(p.Name, p.Role)
	identity := setupIdentity{ID: "coordinator-test", DisplayName: "Coordinator", KeyID: "coordinator-key", PublicKey: strings.Repeat("00", 32), Fingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(make([]byte, 32)))}
	for n := range protocol.Definition.Journey.RequiredEnrollments {
		e := &protocol.Definition.Journey.RequiredEnrollments[n]
		if e.Role == "coordinator" {
			e.Identity.KeyID, e.Identity.Ed25519PublicKeyHex, e.Identity.PublicKeyFingerprint = identity.KeyID, identity.PublicKey, identity.Fingerprint
		}
	}
	b, err := workflowV4ProfileBinding(p, signer, protocol, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.Definition != protocol.DefinitionRefs || b.IdentityID != identity.ID || len(b.Runtimes) != 2 || b.Runtimes["signer"].Mounts["/keys"] != p.Keys {
		t.Fatal("incorrect saved profile binding")
	}
	for _, change := range []func(*guidedProfile){
		func(s *guidedProfile) { s.Name += "-other" },
		func(s *guidedProfile) { s.Work = t.TempDir() },
		func(s *guidedProfile) { s.Keys = t.TempDir() },
		func(s *guidedProfile) { s.ReleaseCommit = strings.Repeat("b", 40) },
		func(s *guidedProfile) { s.Platform = "linux/amd64" },
		func(s *guidedProfile) { s.Image = "mutable:latest" },
		func(s *guidedProfile) { s.Command = []string{"mpc-ceremony", "ops", "sign"} },
		func(s *guidedProfile) { s.Credentials = "/private/credentials" },
		func(s *guidedProfile) { s.R2Parent = "/private/parent" },
		func(s *guidedProfile) { s.R2Control = "/private/control" },
	} {
		bad := signer
		change(&bad)
		if _, err := workflowV4ProfileBinding(p, bad, protocol, identity, nil); err == nil {
			t.Fatal("mismatched signer accepted")
		}
	}
	identity.KeyID = "other-key"
	if _, err := workflowV4ProfileBinding(p, signer, protocol, identity, nil); err == nil {
		t.Fatal("wrong identity accepted")
	}
}

func TestWorkflowV4ParticipantProfileBinding(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	r := b.Runtimes["online"]
	p := guidedProfile{Name: b.Name, Role: b.Role, Work: b.Work, Trust: r.Mounts["/trust"], Keys: r.Mounts["/keys"], Image: r.Image, Platform: r.Platform}
	signer := p
	signer.Role, signer.Name = "decision-signer", offlineRoleAlias(p.Name, p.Role)
	id := setupIdentity{ID: b.IdentityID, DisplayName: "Participant", KeyID: "participant-key", PublicKey: strings.Repeat("00", 32), Fingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(make([]byte, 32)))}
	for n := range protocol.Definition.Journey.RequiredEnrollments {
		e := &protocol.Definition.Journey.RequiredEnrollments[n]
		if e.Role == "participant" {
			e.Identity.KeyID, e.Identity.Ed25519PublicKeyHex, e.Identity.PublicKeyFingerprint = id.KeyID, id.PublicKey, id.Fingerprint
		}
	}
	root := filepath.Join(p.Work, "ceremony", "public")
	c := access.RoleConfig{Schema: access.RoleConfigSchema, Role: "participant", IdentityID: id.ID, Phase: "phase1", CeremonyID: b.CeremonyID, CeremonyHome: filepath.Dir(root), Root: root, Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"), CoordinatorKey: filepath.Join(p.Trust, "coordinator-public-key.hex"), CeremonyBinary: "/usr/local/bin/mpc-ceremony", SigningKey: filepath.Join(p.Keys, "signing.hex"), Environment: filepath.Join(p.Work, "environment.json"), RunRoot: filepath.Join(p.Work, "runs"), StorageConfig: filepath.Join(p.Work, "storage.json"), PublishedBaseURL: "https://public.example.test", PublishedBucket: "published", ExecutionMode: "docker", DockerImage: p.Image, DockerPlatform: p.Platform}
	c.DockerCLI = "docker"
	if _, err := workflowV4ProfileBinding(p, signer, protocol, id, &c); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*access.RoleConfig){
		func(c *access.RoleConfig) { c.IdentityID = "other" },
		func(c *access.RoleConfig) { c.Root = t.TempDir() },
		func(c *access.RoleConfig) { c.SigningKey = filepath.Join(t.TempDir(), "signing.hex") },
		func(c *access.RoleConfig) { c.DockerImage = "example.test/role@sha256:" + strings.Repeat("e", 64) },
		func(c *access.RoleConfig) { c.CoordinatorKey = filepath.Join(t.TempDir(), "key.hex") },
	} {
		bad := c
		mutate(&bad)
		if _, err := workflowV4ProfileBinding(p, signer, protocol, id, &bad); err == nil {
			t.Fatal("mismatched participant profile accepted")
		}
	}
}

func TestWorkflowV4ReleaseSignerProfileBinding(t *testing.T) {
	protocol, existing := workflowV4TestBinding(t)
	r := existing.Runtimes["online"]
	p := guidedProfile{Name: "release-test", Role: "release-signer", Work: existing.Work, Trust: r.Mounts["/trust"], Keys: r.Mounts["/keys"], Image: r.Image, Platform: r.Platform, ReleaseCommit: strings.Repeat("a", 40)}
	signer := p
	signer.Role, signer.Name = "decision-signer", offlineRoleAlias(p.Name, p.Role)
	id := setupIdentity{ID: "release-signer-test", DisplayName: "Release signer", KeyID: "release-key", PublicKey: strings.Repeat("01", 32), Fingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(bytes.Repeat([]byte{1}, 32)))}
	found := false
	for n := range protocol.Definition.Journey.RequiredEnrollments {
		e := &protocol.Definition.Journey.RequiredEnrollments[n]
		if e.Role == "release-signer" {
			e.Identity = transcript.PublicIdentity{ID: id.ID, DisplayName: id.DisplayName, KeyID: id.KeyID, Ed25519PublicKeyHex: id.PublicKey, PublicKeyFingerprint: id.Fingerprint}
			found = true
		}
	}
	if !found {
		t.Fatal("fixture lacks release signer")
	}
	binding, err := workflowV4ProfileBinding(p, signer, protocol, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Role != "release-signer" || binding.IdentityID != id.ID || len(binding.Runtimes) != 2 {
		t.Fatalf("release signer binding = %#v", binding)
	}
}

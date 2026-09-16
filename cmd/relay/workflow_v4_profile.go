package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

// Bind the new workflow to existing onboarding profiles. This does not migrate
// legacy completion records or select a replacement runtime for interrupted work.
func workflowV4ProfileBinding(p, signer guidedProfile, protocol transcript.DefinitionProtocol, identity setupIdentity, participant *access.RoleConfig) (workflowV4Binding, error) {
	var zero workflowV4Binding
	if !protocol.UsesV4() || (p.Role != "coordinator" && p.Role != "participant" && p.Role != "release-signer") || len(p.Command) != 0 {
		return zero, errors.New("storage-first guide requires an authenticated V4 coordinator, participant or release-signer profile")
	}
	if err := identity.check(); err != nil {
		return zero, err
	}
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return zero, err
	}
	assigned := false
	for _, e := range journey.RequiredEnrollments {
		if e.Role == p.Role && e.Identity.ID == identity.ID && e.Identity.KeyID == identity.KeyID && e.Identity.Ed25519PublicKeyHex == identity.PublicKey && e.Identity.PublicKeyFingerprint == identity.Fingerprint {
			assigned = true
		}
	}
	if !assigned {
		return zero, errors.New("your saved identity does not match this role in the authenticated ceremony")
	}
	if signer.Role != "decision-signer" || signer.Name != offlineRoleAlias(p.Name, p.Role) || signer.Work != p.Work || signer.Trust != p.Trust || signer.Keys != p.Keys || signer.ReleaseCommit != p.ReleaseCommit || signer.Platform != p.Platform || len(signer.Command) != 0 || signer.Credentials != "" || signer.R2Parent != "" || signer.R2Control != "" {
		return zero, errors.New("network-disabled signing profile must match this role's folders, platform and release")
	}
	runtime := func(image, platform string) workflowV4Runtime {
		return workflowV4Runtime{Image: image, Platform: platform, Mounts: map[string]string{"/work": p.Work, "/trust": p.Trust, "/keys": p.Keys}}
	}
	b := workflowV4Binding{CeremonyID: protocol.Definition.CeremonyID, Definition: protocol.DefinitionRefs, Name: p.Name, Role: p.Role, IdentityID: identity.ID, Work: p.Work, Runtimes: map[string]workflowV4Runtime{"online": runtime(p.Image, p.Platform), "signer": runtime(signer.Image, signer.Platform)}}
	if p.Role == "participant" {
		if participant == nil {
			return zero, errors.New("prepare your participant phase profile first")
		}
		if err := participant.Validate(); err != nil {
			return zero, err
		}
		if participant.CeremonyBinary != "/usr/local/bin/mpc-ceremony" || participant.CeremonyHome != filepath.Join(p.Work, "ceremony") {
			return zero, errors.New("participant profile must use the saved ceremony folder and the image's fixed proof-tool executable")
		}
		if participant.Role != "participant" || participant.IdentityID != identity.ID || participant.CeremonyID != b.CeremonyID || participant.ExecutionMode != "docker" || participant.DockerImage != p.Image || participant.DockerPlatform != p.Platform || participant.Root != filepath.Join(p.Work, "ceremony", "public") || participant.Ceremony != filepath.Join(participant.Root, "ceremony.json") || participant.CeremonySignature != filepath.Join(participant.Root, "ceremony.sig") || participant.SigningKey != filepath.Join(p.Keys, "signing.hex") {
			return zero, errors.New("participant phase profile does not match the saved ceremony, identity, folders and runtime")
		}
		if _, err := pathWithin(p.Trust, participant.CoordinatorKey, "/trust"); err != nil {
			return zero, fmt.Errorf("participant trust anchor: %w", err)
		}
		for _, path := range []string{participant.Environment, participant.RunRoot, participant.StorageConfig} {
			if _, err := pathWithin(p.Work, path, "/work"); err != nil {
				return zero, fmt.Errorf("participant workspace input: %w", err)
			}
		}
		b.Runtimes["contributor"] = runtime(participant.DockerImage, participant.DockerPlatform)
	}
	if err := validateWorkflowV4Binding(b); err != nil {
		return zero, err
	}
	return b, nil
}

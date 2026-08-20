package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

// TestProofToolCompatibility exercises Relay against a real, locally built
// proof-tool binary and proof-tool's complete signed rehearsal generator. It is
// opt-in because proof-tool is a separate repository and is intentionally not
// a Go dependency of Relay.
//
// Run the fast compatibility checks with:
//
//	(cd /path/to/proof-tool && bash scripts/bootstrap-vendor.sh)
//	RELAY_PROOF_TOOL_DIR=/path/to/proof-tool go test ./cmd/relay \
//	  -run TestProofToolCompatibility -v
//
// Add RELAY_PROOF_TOOL_FULL=1 to also initialize a production-sized ceremony,
// contribute, attest erasure, and verify the resulting candidate.
func TestProofToolCompatibility(t *testing.T) {
	proofToolDir := os.Getenv("RELAY_PROOF_TOOL_DIR")
	if proofToolDir == "" {
		t.Skip("set RELAY_PROOF_TOOL_DIR to run the cross-repository compatibility test")
	}
	proofToolDir, err := filepath.Abs(proofToolDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(proofToolDir, "go.mod")); err != nil {
		t.Fatalf("invalid RELAY_PROOF_TOOL_DIR: %v", err)
	}

	root := t.TempDir()
	ceremonyBinary := filepath.Join(root, "mpc-ceremony")
	workflowHelper := filepath.Join(root, "workflow-helper")
	operationalHelper := filepath.Join(root, "operational-helper")
	buildProofProgram(t, proofToolDir, ceremonyBinary, "./cmd/mpc-ceremony")
	buildProofProgram(t, proofToolDir, workflowHelper, "./internal/mpcceremony/testdata/workflowhelper")
	buildProofProgram(t, proofToolDir, operationalHelper, "./scripts/mpc-rehearsal-operational-evidence")

	downloadableRoot := filepath.Join(root, "downloadable-rehearsal")
	runProofCommand(t, proofToolDir, ceremonyBinary,
		"rehearsal", "init",
		"--created-at", "2026-08-20T06:00:00Z",
		"--out-dir", downloadableRoot)
	downloadableInspector := transcript.Inspector{
		Executable:               ceremonyBinary,
		CeremonyPath:             filepath.Join(downloadableRoot, "public", "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(downloadableRoot, "public", "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(downloadableRoot, "public", "coordinator-public-key.hex"),
		TranscriptRoot:           filepath.Join(downloadableRoot, "public"),
	}
	downloadableDefinition, err := downloadableInspector.Definition()
	if err != nil {
		t.Fatalf("Relay inspection of downloadable tiny rehearsal: %v", err)
	}
	if len(downloadableDefinition.Phase1Participants) != 3 ||
		downloadableDefinition.Phase1Participants[0] != "participant-01" ||
		downloadableDefinition.Phase1Participants[2] != "participant-03" {
		t.Fatalf("downloadable rehearsal definition = %#v", downloadableDefinition)
	}

	workflowRoot := filepath.Join(root, "workflow")
	runProofCommand(t, proofToolDir, workflowHelper, workflowRoot, operationalHelper)
	ceremonyRoot := filepath.Join(workflowRoot, "ceremony")
	keyRoot := filepath.Join(workflowRoot, "identity-keys")
	inspector := transcript.Inspector{
		Executable:               ceremonyBinary,
		CeremonyPath:             filepath.Join(ceremonyRoot, "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(ceremonyRoot, "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(keyRoot, "trusted-coordinator.ed25519.public.hex"),
		TranscriptRoot:           ceremonyRoot,
	}

	definition, err := inspector.Definition()
	if err != nil {
		t.Fatalf("Relay decode of proof-tool definition inspection: %v", err)
	}
	if len(definition.Phase1Participants) != 2 || definition.Phase1Participants[0] != "participant-01" {
		t.Fatalf("definition projection = %#v", definition)
	}
	chainPath := filepath.Join(ceremonyRoot, "phase1", "chain-0002.json")
	chainSignaturePath := filepath.Join(ceremonyRoot, "phase1", "chain-0002.sig")
	chain, err := inspector.Chain(chainPath, chainSignaturePath)
	if err != nil {
		t.Fatalf("Relay decode of proof-tool chain inspection: %v", err)
	}
	if chain.AcceptedCount() != 2 || chain.Records[1].ParticipantID != "participant-02" {
		t.Fatalf("chain projection = %#v", chain)
	}

	participantKey := filepath.Join(keyRoot, "participant-01.ed25519.private.hex")
	participant, err := inspector.Participant(participantKey)
	if err != nil {
		t.Fatalf("Relay decode of proof-tool participant inspection: %v", err)
	}
	if participant.ParticipantID != "participant-01" || participant.Phase1Position == nil || *participant.Phase1Position != 1 {
		t.Fatalf("participant projection = %#v", participant)
	}

	enrollmentRoot := filepath.Join(ceremonyRoot, "operational", "enrollments")
	roleCases := []struct {
		relayRole string
		identity  string
	}{
		{access.RoleWitness, "witness-01"},
		{access.RoleMirror, "mirror-01"},
		{access.RoleAuditor, "auditor-01"},
		{access.RoleRelease, "release-signer"},
		{access.RoleDecision, "coordinator"},
	}
	storage := access.StorageConfig{
		Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: definition.CeremonyID,
		Endpoint: "https://example.r2.cloudflarestorage.com", Region: "auto",
		AccountID: strings.Repeat("a", 32), ParentAccessKeyID: "parent-access-key",
		PublishedBucket: "published", PublishedBaseURL: "https://ceremony.example.org",
		InboxBucket: "inbox", CoordinatorProfile: "coordinator",
		CeremonyPath: inspector.CeremonyPath, CeremonySignature: inspector.CeremonySignaturePath,
		CoordinatorPublicKey: inspector.CoordinatorPublicKeyPath, CeremonyBinary: ceremonyBinary,
	}
	for _, test := range roleCases {
		t.Run("grant-"+test.relayRole, func(t *testing.T) {
			record := filepath.Join(enrollmentRoot, test.identity+".json")
			signature := filepath.Join(enrollmentRoot, test.identity+".sig")
			if err := authenticateGrantIdentity(storage, test.relayRole, test.identity, record, signature); err != nil {
				t.Fatalf("proof-tool enrollment projection rejected: %v", err)
			}
		})
	}

	storagePath := filepath.Join(root, "relay-storage.json")
	if err := writeJSONNoReplace(storagePath, storage, 0o600); err != nil {
		t.Fatal(err)
	}
	productionHome := filepath.Join(root, "production-home")
	publicRoot := filepath.Join(productionHome, "public")
	if err := os.MkdirAll(publicRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		raw, err := os.ReadFile(filepath.Join(ceremonyRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(publicRoot, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	environmentPath := filepath.Join(root, "environment.json")
	if err := os.WriteFile(environmentPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runInitRoleConfig([]string{
		"--home", productionHome, "--role", access.RoleParticipant, "--phase", "phase1",
		"--storage", storagePath, "--coordinator-key", inspector.CoordinatorPublicKeyPath,
		"--ceremony-binary", ceremonyBinary, "--signing-key", participantKey,
		"--environment", environmentPath,
	}); err != nil {
		t.Fatalf("participant production role config: %v", err)
	}
	participantRolePath := filepath.Join(productionHome, "config", "participant-phase1.json")
	participantRole, err := loadRoleConfig(participantRolePath, access.RoleParticipant)
	if err != nil || participantRole.IdentityID != "participant-01" {
		t.Fatalf("load participant production role config = %#v, %v", participantRole, err)
	}
	witnessRecord := filepath.Join(enrollmentRoot, "witness-01.json")
	witnessSignature := filepath.Join(enrollmentRoot, "witness-01.sig")
	if err := runInitRoleConfig([]string{
		"--home", productionHome, "--role", access.RoleWitness, "--phase", "phase1",
		"--storage", storagePath, "--coordinator-key", inspector.CoordinatorPublicKeyPath,
		"--ceremony-binary", ceremonyBinary, "--enrollment", witnessRecord,
		"--enrollment-signature", witnessSignature,
	}); err != nil {
		t.Fatalf("witness production role config: %v", err)
	}
	witnessRolePath := filepath.Join(productionHome, "config", "witness-phase1.json")
	witnessRole, err := loadRoleConfig(witnessRolePath, access.RoleWitness)
	if err != nil || witnessRole.IdentityID != "witness-01" || witnessRole.SigningKey != "" {
		t.Fatalf("load witness production role config = %#v, %v", witnessRole, err)
	}
	prefix, err := access.Prefix(definition.CeremonyID, access.RoleParticipant, "participant-01")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant := access.Grant{
		Schema: access.GrantSchema, Provider: "r2", CeremonyID: definition.CeremonyID,
		Role: access.RoleParticipant, IdentityID: "participant-01",
		Endpoint: storage.Endpoint, Region: "auto", InboxBucket: "inbox", Prefix: prefix,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
		MinimumRemaining: "1h", Credentials: access.SessionCredentials{
			AccessKeyID: "temporary-id", SecretAccessKey: "temporary-secret", SessionToken: "temporary-token",
		},
	}
	grantPath := filepath.Join(root, "participant.grant.json")
	if err := writeJSONNoReplace(grantPath, grant, 0o600); err != nil {
		t.Fatal(err)
	}
	participantConfigPath := filepath.Join(root, "participant.relay.json")
	if err := runEnroll([]string{
		"--storage", storagePath, "--grant", grantPath, "--phase", "phase1",
		"--root", ceremonyRoot, "--ceremony", inspector.CeremonyPath,
		"--ceremony-signature", inspector.CeremonySignaturePath,
		"--coordinator-key", inspector.CoordinatorPublicKeyPath,
		"--ceremony-binary", ceremonyBinary, "--signing-key", participantKey,
		"--environment", environmentPath,
		"--candidate-parent", filepath.Join(root, "candidates"), "--out", participantConfigPath,
	}); err != nil {
		t.Fatalf("Relay enroll against proof-tool: %v", err)
	}
	configRaw, err := os.ReadFile(participantConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Decode(configRaw, access.ParticipantConfig.Validate); err != nil {
		t.Fatalf("generated participant config: %v", err)
	}
	grantFreeConfigPath := filepath.Join(root, "participant-grant-free.relay.json")
	if err := runEnroll([]string{
		"--storage", storagePath, "--phase", "phase1",
		"--root", ceremonyRoot, "--ceremony", inspector.CeremonyPath,
		"--ceremony-signature", inspector.CeremonySignaturePath,
		"--coordinator-key", inspector.CoordinatorPublicKeyPath,
		"--ceremony-binary", ceremonyBinary, "--signing-key", participantKey,
		"--environment", environmentPath,
		"--candidate-parent", filepath.Join(root, "grant-free-candidates"), "--out", grantFreeConfigPath,
	}); err != nil {
		t.Fatalf("grant-free Relay enrollment against proof-tool: %v", err)
	}
	grantFreeRaw, err := os.ReadFile(grantFreeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	grantFreeConfig, err := access.Decode(grantFreeRaw, access.ParticipantConfig.Validate)
	if err != nil {
		t.Fatalf("generated grant-free participant config: %v", err)
	}
	if grantFreeConfig.Schema != access.ParticipantConfigSchema || grantFreeConfig.GrantPath != "" {
		t.Fatalf("grant-free profile schema/grant = %q/%q", grantFreeConfig.Schema, grantFreeConfig.GrantPath)
	}

	tamperedChain := filepath.Join(root, "tampered-chain.json")
	rawChain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedChain, append(rawChain, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Chain(tamperedChain, chainSignaturePath); err == nil {
		t.Fatal("Relay accepted proof-tool inspection of a non-canonical tampered chain")
	}

	t.Run("contribute-and-accept", func(t *testing.T) {
		if os.Getenv("RELAY_PROOF_TOOL_FULL") != "1" {
			t.Skip("set RELAY_PROOF_TOOL_FULL=1 to run the production-sized cryptographic workflow")
		}
		testProofToolContributionCommands(t, ceremonyBinary, workflowRoot)
	})
}

func testProofToolContributionCommands(t *testing.T, ceremonyBinary, fixtureRoot string) {
	t.Helper()
	sourceDefinitionPath := filepath.Join(fixtureRoot, "ceremony", "ceremony.json")
	sourceRaw, err := os.ReadFile(sourceDefinitionPath)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Coordinator   json.RawMessage `json:"coordinator"`
		ReleaseSigner json.RawMessage `json:"release_signer"`
		Auditors      json.RawMessage `json:"auditors"`
		Roster        json.RawMessage `json:"roster"`
		Phase1Policy  json.RawMessage `json:"phase1_policy"`
		Phase2Policy  json.RawMessage `json:"phase2_policy"`
		BeaconPolicy  json.RawMessage `json:"beacon_policy"`
	}
	if err := json.Unmarshal(sourceRaw, &source); err != nil {
		t.Fatal(err)
	}
	participants := struct {
		Coordinator   json.RawMessage `json:"coordinator"`
		ReleaseSigner json.RawMessage `json:"release_signer"`
		Auditors      json.RawMessage `json:"auditors"`
		Roster        json.RawMessage `json:"roster"`
	}{source.Coordinator, source.ReleaseSigner, source.Auditors, source.Roster}
	policy := struct {
		Phase1Policy json.RawMessage `json:"phase1_policy"`
		Phase2Policy json.RawMessage `json:"phase2_policy"`
		BeaconPolicy json.RawMessage `json:"beacon_policy"`
	}{source.Phase1Policy, source.Phase2Policy, source.BeaconPolicy}
	var coordinator struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(source.Coordinator, &coordinator); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	participantsPath := filepath.Join(root, "participants.json")
	policyPath := filepath.Join(root, "policy.json")
	writeTestJSON(t, participantsPath, participants)
	writeTestJSON(t, policyPath, policy)
	ceremonyRoot := filepath.Join(root, "ceremony")
	coordinatorSigningKey := filepath.Join(fixtureRoot, "identity-keys", "coordinator.ed25519.private.hex")
	runProofCommand(t, root, ceremonyBinary,
		"init", "--mode", "rehearsal", "--created-at", "2026-08-18T12:00:00Z",
		"--session-nonce-hex", strings.Repeat("cd", 32),
		"--key-version", "ownership-destination-v2", "--participants", participantsPath,
		"--policy", policyPath, "--coordinator-key-id", coordinator.KeyID,
		"--coordinator-signing-key", coordinatorSigningKey, "--out-dir", ceremonyRoot)

	inspector := transcript.Inspector{
		Executable: ceremonyBinary, CeremonyPath: filepath.Join(ceremonyRoot, "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(ceremonyRoot, "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(ceremonyRoot, "coordinator-public-key.hex"),
		TranscriptRoot:           ceremonyRoot,
	}
	definition, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(ceremonyRoot, "phase1", "chain-0000.json")
	chainSignature := filepath.Join(ceremonyRoot, "phase1", "chain-0000.sig")
	chain, err := inspector.Chain(chainPath, chainSignature)
	if err != nil {
		t.Fatal(err)
	}
	environmentPath := filepath.Join(root, "environment.json")
	writeTestJSON(t, environmentPath, struct {
		OS                           string `json:"os"`
		Architecture                 string `json:"architecture"`
		EntropySource                string `json:"entropy_source"`
		SwapDisabled                 bool   `json:"swap_disabled"`
		CrashDumpsDisabled           bool   `json:"crash_dumps_disabled"`
		TelemetryDisabled            bool   `json:"telemetry_disabled"`
		EphemeralEnvironment         bool   `json:"ephemeral_environment"`
		EphemeralDestructionRequired bool   `json:"ephemeral_destruction_required"`
	}{"linux", "amd64", "operating-system-csprng", true, true, true, true, true})
	participantKey := filepath.Join(fixtureRoot, "identity-keys", "participant-01.ed25519.private.hex")
	candidateDir := filepath.Join(root, "candidate")
	o := roleOpts{
		root: ceremonyRoot, definition: inspector.CeremonyPath, definitionSig: inspector.CeremonySignaturePath,
		coordinatorKey: inspector.CoordinatorPublicKeyPath, ceremonyBinary: ceremonyBinary,
		phase: "phase1", role: "participant-01", signingKey: participantKey,
		envPath: environmentPath, outDir: candidateDir,
	}
	pos := position{definition: definition, chain: chain, chainPath: chainPath, nextID: "participant-01", nextIndex: 1}
	if err := runNext(o, pos); err != nil {
		t.Fatalf("Relay contribution invocation against proof-tool: %v", err)
	}
	if err := runErasure(o); err != nil {
		t.Fatalf("Relay erasure invocation against proof-tool: %v", err)
	}
	runProofCommand(t, root, ceremonyBinary,
		"phase1", "verify", "--ceremony", inspector.CeremonyPath,
		"--ceremony-signature", inspector.CeremonySignaturePath,
		"--coordinator-public-key-file", inspector.CoordinatorPublicKeyPath,
		"--transcript-dir", ceremonyRoot, "--chain", chainPath,
		"--chain-signature", chainSignature, "--candidate-dir", candidateDir,
		"--coordinator-signing-key", coordinatorSigningKey,
		"--accepted-at", defaultAcceptanceTimestamp(time.Now().Add(time.Second)))
	accepted, err := inspector.Chain(
		filepath.Join(ceremonyRoot, "phase1", "chain-0001.json"),
		filepath.Join(ceremonyRoot, "phase1", "chain-0001.sig"),
	)
	if err != nil {
		t.Fatalf("Relay inspection of proof-tool accepted chain: %v", err)
	}
	if accepted.AcceptedCount() != 1 || accepted.Records[0].ParticipantID != "participant-01" {
		t.Fatalf("accepted proof-tool chain = %#v", accepted)
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildProofProgram(t *testing.T, proofToolDir, output, packagePath string) {
	t.Helper()
	command := exec.Command("go", "build", "-mod=vendor", "-o", output, packagePath)
	command.Dir = proofToolDir
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build proof-tool program %s: %v\n%s", packagePath, err, combined)
	}
}

func runProofCommand(t *testing.T, directory, executable string, args ...string) {
	t.Helper()
	command := exec.Command(executable, args...)
	command.Dir = directory
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run %s: %v\n%s", executable, err, combined)
	}
}

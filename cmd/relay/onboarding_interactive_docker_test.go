package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

// These dialogues run the real menus and real Docker cryptographic commands.
// Only software delivery is injected: locally built immutable images are NOT
// represented as published releases. No cloud permissions or independent
// operators are asserted by this same-machine test.
func TestAllRoleInteractiveDockerOnboarding(t *testing.T) {
	if os.Getenv("RELAY_FLOW_DOCKER") != "1" {
		t.Skip("opt-in real Docker dialogue test")
	}
	online, offline := os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), os.Getenv("RELAY_ROLE_OFFLINE_IMAGE")
	if !roleImagePattern.MatchString(online) || !roleImagePattern.MatchString(offline) {
		t.Fatal("immutable local test images required")
	}
	platform := os.Getenv("RELAY_ROLE_PLATFORM")
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	bound := client.BindHost(endpoint)
	var compatibility struct {
		Schema string `json:"schema"`
		Test   string `json:"test"`
		Relay  string `json:"relay_sha256"`
		Proof  string `json:"mpc_ceremony_sha256"`
	}
	if err := setupReadJSON(os.Getenv("RELAY_TEST_COMPATIBILITY"), &compatibility); err != nil {
		t.Fatalf("first run the real binary compatibility script and supply RELAY_TEST_COMPATIBILITY: %v", err)
	}
	if compatibility.Schema != "ceremony-kit-compatibility-v1" || compatibility.Test != "tiny-rehearsal-phase1-contribution-v1" || !sha256HexPattern.MatchString(compatibility.Relay) || !sha256HexPattern.MatchString(compatibility.Proof) {
		t.Fatal("invalid local compatibility evidence")
	}
	run := func(role, work, trust, keys string, command []string) error {
		image := online
		if role == "keygen" || role == "decision-signer" || role == "release-signer" {
			image = offline
		}
		args, err := dockerRoleArgs(dockerRoleOptions{role: role, image: image, platform: platform, work: work, trust: trust, keys: keys}, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		stdout, stderr, err := bound.Output(args...)
		if err != nil {
			return fmt.Errorf("%s: %w\n%s\n%s", role, err, stdout, stderr)
		}
		return nil
	}
	roles := []string{"participant", "witness", "mirror", "auditor", "auditor", "release-signer", "upload-station"}
	preparers := []*rolePreparer{}
	identities := []setupIdentity{}
	dialogue := func(p *rolePreparer, input string) {
		t.Helper()
		p.ui.input = bufio.NewReader(strings.NewReader(input))
		p.ui.output = new(bytes.Buffer)
		if err := p.menu(); err != nil {
			t.Fatal(err)
		}
		output := p.ui.output.(*bytes.Buffer).String()
		if strings.Contains(output, "Stopped:") {
			t.Fatalf("%s menu stopped:\n%s", p.d.Role, output)
		}
		if os.Getenv("RELAY_DIALOGUE_TRACE") == "1" {
			t.Logf("%s dialogue: %s", p.d.Role, output)
		} else {
			t.Logf("%s menu dialogue passed", p.d.Role)
		}
	}
	for n, role := range roles {
		p := preparationFixture(t, role)
		p.d.Name = fmt.Sprintf("local-role-%d", n)
		if role != "upload-station" {
			prepareTestProfile(t, p, "keygen")
			prepareTestProfile(t, p, "decision-signer")
		}
		if role != "participant" {
			prepareTestProfile(t, p, role)
		}
		p.run = func(args []string) error {
			if len(args) > 1 && args[0] == "ceremony" && args[1] == "init-config" {
				binary := os.Getenv("RELAY_NATIVE_TEST_BINARY")
				if binary == "" {
					return fmt.Errorf("native test launcher required for participant profile")
				}
				out, err := exec.Command(binary, args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("native profile: %w\n%s", err, out)
				}
				return nil
			}
			if len(args) < 3 || args[0] != "ceremony" || args[1] != "open" {
				return fmt.Errorf("unexpected test action: %q", args)
			}
			r := commandValue(args, "role")
			split := -1
			for n, arg := range args {
				if arg == "--" {
					split = n
					break
				}
			}
			if split < 0 {
				return fmt.Errorf("missing command")
			}
			work, trust, keys := p.d.Work, p.d.Trust, p.d.Keys
			if r == "keygen" {
				work, trust, keys = p.d.Keys, "", ""
			}
			if r == "witness" || r == "mirror" || r == "upload-station" {
				keys = ""
			}
			return run(r, work, trust, keys, args[split+1:])
		}
		input := "6\n0\n"
		if role != "upload-station" {
			input = fmt.Sprintf("2\nLocal %s %d\n", role, n)
			if role == "release-signer" {
				input += "OFFLINE\n"
			}
			input += "GENERATE\n0\n"
		}
		dialogue(p, input)
		var id setupIdentity
		if role != "upload-station" {
			if err := setupReadJSON(filepath.Join(p.d.Keys, "identity.json"), &id); err != nil {
				t.Fatal(err)
			}
		}
		preparers = append(preparers, p)
		identities = append(identities, id)
	}
	// Coordinator starts empty, generates its own key, and imports the public
	// identity files produced through the other roles' real menu dialogues.
	root := privateRoleTestDir(t)
	w := coordinatorWizard{d: coordinatorDraft{Schema: "relay-coordinator-draft-v1", Name: "interactive-local", Release: "LOCAL-REHEARSAL", Mode: "rehearsal", Circuit: "rehearsal-tiny-v1", ArchitecturePolicy: "single", Status: "draft", Work: filepath.Join(root, "work"), Trust: filepath.Join(root, "trust"), Keys: filepath.Join(root, "keys"), Storage: map[string]string{}}, output: new(bytes.Buffer)}
	w.draftPath = filepath.Join(w.d.Work, "coordinator-setup/draft.json")
	for _, dir := range []string{filepath.Dir(w.draftPath), w.d.Trust, w.d.Keys} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	w.localAction = func(name, role string, command []string, credentials bool) error {
		if credentials {
			return fmt.Errorf("no cloud credentials in dialogue test")
		}
		work, trust, keys := w.d.Work, w.d.Trust, w.d.Keys
		if role == "keygen" {
			work, trust, keys = w.d.Keys, "", ""
		}
		return run(role, work, trust, keys, command)
	}
	var input strings.Builder
	input.WriteString("2\nLocal coordinator\nGENERATE\n\n")
	for n, role := range roles {
		number := ""
		switch role {
		case "participant":
			number = "4"
		case "auditor":
			number = "3"
		case "release-signer":
			number = "2"
		}
		if number != "" {
			fmt.Fprintf(&input, "3\n%s\n%s\nVERIFIED\n", number, filepath.Join(preparers[n].d.Keys, "identity.json"))
		}
	}
	input.WriteString("4\n\n\n\n\n\nREVIEWED\n8\nINITIALIZE REHEARSAL\n0\n")
	w.input = bufio.NewReader(strings.NewReader(input.String()))
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	if w.d.Status != "definition-verified" {
		t.Fatalf("coordinator did not initialize through menu:\n%s", w.output.(*bytes.Buffer))
	}
	if os.Getenv("RELAY_DIALOGUE_TRACE") == "1" {
		t.Logf("Coordinator dialogue: %s", w.output.(*bytes.Buffer))
	}
	copyPublic := func(src, dst string) {
		t.Helper()
		raw, err := readPreparationInput(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := writePublicTextOnce(dst, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for n, p := range preparers {
		dialogue(p, fmt.Sprintf("3\n1\n%s\nIMPORT\n3\n2\n%s\nIMPORT\n3\n3\n%s\nVERIFIED\nIMPORT\n0\n", filepath.Join(w.d.Work, "ceremony/public/ceremony.json"), filepath.Join(w.d.Work, "ceremony/public/ceremony.sig"), filepath.Join(w.d.Trust, "setup-coordinator.hex")))
		if p.d.Role == "upload-station" {
			continue
		}
		input := "7\n"
		if p.d.Role == "witness" || p.d.Role == "mirror" {
			input += "1\n"
		}
		review := "REVIEWED"
		if p.d.Role == "release-signer" {
			review = "OFFLINE AND REVIEWED"
		}
		input += "4\nSame-machine local test; all roles operated by this test process.\nPUBLIC DISCLOSURE\n" + review + "\n0\n"
		dialogue(p, input)
		if _, err := os.Stat(filepath.Join(p.d.Work, "enrollment.sig")); err != nil {
			t.Fatal(err)
		}
		// Reopening must verify and preserve the same identity and enrollment.
		keyBefore, err := setupFileHash(filepath.Join(p.d.Keys, "signing.hex"))
		if err != nil {
			t.Fatal(err)
		}
		resume := "2\n7\n"
		if p.d.Role == "witness" || p.d.Role == "mirror" {
			resume += "\n"
		}
		resume += review + "\n0\n"
		dialogue(p, resume)
		keyAfter, _ := setupFileHash(filepath.Join(p.d.Keys, "signing.hex"))
		if keyAfter != keyBefore {
			t.Fatal("resume replaced signing key")
		}
		_ = identities[n]
	}
	// The upload station imports only the final signer's public enrollment.
	signer, upload := preparers[5], preparers[6]
	copyPublic(filepath.Join(signer.d.Work, "enrollment.json"), filepath.Join(upload.d.Work, "enrollment.json"))
	copyPublic(filepath.Join(signer.d.Work, "enrollment.sig"), filepath.Join(upload.d.Work, "enrollment.sig"))
	if _, err := os.Stat(filepath.Join(upload.d.Keys, "signing.hex")); !os.IsNotExist(err) {
		t.Fatal("upload station acquired a key")
	}
	var definition struct {
		CeremonyID string `json:"ceremony_id"`
	}
	definitionRaw, err := os.ReadFile(filepath.Join(w.d.Work, "ceremony/public/ceremony.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(definitionRaw, &definition); err != nil {
		t.Fatal(err)
	}
	for _, p := range preparers {
		if p.d.Role == "release-signer" {
			continue
		}
		if p.d.Role == "participant" && os.Getenv("RELAY_NATIVE_TEST_BINARY") == "" {
			continue
		}
		// This is local compatibility evidence, not release provenance. The real
		// initializer still checks both running binary hashes and all signatures.
		receipt := fmt.Sprintf("TOOL_IDENTITY_RECEIPT_SCHEMA=ceremony-kit-tool-identity-receipt-v1\nKIT_MODE=rehearsal\nKIT_ROOT=/work\nCOMPATIBILITY_TEST=tiny-rehearsal-phase1-contribution-v1\nRELAY_VERIFIED_PATH=/usr/local/bin/relay\nRELAY_REPOSITORY=local/relay\nRELAY_VERSION=local-compatibility\nRELAY_RELEASE_ID=local/relay@local-compatibility\nRELAY_SHA256=%s\nMPC_CEREMONY_VERIFIED_PATH=/usr/local/bin/mpc-ceremony\nMPC_CEREMONY_REPOSITORY=local/proof-tool\nMPC_CEREMONY_VERSION=local-compatibility\nMPC_CEREMONY_RELEASE_ID=local/proof-tool@local-compatibility\nMPC_CEREMONY_SHA256=%s\n", compatibility.Relay, compatibility.Proof)
		if p.d.Role == "participant" {
			native := os.Getenv("RELAY_NATIVE_TEST_BINARY")
			proof := os.Getenv("RELAY_TEST_PROOF_BINARY")
			nativeHash, err := setupFileHash(native)
			if err != nil {
				t.Fatal(err)
			}
			proofHash, err := setupFileHash(proof)
			if err != nil || proofHash != compatibility.Proof {
				t.Fatal("host-cached Linux proof tool must match the tested image", err)
			}
			// A measured local test-pair receipt, never a production approval. The
			// real disposable contribution below is this native pairing's gate.
			receipt = strings.ReplaceAll(receipt, compatibility.Relay, nativeHash)
			receipt = strings.ReplaceAll(receipt, "/usr/local/bin/relay", native)
			receipt = strings.ReplaceAll(receipt, "/usr/local/bin/mpc-ceremony", proof)
			p.d.Values["image"], p.d.Values["platform"], p.d.Values["binary"] = offline, platform, proof
		}
		if err := writePublicTextOnce(filepath.Join(p.d.Trust, "tool-identity-receipt.env"), receipt); err != nil {
			t.Fatal(err)
		}
		storage := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: definition.CeremonyID, Endpoint: "https://local-test.invalid", Region: "auto", AccountID: "local-test", ParentAccessKeyID: "local-test", PublishedBucket: "local-test-public", PublishedBaseURL: "https://local-test.invalid", InboxBucket: "local-test-inbox", CoordinatorProfile: "local-test", CeremonyPath: "/work/ceremony/public/ceremony.json", CeremonySignature: "/work/ceremony/public/ceremony.sig", CoordinatorPublicKey: "/trust/coordinator-public-key.hex", CeremonyBinary: "/usr/local/bin/mpc-ceremony"}
		storagePath := filepath.Join(p.d.Work, "test-storage-handoff.json")
		if err := writeJSONNoReplace(storagePath, storage, 0600); err != nil {
			t.Fatal(err)
		}
		if p.d.Role == "participant" {
			dialogue(p, fmt.Sprintf("3\n4\n%s\nIMPORT\n4\n1\nPRECAUTIONS REVIEWED\nREVIEWED\n4\n2\nPRECAUTIONS REVIEWED\nREVIEWED\n0\n", storagePath))
		} else {
			dialogue(p, fmt.Sprintf("3\n4\n%s\nIMPORT\n4\n1\n4\n2\n0\n", storagePath))
		}
		role := p.d.Role
		if role == "upload-station" {
			role = "release"
		}
		for _, phase := range []string{"phase1", "phase2"} {
			var config access.RoleConfig
			if err := setupReadJSON(filepath.Join(p.d.Work, "ceremony/config", role+"-"+phase+".json"), &config); err != nil {
				t.Fatal(err)
			}
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			if config.CeremonyID != definition.CeremonyID || config.IdentityID == "" {
				t.Fatal("unbound profile")
			}
		}
	}
	// Exercise the participant's real environment prompt and disposable
	// contribution, then prepare/sign observations through the workflow menus.
	participant := preparers[0]
	participant.d.Values["image"], participant.d.Values["platform"] = offline, platform
	participant.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
	environment, err := participant.environment()
	if err != nil {
		t.Fatal(err)
	}
	publicRoot := filepath.Join(w.d.Work, "ceremony/public")
	parent := filepath.Join(w.d.Work, "candidates")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	config := access.ParticipantConfig{Schema: access.ParticipantConfigSchema, Phase: "phase1", Root: publicRoot, Ceremony: filepath.Join(publicRoot, "ceremony.json"), CeremonySignature: filepath.Join(publicRoot, "ceremony.sig"), CoordinatorKey: filepath.Join(w.d.Trust, "setup-coordinator.hex"), CeremonyBinary: "/usr/local/bin/mpc-ceremony", SigningKey: filepath.Join(participant.d.Keys, "signing.hex"), Environment: environment, CandidateParentDir: parent, PublishedBaseURL: "https://local-test.invalid", PublishedBucket: "unused", ExecutionMode: dockerExecutionMode, DockerImage: offline, DockerPlatform: platform, DockerCLI: "docker"}
	driver := dockerDriverForParticipant(config)
	if err := driver.preflight(); err != nil {
		t.Fatal(err)
	}
	def, err := driver.inspector().Definition()
	if err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(publicRoot, "phase1/chain-0000.json")
	chainSig := filepath.Join(publicRoot, "phase1/chain-0000.sig")
	chain, err := driver.inspector().Chain(chainPath, chainSig)
	if err != nil {
		t.Fatal(err)
	}
	o := participantRoleOptions(config, identities[0].ID)
	o.outDir = filepath.Join(parent, "participant")
	if err := runNextAt(o, position{definition: def, chain: chain, chainPath: chainPath, nextID: identities[0].ID, nextIndex: 1}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = write.WriteString("CLEANUP PRECAUTIONS CONFIRMED\n"); err != nil {
		t.Fatal(err)
	}
	write.Close()
	stdin := os.Stdin
	os.Stdin = read
	err = confirmDockerNoCopies(o)
	os.Stdin = stdin
	read.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runErasure(o); err != nil {
		t.Fatal(err)
	}
	co := o
	co.root, co.definition, co.definitionSig, co.coordinatorKey = "/work/ceremony/public", "/work/ceremony/public/ceremony.json", "/work/ceremony/public/ceremony.sig", "/trust/setup-coordinator.hex"
	accept := candidateVerificationCommand(co, "/work/ceremony/public/phase1/chain-0000.json", "/work/ceremony/public/phase1/chain-0000.sig", "/work/candidates/participant", "/keys/signing.hex", time.Now().UTC().Format(time.RFC3339Nano))
	if err := run("coordinator", w.d.Work, w.d.Trust, w.d.Keys, append([]string{"mpc-ceremony"}, accept.Args[1:]...)); err != nil {
		t.Fatal(err)
	}
	closeArgs := []string{"mpc-ceremony", "phase1", "close", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/setup-coordinator.hex", "--transcript-dir", "/work/ceremony/public", "--chain", "/work/ceremony/public/phase1/chain-0001.json", "--chain-signature", "/work/ceremony/public/phase1/chain-0001.sig", "--coordinator-signing-key", "/keys/signing.hex", "--beacon-round-lead", "600"}
	if err := run("coordinator", w.d.Work, w.d.Trust, w.d.Keys, closeArgs); err != nil {
		t.Fatal(err)
	}
	for _, p := range preparers[1:3] {
		if err := filepath.WalkDir(publicRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(publicRoot, path)
			if err != nil {
				return err
			}
			dest := filepath.Join(p.d.Work, "ceremony/public", rel)
			if entry.IsDir() {
				return os.MkdirAll(dest, 0700)
			}
			copyPublic(path, dest)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f := roleFlow{state: roleFlowState{Schema: roleFlowSchema, Name: p.d.Name, Role: p.d.Role, Stage: 1, Values: map[string]string{}, Profile: guidedProfile{Work: p.d.Work, Trust: p.d.Trust, Image: online, Platform: platform}}, stages: roleFlowStages(p.d.Role), path: filepath.Join(p.d.Work, "observation-flow.json"), ui: coordinatorWizard{output: new(bytes.Buffer)}}
		f.run = func(task flowTask, command []string, id string, retry bool) error {
			role, keys := p.d.Role, ""
			if task.Offline {
				role, keys = "decision-signer", p.d.Keys
				digest, err := f.reviewOfflineRecord(command)
				if err != nil {
					return err
				}
				command = append(command, "--reviewed-sha256", digest)
			}
			return run(role, p.d.Work, p.d.Trust, keys, command)
		}
		for _, task := range f.stages[1].Tasks {
			if task.ID != "draft-receipt" && task.ID != "receipt" && task.ID != "sign-receipt" {
				continue
			}
			var answers strings.Builder
			for _, field := range task.Fields {
				if p.d.Role == "mirror" && task.ID == "draft-receipt" && field.Flag == "chain" {
					answers.WriteString("1\n")
				}
				value := ""
				switch field.Flag {
				case "location":
					value = "file://" + p.d.Work
				case "publication-location":
					value = "https://local-test.invalid/phase1/closure"
				case "observed-at", "stored-at":
					value = time.Now().UTC().Format(time.RFC3339Nano)
				}
				answers.WriteString(value + "\n")
			}
			answers.WriteString("RUN\n")
			if task.Offline {
				answers.WriteString("REVIEWED\n")
			}
			f.ui.input = bufio.NewReader(strings.NewReader(answers.String()))
			if err := f.execute(task); err != nil {
				t.Fatalf("%s %s: %v\n%s", p.d.Role, task.ID, err, f.ui.output.(*bytes.Buffer))
			}
		}
		if _, err := os.Stat(filepath.Join(p.d.Work, "phase1-receipt/receipt.sig")); err != nil {
			t.Fatal(err)
		}
		testOfflineReceiptTerminal(t, p, online, offline, platform)
	}
}

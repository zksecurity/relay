package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

// Appending --help after every flag exercises the real parsers without opening
// any input, mounting a key, signing, or accessing a storage endpoint.
func TestRoleFlowDockerRecipeFlags(t *testing.T) {
	if os.Getenv("RELAY_FLOW_DOCKER") != "1" {
		t.Skip("set RELAY_FLOW_DOCKER=1 and RELAY_ROLE_ONLINE_IMAGE")
	}
	image := os.Getenv("RELAY_ROLE_ONLINE_IMAGE")
	if image == "" {
		t.Fatal("missing immutable test image")
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	bound := client.BindHost(endpoint)
	seen := map[string]bool{}
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		for _, stage := range roleFlowStages(role) {
			for _, task := range stage.Tasks {
				if task.Handoff {
					continue
				}
				command := append([]string(nil), task.Command...)
				if role == "participant" {
					command = append([]string{"relay", "participant"}, command...)
				}
				fields := append(append([]flowField(nil), task.Fields...), task.ExtraFields...)
				for _, field := range fields {
					value := field.Default
					if value == "NOW" || field.Kind == "time" {
						value = "2026-09-08T12:00:00Z"
					}
					if value == "" {
						value = "example"
						if field.Kind == "path" || field.Kind == "host" {
							value = "/work/test-input"
						} else if field.Kind == "number" {
							value = "1"
						}
					}
					command = append(command, "--"+field.Flag, value)
				}
				key := strings.Join(command, "\x00")
				if seen[key] {
					continue
				}
				seen[key] = true
				t.Run(role+"/"+stage.ID+"/"+task.ID, func(t *testing.T) {
					args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", command[0]}
					if platform := os.Getenv("RELAY_ROLE_PLATFORM"); platform != "" {
						args = append(args, "--platform", platform)
					}
					args = append(append(append(args, image), command[1:]...), "--help")
					stdout, stderr, err := bound.Output(args...)
					if command[0] == "mpc-ceremony" {
						if err != nil || !bytes.Contains(stdout, []byte("Usage:")) {
							t.Fatalf("proof-tool parser rejected recipe: %v\n%s\n%s", err, stdout, stderr)
						}
					} else if err != nil || !bytes.Contains(stderr, []byte("Usage of")) || bytes.Contains(stderr, []byte("flag provided but not defined")) {
						t.Fatalf("Relay parser rejected recipe: %v\n%s\n%s", err, stdout, stderr)
					}
				})
			}
		}
	}
}

// This opt-in integration runs real tiny phase1 AND phase2 contributions in
// disposable Docker containers, followed by the guide's finalization/audit/
// release recipes. It waits for two real future Quicknet rounds. Public-file
// handoff and explicitly same-host operational fixtures replace cloud transport
// and independent humans; neither is claimed to be tested by this lane.
func TestRoleFlowDockerFullCeremony(t *testing.T) {
	if os.Getenv("RELAY_FLOW_DOCKER") != "1" {
		t.Skip("set RELAY_FLOW_DOCKER=1 plus image and proof-tool source variables")
	}
	online, offline := os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), os.Getenv("RELAY_ROLE_OFFLINE_IMAGE")
	platform := os.Getenv("RELAY_ROLE_PLATFORM")
	proofSource := os.Getenv("RELAY_PROOF_TOOL_DIR")
	if proofSource == "" || online == "" || offline == "" {
		t.Fatal("missing test inputs")
	}
	work := os.Getenv("RELAY_FLOW_WORK")
	if work == "" {
		work = privateRoleTestDir(t)
	} else {
		if !filepath.IsAbs(work) || filepath.Clean(work) != work {
			t.Fatal("use fresh absolute RELAY_FLOW_WORK")
		}
		if err := os.Mkdir(work, 0700); err != nil {
			t.Fatal(err)
		}
	}
	private, trust := privateRoleTestDir(t), privateRoleTestDir(t)
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	bound := client.BindHost(endpoint)
	keyDirs := map[string]string{}
	cloud := os.Getenv("RELAY_FLOW_AWS_APPROVED") == "1"
	cloudCredentials := ""
	var cloudSettings coordinatorStorageSettings
	if cloud {
		cloudCredentials = os.Getenv("RELAY_AWS_LIVE_CREDENTIALS_FILE")
		if _, err := readProtectedCredentialBytes(cloudCredentials, 1<<20); err != nil {
			t.Fatal("AWS test credentials unavailable")
		}
		if err := setupReadJSON(os.Getenv("RELAY_AWS_LIVE_SETTINGS_FILE"), &cloudSettings); err != nil {
			t.Fatal(err)
		}
		c, err := cloudSettings.infrastructure()
		if err != nil {
			t.Fatal(err)
		}
		requireAWSLiveConfiguration(t, c)
	}
	runRole := func(role, identity string, command []string) error {
		image := online
		if len(command) >= 3 && command[0] == "mpc-ceremony" && command[1] == "ops" && command[2] == "sign" {
			role = "decision-signer" // Isolated signing image; no claim the test host is offline.
		}
		if role == "release-signer" || role == "keygen" || role == "decision-signer" {
			image = offline
		}
		o := dockerRoleOptions{role: role, image: image, platform: platform, work: work, trust: trust, keys: keyDirs[identity]}
		if cloud && role == "coordinator" {
			o.credentials = freshAWSLiveCredentials(t)
		}
		args, err := dockerRoleArgs(o, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		return bound.Attached(os.Stdout, os.Stderr, args...)
	}
	if err := runRole("coordinator", "", []string{"mpc-ceremony", "rehearsal", "init", "--created-at", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), "--out-dir", "/work/ceremony"}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(work, "ceremony", "public")
	fixtureKeys := filepath.Join(private, "fixture-keys")
	if err := os.Rename(filepath.Join(work, "ceremony", "keys"), fixtureKeys); err != nil {
		t.Fatal(err)
	}
	copyFile := func(source, target string) {
		t.Helper()
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(raw); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"coordinator", "auditor-01", "auditor-02", "release-signer", "witness-01", "mirror-01"} {
		keyDirs[id] = filepath.Join(private, id)
		if err := os.Mkdir(keyDirs[id], 0700); err != nil {
			t.Fatal(err)
		}
		copyFile(filepath.Join(fixtureKeys, id+".ed25519.private.hex"), filepath.Join(keyDirs[id], "signing.hex"))
	}
	copyFile(filepath.Join(root, "coordinator-public-key.hex"), filepath.Join(trust, "coordinator-public-key.hex"))
	var roster setupRoster
	if err := setupReadJSON(filepath.Join(work, "ceremony", "config", "participants.json"), &roster); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trust, "release-public-key.hex"), []byte(roster.ReleaseSigner.PublicKey), 0600); err != nil {
		t.Fatal(err)
	}
	f := roleFlow{state: roleFlowState{Schema: roleFlowSchema, Name: "docker-full-test", Role: "coordinator", Values: map[string]string{}}, stages: coordinatorFlowStages(), path: filepath.Join(work, "flow-state.json"), ui: coordinatorWizard{output: os.Stdout}}
	find := func(role, stageID, taskID string) flowTask {
		t.Helper()
		for index, stage := range roleFlowStages(role) {
			if stage.ID == stageID {
				f.state.Stage = index
				for _, task := range stage.Tasks {
					if task.ID == taskID {
						return task
					}
				}
			}
		}
		t.Fatalf("missing %s/%s/%s recipe", role, stageID, taskID)
		return flowTask{}
	}
	execute := func(role, identity, stage, id string, values map[string][]string) {
		t.Helper()
		f.stages, f.state.Role = roleFlowStages(role), role
		task := find(role, stage, id)
		used := map[string]int{}
		var input strings.Builder
		if len(task.ExtraFields) > 0 {
			input.WriteString("0\n")
		}
		for _, field := range task.Fields {
			value := field.Default
			if options := values[field.Flag]; len(options) > 0 {
				n := used[field.Flag]
				if n >= len(options) {
					n = len(options) - 1
				}
				value = options[n]
				used[field.Flag]++
			}
			if value == "NOW" {
				value = time.Now().UTC().Format(time.RFC3339Nano)
			}
			if value == "" && !field.Optional {
				t.Fatalf("missing test value --%s", field.Flag)
			}
			input.WriteString(value + "\n")
		}
		input.WriteString("RUN\n")
		f.ui.input = bufio.NewReader(strings.NewReader(input.String()))
		f.run = func(_ flowTask, command []string, _ string, _ bool) error { return runRole(role, identity, command) }
		if err := f.execute(task); err != nil {
			t.Fatalf("%s/%s/%s: %v", role, stage, id, err)
		}
	}
	if cloud {
		cmd := []string{"relay", "coordinator", "configure-storage", "--home", "/work/ceremony", "--coordinator-key", "/trust/coordinator-public-key.hex"}
		for _, field := range []string{"provider", "region", "published-bucket", "published-base-url", "inbox-bucket", "profile", "issuer-profile", "grant-role-arn", "grant-role-max-ttl"} {
			cmd = append(cmd, "--"+field, cloudSettings.Settings[field])
		}
		if err := runRole("coordinator", "", cmd); err != nil {
			t.Fatal(err)
		}
	}
	publishCloud := func(phase string, index int, closed bool) {
		t.Helper()
		if !cloud {
			return
		}
		chain := fmt.Sprintf("/work/ceremony/public/%s/chain-%04d", phase, index)
		cmd := []string{"relay", "coordinator", "publish", "--storage", "/work/ceremony/config/relay-storage.json", "--phase", phase, "--chain", chain + ".json", "--chain-signature", chain + ".sig", "--verify"}
		if closed {
			cmd = append(cmd, "--closed")
		}
		if err := runRole("coordinator", "", cmd); err != nil {
			t.Fatal(err)
		}
	}
	for _, phase := range []string{"phase1", "phase2"} {
		publishCloud(phase, 0, false)
		parent := filepath.Join(work, phase+"-candidates")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		for index := 1; index <= 3; index++ {
			id := fmt.Sprintf("participant-%02d", index)
			t.Logf("%s: real Docker contribution %s", phase, id)
			config := access.ParticipantConfig{Schema: access.ParticipantConfigSchema, Phase: phase, Root: root, Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"), CoordinatorKey: filepath.Join(trust, "coordinator-public-key.hex"), CeremonyBinary: "/usr/local/bin/mpc-ceremony", SigningKey: filepath.Join(fixtureKeys, id+".ed25519.private.hex"), Environment: filepath.Join(work, "ceremony", "config", "environment.json"), CandidateParentDir: parent, PublishedBaseURL: "https://ceremony.example", PublishedBucket: "unused", ExecutionMode: dockerExecutionMode, DockerImage: offline, DockerPlatform: platform, DockerCLI: "docker"}
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			driver := dockerDriverForParticipant(config)
			if err := driver.preflight(); err != nil {
				t.Fatal(err)
			}
			definition, err := driver.inspector().Definition()
			if err != nil {
				t.Fatal(err)
			}
			chainPath := filepath.Join(root, phase, fmt.Sprintf("chain-%04d.json", index-1))
			chainSig := strings.TrimSuffix(chainPath, ".json") + ".sig"
			chain, err := driver.inspector().Chain(chainPath, chainSig)
			if err != nil {
				t.Fatal(err)
			}
			o := participantRoleOptions(config, id)
			o.outDir = filepath.Join(parent, id)
			if phase == "phase2" {
				o.phase1Seal = filepath.Join(root, "phase1", "sealed", "seal.json")
				o.phase1SealSig = filepath.Join(root, "phase1", "sealed", "seal.sig")
			}
			pos := position{definition: definition, chain: chain, chainPath: chainPath, nextID: id, nextIndex: index}
			if err := runNextAt(o, pos, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_, err = write.WriteString("CLEANUP PRECAUTIONS CONFIRMED\n")
			write.Close()
			if err != nil {
				read.Close()
				t.Fatal(err)
			}
			old := os.Stdin
			os.Stdin = read
			err = confirmDockerNoCopies(o)
			os.Stdin = old
			read.Close()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runErasure(o); err != nil {
				t.Fatal(err)
			}
			containerPath := func(path string) string { return "/work/" + strings.TrimPrefix(path, work+"/") }
			if cloud {
				cloudCredentials = freshAWSLiveCredentials(t)
				args := []string{"run", "--rm", "--env", "RELAY_AWS_LIVE_EXPECTED_ACCOUNT=" + os.Getenv("RELAY_AWS_LIVE_EXPECTED_ACCOUNT"), "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--ulimit", "core=0:0", "--log-driver", "none", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
					"--mount", "type=bind,src=" + work + ",dst=/work", "--mount", "type=bind,src=" + trust + ",dst=/trust,readonly",
					"--mount", "type=bind,src=" + cloudCredentials + ",dst=/credentials,readonly", "--mount", "type=bind,src=" + os.Getenv("RELAY_AWS_TEST_BINARY") + ",dst=/tests,readonly",
					"--env", "HOME=/tmp", "--env", "AWS_SHARED_CREDENTIALS_FILE=/credentials", "--env", "RELAY_AWS_CANDIDATE_APPROVED=1", "--env", "RELAY_TEST_PHASE=" + phase, "--env", "RELAY_TEST_ID=" + id, "--env", "RELAY_TEST_CANDIDATE=" + containerPath(o.outDir), "--entrypoint", "/tests", online, "-test.run", "^TestAWSLiveCandidateTransport$", "-test.v"}
				if err := bound.Attached(os.Stdout, os.Stderr, args...); err != nil {
					t.Fatal(err)
				}
				key, err := os.ReadFile(filepath.Join(o.outDir, "aws-manifest-key.txt"))
				if err != nil {
					t.Fatal(err)
				}
				cmd := []string{"relay", "coordinator", "accept", "--storage", "/work/ceremony/config/relay-storage.json", "--candidate-key", string(key), "--coordinator-signing-key", "/keys/signing.hex", "--verify-publish"}
				if phase == "phase2" {
					cmd = append(cmd, "--phase1-seal", "/work/ceremony/public/phase1/sealed/seal.json", "--phase1-seal-signature", "/work/ceremony/public/phase1/sealed/seal.sig")
				}
				if err := runRole("coordinator", "coordinator", cmd); err != nil {
					t.Fatal(err)
				}
				continue
			}
			co := o
			co.root, co.definition, co.definitionSig, co.coordinatorKey = "/work/ceremony/public", "/work/ceremony/public/ceremony.json", "/work/ceremony/public/ceremony.sig", "/trust/coordinator-public-key.hex"
			co.phase1Seal, co.phase1SealSig = "/work/ceremony/public/phase1/sealed/seal.json", "/work/ceremony/public/phase1/sealed/seal.sig"
			cmd := candidateVerificationCommand(co, containerPath(chainPath), containerPath(chainSig), containerPath(o.outDir), "/keys/signing.hex", time.Now().UTC().Format(time.RFC3339Nano))
			if err := runRole("coordinator", "coordinator", append([]string{"mpc-ceremony"}, cmd.Args[1:]...)); err != nil {
				t.Fatal(err)
			}
		}
		values := map[string][]string{"chain": {"/work/ceremony/public/" + phase + "/chain-0003.json"}, "chain-signature": {"/work/ceremony/public/" + phase + "/chain-0003.sig"}, "beacon-round-lead": {"305"}}
		execute("coordinator", "coordinator", phase+"-close", "close", values)
		publishCloud(phase, 3, true)
		var closure struct {
			Round     uint64 `json:"beacon_round"`
			NotBefore string `json:"beacon_not_before"`
		}
		raw, err := os.ReadFile(filepath.Join(root, phase, "closure", "record.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &closure); err != nil {
			t.Fatal(err)
		}
		ready, err := time.Parse(time.RFC3339, closure.NotBefore)
		if err != nil {
			t.Fatal(err)
		}
		for time.Now().Before(ready.Add(4 * time.Second)) {
			remaining := time.Until(ready.Add(4 * time.Second))
			t.Logf("%s: waiting for committed Quicknet round %d (%s)", phase, closure.Round, remaining.Round(time.Second))
			if remaining > 30*time.Second {
				remaining = 30 * time.Second
			}
			time.Sleep(remaining)
		}
		httpClient := &http.Client{Timeout: 30 * time.Second}
		url := fmt.Sprintf("https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/%d", closure.Round)
		response, err := httpClient.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		beaconBytes, err := io.ReadAll(io.LimitReader(response.Body, 8192))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("beacon response %d: %v", response.StatusCode, err)
		}
		if err := os.WriteFile(filepath.Join(work, phase+"-beacon-response.json"), beaconBytes, 0600); err != nil {
			t.Fatal(err)
		}
		execute("coordinator", "coordinator", phase+"-close", "beacon", nil)
		// Explicitly same-host fixture identities: not two independent operators.
		relays := filepath.Join(work, phase+"-relays")
		if err := os.Mkdir(relays, 0700); err != nil {
			t.Fatal(err)
		}
		rows := "relay_id\toperator_id\tendpoint_sha256\tretrieved_at\tfilename\n"
		for i := 1; i <= 2; i++ {
			name := fmt.Sprintf("relay-%02d.json", i)
			if err := os.WriteFile(filepath.Join(relays, name), beaconBytes, 0600); err != nil {
				t.Fatal(err)
			}
			rows += fmt.Sprintf("relay-%02d\toperator-%02d\tsha256:%s\t%s\t%s\n", i, i, strings.Repeat(fmt.Sprintf("%x", i), 64), time.Now().UTC().Format(time.RFC3339), name)
		}
		if err := os.WriteFile(filepath.Join(relays, "relays.tsv"), []byte(rows), 0600); err != nil {
			t.Fatal(err)
		}
		if phase == "phase1" {
			execute("coordinator", "coordinator", "phase2-init", "seal", nil)
			execute("coordinator", "coordinator", "phase2-init", "phase2-init", nil)
		}
	}
	replay := map[string][]string{"phase1-chain": {"/work/ceremony/public/phase1/chain-0003.json"}, "phase1-chain-signature": {"/work/ceremony/public/phase1/chain-0003.sig"}, "phase2-chain": {"/work/ceremony/public/phase2/chain-0003.json"}, "phase2-chain-signature": {"/work/ceremony/public/phase2/chain-0003.sig"}}
	execute("coordinator", "coordinator", "finalization", "prepare", replay)
	// Build separate test-only evidence helpers inside proof-tool's module so
	// that its internal API, canonical format and real proof implementation are used.
	bridge, err := os.MkdirTemp(filepath.Join(proofSource, "internal", "mpcceremony", "testdata"), "relay-flow-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(bridge)
	source, err := os.ReadFile(filepath.Join("testdata", "tiny-public-evidence", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bridge, "main.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	tinyHelper, operationalHelper := filepath.Join(private, "tiny-helper"), filepath.Join(private, "ops-helper")
	buildProofProgram(t, proofSource, tinyHelper, "./"+strings.TrimPrefix(bridge, proofSource+"/"))
	buildProofProgram(t, proofSource, operationalHelper, "./scripts/mpc-rehearsal-operational-evidence")
	var definition struct {
		ID string `json:"ceremony_id"`
	}
	defBytes, err := os.ReadFile(filepath.Join(root, "ceremony.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(defBytes, &definition); err != nil {
		t.Fatal(err)
	}
	runProofCommand(t, proofSource, tinyHelper, filepath.Join(work, "preliminary"), filepath.Join(trust, "coordinator-public-key.hex"), definition.ID, filepath.Join(work, "public-finalization-evidence.json"))
	execute("coordinator", "coordinator", "finalization", "complete", replay)
	for _, id := range []string{"auditor-01", "auditor-02"} {
		values := map[string][]string{}
		for k, v := range replay {
			values[k] = v
		}
		values["auditor-id"], values["out"], values["audit-signature"] = []string{id}, []string{"/work/" + id + ".json"}, []string{"/work/" + id + ".sig"}
		execute("auditor", id, "audit", "audit", values)
	}
	runProofCommand(t, proofSource, operationalHelper, "--transcript-root", root, "--keys-dir", fixtureKeys, "--coordinator-public-key-file", filepath.Join(trust, "coordinator-public-key.hex"), "--phase1-relays", filepath.Join(work, "phase1-relays"), "--phase2-relays", filepath.Join(work, "phase2-relays"), "--assembled-at", time.Now().UTC().Format(time.RFC3339), "--out-dir", filepath.Join(root, "operational"))
	// Release verification requires the bundle itself inside the evidence root.
	const preparedBundle = "/work/ceremony/public/prepared-ops/evidence-bundle"
	execute("coordinator", "coordinator", "operational-evidence", "ops-prepare", map[string][]string{"out-dir": {"/work/ceremony/public/prepared-ops"}})
	execute("coordinator", "coordinator", "operational-evidence", "ops-sign", map[string][]string{"record": {preparedBundle + ".json"}, "out": {preparedBundle + ".sig"}})
	execute("coordinator", "coordinator", "release", "ops-verify", map[string][]string{"record": {preparedBundle + ".json"}, "signature": {preparedBundle + ".sig"}})
	execute("release-signer", "release-signer", "sign", "sign", map[string][]string{"audit-report": {"/work/auditor-01.json", "/work/auditor-02.json"}, "audit-signature": {"/work/auditor-01.sig", "/work/auditor-02.sig"}, "signature-key-id": {roster.ReleaseSigner.KeyID}, "operational-bundle": {preparedBundle + ".json"}, "operational-bundle-signature": {preparedBundle + ".sig"}})
	execute("coordinator", "coordinator", "release", "release-verify", map[string][]string{"signature-key-id": {roster.ReleaseSigner.KeyID}})
	// The negative lane must fail even though local workflow history says success.
	var state roleFlowState
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	last := state.Attempts[len(state.Attempts)-1]
	for n, arg := range last.Command {
		if arg == "--signature-key-id" {
			last.Command[n+1] = "wrong-key"
		}
	}
	if err := runRole("coordinator", "coordinator", last.Command); err == nil {
		t.Fatal("wrong release identity accepted")
	}
	if bytes.Contains(raw, []byte("private_key_hex")) {
		t.Fatal("secret persisted in workflow")
	}
	transport := "local public-file transport"
	if cloud {
		transport = "real AWS scoped candidate uploads, coordinator downloads/acceptance and S3/CloudFront head publication; audit/final-signer handoffs remain local"
	}
	t.Logf("PASS: 3+3 Docker contributions, removal+signed cleanup, real future beacons, both-phase replay, public proof, two audits, operational fixture verification, release signing/verification. Transport: %s. Same-host operational fixtures, not independent operators or production approval. Public outputs: %s", transport, work)
}

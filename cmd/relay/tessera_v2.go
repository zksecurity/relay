package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/zksecurity/relay/contracts/setupv2"
	"github.com/zksecurity/relay/internal/transcript"
	releaseassets "github.com/zksecurity/relay/release"
)

type setupReleaseManifest struct {
	Schema          string          `json:"schema"`
	ReleaseTag      string          `json:"release_tag"`
	CLICommit       string          `json:"cli_commit"`
	ProofToolCommit string          `json:"proof_tool_commit"`
	ContractSHA256  string          `json:"contract_sha256"`
	Ruleset         setupv2.Ruleset `json:"ruleset"`
	RoleImages      json.RawMessage `json:"role_images"`
	Inputs          json.RawMessage `json:"role_image_inputs"`
	Recipe          json.RawMessage `json:"workflow_recipe"`
}

func setupRecipeDigestV2() string {
	var recipe any
	if err := json.Unmarshal(tesseraRecipe(), &recipe); err != nil {
		panic(err)
	}
	raw, err := setupv2.Canonical(recipe)
	if err != nil {
		panic(err)
	}
	return setupv2.Hash(raw)
}

func checkSetupDraftV2(d coordinatorDraft) error {
	s := d.TesseraSetup
	if s == nil {
		return errors.New("open the website setup first")
	}
	if s.Result != nil {
		return errors.New("completed setup is review only")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	c := setupContextV2(*s)
	roster, p1, p2 := c.setupInputs()
	expected, _ := setupv2.Canonical([]any{s.Plan.Mode, s.Plan.Circuit, s.Plan.SoftwareRelease.ReleaseTag, roster, p1, p2, s.Plan.BeaconPolicy, s.Plan.Storage})
	storage := setupv2.Storage{Provider: d.Storage["provider"], Region: d.Storage["region"], PublicBaseURL: d.Storage["published-base-url"], PublishedBucket: d.Storage["published-bucket"], InboxBucket: d.Storage["inbox-bucket"]}
	actual, _ := setupv2.Canonical([]any{d.Mode, d.Circuit, d.Release, d.Identities, d.Policy.Phase1, d.Policy.Phase2, d.Policy.Beacon, storage})
	if !bytes.Equal(actual, expected) {
		return errors.New("public setup changed locally; edit it in Tessera and open the updated download before initializing")
	}
	return nil
}
func (w *coordinatorWizard) importSetupV2(path string, raw []byte) error {
	s, err := setupv2.Parse(raw)
	if err != nil {
		return err
	}
	if s.Result != nil {
		fmt.Fprintln(w.output, "This setup already contains a signed result. Verifying it for review; it will not initialize or sign again.")
		return runSetupV2([]string{"--setup", path}, false)
	}
	if err = checkLauncherRelease(s.Plan.SoftwareRelease.CLICommit); err != nil {
		return err
	}
	// Authenticate release metadata before accepting the plan, rather than waiting
	// until after a potentially expensive initialization to discover a mismatch.
	_, _, images, err := verifiedReleaseImageMap(s.Plan.SoftwareRelease.ReleaseTag, "coordinator", "linux/"+runtime.GOARCH)
	if err != nil {
		return err
	}
	manifest, err := setupManifestV2(s.Plan.SoftwareRelease.CLICommit, images)
	if err != nil {
		return err
	}
	if setupv2.Hash(manifest) != s.Plan.SoftwareRelease.ManifestSHA256 || setupRecipeDigestV2() != s.Plan.SoftwareRelease.WorkflowRecipeSHA256 {
		return errors.New("website selected a different software manifest or workflow")
	}
	fmt.Fprintf(w.output, "Website setup %s revision %d\nMode: %s\nCircuit: %s\nRelease: %s\nPublic storage: %s\n", s.ID, s.PlanRevision, s.Plan.Mode, s.Plan.Circuit, s.Plan.SoftwareRelease.ReleaseTag, s.Plan.Storage.PublicBaseURL)
	for _, i := range s.Plan.Identities {
		fmt.Fprintf(w.output, "%q · %s\n", i.DisplayName, i.Fingerprint)
	}
	fmt.Fprintln(w.output, "This imports all public settings. Private key and credential paths remain local. Compare public fingerprints with their owners.")
	if err = w.confirm("Accept this setup", "IMPORT SETUP"); err != nil {
		return err
	}
	previous := w.d
	w.d.Tessera = nil
	w.d.TesseraSetup = s
	w.d.Mode = s.Plan.Mode
	w.d.Circuit = s.Plan.Circuit
	w.d.Release = s.Plan.SoftwareRelease.ReleaseTag
	w.d.Identities, w.d.Policy.Phase1, w.d.Policy.Phase2 = setupContextV2(*s).setupInputs()
	b, _ := json.Marshal(s.Plan.BeaconPolicy)
	if err = json.Unmarshal(b, &w.d.Policy.Beacon); err != nil {
		w.d = previous
		return err
	}
	// Copy the map so a failed save can restore the prior draft without aliases.
	storage := map[string]string{}
	for k, v := range w.d.Storage {
		storage[k] = v
	}
	p := s.Plan.Storage
	storage["provider"] = p.Provider
	storage["region"] = p.Region
	storage["published-base-url"] = p.PublicBaseURL
	storage["published-bucket"] = p.PublishedBucket
	storage["inbox-bucket"] = p.InboxBucket
	w.d.Storage = storage
	if err = w.save(); err != nil {
		w.d = previous
		return err
	}
	fmt.Fprintln(w.output, "Setup imported. Review the draft and approve initialization. After verification, export the completed setup for Tessera.")
	return nil
}
func (w *coordinatorWizard) exportSetupV2() error {
	out, err := w.required("Fresh completed setup JSON path", filepath.Join(w.d.Work, "tessera-setup.json"))
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "setup-input-v2-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "setup.json")
	if err = setupWriteNew(path, w.d.TesseraSetup); err != nil {
		return err
	}
	return runSetupV2([]string{"--setup", path, "--out", out, "--ceremony", filepath.Join(w.d.Work, "ceremony/public/ceremony.json"), "--ceremony-signature", filepath.Join(w.d.Work, "ceremony/public/ceremony.sig"), "--coordinator-key-file", filepath.Join(w.d.Trust, "setup-coordinator.hex")}, true)
}

func setupManifestV2(commit string, images []byte) ([]byte, error) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		if _, err := selectReleaseImage(images, commit, "coordinator", platform); err != nil {
			return nil, err
		}
	}
	var pins struct {
		MPC map[string]struct {
			URL string `json:"url"`
		} `json:"mpc"`
	}
	if err := json.Unmarshal(releaseassets.RoleImageInputs(), &pins); err != nil {
		return nil, err
	}
	proof := ""
	for _, p := range pins.MPC {
		parts := strings.Split(p.URL, "mpc-ci-")
		if len(parts) != 2 {
			return nil, errors.New("invalid embedded proof-tool release")
		}
		c := strings.Split(parts[1], "/")[0]
		if proof != "" && proof != c {
			return nil, errors.New("mixed embedded proof-tool commits")
		}
		proof = c
	}
	m := setupReleaseManifest{"ceremony-software-manifest-v2", "role-images-" + commit, commit, proof, setupv2.Hash(setupv2.SchemaJSON), setupv2.Rules(), images, releaseassets.RoleImageInputs(), tesseraRecipe()}
	return setupv2.Canonical(m)
}
func runSetupManifest(args []string) error {
	f := flag.NewFlagSet("tessera release-manifest", flag.ContinueOnError)
	path := f.String("role-images", "", "attested CI role image map")
	out := f.String("out", "", "fresh software manifest output")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *path == "" || *out == "" || f.NArg() != 0 {
		return errors.New("--role-images and --out are required")
	}
	commit := launcherCommit()
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return errors.New("release build required")
	}
	raw, err := readTesseraRegularFile(*path, 1<<20, false)
	if err != nil {
		return err
	}
	manifest, err := setupManifestV2(commit, raw)
	if err != nil {
		return err
	}
	return writeTesseraFresh(*out, manifest, 0600)
}

// Only an internal adapter for the existing protocol projection checker; this
// shape is never emitted or accepted as a v2 transport file.
func setupContextV2(s setupv2.Setup) tesseraContext {
	c := tesseraContext{Schema: "tessera-draft-context-v1", CeremonyID: s.ID, Revision: s.PlanRevision, Mode: s.Plan.Mode, Assignments: []tesseraAssignment{}, Schedules: []tesseraSchedule{}}
	ids := map[string]setupIdentity{}
	roleIDs := map[string]string{}
	for _, i := range s.Plan.Identities {
		ids[i.ID] = setupIdentity{i.ID, i.DisplayName, i.KeyID, i.PublicKey, i.Fingerprint}
	}
	for _, r := range s.Plan.Roles {
		phases := []string{}
		for _, p := range s.Plan.Phases {
			for _, id := range p.IdentityIDs {
				if id == r.IdentityID {
					phases = append(phases, p.ID)
				}
			}
		}
		c.Assignments = append(c.Assignments, tesseraAssignment{r.ID, r.ID, 1, r.Role, phases, ids[r.IdentityID]})
		roleIDs[r.IdentityID] = r.ID
	}
	for _, p := range s.Plan.Phases {
		a := []string{}
		for _, id := range p.IdentityIDs {
			a = append(a, roleIDs[id])
		}
		c.Schedules = append(c.Schedules, tesseraSchedule{p.ID, a, p.Minimum})
	}
	return c
}
func checkSetupDefinitionV2(s setupv2.Setup, definition, key, manifest []byte, inspected transcript.Definition) error {
	d, err := checkTesseraDefinition(setupContextV2(s), definition, inspected)
	if err != nil {
		return err
	}
	var public struct {
		Circuit struct {
			KeyVersion string `json:"key_version"`
		} `json:"circuit"`
		Beacon map[string]any `json:"beacon_policy"`
	}
	if err = json.Unmarshal(definition, &public); err != nil {
		return err
	}
	actual, _ := setupv2.Canonical(public.Beacon)
	expected, _ := setupv2.Canonical(s.Plan.BeaconPolicy)
	if public.Circuit.KeyVersion != s.Plan.Circuit || !bytes.Equal(actual, expected) {
		return errors.New("signed circuit or beacon policy differs from website plan")
	}
	if strings.TrimSpace(string(key)) != d.Coordinator.PublicKey {
		return errors.New("coordinator public key differs from website plan")
	}
	var m setupReleaseManifest
	if err = tesseraJSON(manifest, &m); err != nil {
		return err
	}
	expectedManifest, err := setupManifestV2(s.Plan.SoftwareRelease.CLICommit, m.RoleImages)
	if err != nil {
		return err
	}
	if !bytes.Equal(manifest, expectedManifest) || setupv2.Hash(manifest) != s.Plan.SoftwareRelease.ManifestSHA256 || m.ProofToolCommit != s.Plan.SoftwareRelease.ProofToolCommit || m.ProofToolCommit != d.Software.Commit || setupRecipeDigestV2() != s.Plan.SoftwareRelease.WorkflowRecipeSHA256 {
		return errors.New("setup software differs from this approved CLI release")
	}
	// Reuse the pinned native binary checks, including every allowed architecture.
	_, err = tesseraManifest(d, m.ReleaseTag, m.RoleImages)
	return err
}
func inspectSetupV2(definition, signature, key []byte, image, platform string) (transcript.Definition, error) {
	dir, err := os.MkdirTemp("", "setup-v2-")
	if err != nil {
		return transcript.Definition{}, err
	}
	defer os.RemoveAll(dir)
	for name, raw := range map[string][]byte{"ceremony.json": definition, "ceremony.sig": signature, "coordinator.hex": key} {
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			return transcript.Definition{}, err
		}
	}
	inspector := transcript.Inspector{Executable: "mpc-ceremony", CeremonyPath: "/input/ceremony.json", CeremonySignaturePath: "/input/ceremony.sig", CoordinatorPublicKeyPath: "/input/coordinator.hex", Runner: func(_ string, args ...string) ([]byte, []byte, error) {
		argv := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--platform", platform, "--mount", "type=bind,src=" + dir + ",dst=/input,readonly", "--entrypoint", "/usr/local/bin/mpc-ceremony", image}
		cmd := exec.Command("docker", append(argv, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}}
	return inspector.Definition()
}

func runSetupV2(args []string, complete bool) error {
	f := flag.NewFlagSet("tessera setup-v2", flag.ContinueOnError)
	path := f.String("setup", "", "website setup JSON")
	out := f.String("out", "", "fresh output JSON (completion only)")
	definitionPath := f.String("ceremony", "", "signed definition")
	signaturePath := f.String("ceremony-signature", "", "definition signature")
	keyPath := f.String("coordinator-key-file", "", "public coordinator key")
	manifestPath := f.String("trusted-manifest", "", "locally provisioned, independently attested release manifest; otherwise retrieve from GitHub")
	platform := f.String("platform", "linux/"+runtime.GOARCH, "approved Linux inspection platform")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *path == "" || f.NArg() != 0 {
		return errors.New("--setup is required")
	}
	raw, err := readTesseraRegularFile(*path, setupv2.MaxBytes, false)
	if err != nil {
		return err
	}
	s, err := setupv2.Parse(raw)
	if err != nil {
		return err
	}
	if err = checkLauncherRelease(s.Plan.SoftwareRelease.CLICommit); err != nil {
		return err
	}
	if complete && s.Result != nil {
		return errors.New("setup already contains a result; use verify-setup to review it, without initializing or signing again")
	}
	if !complete && s.Result == nil {
		return errors.New("setup has no signed result to verify")
	}
	var manifest []byte
	var image string
	if *manifestPath != "" {
		manifest, err = readTesseraRegularFile(*manifestPath, 1<<20, false)
		if err != nil {
			return err
		}
		var m setupReleaseManifest
		if err = tesseraJSON(manifest, &m); err != nil {
			return err
		}
		image, err = selectReleaseImage(m.RoleImages, s.Plan.SoftwareRelease.CLICommit, "coordinator", *platform)
	} else {
		var images []byte
		image, _, images, err = verifiedReleaseImageMap(s.Plan.SoftwareRelease.ReleaseTag, "coordinator", *platform)
		if err == nil {
			manifest, err = setupManifestV2(s.Plan.SoftwareRelease.CLICommit, images)
		}
	}
	if err != nil {
		return err
	}
	if setupv2.Hash(manifest) != s.Plan.SoftwareRelease.ManifestSHA256 {
		return errors.New("release manifest does not match downloaded setup")
	}
	artifacts := map[string][]byte{"software-manifest": manifest}
	if complete {
		if *out == "" || *definitionPath == "" || *signaturePath == "" || *keyPath == "" {
			return errors.New("completion requires --out, --ceremony, --ceremony-signature and --coordinator-key-file")
		}
		for kind, path := range map[string]string{"definition": *definitionPath, "definition-signature": *signaturePath, "coordinator-key": *keyPath} {
			artifacts[kind], err = readTesseraRegularFile(path, 1<<20, false)
			if err != nil {
				return err
			}
		}
	} else {
		for _, a := range s.Result.Artifacts {
			if a.Platform == "none" {
				artifacts[a.Kind], _ = base64.StdEncoding.DecodeString(a.ContentB64)
			}
		}
		if !bytes.Equal(artifacts["software-manifest"], manifest) {
			return errors.New("artifact manifest differs from trusted release")
		}
	}
	inspected, err := inspectSetupV2(artifacts["definition"], artifacts["definition-signature"], artifacts["coordinator-key"], image, *platform)
	if err != nil {
		return err
	}
	if err = checkSetupDefinitionV2(*s, artifacts["definition"], artifacts["coordinator-key"], manifest, inspected); err != nil {
		return err
	}
	if complete {
		input, err := s.InputDigest()
		if err != nil {
			return err
		}
		s.Result = &setupv2.Result{InputSHA256: input, ProtocolID: inspected.CeremonyID, Artifacts: []setupv2.Artifact{}}
		for _, kind := range []string{"definition", "definition-signature", "coordinator-key", "software-manifest"} {
			b := artifacts[kind]
			s.Result.Artifacts = append(s.Result.Artifacts, setupv2.Artifact{Kind: kind, Platform: "none", SHA256: setupv2.Hash(b), ByteLength: len(b), ContentB64: base64.StdEncoding.EncodeToString(b)})
		}
		if err = s.Validate(); err != nil {
			return err
		}
		raw, err = json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		if err = writeTesseraFresh(*out, append(raw, '\n'), 0600); err != nil {
			return err
		}
	} else if s.Result.ProtocolID != inspected.CeremonyID {
		return errors.New("result protocol ID differs from authenticated definition")
	}
	input, _ := s.InputDigest()
	sha, _ := s.Digest()
	result, _ := s.Result.Digest()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "ceremony-setup-verification-v2", "setup_sha256": sha, "input_sha256": input, "result_sha256": result, "protocol_id": s.Result.ProtocolID, "signature_verified": true, "software_verified": true})
}

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func preparationFixture(t *testing.T, role string) *rolePreparer {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &rolePreparer{d: rolePreparation{Schema: "relay-role-preparation-v1", Name: "demo", Role: role, Release: "role-images-" + strings.Repeat("a", 40), Work: filepath.Join(root, "work"), Trust: filepath.Join(root, "trust"), Keys: filepath.Join(root, "keys"), Values: map[string]string{}}, path: filepath.Join(root, "draft.json"), settingsRoot: filepath.Join(root, "settings"), ui: coordinatorWizard{input: bufio.NewReader(strings.NewReader("")), output: new(bytes.Buffer)}}
	for _, dir := range []string{p.d.Work, p.d.Trust, p.d.Keys, filepath.Join(p.d.Work, "ceremony/public"), filepath.Join(p.d.Work, "ceremony/config")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p.run = func([]string) error { t.Fatal("unexpected child execution"); return nil }
	return p
}
func prepareTestProfile(t *testing.T, p *rolePreparer, role string) {
	t.Helper()
	work, trust, keys := p.d.Work, p.d.Trust, p.d.Keys
	if role == "keygen" {
		work, trust, keys = p.d.Keys, "", ""
	}
	if role == "upload-station" || role == "witness" || role == "mirror" {
		keys = ""
	}
	dir, _ := guidedDirectory(p.settingsRoot, p.alias(role), role)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	v := guidedProfile{Schema: guidedSchema, Name: p.alias(role), Role: role, ReleaseCommit: strings.Repeat("a", 40), Image: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64", Work: work, Trust: trust, Keys: keys}
	if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), v, 0600); err != nil {
		t.Fatal(err)
	}
}
func prepareTestIdentity(t *testing.T, p *rolePreparer) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	i := setupIdentity{ID: "my-id", DisplayName: "My name", KeyID: "my-key", PublicKey: hex.EncodeToString(pub), Fingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(pub))}
	if err := writeJSONNoReplace(filepath.Join(p.d.Keys, "identity.json"), i, 0600); err != nil {
		t.Fatal(err)
	}
}

func prepareParticipantRoleConfig(t *testing.T, p *rolePreparer, image, platform string) string {
	t.Helper()
	ceremonyID := "sha256:" + strings.Repeat("1", 64)
	configDir := filepath.Join(p.d.Work, "ceremony", "config")
	storagePath := filepath.Join(configDir, "relay-storage.json")
	storage := access.StorageConfig{
		Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: ceremonyID,
		Endpoint: "https://account.invalid", AccountID: "account", ParentAccessKeyID: "parent",
		PublishedBucket: "published", PublishedBaseURL: "https://public.invalid", InboxBucket: "inbox",
		CoordinatorProfile: "coordinator", CeremonyPath: filepath.Join(p.d.Work, "ceremony/public/ceremony.json"),
		CeremonySignature:    filepath.Join(p.d.Work, "ceremony/public/ceremony.sig"),
		CoordinatorPublicKey: filepath.Join(p.d.Trust, "coordinator-public-key.hex"), CeremonyBinary: "/usr/local/bin/mpc-ceremony",
	}
	if err := writeJSONNoReplace(storagePath, storage, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "participant-phase1.json")
	config := access.RoleConfig{
		Schema: access.RoleConfigSchema, Role: access.RoleParticipant, IdentityID: "participant-1", Phase: "phase1", CeremonyID: ceremonyID,
		CeremonyHome: filepath.Join(p.d.Work, "ceremony"), Root: filepath.Join(p.d.Work, "ceremony/public"),
		Ceremony: storage.CeremonyPath, CeremonySignature: storage.CeremonySignature, CoordinatorKey: storage.CoordinatorPublicKey,
		CeremonyBinary: storage.CeremonyBinary, SigningKey: filepath.Join(p.d.Keys, "signing.hex"),
		Environment: filepath.Join(configDir, "environment.json"), RunRoot: p.d.Work, StorageConfig: storagePath,
		PublishedBaseURL: storage.PublishedBaseURL, PublishedBucket: storage.PublishedBucket,
		ExecutionMode: dockerExecutionMode, DockerImage: image, DockerPlatform: platform, DockerCLI: "docker",
	}
	if err := writeJSONNoReplace(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}
func TestRolePreparationIdentityAndOfflineResume(t *testing.T) {
	p := preparationFixture(t, "release-signer")
	prepareTestProfile(t, p, "keygen")
	p.ui.input = bufio.NewReader(strings.NewReader("\nAlice\nOFFLINE\nGENERATE\n"))
	calls := 0
	p.run = func(args []string) error {
		calls++
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "ceremony open") || strings.Contains(joined, "--release") || !strings.Contains(joined, "--identity-id release-signer-") || !strings.Contains(joined, "--display-name Alice") {
			t.Fatalf("unexpected identity action: %q", args)
		}
		return nil
	}
	if err := p.identity(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || p.d.Values["identity-id"] == "" {
		t.Fatal("identity was not saved before execution")
	}
	if !strings.Contains(p.ui.output.(*bytes.Buffer).String(), "This value is required") {
		t.Fatal("blank display name accepted")
	}
	var saved rolePreparation
	if err := setupReadJSON(p.path, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Values["identity-id"] != p.d.Values["identity-id"] {
		t.Fatal("identity changed across resume")
	}
	if err := os.WriteFile(filepath.Join(p.d.Keys, "signing.hex"), []byte("partial fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.identity(); err == nil {
		t.Fatal("existing private output would be regenerated")
	}
	if calls != 1 {
		t.Fatal("private output caused a second execution")
	}
}
func TestRolePreparationKeyProfilesAreRoleSpecific(t *testing.T) {
	p := preparationFixture(t, "witness")
	first := p.alias("keygen")
	p.d.Role = "mirror"
	if first == p.alias("keygen") || !guidedName.MatchString(first) {
		t.Fatal("roles share a key-generation profile")
	}
}
func TestRolePreparationTransportProfilesBindOwnIdentity(t *testing.T) {
	for _, role := range []string{"witness", "mirror", "auditor", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			p := preparationFixture(t, role)
			prepareTestProfile(t, p, role)
			if role != "upload-station" {
				prepareTestIdentity(t, p)
			}
			p.ui.input = bufio.NewReader(strings.NewReader("2\n"))
			for _, name := range []string{"enrollment.json", "enrollment.sig"} {
				if err := writePublicTextOnce(filepath.Join(p.d.Work, name), "{}"); err != nil {
					t.Fatal(err)
				}
			}
			p.run = func(args []string) error {
				joined := strings.Join(args, " ")
				if !strings.Contains(joined, "--phase phase2") || !strings.Contains(joined, "--enrollment /work/enrollment.json") || !strings.Contains(joined, "--tool-identity-receipt /trust/tool-identity-receipt.env") {
					t.Fatalf("bad initializer: %q", args)
				}
				if role != "upload-station" && !strings.Contains(joined, "--identity my-id") {
					t.Fatal("own identity not checked")
				}
				if role == "upload-station" && !strings.Contains(joined, "--role release") {
					t.Fatal("wrong transport role")
				}
				return nil
			}
			if err := p.initProfile(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRolePreparationImportIsExplicitAndCreateOnly(t *testing.T) {
	p := preparationFixture(t, "auditor")
	source := filepath.Join(filepath.Dir(p.path), "public.json")
	if err := os.WriteFile(source, []byte(`{"schema":"test-public"}`), 0600); err != nil {
		t.Fatal(err)
	}
	answers := "1\n" + source + "\nIMPORT\n"
	p.ui.input = bufio.NewReader(strings.NewReader(answers))
	if err := p.importFile(); err != nil {
		t.Fatal(err)
	}
	dest := preparationDestination(p.d, "definition")
	before, _ := os.ReadFile(dest)
	p.ui.input = bufio.NewReader(strings.NewReader(answers))
	if err := p.importFile(); err != nil {
		t.Fatal("identical import should be harmless", err)
	}
	if err := os.WriteFile(source, []byte(`{"schema":"different"}`), 0600); err != nil {
		t.Fatal(err)
	}
	p.ui.input = bufio.NewReader(strings.NewReader(answers))
	if err := p.importFile(); err == nil {
		t.Fatal("different existing public file overwritten")
	}
	after, _ := os.ReadFile(dest)
	if !bytes.Equal(before, after) {
		t.Fatal("public bytes changed")
	}
	link := filepath.Join(filepath.Dir(p.path), "linked.json")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPreparationInput(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := readPreparationInput("relative.json"); err == nil {
		t.Fatal("accepted relative path")
	}
}
func TestRolePreparationUploadAndObserversNeverMountSigningKeys(t *testing.T) {
	for _, role := range []string{"upload-station", "witness", "mirror"} {
		t.Run(role, func(t *testing.T) {
			p := preparationFixture(t, role)
			p.run = func(args []string) error {
				for _, v := range args {
					if v == "--keys" {
						t.Fatal("unnecessary signing key mount")
					}
				}
				return nil
			}
			if err := p.setup(role); err != nil {
				t.Fatal(err)
			}
			if role == "upload-station" && p.identity() == nil {
				t.Fatal("upload station generated identity")
			}
		})
	}
}
func TestRolePreparationRejectsChangedProfileAndMissingImages(t *testing.T) {
	p := preparationFixture(t, "auditor")
	if err := p.open("auditor", "inspect", []string{"mpc-ceremony", "inspect"}); err == nil {
		t.Fatal("opened without preparation")
	}
	prepareTestProfile(t, p, "auditor")
	p.d.Release = "role-images-" + strings.Repeat("c", 40)
	if _, err := p.profile("auditor"); err == nil {
		t.Fatal("accepted another release")
	}
}

func TestRolePreparationExplainsHostDisconnectionPrecisely(t *testing.T) {
	for _, role := range []string{"participant", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			p := preparationFixture(t, role)
			p.ui.input = bufio.NewReader(strings.NewReader("6\n0\n"))
			if err := p.menu(); err != nil {
				t.Fatal(err)
			}
			out := p.ui.output.(*bytes.Buffer).String()
			if !strings.Contains(out, "Only the final signer must disconnect the host") || strings.Contains(out, "Disconnect the signing host when prompted") {
				t.Fatalf("imprecise host-disconnection guidance: %s", out)
			}
		})
	}
}

func TestRolePreparationUsesAuthoredSetupOrder(t *testing.T) {
	p := preparationFixture(t, "participant")
	if got := p.nextPreparationAction().choice; got != "1" {
		t.Fatalf("initial step = %s, want images", got)
	}
	prepareTestProfile(t, p, "keygen")
	prepareTestProfile(t, p, "decision-signer")
	p.d.Values["image"] = "sha256:" + strings.Repeat("b", 64)
	p.d.Values["binary"] = "/usr/local/bin/mpc-ceremony"
	if got := p.nextPreparationAction().choice; got != "2" {
		t.Fatalf("after images = %s, want identity", got)
	}
	prepareTestIdentity(t, p)
	if got := p.nextPreparationAction().choice; got != "3" {
		t.Fatalf("after identity = %s, want public inputs", got)
	}
	for _, path := range []string{
		filepath.Join(p.d.Work, "ceremony/public/ceremony.json"),
		filepath.Join(p.d.Work, "ceremony/public/ceremony.sig"),
		filepath.Join(p.d.Trust, "coordinator-public-key.hex"),
	} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.nextPreparationAction().choice; got != "7" {
		t.Fatalf("after public inputs = %s, want enrollment", got)
	}
	for _, name := range []string{"enrollment.json", "enrollment.sig"} {
		if err := os.WriteFile(filepath.Join(p.d.Work, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.nextPreparationAction().choice; got != "4" {
		t.Fatalf("after enrollment = %s, want phase profile", got)
	}
	if err := os.WriteFile(filepath.Join(p.d.Work, "ceremony/config/participant-phase1.json"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := p.nextPreparationAction().choice; got != "5" {
		t.Fatalf("after phase profile = %s, want operations", got)
	}
}

func TestRolePreparationParticipantWorkflowDefaults(t *testing.T) {
	f := flowFixture(t)
	f.state.Role = "participant"
	f.state.Profile.Config = "/test/ceremony/config/participant-phase1.json"
	f.stages = roleFlowStages("participant")
	for _, stage := range []int{1, 2} {
		f.state.Stage = stage
		f.ui.input = bufio.NewReader(strings.NewReader("\n"))
		args, err := f.command(f.stages[stage].Tasks[0])
		if err != nil {
			t.Fatal(err)
		}
		want := "/test/ceremony/config/participant-" + f.stages[stage].ID + ".json"
		if len(args) != 3 || args[2] != want {
			t.Fatalf("wrong phase default: %q", args)
		}
	}
}

func TestRolePreparationMigratesLegacyParticipantProfileForCustody(t *testing.T) {
	p := preparationFixture(t, "participant")
	image, platform := "sha256:"+strings.Repeat("b", 64), "linux/arm64"
	configPath := prepareParticipantRoleConfig(t, p, image, platform)
	dir, err := guidedDirectory(p.settingsRoot, p.d.Name, "participant")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := guidedProfile{Schema: guidedSchema, Name: p.d.Name, Role: "participant", ReleaseCommit: strings.Repeat("a", 40), Config: configPath}
	profilePath := filepath.Join(dir, "profile.json")
	if err := writeJSONNoReplace(profilePath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := p.profile("participant")
	if err != nil {
		t.Fatal(err)
	}
	if got.Work != p.d.Work || got.Trust != p.d.Trust || got.Keys != p.d.Keys {
		t.Fatalf("participant directories were not migrated: %#v", got)
	}
	if got.Image != image || got.Platform != platform {
		t.Fatalf("participant runtime was not migrated: %#v", got)
	}
	var backup guidedProfile
	if err := setupReadJSON(profilePath+".pre-custody-v1.bak", &backup); err != nil {
		t.Fatal(err)
	}
	if backup.Work != "" || backup.Trust != "" || backup.Keys != "" {
		t.Fatal("migration backup was changed")
	}
	if err := setupReadJSON(profilePath+".pre-runtime-v1.bak", &backup); err != nil {
		t.Fatal(err)
	}
	if backup.Image != "" || backup.Platform != "" || backup.Work != p.d.Work {
		t.Fatal("runtime migration backup was changed")
	}
}

func TestRolePreparationRejectsParticipantRuntimeMismatch(t *testing.T) {
	p := preparationFixture(t, "participant")
	image, platform := "sha256:"+strings.Repeat("b", 64), "linux/arm64"
	configPath := prepareParticipantRoleConfig(t, p, image, platform)
	dir, err := guidedDirectory(p.settingsRoot, p.d.Name, "participant")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := guidedProfile{Schema: guidedSchema, Name: p.d.Name, Role: "participant", ReleaseCommit: strings.Repeat("a", 40), Config: configPath, Work: p.d.Work, Trust: p.d.Trust, Keys: p.d.Keys, Image: "sha256:" + strings.Repeat("c", 64), Platform: platform}
	if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), profile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.profile("participant"); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("participant runtime mismatch accepted: %v", err)
	}
}

func TestRolePreparationParticipantSetupSavesCustodyDirectories(t *testing.T) {
	p := preparationFixture(t, "participant")
	p.run = func(args []string) error {
		joined := strings.Join(args, "\x00")
		for _, want := range []string{"--config", "--work", p.d.Work, "--trust", p.d.Trust, "--keys", p.d.Keys} {
			if !strings.Contains(joined, want) {
				t.Fatalf("participant setup omitted %q: %q", want, args)
			}
		}
		return nil
	}
	if err := p.setup("participant"); err != nil {
		t.Fatal(err)
	}
}

func TestRolePreparationInstallerEntryPoint(t *testing.T) {
	root := t.TempDir()
	launcher := filepath.Join(root, "release")
	if err := os.Mkdir(launcher, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(launcher, "relay"), []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	installer, err := filepath.Abs("../../scripts/install-launcher.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"coordinator", "participant", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			folder := filepath.Join(root, role+" ' $ ! space")
			cmd := exec.Command("bash", "-c", `source "$1"; destination=$2; role_folder=$3; guided_role=$4; guided_name=example; commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; tag=role-images-$commit; save_guided_settings`, "test", installer, launcher, folder, role)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("installer settings: %v\n%s", err, out)
			}
			for _, shell := range []string{"bash", "zsh"} {
				if _, err := exec.LookPath(shell); err != nil {
					continue
				}
				cmd := exec.Command(shell, "-c", `"$1"`, "entry-test", filepath.Join(folder, "start.sh"))
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("entry: %v\n%s", err, out)
				}
				words := strings.Split(strings.TrimSpace(string(out)), "\n")
				want := []string{"ceremony", "prepare", "--name", "example", "--role", role, "--release", "role-images-" + strings.Repeat("a", 40), "--work", filepath.Join(folder, "work"), "--trust", filepath.Join(folder, "trust"), "--keys", filepath.Join(folder, "keys")}
				if role == "coordinator" {
					want = append([]string{"coordinator", "prepare", "--name", "example"}, want[6:]...)
				}
				if strings.Join(words, "\x00") != strings.Join(want, "\x00") {
					t.Fatalf("%s arguments: %q; want %q", shell, words, want)
				}
			}
		})
	}
}

// Real offline-image key generation, using only fresh temporary keys. This does
// not test GitHub provenance, enrollment signing, or a full ceremony.
func TestRolePreparationDockerIdentity(t *testing.T) {
	if os.Getenv("RELAY_FLOW_DOCKER") != "1" {
		t.Skip("opt-in Docker test")
	}
	image := os.Getenv("RELAY_ROLE_OFFLINE_IMAGE")
	if !roleImagePattern.MatchString(image) {
		t.Fatal("provide immutable offline test image")
	}
	p := preparationFixture(t, "release-signer")
	prepareTestProfile(t, p, "keygen")
	p.ui.input = bufio.NewReader(strings.NewReader("Temporary test signer\nOFFLINE\nGENERATE\n"))
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	bound := client.BindHost(endpoint)
	p.run = func(args []string) error {
		idx := -1
		for n, v := range args {
			if v == "--" {
				idx = n
				break
			}
		}
		if idx < 0 {
			t.Fatal("missing command boundary")
		}
		platform := os.Getenv("RELAY_ROLE_PLATFORM")
		if platform == "" {
			platform = "linux/arm64"
		}
		dockerArgs, err := dockerRoleArgs(dockerRoleOptions{role: "keygen", image: image, platform: platform, work: p.d.Keys}, args[idx+1:], os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		_, stderr, err := bound.Output(dockerArgs...)
		if err != nil {
			return fmt.Errorf("Docker identity: %w: %s", err, stderr)
		}
		return nil
	}
	if err := p.identity(); err != nil {
		t.Fatal(err)
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(p.d.Keys, "identity.json"), &identity); err != nil {
		t.Fatal(err)
	}
	if err := identity.check(); err != nil {
		t.Fatal(err)
	}
	if identity.ID != p.d.Values["identity-id"] {
		t.Fatal("generated identity differs from saved ID")
	}
	st, err := os.Stat(filepath.Join(p.d.Keys, "signing.hex"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("missing protected key")
	}
	p.run = func([]string) error { t.Fatal("resume regenerated the key"); return nil }
	if err := p.identity(); err != nil {
		t.Fatal(err)
	}
}

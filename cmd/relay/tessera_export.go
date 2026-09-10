package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zksecurity/relay/internal/transcript"
	releaseassets "github.com/zksecurity/relay/release"
)

type tesseraAssignment struct {
	ID       string        `json:"id"`
	Person   string        `json:"person_ref"`
	Revision int           `json:"revision"`
	Role     string        `json:"role"`
	Phases   []string      `json:"phases"`
	Identity setupIdentity `json:"identity"`
}
type tesseraSchedule struct {
	Phase   string   `json:"phase"`
	IDs     []string `json:"assignment_ids"`
	Minimum int      `json:"minimum"`
}
type tesseraContext struct {
	Schema      string              `json:"schema"`
	CeremonyID  string              `json:"ceremony_id"`
	Revision    int                 `json:"config_revision"`
	Mode        string              `json:"mode"`
	Assignments []tesseraAssignment `json:"assignments"`
	Schedules   []tesseraSchedule   `json:"schedules"`
}
type tesseraStorage struct {
	Provider        string `json:"provider"`
	Region          string `json:"region"`
	PublicURL       string `json:"public_base_url"`
	PublishedBucket string `json:"published_bucket"`
	InboxBucket     string `json:"inbox_bucket"`
}
type tesseraArtifact struct {
	Kind     string `json:"kind"`
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
	Length   int    `json:"byte_length"`
	Content  string `json:"content_b64"`
}
type tesseraSoftware struct {
	Commit      string `json:"relay_commit"`
	Tag         string `json:"release_tag"`
	ProofCommit string `json:"proof_tool_commit"`
	ManifestSHA string `json:"manifest_sha256"`
	RecipeSHA   string `json:"workflow_recipe_sha256"`
}
type tesseraWorkflow struct {
	Schema    string `json:"schema"`
	Template  string `json:"template"`
	RecipeSHA string `json:"recipe_sha256"`
}
type tesseraBundle struct {
	Schema        string              `json:"schema"`
	CeremonyID    string              `json:"ceremony_id"`
	Revision      int                 `json:"config_revision"`
	Mode          string              `json:"mode"`
	ProtocolID    string              `json:"protocol_id"`
	DefinitionSHA string              `json:"definition_sha256"`
	Software      tesseraSoftware     `json:"software"`
	Workflow      tesseraWorkflow     `json:"workflow"`
	Storage       tesseraStorage      `json:"storage"`
	Assignments   []tesseraAssignment `json:"assignments"`
	Schedules     []tesseraSchedule   `json:"schedules"`
	Artifacts     []tesseraArtifact   `json:"artifacts"`
}

func tesseraDigest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }

// Unlike signed consent payloads, downloaded JSON permits arbitrary key order.
// Reject duplicate keys before decoding so a producer cannot hide a second value.
func tesseraJSON(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting exceeds 32 levels")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON field")
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func loadTesseraContext(path string) (tesseraContext, error) {
	var context tesseraContext
	raw, err := readTesseraRegularFile(path, 1<<20, false)
	if err != nil {
		return context, err
	}
	if err := tesseraJSON(raw, &context); err != nil {
		return context, fmt.Errorf("roster JSON: %w", err)
	}
	return context, context.validate()
}
func (c tesseraContext) validate() error {
	if c.Schema != "tessera-draft-context-v1" || !tesseraUUID.MatchString(c.CeremonyID) || c.Revision < 1 || (c.Mode != "rehearsal" && c.Mode != "production") || len(c.Assignments) < 1 || len(c.Assignments) > 100 || len(c.Schedules) != 2 {
		return errors.New("invalid Tessera roster; download it again after saving both phase orders")
	}
	ids, keys, identityIDs, keyIDs := map[string]tesseraAssignment{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	counts := map[string]int{}
	for _, a := range c.Assignments {
		if !tesseraUUID.MatchString(a.ID) || !tesseraUUID.MatchString(a.Person) || a.Revision < 1 || a.Phases == nil || !slices.Contains([]string{"coordinator", "participant", "auditor", "release-signer", "witness", "mirror"}, a.Role) {
			return errors.New("invalid roster assignment")
		}
		if err := a.Identity.check(); err != nil {
			return err
		}
		if !tesseraID.MatchString(a.Identity.ID) || !tesseraID.MatchString(a.Identity.KeyID) {
			return errors.New("identity IDs must use letters, digits, dots, underscores or hyphens")
		}
		if _, found := ids[a.ID]; found || keys[a.Identity.PublicKey] || identityIDs[a.Identity.ID] || keyIDs[a.Identity.KeyID] {
			return errors.New("roles require distinct assignment IDs, identity IDs, key IDs and public keys")
		}
		phases := map[string]bool{}
		for _, p := range a.Phases {
			if (p != "phase1" && p != "phase2") || phases[p] || a.Role != "participant" {
				return errors.New("only participant roles can have distinct contribution phases")
			}
			phases[p] = true
		}
		if a.Role == "participant" && len(phases) == 0 {
			return errors.New("assign each participant to at least one phase")
		}
		ids[a.ID] = a
		keys[a.Identity.PublicKey] = true
		identityIDs[a.Identity.ID] = true
		keyIDs[a.Identity.KeyID] = true
		counts[a.Role]++
	}
	if counts["coordinator"] != 1 || counts["release-signer"] != 1 || counts["auditor"] < 1 {
		return errors.New("the CLI requires one coordinator, one release signer and at least one auditor; update the website roster")
	}
	phases := map[string]bool{}
	for _, s := range c.Schedules {
		if (s.Phase != "phase1" && s.Phase != "phase2") || phases[s.Phase] || len(s.IDs) < 1 || len(s.IDs) > 20 || s.Minimum < 1 || s.Minimum > len(s.IDs) {
			return errors.New("invalid phase order or minimum")
		}
		phases[s.Phase] = true
		seen := map[string]bool{}
		for _, id := range s.IDs {
			a, ok := ids[id]
			if !ok || seen[id] || !slices.Contains(a.Phases, s.Phase) {
				return errors.New("phase order does not match participant assignments")
			}
			seen[id] = true
		}
		for _, a := range c.Assignments {
			if slices.Contains(a.Phases, s.Phase) && !seen[a.ID] {
				return errors.New("phase order is missing a participant")
			}
		}
		if c.Mode == "production" && (len(s.IDs) < 2 || s.Minimum != len(s.IDs)) {
			return errors.New("production requires at least two participants and every contribution in each phase")
		}
	}
	return nil
}
func (c tesseraContext) setupInputs() (setupRoster, setupPhase, setupPhase) {
	roster := setupRoster{Auditors: []setupIdentity{}, Roster: []setupParticipant{}}
	ids := map[string]string{}
	for _, a := range c.Assignments {
		ids[a.ID] = a.Identity.ID
		switch a.Role {
		case "coordinator":
			roster.Coordinator = a.Identity
		case "release-signer":
			roster.ReleaseSigner = a.Identity
		case "auditor":
			roster.Auditors = append(roster.Auditors, a.Identity)
		case "participant":
			roster.Roster = append(roster.Roster, setupParticipant{Identity: a.Identity})
		}
	}
	phases := map[string]setupPhase{}
	for _, s := range c.Schedules {
		p := setupPhase{Participants: []string{}, Minimum: s.Minimum}
		for _, id := range s.IDs {
			p.Participants = append(p.Participants, ids[id])
		}
		phases[s.Phase] = p
	}
	return roster, phases["phase1"], phases["phase2"]
}
func (s tesseraStorage) validate() error {
	u, err := url.Parse(s.PublicURL)
	bucket := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	if s.Provider != "aws" || !regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`).MatchString(s.Region) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !bucket.MatchString(s.PublishedBucket) || !bucket.MatchString(s.InboxBucket) || s.PublishedBucket == s.InboxBucket {
		return errors.New("public storage requires AWS region, distinct bucket names and an HTTPS public URL without credentials, query or fragment")
	}
	return nil
}

// This projection is read only after the exact bytes have been authenticated by
// proof-tool. Protocol interpretation/signature verification stays in proof-tool.
type tesseraDefinition struct {
	Schema        string             `json:"schema"`
	ProtocolID    string             `json:"ceremony_id"`
	Mode          string             `json:"mode"`
	Coordinator   setupIdentity      `json:"coordinator"`
	ReleaseSigner setupIdentity      `json:"release_signer"`
	Auditors      []setupIdentity    `json:"auditors"`
	Roster        []setupParticipant `json:"roster"`
	Phase1        setupPhase         `json:"phase1_policy"`
	Phase2        setupPhase         `json:"phase2_policy"`
	Software      struct {
		Commit   string            `json:"source_commit"`
		Dirty    bool              `json:"source_dirty"`
		OS       string            `json:"goos"`
		Arch     string            `json:"goarch"`
		Binary   tesseraToolDigest `json:"tool_binary"`
		Binaries []struct {
			OS     string            `json:"goos"`
			Arch   string            `json:"goarch"`
			Binary tesseraToolDigest `json:"tool_binary"`
		} `json:"binaries"`
	} `json:"software"`
}

type tesseraToolDigest struct {
	SHA256 string `json:"sha256"`
}

func checkTesseraDefinition(c tesseraContext, raw []byte, inspected transcript.Definition) (tesseraDefinition, error) {
	var d tesseraDefinition
	// Unknown signed protocol fields are retained in the original artifact.
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	if d.Schema != "proof-tool-mpc-ceremony-definition-v2" || d.ProtocolID != inspected.CeremonyID || !tesseraHash.MatchString(d.ProtocolID) || d.Mode != c.Mode || d.Mode != inspected.Mode || !slices.Equal(d.Phase1.Participants, inspected.Phase1Participants) || !slices.Equal(d.Phase2.Participants, inspected.Phase2Participants) {
		return d, errors.New("signed definition and authenticated inspection disagree with the website roster")
	}
	roster, p1, p2 := c.setupInputs()
	equal := func(a, b any) bool {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Equal(left, right)
	}
	if !equal(p1, d.Phase1) || !equal(p2, d.Phase2) || roster.Coordinator != d.Coordinator || roster.ReleaseSigner != d.ReleaseSigner {
		return d, errors.New("signed definition has different coordinator, release signer, phase order or minimum; regenerate from the saved website roster")
	}
	// Auditor and roster array order is not an assignment; phase order is.
	matches := map[string]setupIdentity{}
	for _, i := range d.Auditors {
		matches["auditor/"+i.ID] = i
	}
	for _, p := range d.Roster {
		matches["participant/"+p.Identity.ID] = p.Identity
	}
	if len(d.Auditors) != len(roster.Auditors) || len(d.Roster) != len(roster.Roster) {
		return d, errors.New("signed definition roster has extra or missing identities")
	}
	for _, a := range c.Assignments {
		if a.Role == "auditor" || a.Role == "participant" {
			if matches[a.Role+"/"+a.Identity.ID] != a.Identity {
				return d, errors.New("signed definition identity differs from website assignment")
			}
		}
	}
	return d, nil
}

func tesseraRecipe() []byte {
	catalog := map[string][]flowStage{}
	for _, role := range []string{"coordinator", "participant", "auditor", "release-signer", "witness", "mirror"} {
		catalog[role] = roleFlowStages(role)
	}
	raw, _ := json.Marshal(catalog)
	return raw
}
func tesseraManifest(d tesseraDefinition, tag string, releaseMap []byte) ([]byte, error) {
	var inputs struct {
		MPC map[string]struct {
			URL string `json:"url"`
			SHA string `json:"sha256"`
		} `json:"mpc"`
	}
	if err := json.Unmarshal(releaseassets.RoleImageInputs(), &inputs); err != nil {
		return nil, err
	}
	if d.Software.Dirty || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(d.Software.Commit) {
		return nil, errors.New("signed definition must use a clean approved proof-tool build")
	}
	check := func(osName, arch, digest string) bool {
		pin, ok := inputs.MPC[osName+"_"+arch]
		return ok && digest == "sha256:"+pin.SHA && strings.HasPrefix(pin.URL, "https://github.com/zksecurity/proof-tool/releases/download/mpc-ci-"+d.Software.Commit+"/")
	}
	if !check(d.Software.OS, d.Software.Arch, d.Software.Binary.SHA256) {
		return nil, errors.New("signed definition's proof-tool is not part of this CLI release")
	}
	for _, binary := range d.Software.Binaries {
		if !check(binary.OS, binary.Arch, binary.Binary.SHA256) {
			return nil, errors.New("signed definition permits a binary outside this CLI release")
		}
	}
	return json.Marshal(struct {
		Schema  string          `json:"schema"`
		Release string          `json:"release_tag"`
		Map     json.RawMessage `json:"role_images"`
		Inputs  json.RawMessage `json:"role_image_inputs"`
		Recipe  json.RawMessage `json:"workflow_recipe"`
	}{"tessera-software-manifest-v1", tag, releaseMap, releaseassets.RoleImageInputs(), tesseraRecipe()})
}
func buildTesseraBundle(c tesseraContext, storage tesseraStorage, definition, signature, key, manifest []byte, inspected transcript.Definition, commit, proofCommit string) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := storage.validate(); err != nil {
		return nil, err
	}
	d, err := checkTesseraDefinition(c, definition, inspected)
	if err != nil {
		return nil, err
	}
	if d.Software.Commit != proofCommit || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return nil, errors.New("software commit mismatch")
	}
	if strings.TrimSpace(string(key)) != d.Coordinator.PublicKey {
		return nil, errors.New("coordinator trust key does not match website assignment")
	}
	b := tesseraBundle{Schema: "tessera-bundle-v1", CeremonyID: c.CeremonyID, Revision: c.Revision, Mode: c.Mode, ProtocolID: d.ProtocolID, DefinitionSHA: tesseraDigest(definition), Software: tesseraSoftware{commit, "role-images-" + commit, proofCommit, tesseraDigest(manifest), tesseraDigest(tesseraRecipe())}, Workflow: tesseraWorkflow{"tessera-workflow-v1", "relay-two-phase-v1", tesseraDigest(tesseraRecipe())}, Storage: storage, Assignments: c.Assignments, Schedules: append([]tesseraSchedule(nil), c.Schedules...)}
	slices.SortFunc(b.Schedules, func(a, b tesseraSchedule) int { return strings.Compare(a.Phase, b.Phase) })
	for _, a := range []struct {
		kind string
		raw  []byte
	}{{"definition", definition}, {"definition-signature", signature}, {"coordinator-key", key}, {"software-manifest", manifest}} {
		if len(a.raw) < 1 || len(a.raw) > 1<<20 {
			return nil, errors.New("setup artifact exceeds 1 MiB or is empty")
		}
		b.Artifacts = append(b.Artifacts, tesseraArtifact{a.kind, "none", tesseraDigest(a.raw), len(a.raw), base64.StdEncoding.EncodeToString(a.raw)})
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if len(raw) > 8<<20 {
		return nil, errors.New("setup exceeds 8 MiB")
	}
	return append(raw, '\n'), err
}

func runTesseraExport(args []string) error {
	flags := flag.NewFlagSet("tessera export-setup", flag.ContinueOnError)
	contextPath := flags.String("context", "", "website roster JSON")
	definitionPath := flags.String("ceremony", "", "signed ceremony definition")
	signaturePath := flags.String("ceremony-signature", "", "definition signature")
	keyPath := flags.String("coordinator-key-file", "", "independently checked coordinator public key")
	release := flags.String("release", "", "exact role-images release of this launcher")
	storagePath := flags.String("storage-public", "", "public-only AWS storage JSON")
	output := flags.String("out", "", "fresh output setup JSON")
	platform := flags.String("platform", "linux/"+runtime.GOARCH, "approved Linux inspection platform")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *contextPath == "" || *definitionPath == "" || *signaturePath == "" || *keyPath == "" || *release == "" || *storagePath == "" || *output == "" {
		return errors.New("--context, --ceremony, --ceremony-signature, --coordinator-key-file, --release, --storage-public and --out are required")
	}
	c, err := loadTesseraContext(*contextPath)
	if err != nil {
		return err
	}
	var storage tesseraStorage
	raw, err := readTesseraRegularFile(*storagePath, 16384, false)
	if err != nil {
		return err
	}
	if err = tesseraJSON(raw, &storage); err != nil {
		return err
	}
	if err = storage.validate(); err != nil {
		return err
	}
	definition, err := readTesseraRegularFile(*definitionPath, 1<<20, false)
	if err != nil {
		return err
	}
	signature, err := readTesseraRegularFile(*signaturePath, 1<<20, false)
	if err != nil {
		return err
	}
	key, err := readTesseraRegularFile(*keyPath, 256, false)
	if err != nil {
		return err
	}
	key = bytes.TrimSpace(key)
	if decoded, err := hex.DecodeString(string(key)); err != nil || len(decoded) != 32 {
		return errors.New("coordinator key must contain only the public 32-byte hexadecimal key")
	}
	if _, err = os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output already exists or cannot be checked; choose a fresh filename")
	}
	image, commit, releaseMap, err := verifiedReleaseImageMap(*release, "coordinator", *platform)
	if err != nil {
		return err
	}
	// Inspect a bounded snapshot, then embed those exact bytes. No private mounts,
	// network, host tools, or credentials are passed to the inspection container.
	dir, err := os.MkdirTemp("", "tessera-export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for name, raw := range map[string][]byte{"ceremony.json": definition, "ceremony.sig": signature, "coordinator.hex": key} {
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			return err
		}
	}
	inspector := transcript.Inspector{Executable: "mpc-ceremony", CeremonyPath: "/input/ceremony.json", CeremonySignaturePath: "/input/ceremony.sig", CoordinatorPublicKeyPath: "/input/coordinator.hex", Runner: func(executable string, args ...string) ([]byte, []byte, error) {
		argv := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--platform", *platform, "--mount", "type=bind,src=" + dir + ",dst=/input,readonly", "--entrypoint", "/usr/local/bin/mpc-ceremony", image}
		command := exec.Command("docker", append(argv, args...)...)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}}
	inspected, err := inspector.Definition()
	if err != nil {
		return fmt.Errorf("verify signed definition with the installed release image (install/preload it first): %w", err)
	}
	d, err := checkTesseraDefinition(c, definition, inspected)
	if err != nil {
		return err
	}
	manifest, err := tesseraManifest(d, *release, releaseMap)
	if err != nil {
		return err
	}
	bundle, err := buildTesseraBundle(c, storage, definition, signature, key, manifest, inspected, commit, d.Software.Commit)
	if err != nil {
		return err
	}
	if err = writeTesseraFresh(*output, bundle, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Setup exported. Import this JSON in Tessera, review it, then freeze explicitly. Witness and mirror assignments still require separate protocol enrollment.")
	return nil
}

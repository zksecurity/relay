package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

var candidateFileNames = []string{
	"contribution.bin", "attestation.json", "attestation.sig", "erasure.json", "erasure.sig",
}

const localCandidateManifestName = ".relay-upload-manifest.json"

type candidateObjectStore interface {
	PutNoReplace(key, localPath string) error
	Get(key, localPath string) error
}

func runEnroll(args []string) error {
	set := flag.NewFlagSet("enroll", flag.ContinueOnError)
	var storagePath, grantPath, phase, root, ceremony, ceremonySignature, coordinatorKey, ceremonyBinary string
	var executionMode, dockerImage, dockerPlatform, dockerCLI string
	var signingKey, environment, candidateParent, out string
	set.StringVar(&storagePath, "storage", "", "storage configuration supplied by the coordinator")
	set.StringVar(&grantPath, "grant", "", "optional temporary participant grant supplied by the coordinator")
	set.StringVar(&phase, "phase", "", "phase1 or phase2")
	set.StringVar(&root, "root", "", "local transcript root")
	set.StringVar(&ceremony, "ceremony", "", "local signed ceremony definition")
	set.StringVar(&ceremonySignature, "ceremony-signature", "", "local definition signature")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "out-of-band coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted ceremony executable")
	set.StringVar(&executionMode, "execution-mode", nativeExecutionMode, "native or docker")
	set.StringVar(&dockerImage, "docker-image", "", "locally preloaded ceremony image pinned by immutable SHA-256")
	set.StringVar(&dockerPlatform, "docker-platform", "linux/amd64", "approved image platform: linux/amd64 or linux/arm64")
	set.StringVar(&dockerCLI, "docker-cli", "docker", "Docker command used by the native Relay supervisor")
	set.StringVar(&signingKey, "signing-key", "", "participant Ed25519 private key")
	set.StringVar(&environment, "environment", "", "canonical environment.json")
	set.StringVar(&candidateParent, "candidate-parent", "", "directory in which a fresh candidate will be created")
	set.StringVar(&out, "out", defaultParticipantConfigPath(), "fresh participant configuration file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if executionMode == dockerExecutionMode && !hasNamedFlag(args, "ceremony-binary") {
		ceremonyBinary = "/usr/local/bin/mpc-ceremony"
	}
	if executionMode == nativeExecutionMode {
		dockerImage, dockerPlatform, dockerCLI = "", "", ""
	}
	if candidateParent == "" && out != "" {
		candidateParent = filepath.Join(filepath.Dir(out), "candidates")
	}
	if storagePath == "" || phase == "" || root == "" || ceremony == "" || ceremonySignature == "" || coordinatorKey == "" || signingKey == "" || environment == "" || candidateParent == "" || out == "" {
		return errors.New("--storage, --phase, --root, --ceremony, --ceremony-signature, --coordinator-key, --signing-key and --environment are required; --candidate-parent and --out have local defaults")
	}
	storageConfig, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, Phase: phase, Root: root,
		Ceremony: ceremony, CeremonySignature: ceremonySignature,
		CoordinatorKey: coordinatorKey, CeremonyBinary: ceremonyBinary,
		SigningKey: signingKey, Environment: environment, CandidateParentDir: candidateParent,
		PublishedBaseURL: storageConfig.PublishedBaseURL, PublishedBucket: storageConfig.PublishedBucket,
		GrantPath: grantPath, ExecutionMode: executionMode, DockerImage: dockerImage,
		DockerPlatform: dockerPlatform, DockerCLI: dockerCLI,
	}
	if err := config.Validate(); err != nil {
		return err
	}
	inspector := transcript.Inspector{Executable: ceremonyBinary, CeremonyPath: ceremony,
		CeremonySignaturePath: ceremonySignature, CoordinatorPublicKeyPath: coordinatorKey, TranscriptRoot: root}
	if executionMode == dockerExecutionMode {
		driver := dockerDriverForParticipant(config)
		if err := driver.preflight(); err != nil {
			return err
		}
		inspector = driver.inspector()
	}
	participant, err := inspector.Participant(signingKey)
	if err != nil {
		return err
	}
	if participant.CeremonyID != storageConfig.CeremonyID {
		return errors.New("local participant key does not match the storage ceremony")
	}
	if grantPath != "" {
		grant, err := loadGrant(grantPath)
		if err != nil {
			return err
		}
		if grant.Role != access.RoleParticipant || grant.CeremonyID != storageConfig.CeremonyID ||
			grant.Provider != storageConfig.Provider || grant.InboxBucket != storageConfig.InboxBucket ||
			grant.IdentityID != participant.ParticipantID {
			return errors.New("participant grant does not match the storage configuration and local key")
		}
	}
	slot := participant.Phase1Position
	if phase == "phase2" {
		slot = participant.Phase2Position
	} else if phase != "phase1" {
		return errors.New("--phase must be phase1 or phase2")
	}
	if slot == nil {
		return fmt.Errorf("participant %s is not scheduled in %s", participant.ParticipantID, phase)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	if err := writeJSONNoReplace(out, config, 0o600); err != nil {
		return err
	}
	fmt.Printf("enrolled %s for %s at index %d\n", participant.ParticipantID, phase, *slot)
	fmt.Printf("saved local profile: %s\n", out)
	if grantPath == "" {
		fmt.Printf("check your turn: relay participant status --config %s\n", out)
		fmt.Printf("when access is issued: relay participant run --config %s --grant GRANT.json\n", out)
	} else {
		fmt.Printf("when the coordinator tells you to begin, run: relay participant run --config %s\n", out)
	}
	return nil
}

func defaultParticipantConfigPath() string {
	if configured := os.Getenv("RELAY_CONFIG"); configured != "" {
		return configured
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "relay", "participant.json")
}

func runParticipate(args []string) error {
	set := flag.NewFlagSet("participate", flag.ContinueOnError)
	var configPath, grantOverride, resumeCandidate string
	set.StringVar(&configPath, "config", defaultParticipantConfigPath(), "participant configuration created by relay participant enroll")
	set.StringVar(&grantOverride, "grant", "", "fresh temporary participant grant; overrides the profile grant")
	set.StringVar(&resumeCandidate, "resume-candidate", "", "completed local candidate directory whose interrupted upload should resume")
	if err := set.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("--config is required because no default configuration directory is available")
	}
	config, configuredIdentity, err := loadParticipantProfile(configPath)
	if err != nil {
		return err
	}
	if effectiveExecutionMode(config.ExecutionMode) == dockerExecutionMode {
		driver := dockerDriverForParticipant(config)
		if err := driver.cleanupOrphan(); err != nil {
			return err
		}
	}
	grantPath := config.GrantPath
	if grantOverride != "" {
		grantPath = grantOverride
	}
	if grantPath == "" {
		return errors.New("no temporary upload grant: pass --grant FILE when the coordinator tells you it is your turn")
	}
	grant, err := loadGrant(grantPath)
	if err != nil {
		return err
	}
	if err := grant.CheckUsable(time.Now()); err != nil {
		return err
	}
	if grant.Role != access.RoleParticipant {
		return errors.New("participant configuration refers to a non-participant grant")
	}
	o := participantRoleOptions(config, grant.IdentityID)
	participant, err := o.inspector().Participant(config.SigningKey)
	if err != nil {
		return err
	}
	if configuredIdentity != "" && participant.ParticipantID != configuredIdentity {
		return errors.New("configured participant identity does not match the local signing key")
	}
	if participant.CeremonyID != grant.CeremonyID || participant.ParticipantID != grant.IdentityID {
		return errors.New("local participant key does not match the grant")
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	if pos.phaseClosed {
		return fmt.Errorf("not your turn: %s is closed", o.phase)
	}
	if pos.nextID != grant.IdentityID {
		slot, slotErr := pos.definition.SlotOf(o.phase, grant.IdentityID)
		if slotErr != nil {
			return slotErr
		}
		return fmt.Errorf("not your turn: you are index %d, %d accepted, waiting on %s", slot, pos.accepted, pos.nextID)
	}
	if resumeCandidate != "" {
		return resumeCandidateUpload(config, grant, pos, resumeCandidate)
	}
	if err := runWithProgress("downloading authenticated transcript", func() error {
		return fetchForContribution(o, pos)
	}); err != nil {
		return err
	}
	attempt, err := randomID()
	if err != nil {
		return err
	}
	o.outDir = filepath.Join(config.CandidateParentDir, fmt.Sprintf("%s-%04d-%s", config.Phase, pos.nextIndex, attempt))
	if err := runNext(o, pos); err != nil {
		return err
	}
	if err := confirmErasure(o); err != nil {
		return err
	}
	destroyedAt, err := runErasure(o)
	if err != nil {
		return err
	}
	manifest, err := prepareCandidateManifest(o.outDir, grant, config.Phase, pos, attempt)
	if err != nil {
		return err
	}
	localManifest := filepath.Join(o.outDir, localCandidateManifestName)
	if err := writeJSONNoReplace(localManifest, manifest, 0o600); err != nil {
		return fmt.Errorf("save resumable candidate metadata: %w", err)
	}
	if err := grant.CheckUnexpired(time.Now()); err != nil {
		return fmt.Errorf("%w; completed candidate remains at %s", err, o.outDir)
	}
	latest, err := resolvePosition(o)
	if err != nil {
		return fmt.Errorf("recheck published head; completed candidate remains at %s and can be resumed after the state is reachable: %w", o.outDir, err)
	}
	if latest.nextID != pos.nextID || latest.nextIndex != pos.nextIndex || latest.pointer.Chain.SHA256 != pos.pointer.Chain.SHA256 {
		return fmt.Errorf("published chain advanced while the contribution was running; candidate at %s was not uploaded and cannot be resumed against the new head", o.outDir)
	}
	manifestKey, err := uploadCandidate(grantClient(grant), grant.Prefix, o.outDir, localManifest, manifest)
	if err != nil {
		return fmt.Errorf("upload interrupted; completed candidate remains at %s and can be resumed with a fresh grant: %w", o.outDir, err)
	}
	fmt.Printf("candidate submitted for coordinator review\n")
	fmt.Printf("attempt: %s\ncandidate directory: %s\ndestroyed_at: %s\nmanifest: %s\n",
		attempt, o.outDir, destroyedAt.UTC().Format(time.RFC3339), manifestKey)
	return nil
}

func prepareCandidateManifest(candidateDir string, grant access.Grant, phase string, pos position, attempt string) (access.CandidateManifest, error) {
	manifest := access.CandidateManifest{
		Schema: access.CandidateManifestSchema, CeremonyID: grant.CeremonyID, Phase: phase,
		Index: pos.nextIndex, ParticipantID: grant.IdentityID, ParentChainSHA256: pos.pointer.Chain.SHA256,
		AttemptID: attempt, CompletedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	for _, name := range candidateFileNames {
		ref, err := regularFileRef(filepath.Join(candidateDir, name), name)
		if err != nil {
			return access.CandidateManifest{}, err
		}
		manifest.Files = append(manifest.Files, ref)
	}
	if err := manifest.Validate(); err != nil {
		return access.CandidateManifest{}, err
	}
	return manifest, nil
}

func resumeCandidateUpload(config access.ParticipantConfig, grant access.Grant, pos position, candidateDir string) error {
	info, err := os.Lstat(candidateDir)
	if err != nil {
		return fmt.Errorf("load resumable candidate: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("--resume-candidate must be a non-symlink directory")
	}
	localManifest := filepath.Join(candidateDir, localCandidateManifestName)
	raw, err := os.ReadFile(localManifest)
	if err != nil {
		return fmt.Errorf("load resumable candidate metadata: %w", err)
	}
	manifest, err := access.Decode(raw, access.CandidateManifest.Validate)
	if err != nil {
		return fmt.Errorf("validate resumable candidate metadata: %w", err)
	}
	if err := validateResumableCandidate(manifest, config, grant, pos); err != nil {
		return err
	}
	if err := verifyLocalCandidate(candidateDir, manifest); err != nil {
		return err
	}
	destroyedAt, err := candidateDestroyedAt(candidateDir)
	if err != nil {
		return err
	}
	manifestKey, err := uploadCandidate(grantClient(grant), grant.Prefix, candidateDir, localManifest, manifest)
	if err != nil {
		return fmt.Errorf("upload interrupted again; completed candidate remains at %s: %w", candidateDir, err)
	}
	fmt.Printf("candidate upload resumed without recomputing the contribution\n")
	fmt.Printf("attempt: %s\ncandidate directory: %s\ndestroyed_at: %s\nmanifest: %s\n",
		manifest.AttemptID, candidateDir, destroyedAt, manifestKey)
	return nil
}

func candidateDestroyedAt(candidateDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(candidateDir, "erasure.json"))
	if err != nil {
		return "", fmt.Errorf("read saved erasure record: %w", err)
	}
	var erasure struct {
		DestroyedAt string `json:"destroyed_at"`
	}
	if err := json.Unmarshal(raw, &erasure); err != nil {
		return "", fmt.Errorf("decode saved erasure record: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, erasure.DestroyedAt); err != nil {
		return "", errors.New("saved erasure record has an invalid destroyed_at")
	}
	return erasure.DestroyedAt, nil
}

func verifyLocalCandidate(candidateDir string, manifest access.CandidateManifest) error {
	refs := make(map[string]access.FileRef, len(manifest.Files))
	for _, ref := range manifest.Files {
		refs[ref.Name] = ref
	}
	for _, name := range candidateFileNames {
		got, err := regularFileRef(filepath.Join(candidateDir, name), name)
		if err != nil {
			return fmt.Errorf("verify saved candidate %s: %w", name, err)
		}
		want := refs[name]
		if got.SHA256 != want.SHA256 || got.Size != want.Size {
			return fmt.Errorf("saved candidate %s no longer matches its recorded digest", name)
		}
	}
	return nil
}

func validateResumableCandidate(manifest access.CandidateManifest, config access.ParticipantConfig, grant access.Grant, pos position) error {
	if manifest.CeremonyID != grant.CeremonyID || manifest.Phase != config.Phase ||
		manifest.ParticipantID != grant.IdentityID {
		return errors.New("saved candidate does not match the grant, participant, ceremony, and phase")
	}
	if manifest.Index != pos.nextIndex || manifest.ParentChainSHA256 != pos.pointer.Chain.SHA256 {
		return errors.New("saved candidate was built from a different ceremony head and cannot be resumed")
	}
	return nil
}

func uploadCandidate(client candidateObjectStore, grantPrefix, candidateDir, localManifest string, manifest access.CandidateManifest) (string, error) {
	prefix := grantPrefix + manifest.Phase + "/" + fmt.Sprintf("%04d", manifest.Index) + "/" + manifest.AttemptID + "/"
	manifestKey := prefix + "manifest.json"
	if err := runWithProgress("uploading contribution candidate", func() error {
		for _, ref := range manifest.Files {
			local := filepath.Join(candidateDir, ref.Name)
			got, err := regularFileRef(local, ref.Name)
			if err != nil {
				return err
			}
			if got.SHA256 != ref.SHA256 || got.Size != ref.Size {
				return fmt.Errorf("saved candidate %s no longer matches its recorded digest", ref.Name)
			}
			fmt.Fprintf(os.Stderr, "  uploading %s (%s)\n", ref.Name, formatBytes(ref.Size))
			if err := putFreshOrVerify(client, prefix+ref.Name, local, ref); err != nil {
				return err
			}
		}
		manifestRef, err := regularFileRef(localManifest, "manifest.json")
		if err != nil {
			return err
		}
		return putFreshOrVerify(client, manifestKey, localManifest, manifestRef)
	}); err != nil {
		return "", err
	}
	return manifestKey, nil
}

func participantRoleOptions(config access.ParticipantConfig, identity string) roleOpts {
	o := roleOpts{
		root: config.Root, definition: config.Ceremony, definitionSig: config.CeremonySignature,
		coordinatorKey: config.CoordinatorKey, ceremonyBinary: config.CeremonyBinary,
		phase: config.Phase, role: identity, signingKey: config.SigningKey, envPath: config.Environment,
		client: store.Client{Bucket: config.PublishedBucket, PublicBaseURL: config.PublishedBaseURL},
	}
	if effectiveExecutionMode(config.ExecutionMode) == dockerExecutionMode {
		o.docker = dockerDriverForParticipant(config)
	}
	return o
}

func fetchForContribution(o roleOpts, pos position) error {
	files, err := transcript.TranscriptFiles(o.root, pos.chain)
	if err != nil {
		return err
	}
	if r1cs, err := pos.definition.R1CS(); err == nil {
		files = append(files, transcript.File{Name: r1cs.Name, Digest: r1cs.Digest})
	}
	extra := append([]state.Ref(nil), pos.pointer.Files...)
	if o.phase == "phase2" {
		if phase1 := readPointer(o, pos.definition.CeremonyID, "phase1"); phase1 != nil {
			extra = append(extra, phase1.Files...)
		}
	}
	if _, err := fetchListed(o, extra); err != nil {
		return err
	}
	for _, file := range files {
		local, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			return err
		}
		if sum, size, err := transcript.DigestFile(local); err == nil {
			if file.HasDigest() && (sum != file.Digest.SHA256 || size != file.Digest.Size) {
				return fmt.Errorf("%s: local copy differs from authenticated digest", file.Name)
			}
			continue
		}
		if !file.HasDigest() {
			continue
		}
		fmt.Fprintf(os.Stderr, "  downloading %s (%s)\n", file.Name, formatBytes(file.Digest.Size))
		if err := fetchVerified(o.client, state.Ref{Name: file.Name, SHA256: file.Digest.SHA256}, local); err != nil {
			return err
		}
	}
	return nil
}

func confirmErasure(o roleOpts) error {
	if o.docker != nil {
		return confirmDockerNoCopies(o)
	}
	// The prompt goes to stdout so that a logged or tee'd transcript of the
	// run contains it: operators and automation watch that transcript, and a
	// prompt that only ever reaches the terminal's stderr is invisible to
	// both after the fact.
	fmt.Println("Contribution complete. Destroy the contribution environment now.")
	fmt.Print("After it is destroyed, type DESTROYED and press Enter: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	if strings.TrimSpace(line) != "DESTROYED" {
		return errors.New("erasure was not confirmed; candidate remains local and was not uploaded")
	}
	return nil
}

func confirmDockerNoCopies(o roleOpts) error {
	path := filepath.Join(o.outDir, dockerLifecycleLogName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Docker lifecycle record: %w", err)
	}
	var receipt dockerLifecycleReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil || receipt.Schema != dockerLifecycleSchema ||
		!receipt.RemovalVerified || !verifiedLifecycleFacts(receipt.Security) {
		return errors.New("Docker lifecycle record does not prove the required measured cleanup")
	}
	shortID := shortContainerID(receipt.ContainerID)
	fmt.Printf(`Contribution completed.

Relay verified:
  ✓ contributor exited
  ✓ container %s was removed
  ✓ container %s no longer exists
  ✓ its writable layer and tmpfs were removed

Confirm that you:
  • did not create or retain a VM/container snapshot;
  • did not dump or copy the contributor's memory;
  • did not retain any other copy of the contribution randomness; and
  • did not configure the disposable environment for backup.

Type NO COPIES RETAINED to continue: `, shortID, shortID)
	line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
	if readErr != nil && len(line) == 0 {
		return readErr
	}
	if strings.TrimSpace(line) != "NO COPIES RETAINED" {
		return errors.New("no-copy confirmation was not given; candidate remains local and was not uploaded")
	}
	receipt.ParticipantConfirmation = "NO COPIES RETAINED"
	receipt.ConfirmedAt = time.Now().UTC().Format(time.RFC3339)
	return writeJSONAtomic(path, receipt, 0o600)
}

// erasureTimestamp returns a destroyed_at that proof-tool will accept:
// strictly after the candidate's contributed_at at whole-second resolution.
// Timestamps are stamped in whole seconds, so a contribution that completes
// and is confirmed within the same second would otherwise be rejected with
// "destroyed_at must be strictly after contributed_at". Waiting out the
// remainder of that second preserves the strict ordering rule instead of
// weakening it.
func erasureTimestamp(candidateDir string, now time.Time) time.Time {
	raw, err := os.ReadFile(filepath.Join(candidateDir, "attestation.json"))
	if err != nil {
		return now
	}
	var attestation struct {
		ContributedAt string `json:"contributed_at"`
	}
	if json.Unmarshal(raw, &attestation) != nil {
		return now
	}
	contributed, err := time.Parse(time.RFC3339, attestation.ContributedAt)
	if err != nil {
		return now
	}
	if !now.Truncate(time.Second).After(contributed.Truncate(time.Second)) {
		wait := contributed.Truncate(time.Second).Add(time.Second).Sub(now)
		if wait > 0 && wait <= 2*time.Second {
			time.Sleep(wait)
		}
		return contributed.Truncate(time.Second).Add(time.Second)
	}
	return now
}

func runErasure(o roleOpts) (time.Time, error) {
	destroyedAt := erasureTimestamp(o.outDir, time.Now().UTC())
	return destroyedAt, runErasureAt(o, destroyedAt)
}

func runErasureAt(o roleOpts, destroyedAt time.Time) error {
	if o.docker != nil {
		return runWithProgress("creating erasure attestation", func() error {
			return o.docker.attestErasure(o, destroyedAt)
		})
	}
	argv := []string{o.phase, "attest-erasure", "--ceremony", o.definition,
		"--ceremony-signature", o.definitionSig, "--coordinator-public-key-file", o.coordinatorKey,
		"--participant-id", o.role, "--participant-signing-key", o.signingKey,
		"--candidate-dir", o.outDir, "--destroyed-at", destroyedAt.UTC().Format(time.RFC3339)}
	cmd := exec.Command(o.ceremonyExecutable(), argv...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return runWithProgress("creating erasure attestation", cmd.Run)
}

func regularFileRef(local, logical string) (access.FileRef, error) {
	info, err := os.Lstat(local)
	if err != nil {
		return access.FileRef{}, err
	}
	if !info.Mode().IsRegular() {
		return access.FileRef{}, fmt.Errorf("%s is not a regular file", local)
	}
	sum, size, err := transcript.DigestFile(local)
	if err != nil {
		return access.FileRef{}, err
	}
	return access.FileRef{Name: filepath.ToSlash(logical), SHA256: sum, Size: size}, nil
}

func putFresh(client store.Client, key, local string) error {
	err := client.PutNoReplace(key, local)
	if errors.Is(err, store.ErrExists) {
		return fmt.Errorf("submission object already exists: %s", key)
	}
	if err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	return nil
}

// putFreshOrVerify makes an interrupted candidate upload idempotent without
// weakening create-only storage. An existing object is accepted only after it
// is downloaded with the replacement grant and shown to contain the exact
// bytes recorded in the local candidate manifest.
func putFreshOrVerify(client candidateObjectStore, key, local string, want access.FileRef) error {
	err := client.PutNoReplace(key, local)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	temp, tempErr := os.MkdirTemp("", "relay-resume-object-")
	if tempErr != nil {
		return tempErr
	}
	defer os.RemoveAll(temp)
	downloaded := filepath.Join(temp, "object")
	if err := client.Get(key, downloaded); err != nil {
		return fmt.Errorf("verify existing upload %s: %w", key, err)
	}
	got, err := regularFileRef(downloaded, want.Name)
	if err != nil {
		return err
	}
	if got.SHA256 != want.SHA256 || got.Size != want.Size {
		return fmt.Errorf("existing submission object conflicts with the saved candidate: %s", key)
	}
	fmt.Fprintf(os.Stderr, "  verified existing %s\n", want.Name)
	return nil
}

func uploadJSONLast(client store.Client, key string, value any) error {
	dir, err := os.MkdirTemp("", "relay-manifest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	local := filepath.Join(dir, "manifest.json")
	if err := writeJSONNoReplace(local, value, 0o600); err != nil {
		return err
	}
	return putFresh(client, key, local)
}

type stringList []string

func (values *stringList) String() string         { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error { *values = append(*values, value); return nil }

func runSubmitEvidence(args []string) error {
	return runSubmitEvidenceForRole(args, "")
}

func runReleaseEvidence(args []string) error {
	return runSubmitEvidenceForRole(args, access.RoleRelease)
}

func runSubmitEvidenceForRole(args []string, expectedRole string) error {
	set := flag.NewFlagSet("submit-evidence", flag.ContinueOnError)
	var configPath, grantPath, directory string
	var files stringList
	set.StringVar(&configPath, "config", "", "optional validated role configuration")
	set.StringVar(&grantPath, "grant", "", "temporary role grant")
	set.Var(&files, "file", "regular evidence file (repeatable)")
	set.StringVar(&directory, "dir", "", "evidence directory; symlinks are rejected")
	if err := set.Parse(args); err != nil {
		return err
	}
	if grantPath == "" || (len(files) == 0) == (directory == "") {
		return errors.New("--grant and exactly one of --file (repeatable) or --dir are required")
	}
	grant, err := loadGrant(grantPath)
	if err != nil {
		return err
	}
	if grant.Role == access.RoleParticipant {
		return errors.New("participant candidates must use relay participant run")
	}
	if expectedRole != "" && grant.Role != expectedRole {
		return fmt.Errorf("grant role is %s, want %s", grant.Role, expectedRole)
	}
	if configPath != "" {
		config, err := loadRoleConfig(configPath, expectedRole)
		if err != nil {
			return err
		}
		if config.Role != grant.Role || config.IdentityID != grant.IdentityID || config.CeremonyID != grant.CeremonyID {
			return errors.New("temporary grant does not match the configured role, identity, and ceremony")
		}
	}
	if err := grant.CheckUsable(time.Now()); err != nil {
		return err
	}
	inputs, err := collectEvidence(files, directory)
	if err != nil {
		return err
	}
	attempt, err := randomID()
	if err != nil {
		return err
	}
	prefix := grant.Prefix + attempt + "/"
	manifest := access.SubmissionManifest{Schema: access.SubmissionManifestSchema, CeremonyID: grant.CeremonyID,
		Role: grant.Role, IdentityID: grant.IdentityID, AttemptID: attempt,
		CompletedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	client := grantClient(grant)
	key := prefix + "manifest.json"
	if err := runWithProgress("uploading signed role evidence", func() error {
		for _, input := range inputs {
			ref, err := regularFileRef(input.local, input.name)
			if err != nil {
				return err
			}
			manifest.Files = append(manifest.Files, ref)
			fmt.Fprintf(os.Stderr, "  uploading %s (%s)\n", ref.Name, formatBytes(ref.Size))
			if err := putFresh(client, prefix+ref.Name, input.local); err != nil {
				return err
			}
		}
		if err := manifest.Validate(); err != nil {
			return err
		}
		return uploadJSONLast(client, key, manifest)
	}); err != nil {
		return err
	}
	fmt.Printf("evidence submitted for coordinator review\nmanifest: %s\n", key)
	return nil
}

type evidenceInput struct{ local, name string }

func collectEvidence(files []string, directory string) ([]evidenceInput, error) {
	var out []evidenceInput
	if directory != "" {
		err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == directory {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink is not allowed in evidence: %s", path)
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("non-regular evidence file: %s", path)
			}
			relative, err := filepath.Rel(directory, path)
			if err != nil {
				return err
			}
			out = append(out, evidenceInput{path, filepath.ToSlash(relative)})
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		for _, file := range files {
			out = append(out, evidenceInput{file, filepath.Base(file)})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no evidence files found")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	seen := map[string]bool{}
	for _, input := range out {
		lower := strings.ToLower(input.name)
		base := strings.ToLower(filepath.Base(input.name))
		if seen[input.name] {
			return nil, fmt.Errorf("duplicate evidence name %q", input.name)
		}
		seen[input.name] = true
		if strings.Contains(lower, ".private") || strings.Contains(base, "credential") || strings.Contains(base, "grant") || strings.Contains(base, "signing-key") || strings.HasSuffix(base, ".key") {
			return nil, fmt.Errorf("refusing possible secret evidence file %q", input.name)
		}
	}
	return out, nil
}

package main

import (
	"bufio"
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

func runEnroll(args []string) error {
	set := flag.NewFlagSet("enroll", flag.ContinueOnError)
	var storagePath, grantPath, phase, root, ceremony, ceremonySignature, coordinatorKey, ceremonyBinary string
	var signingKey, environment, candidateParent, out string
	set.StringVar(&storagePath, "storage", "", "storage configuration supplied by the coordinator")
	set.StringVar(&grantPath, "grant", "", "temporary participant grant supplied by the coordinator")
	set.StringVar(&phase, "phase", "", "phase1 or phase2")
	set.StringVar(&root, "root", "", "local transcript root")
	set.StringVar(&ceremony, "ceremony", "", "local signed ceremony definition")
	set.StringVar(&ceremonySignature, "ceremony-signature", "", "local definition signature")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "out-of-band coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted ceremony executable")
	set.StringVar(&signingKey, "signing-key", "", "participant Ed25519 private key")
	set.StringVar(&environment, "environment", "", "canonical environment.json")
	set.StringVar(&candidateParent, "candidate-parent", "", "directory in which a fresh candidate will be created")
	set.StringVar(&out, "out", "", "fresh participant configuration file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if storagePath == "" || grantPath == "" || phase == "" || root == "" || ceremony == "" || ceremonySignature == "" || coordinatorKey == "" || signingKey == "" || environment == "" || candidateParent == "" || out == "" {
		return errors.New("--storage, --grant, --phase, --root, --ceremony, --ceremony-signature, --coordinator-key, --signing-key, --environment, --candidate-parent and --out are required")
	}
	storageConfig, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	grant, err := loadGrant(grantPath)
	if err != nil {
		return err
	}
	if grant.Role != access.RoleParticipant || grant.CeremonyID != storageConfig.CeremonyID || grant.Provider != storageConfig.Provider || grant.InboxBucket != storageConfig.InboxBucket {
		return errors.New("participant grant does not match the storage configuration")
	}
	inspector := transcript.Inspector{Executable: ceremonyBinary, CeremonyPath: ceremony,
		CeremonySignaturePath: ceremonySignature, CoordinatorPublicKeyPath: coordinatorKey,
		TranscriptRoot: root}
	participant, err := inspector.Participant(signingKey)
	if err != nil {
		return err
	}
	if participant.CeremonyID != storageConfig.CeremonyID || participant.ParticipantID != grant.IdentityID {
		return errors.New("local participant key does not match the grant identity and ceremony")
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
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, Phase: phase, Root: root,
		Ceremony: ceremony, CeremonySignature: ceremonySignature,
		CoordinatorKey: coordinatorKey, CeremonyBinary: ceremonyBinary,
		SigningKey: signingKey, Environment: environment, CandidateParentDir: candidateParent,
		PublishedBaseURL: storageConfig.PublishedBaseURL, PublishedBucket: storageConfig.PublishedBucket,
		GrantPath: grantPath,
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := writeJSONNoReplace(out, config, 0o600); err != nil {
		return err
	}
	fmt.Printf("enrolled %s for %s at index %d\n", participant.ParticipantID, phase, *slot)
	fmt.Printf("when the coordinator tells you to begin, run: relay participate --config %s\n", out)
	return nil
}

func runParticipate(args []string) error {
	set := flag.NewFlagSet("participate", flag.ContinueOnError)
	var configPath string
	set.StringVar(&configPath, "config", "", "participant configuration created by relay enroll")
	if err := set.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("--config is required")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	config, err := access.Decode(raw, access.ParticipantConfig.Validate)
	if err != nil {
		return err
	}
	grant, err := loadGrant(config.GrantPath)
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
	if err := confirmErasure(); err != nil {
		return err
	}
	if err := runErasure(o); err != nil {
		return err
	}
	if err := grant.CheckUnexpired(time.Now()); err != nil {
		return err
	}
	latest, err := resolvePosition(o)
	if err != nil {
		return err
	}
	if latest.nextID != pos.nextID || latest.nextIndex != pos.nextIndex || latest.pointer.Chain.SHA256 != pos.pointer.Chain.SHA256 {
		return errors.New("published chain advanced while the contribution was running; candidate was not uploaded")
	}
	prefix := grant.Prefix + config.Phase + "/" + fmt.Sprintf("%04d", pos.nextIndex) + "/" + attempt + "/"
	manifest := access.CandidateManifest{
		Schema: access.CandidateManifestSchema, CeremonyID: grant.CeremonyID, Phase: config.Phase,
		Index: pos.nextIndex, ParticipantID: grant.IdentityID, ParentChainSHA256: pos.pointer.Chain.SHA256,
		AttemptID: attempt, CompletedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	client := grantClient(grant)
	manifestKey := prefix + "manifest.json"
	if err := runWithProgress("uploading contribution candidate", func() error {
		for _, name := range candidateFileNames {
			local := filepath.Join(o.outDir, name)
			ref, err := regularFileRef(local, name)
			if err != nil {
				return err
			}
			manifest.Files = append(manifest.Files, ref)
			fmt.Fprintf(os.Stderr, "  uploading %s (%s)\n", name, formatBytes(ref.Size))
			if err := putFresh(client, prefix+name, local); err != nil {
				return err
			}
		}
		if err := manifest.Validate(); err != nil {
			return err
		}
		return uploadJSONLast(client, manifestKey, manifest)
	}); err != nil {
		return err
	}
	fmt.Printf("candidate submitted for coordinator review\nmanifest: %s\n", manifestKey)
	return nil
}

func participantRoleOptions(config access.ParticipantConfig, identity string) roleOpts {
	return roleOpts{
		root: config.Root, definition: config.Ceremony, definitionSig: config.CeremonySignature,
		coordinatorKey: config.CoordinatorKey, ceremonyBinary: config.CeremonyBinary,
		phase: config.Phase, role: identity, signingKey: config.SigningKey, envPath: config.Environment,
		client: store.Client{Bucket: config.PublishedBucket, PublicBaseURL: config.PublishedBaseURL},
	}
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

func confirmErasure() error {
	fmt.Fprintln(os.Stderr, "Contribution complete. Destroy the contribution environment now.")
	fmt.Fprint(os.Stderr, "After it is destroyed, type DESTROYED and press Enter: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	if strings.TrimSpace(line) != "DESTROYED" {
		return errors.New("erasure was not confirmed; candidate remains local and was not uploaded")
	}
	return nil
}

func runErasure(o roleOpts) error {
	argv := []string{o.phase, "attest-erasure", "--ceremony", o.definition,
		"--ceremony-signature", o.definitionSig, "--coordinator-public-key-file", o.coordinatorKey,
		"--participant-id", o.role, "--participant-signing-key", o.signingKey,
		"--candidate-dir", o.outDir, "--destroyed-at", time.Now().UTC().Format(time.RFC3339)}
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
	set := flag.NewFlagSet("submit-evidence", flag.ContinueOnError)
	var grantPath, directory string
	var files stringList
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
		return errors.New("participant candidates must use relay participate")
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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
)

const maxInboxManifestBytes int64 = 1 << 20

func runCandidates(args []string) error {
	set := flag.NewFlagSet("coordinator candidates", flag.ContinueOnError)
	var storagePath, phase string
	set.StringVar(&storagePath, "storage", "", "storage configuration")
	set.StringVar(&phase, "phase", "", "optional phase1 or phase2 filter")
	if err := set.Parse(args); err != nil {
		return err
	}
	if storagePath == "" {
		return errors.New("--storage is required")
	}
	if phase != "" && phase != "phase1" && phase != "phase2" {
		return errors.New("--phase must be phase1 or phase2")
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	prefix := "candidates/" + strings.TrimPrefix(config.CeremonyID, "sha256:") + "/"
	objects, err := coordinatorClient(config, config.InboxBucket).List(prefix)
	if err != nil {
		return err
	}
	keys := manifestKeys(objects)
	count := 0
	for _, key := range keys {
		manifest, err := downloadCandidateManifest(config, key)
		if err != nil {
			fmt.Printf("invalid  %s  (%v)\n", key, err)
			continue
		}
		if phase != "" && manifest.Phase != phase {
			continue
		}
		fmt.Printf("ready    %-12s %s index %d  %s\n", manifest.ParticipantID, manifest.Phase, manifest.Index, key)
		count++
	}
	if count == 0 {
		fmt.Println("no complete candidate manifests found")
	}
	return nil
}

func runAcceptCandidate(args []string) error {
	set := flag.NewFlagSet("coordinator accept", flag.ContinueOnError)
	var storagePath, candidateKey, root, candidateDir, coordinatorSigningKey, acceptedAt string
	var phase1Seal, phase1SealSignature string
	var verify bool
	set.StringVar(&storagePath, "storage", "", "storage configuration")
	set.StringVar(&candidateKey, "candidate-key", "", "candidate manifest key printed by relay participant run")
	set.StringVar(&root, "root", "", "coordinator transcript root")
	set.StringVar(&candidateDir, "candidate-dir", "", "fresh local directory for the downloaded candidate")
	set.StringVar(&coordinatorSigningKey, "coordinator-signing-key", "", "coordinator Ed25519 private key")
	set.StringVar(&acceptedAt, "accepted-at", "", "acceptance timestamp (defaults to the current time after candidate download)")
	set.StringVar(&phase1Seal, "phase1-seal", "", "phase 2: sealed phase-1 record")
	set.StringVar(&phase1SealSignature, "phase1-seal-signature", "", "phase 2: phase-1 seal signature")
	set.BoolVar(&verify, "verify-publish", false, "confirm every published object after advancing the head")
	if err := set.Parse(args); err != nil {
		return err
	}
	if storagePath == "" || candidateKey == "" || coordinatorSigningKey == "" {
		return errors.New("--storage, --candidate-key and --coordinator-signing-key are required; --root and --candidate-dir have ceremony-home defaults")
	}
	if acceptedAt != "" {
		if _, err := time.Parse(time.RFC3339, acceptedAt); err != nil {
			return errors.New("--accepted-at must be RFC3339")
		}
	}
	if !safeObjectKey(candidateKey) || !strings.HasSuffix(candidateKey, "/manifest.json") {
		return errors.New("--candidate-key must be a safe manifest object key")
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	if root == "" {
		root = filepath.Dir(config.CeremonyPath)
	}
	manifest, err := downloadCandidateManifest(config, candidateKey)
	if err != nil {
		return err
	}
	prefix, err := access.Prefix(config.CeremonyID, access.RoleParticipant, manifest.ParticipantID)
	if err != nil {
		return err
	}
	expectedKey := prefix + manifest.Phase + "/" + fmt.Sprintf("%04d", manifest.Index) + "/" + manifest.AttemptID + "/manifest.json"
	if candidateKey != expectedKey {
		return fmt.Errorf("candidate manifest is at %q, want %q", candidateKey, expectedKey)
	}
	if candidateDir == "" {
		candidateDir = filepath.Join(filepath.Dir(root), "run", "review",
			manifest.Phase+"-"+manifest.ParticipantID+"-"+manifest.AttemptID)
	}
	o := roleOpts{
		root: root, definition: config.CeremonyPath, definitionSig: config.CeremonySignature,
		coordinatorKey: config.CoordinatorPublicKey, ceremonyBinary: config.CeremonyBinary,
		phase: manifest.Phase, role: manifest.ParticipantID,
		client:     store.Client{Bucket: config.PublishedBucket, PublicBaseURL: config.PublishedBaseURL},
		phase1Seal: phase1Seal, phase1SealSig: phase1SealSignature,
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	if pos.phaseClosed || pos.nextID != manifest.ParticipantID || pos.nextIndex != manifest.Index {
		return fmt.Errorf("candidate is out of turn: published next participant is %s at index %d", pos.nextID, pos.nextIndex)
	}
	if manifest.ParentChainSHA256 != pos.pointer.Chain.SHA256 {
		return errors.New("candidate was built from a different chain head")
	}
	if err := runWithProgress("downloading accepted transcript", func() error {
		return fetchForContribution(o, pos)
	}); err != nil {
		return fmt.Errorf("fetch accepted transcript: %w", err)
	}
	if _, err := os.Lstat(candidateDir); err == nil {
		return fmt.Errorf("--candidate-dir already exists: %s", candidateDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(candidateDir, 0o700); err != nil {
		return err
	}
	base := strings.TrimSuffix(candidateKey, "manifest.json")
	filesByName := make(map[string]access.FileRef, len(manifest.Files))
	for _, ref := range manifest.Files {
		filesByName[ref.Name] = ref
	}
	inbox := coordinatorClient(config, config.InboxBucket)
	if err := runWithProgress("downloading contribution candidate", func() error {
		for _, name := range candidateFileNames {
			ref := filesByName[name]
			local := filepath.Join(candidateDir, name)
			fmt.Fprintf(os.Stderr, "  downloading %s (%s)\n", name, formatBytes(ref.Size))
			if err := inbox.Get(base+name, local); err != nil {
				return fmt.Errorf("download candidate %s: %w", name, err)
			}
			got, err := regularFileRef(local, name)
			if err != nil {
				return err
			}
			if got.SHA256 != ref.SHA256 || got.Size != ref.Size {
				return fmt.Errorf("candidate %s does not match its manifest", name)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if acceptedAt == "" {
		acceptedAt = defaultAcceptanceTimestamp(time.Now())
	}
	cmd := candidateVerificationCommand(
		o, pos.chainPath, pos.chain.ChainSignaturePath, candidateDir,
		coordinatorSigningKey, acceptedAt,
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := runWithProgress("verifying contribution candidate", cmd.Run); err != nil {
		return err
	}
	latest, err := resolvePosition(o)
	if err != nil {
		return fmt.Errorf("recheck published head after verification: %w", err)
	}
	if latest.pointer.Chain.SHA256 != pos.pointer.Chain.SHA256 || latest.nextIndex != pos.nextIndex || latest.nextID != pos.nextID {
		return errors.New("published head advanced during candidate verification; the accepted files remain local but were not published")
	}
	chainPath := filepath.Join(root, manifest.Phase, fmt.Sprintf("chain-%04d.json", manifest.Index))
	chainSignature := filepath.Join(root, manifest.Phase, fmt.Sprintf("chain-%04d.sig", manifest.Index))
	o.client = coordinatorClient(config, config.PublishedBucket)
	if err := runWithProgress("publishing accepted contribution", func() error {
		return publishHead(o, chainPath, chainSignature, false, verify)
	}); err != nil {
		return err
	}
	fmt.Printf("accepted candidate %s and advanced the published head\n", candidateKey)
	return nil
}

func defaultAcceptanceTimestamp(now time.Time) string {
	return now.UTC().Format(time.RFC3339Nano)
}

// candidateVerificationCommand is shared by the coordinator acceptance path
// and the source-free release-pair gate. Keeping the argv construction here
// prevents the release gate from testing a second approximation of Relay's
// mpc-ceremony interface.
func candidateVerificationCommand(
	o roleOpts,
	chainPath, chainSignaturePath, candidateDir, coordinatorSigningKey, acceptedAt string,
) *exec.Cmd {
	command := []string{o.phase, "verify", "--ceremony", o.definition,
		"--ceremony-signature", o.definitionSig, "--coordinator-public-key-file", o.coordinatorKey,
		"--transcript-dir", o.root, "--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--candidate-dir", candidateDir, "--coordinator-signing-key", coordinatorSigningKey,
		"--accepted-at", acceptedAt}
	if o.phase == "phase2" {
		phase1Seal := o.phase1Seal
		phase1SealSignature := o.phase1SealSig
		if phase1Seal == "" {
			phase1Seal = filepath.Join(o.root, "phase1", "sealed", "seal.json")
		}
		if phase1SealSignature == "" {
			phase1SealSignature = filepath.Join(o.root, "phase1", "sealed", "seal.sig")
		}
		command = append(command, "--phase1-seal", phase1Seal, "--phase1-seal-signature", phase1SealSignature)
	}
	return exec.Command(o.ceremonyExecutable(), command...)
}

func runEvidenceInbox(args []string) error {
	set := flag.NewFlagSet("coordinator evidence", flag.ContinueOnError)
	var storagePath, role, manifestKey, outDir string
	set.StringVar(&storagePath, "storage", "", "storage configuration")
	set.StringVar(&role, "role", "", "optional witness, mirror, auditor, release, decision filter")
	set.StringVar(&manifestKey, "manifest-key", "", "exact submitted manifest key to download for review")
	set.StringVar(&outDir, "out-dir", "", "fresh evidence review directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	if storagePath == "" {
		return errors.New("--storage is required")
	}
	roles := []string{access.RoleWitness, access.RoleMirror, access.RoleAuditor, access.RoleRelease, access.RoleDecision}
	if role != "" {
		valid := false
		for _, candidate := range roles {
			if candidate == role {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("unsupported evidence role %q", role)
		}
		roles = []string{role}
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	client := coordinatorClient(config, config.InboxBucket)
	if manifestKey != "" || outDir != "" {
		if manifestKey == "" || outDir == "" || !safeObjectKey(manifestKey) {
			return errors.New("--manifest-key and --out-dir must be supplied together with a safe key")
		}
		manifest, err := downloadSubmissionManifest(client, manifestKey)
		if err != nil {
			return err
		}
		if err := runWithProgress("downloading evidence for review", func() error {
			return receiveEvidence(config.CeremonyID, role, manifestKey, outDir, manifest, client.GetSized)
		}); err != nil {
			return err
		}
		fmt.Println("Downloaded evidence with matching manifest scope, sizes and hashes. Signatures and ceremony evidence still require independent verification.")
		return nil
	}
	count := 0
	for _, currentRole := range roles {
		prefix, _ := access.Prefix(config.CeremonyID, currentRole, "placeholder")
		prefix = strings.TrimSuffix(prefix, "placeholder/")
		objects, err := client.List(prefix)
		if err != nil {
			return err
		}
		for _, key := range manifestKeys(objects) {
			// Only identity/attempt/manifest.json marks a completed upload.
			// A payload may legitimately contain files/manifest.json of its own.
			if len(strings.Split(strings.TrimPrefix(key, prefix), "/")) != 3 {
				continue
			}
			manifest, err := downloadSubmissionManifest(client, key)
			if err != nil {
				fmt.Printf("invalid  %s  (%v)\n", key, err)
				continue
			}
			expectedPrefix, prefixErr := access.Prefix(config.CeremonyID, manifest.Role, manifest.IdentityID)
			expected := expectedPrefix + manifest.AttemptID + "/manifest.json"
			if prefixErr != nil || manifest.Role != currentRole || expected != key {
				fmt.Printf("invalid  %s  (manifest scope does not match its key)\n", key)
				continue
			}
			fmt.Printf("ready    %-10s %-16s %d files  %s\n", manifest.Role, manifest.IdentityID, len(manifest.Files), key)
			count++
		}
	}
	if count == 0 {
		fmt.Println("no complete evidence manifests found")
	}
	return nil
}

func manifestKeys(objects []store.Object) []string {
	var keys []string
	for _, object := range objects {
		if strings.HasSuffix(object.Key, "/manifest.json") && safeObjectKey(object.Key) {
			keys = append(keys, object.Key)
		}
	}
	sort.Strings(keys)
	return keys
}

func safeObjectKey(key string) bool {
	return key != "" && path.Clean(key) == key && !strings.HasPrefix(key, "/") && !strings.HasPrefix(key, "../") && !strings.Contains(key, `\`)
}

func downloadCandidateManifest(config access.StorageConfig, key string) (access.CandidateManifest, error) {
	client := coordinatorClient(config, config.InboxBucket)
	dir, err := os.MkdirTemp("", "relay-candidate-manifest-")
	if err != nil {
		return access.CandidateManifest{}, err
	}
	defer os.RemoveAll(dir)
	local := filepath.Join(dir, "manifest.json")
	if err := client.Get(key, local); err != nil {
		return access.CandidateManifest{}, err
	}
	raw, err := readInboxManifest(local)
	if err != nil {
		return access.CandidateManifest{}, err
	}
	manifest, err := access.Decode(raw, access.CandidateManifest.Validate)
	if err != nil {
		return access.CandidateManifest{}, err
	}
	if manifest.CeremonyID != config.CeremonyID {
		return access.CandidateManifest{}, errors.New("candidate is for a different ceremony")
	}
	return manifest, nil
}

func downloadSubmissionManifest(client store.Client, key string) (access.SubmissionManifest, error) {
	dir, err := os.MkdirTemp("", "relay-evidence-manifest-")
	if err != nil {
		return access.SubmissionManifest{}, err
	}
	defer os.RemoveAll(dir)
	local := filepath.Join(dir, "manifest.json")
	if err := client.GetAtMost(key, local, maxInboxManifestBytes); err != nil {
		return access.SubmissionManifest{}, err
	}
	raw, err := readInboxManifest(local)
	if err != nil {
		return access.SubmissionManifest{}, err
	}
	return access.Decode(raw, access.SubmissionManifest.Validate)
}

func readInboxManifest(local string) ([]byte, error) {
	info, err := os.Lstat(local)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxInboxManifestBytes {
		return nil, fmt.Errorf("inbox manifest must be a regular file no larger than %d bytes", maxInboxManifestBytes)
	}
	return os.ReadFile(local)
}

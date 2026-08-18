package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// roleOpts are the flags every role-scoped command shares.
type roleOpts struct {
	root           string
	definition     string
	definitionSig  string
	coordinatorKey string
	ceremonyBinary string
	phase          string
	role           string
	client         store.Client
	signingKey     string
	envPath        string
	outDir         string
	phase1Seal     string
	phase1SealSig  string
}

// registerRole declares the shared flags without parsing, so a command can add
// its own before the single Parse call. Parsing in two passes would reject the
// second command's flags during the first pass.
func registerRole(set *flag.FlagSet, o *roleOpts) {
	set.StringVar(&o.root, "root", "", "local transcript root")
	set.StringVar(&o.definition, "ceremony", "", "path to the signed ceremony definition")
	set.StringVar(&o.definitionSig, "ceremony-signature", "", "path to the definition's detached signature")
	set.StringVar(&o.coordinatorKey, "coordinator-key", "",
		"path to coordinator-public-key.hex, obtained out of band")
	set.StringVar(&o.ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted mpc-ceremony executable")
	set.StringVar(&o.phase, "phase", "phase1", "phase1 or phase2")
	set.StringVar(&o.client.Bucket, "bucket", "", "bucket name")
	set.StringVar(&o.client.Endpoint, "endpoint", "", "S3-compatible endpoint URL")
	set.StringVar(&o.client.Profile, "profile", "default", "AWS CLI profile holding the credentials")
}

func checkRole(o roleOpts) error {
	for name, value := range map[string]string{
		"--root": o.root, "--ceremony": o.definition,
		"--ceremony-signature": o.definitionSig, "--coordinator-key": o.coordinatorKey,
		"--bucket": o.client.Bucket, "--endpoint": o.client.Endpoint,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if o.phase != "phase1" && o.phase != "phase2" {
		return fmt.Errorf("--phase %q must be phase1 or phase2", o.phase)
	}
	return nil
}

func (o roleOpts) inspector() transcript.Inspector {
	return transcript.Inspector{
		Executable:               o.ceremonyBinary,
		CeremonyPath:             o.definition,
		CeremonySignaturePath:    o.definitionSig,
		CoordinatorPublicKeyPath: o.coordinatorKey,
		TranscriptRoot:           o.root,
	}
}

func (o roleOpts) ceremonyExecutable() string {
	if o.ceremonyBinary == "" {
		return "mpc-ceremony"
	}
	return o.ceremonyBinary
}

// bindRole is the common case: shared flags only.
func bindRole(set *flag.FlagSet, args []string) (roleOpts, error) {
	var o roleOpts
	registerRole(set, &o)
	if err := set.Parse(args); err != nil {
		return o, err
	}
	return o, checkRole(o)
}

// position is what the tool has worked out about where the ceremony stands,
// after re-deriving everything the pointer claimed from signed artifacts.
type position struct {
	definition  transcript.Definition
	pointer     state.Pointer
	chain       transcript.Chain
	chainPath   string
	accepted    int
	nextID      string
	nextIndex   int
	phaseClosed bool
}

// resolvePosition reads the published pointer, fetches the chain it names,
// re-counts the accepted contributions from that chain, and refuses a pointer
// that has moved backwards.
//
// The pointer is never believed. Its index is a claim; the count of records in
// the fetched chain is what is used. Its refs are content-addressed, so a
// pointer naming the wrong object fails the digest check. All it really
// supplies is which object to go and get.
func resolvePosition(o roleOpts) (position, error) {
	definition, err := o.inspector().Definition()
	if err != nil {
		return position{}, err
	}

	temp, err := os.MkdirTemp("", "relay-state-")
	if err != nil {
		return position{}, err
	}
	defer os.RemoveAll(temp)

	raw := filepath.Join(temp, "head.json")
	if err := o.client.Get(state.Key(definition.CeremonyID, o.phase), raw); err != nil {
		return position{}, fmt.Errorf(
			"no published state for %s: the coordinator has not run publish, or the bucket is wrong: %w",
			o.phase, err)
	}
	rawBytes, err := os.ReadFile(raw)
	if err != nil {
		return position{}, err
	}
	pointer, err := state.Decode(rawBytes)
	if err != nil {
		return position{}, err
	}
	if pointer.CeremonyID != definition.CeremonyID {
		return position{}, fmt.Errorf(
			"published state is for ceremony %s, but the local definition is %s",
			pointer.CeremonyID, definition.CeremonyID)
	}
	if pointer.Phase != o.phase {
		return position{}, fmt.Errorf("published state is for %s, not %s", pointer.Phase, o.phase)
	}

	highWater, err := state.OpenHighWater(definition.CeremonyID)
	if err != nil {
		return position{}, err
	}
	if err := highWater.CheckNotBehind(o.phase, pointer.Index); err != nil {
		return position{}, err
	}

	// Fetch the chain the pointer names and count for ourselves.
	chainPath, err := transcript.Resolve(o.root, pointer.Chain.Name)
	if err != nil {
		return position{}, err
	}
	if err := fetchVerified(o.client, pointer.Chain, chainPath); err != nil {
		return position{}, err
	}
	sigPath, err := transcript.Resolve(o.root, pointer.ChainSignature.Name)
	if err != nil {
		return position{}, err
	}
	if err := fetchVerified(o.client, pointer.ChainSignature, sigPath); err != nil {
		return position{}, err
	}

	chain, err := o.inspector().Chain(chainPath, sigPath)
	if err != nil {
		return position{}, err
	}
	accepted := chain.AcceptedCount()
	if err := highWater.Record(o.phase, accepted); err != nil {
		return position{}, err
	}

	pos := position{
		definition:  definition,
		pointer:     pointer,
		chain:       chain,
		chainPath:   chainPath,
		accepted:    accepted,
		phaseClosed: pointer.Closed,
	}
	if id, index, err := definition.NextContributor(o.phase, accepted); err == nil {
		pos.nextID, pos.nextIndex = id, index
	}
	return pos, nil
}

// fetchVerified downloads a content-addressed object and confirms the bytes
// hash to the name they were fetched under. Downloading to a path that already
// holds different bytes is refused rather than overwritten.
func fetchVerified(client store.Client, ref state.Ref, localPath string) error {
	if existing, _, err := transcript.DigestFile(localPath); err == nil {
		if existing == ref.SHA256 {
			return nil
		}
		return fmt.Errorf("%s already exists locally with different content", ref.Name)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return err
	}
	if err := client.Get(store.Key(ref.SHA256), localPath); err != nil {
		return fmt.Errorf("fetch %s: %w", ref.Name, err)
	}
	sum, _, err := transcript.DigestFile(localPath)
	if err != nil {
		return err
	}
	if sum != ref.SHA256 {
		_ = os.Remove(localPath)
		return fmt.Errorf("%s: fetched bytes hash to %s, not %s", ref.Name, sum, ref.SHA256)
	}
	return nil
}

func runStatus(args []string) error {
	var o roleOpts
	set := flag.NewFlagSet("participant status", flag.ContinueOnError)
	registerRole(set, &o)
	set.StringVar(&o.role, "role", "", "participant identity, e.g. participant-03")
	if err := set.Parse(args); err != nil {
		return err
	}
	if err := checkRole(o); err != nil {
		return err
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	schedule, err := pos.definition.Schedule(o.phase)
	if err != nil {
		return err
	}

	fmt.Printf("ceremony  %s  (%s)\n", pos.definition.CeremonyID, pos.definition.Mode)
	fmt.Printf("%s     %d of %d accepted\n", o.phase, pos.accepted, len(schedule))
	if pos.phaseClosed {
		fmt.Printf("          phase is closed; no further contributions\n")
	} else if pos.nextID != "" {
		fmt.Printf("next      %s at index %d\n", pos.nextID, pos.nextIndex)
	}

	if o.role == "" {
		return nil
	}
	return reportTurn(o, pos)
}

// reportTurn is the refusal path: telling a participant plainly that it is not
// their turn is the point of the command, because discovering it after a
// multi-hour replay is the expensive way to find out.
func reportTurn(o roleOpts, pos position) error {
	slot, err := pos.definition.SlotOf(o.phase, o.role)
	if err != nil {
		fmt.Printf("role      %s is not a scheduled contributor in %s\n", o.role, o.phase)
		return nil
	}
	switch {
	case pos.phaseClosed:
		return fmt.Errorf("not your turn: %s is closed", o.phase)
	case slot == pos.nextIndex:
		fmt.Printf("your turn yes, index %d\n", slot)
		return nil
	case slot < pos.nextIndex:
		fmt.Printf("your turn no, index %d was accepted already\n", slot)
		return nil
	default:
		return fmt.Errorf(
			"not your turn: you are index %d, %d of %d accepted, waiting on %s",
			slot, pos.accepted, len(mustSchedule(pos, o.phase)), pos.nextID)
	}
}

func mustSchedule(pos position, phase string) []string {
	schedule, _ := pos.definition.Schedule(phase)
	return schedule
}

// runNext runs the ceremony command this role owes next.
//
// Running is the default because the checks that matter are enforced by the
// ceremony binary itself, not by a human reading a command line:
// VerifyRunningSoftware digests the running executable against the definition,
// LoadSignedDefinition verifies the coordinator signature, and the chain
// rejects a contribution at the wrong index. The genuinely human step is
// confirming the coordinator public key and binary hash arrived over a trusted
// channel, and that happens once at setup rather than per contribution.
func runNext(o roleOpts, pos position) error {
	command := []string{
		o.ceremonyExecutable(), o.phase, "contribute",
		"--ceremony", o.definition,
		"--ceremony-signature", o.definitionSig,
		"--coordinator-public-key-file", o.coordinatorKey,
		"--transcript-dir", o.root,
		"--chain", pos.chainPath,
		"--chain-signature", pos.chain.ChainSignaturePath,
		"--participant-id", o.role,
		"--participant-signing-key", o.signingKey,
		"--environment", o.envPath,
		"--contributed-at", time.Now().UTC().Format(time.RFC3339),
		"--out-dir", o.outDir,
	}

	// Phase 2 builds on the sealed phase-1 commons, so contribute needs the
	// seal record and its signature as well. Phase 1 has no such input.
	if o.phase == "phase2" {
		seal, sealSig := o.phase1Seal, o.phase1SealSig
		if seal == "" {
			seal = filepath.Join(o.root, "phase1", "sealed", "seal.json")
		}
		if sealSig == "" {
			sealSig = filepath.Join(o.root, "phase1", "sealed", "seal.sig")
		}
		command = append(command, "--phase1-seal", seal, "--phase1-seal-signature", sealSig)
	}

	// The trust inputs are never derived from a path and never fetched from the
	// bucket. The coordinator public key decides whether any signature counts,
	// so taking it from the same place as the artifacts it checks would prove
	// only that the bucket agrees with itself. It has to be supplied.
	if o.definitionSig == "" || o.coordinatorKey == "" {
		return errors.New(
			"--ceremony-signature and --coordinator-key are required to run: " +
				"the coordinator public key is the out-of-band trust anchor and is " +
				"deliberately not fetched from the bucket")
	}
	if o.signingKey == "" || o.envPath == "" || o.outDir == "" {
		return errors.New("participant signing key, environment and candidate directory are required")
	}
	// contribute requires the directory itself to be absent but will not create
	// its parent.
	if err := os.MkdirAll(filepath.Dir(o.outDir), 0o700); err != nil {
		return err
	}
	fmt.Printf("\nrunning: %s\n\n", strings.Join(command[:3], " "))
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return runWithProgress(o.phase+" contribution", cmd.Run)
}

// runPublish is the coordinator's write path: push the transcript, then move
// the pointer. Order matters — the pointer must never name an object that is
// not yet in the bucket, or a reader races ahead of the data.
func runPublish(args []string) error {
	var o roleOpts
	set := flag.NewFlagSet("coordinator publish", flag.ContinueOnError)
	registerRole(set, &o)
	var chainPath string
	var chainSignaturePath string
	var closed bool
	set.StringVar(&chainPath, "chain", "", "chain document to publish as the new head")
	set.StringVar(&chainSignaturePath, "chain-signature", "", "detached signature for the chain head")
	set.BoolVar(&closed, "closed", false, "mark the phase as closed")
	var verify bool
	set.BoolVar(&verify, "verify", false,
		"after publishing, re-derive the expected file set and confirm the bucket holds all of it")
	if err := set.Parse(args); err != nil {
		return err
	}
	if err := checkRole(o); err != nil {
		return err
	}
	if chainPath == "" || chainSignaturePath == "" {
		return errors.New("--chain and --chain-signature are required")
	}
	return runWithProgress("publishing authenticated transcript", func() error {
		return publishHead(o, chainPath, chainSignaturePath, closed, verify)
	})
}

func publishHead(o roleOpts, chainPath, chainSignaturePath string, closed, verify bool) error {
	definition, err := o.inspector().Definition()
	if err != nil {
		return err
	}
	chain, err := o.inspector().Chain(chainPath, chainSignaturePath)
	if err != nil {
		return err
	}
	files, err := transcript.TranscriptFiles(o.root, chain)
	if err != nil {
		return err
	}

	var chainRef, chainSigRef state.Ref
	var published []state.Ref
	for _, file := range files {
		local, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			return err
		}
		sum, size, err := transcript.DigestFile(local)
		if err != nil {
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		if file.HasDigest() && (sum != file.Digest.SHA256 || size != file.Digest.Size) {
			return fmt.Errorf("%s: local file does not match the chain digest", file.Name)
		}
		fmt.Fprintf(os.Stderr, "  uploading %s (%s)\n", file.Name, formatBytes(size))
		switch err := o.client.PutNoReplace(store.Key(sum), local); {
		case err == nil:
			fmt.Printf("  put    %s\n", file.Name)
		case errors.Is(err, store.ErrExists):
			fmt.Printf("  exists %s\n", file.Name)
		default:
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		published = append(published, state.Ref{Name: file.Name, SHA256: sum})
		if sameLocalPath(local, chainPath) {
			chainRef = state.Ref{Name: file.Name, SHA256: sum}
		}
		if sameLocalPath(local, chainSignaturePath) {
			chainSigRef = state.Ref{Name: file.Name, SHA256: sum}
		}
	}
	if chainRef.Name == "" || chainSigRef.Name == "" {
		return errors.New("published file set did not contain the requested chain and signature")
	}

	pointer := state.Pointer{
		Schema:         state.Schema,
		CeremonyID:     definition.CeremonyID,
		Phase:          chain.Phase,
		Index:          chain.AcceptedCount(),
		Chain:          chainRef,
		ChainSignature: chainSigRef,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
		Closed:         closed,
		Files:          published,
	}
	encoded, err := pointer.Encode()
	if err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "relay-publish-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	local := filepath.Join(temp, "head.json")
	if err := os.WriteFile(local, encoded, 0o600); err != nil {
		return err
	}
	// The pointer is the one object that must be overwritable: it is how the
	// ceremony advances. Everything it names is immutable and content-addressed.
	if err := o.client.Put(state.Key(definition.CeremonyID, chain.Phase), local); err != nil {
		return err
	}
	fmt.Printf("published %s head at index %d\n", chain.Phase, pointer.Index)

	if !verify {
		fmt.Println("verification: skipped (pass --verify to confirm the bucket is complete)")
		return nil
	}
	return verifyPublished(o, definition, chain, files)
}

func sameLocalPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

// verifyPublished re-derives what a participant will look for and confirms the
// bucket holds every object.
//
// This exists because a successful publish is not evidence of a complete
// bucket. Uploading only reports on the files this run happened to enumerate,
// so a file the coordinator's tool did not know to include is silently absent,
// and nothing detects it until a participant fails hours later on a machine the
// coordinator cannot see. Checking from the reader's side moves that discovery
// back to the coordinator, where it belongs.
func verifyPublished(
	o roleOpts,
	definition transcript.Definition,
	chain transcript.Chain,
	files []transcript.File,
) error {
	expected := make([]transcript.File, 0, len(files)+1)
	expected = append(expected, files...)

	// The constraint system is named by the definition rather than the chain,
	// so a reader asks for it separately and a publisher must not forget it.
	if r1cs, err := definition.R1CS(); err == nil {
		expected = append(expected, transcript.File{Name: r1cs.Name, Digest: r1cs.Digest})
	}

	seen := make(map[string]struct{}, len(expected))
	var missing []string
	for _, file := range expected {
		local, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			return err
		}
		sum := file.Digest.SHA256
		if sum == "" {
			// No signed digest: the object was keyed by its own hash on upload.
			sum, _, err = transcript.DigestFile(local)
			if err != nil {
				return fmt.Errorf("%s: %w", file.Name, err)
			}
		}
		key := store.Key(sum)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		present, err := o.client.Head(key)
		if err != nil {
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		if !present {
			missing = append(missing, file.Name)
			continue
		}
		fmt.Printf("  ok     %s\n", file.Name)
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"published state names a head whose transcript is incomplete; the bucket is missing: %s",
			strings.Join(missing, ", "))
	}
	fmt.Printf("verification: %d objects present for %s at index %d\n",
		len(seen), chain.Phase, chain.AcceptedCount())
	return nil
}

// readPointer fetches a phase pointer without resolving a full position.
//
// Used when one phase needs another's artifacts: phase 2 is built on phase 1's
// sealed commons, and contribute loads the closed phase 1, so a phase-2
// participant needs records that live under phase 1's pointer. A missing or
// malformed pointer returns nil rather than failing, because the caller can
// still proceed if it already holds those files locally.
func readPointer(o roleOpts, ceremonyID, phase string) *state.Pointer {
	temp, err := os.MkdirTemp("", "relay-peer-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(temp)
	local := filepath.Join(temp, "head.json")
	if err := o.client.Get(state.Key(ceremonyID, phase), local); err != nil {
		return nil
	}
	raw, err := os.ReadFile(local)
	if err != nil {
		return nil
	}
	pointer, err := state.Decode(raw)
	if err != nil {
		return nil
	}
	return &pointer
}

// fetchListed downloads objects the publisher listed in the pointer, skipping
// any already held. Each is fetched by its own hash and re-hashed on arrival,
// so a wrong entry fails rather than substituting content.
func fetchListed(o roleOpts, refs []state.Ref) (int, error) {
	var got int
	for _, ref := range refs {
		local, err := transcript.Resolve(o.root, ref.Name)
		if err != nil {
			return got, err
		}
		if sum, _, err := transcript.DigestFile(local); err == nil {
			if sum != ref.SHA256 {
				return got, fmt.Errorf("%s: local copy differs from the published object", ref.Name)
			}
			continue
		}
		if err := fetchVerified(o.client, ref, local); err != nil {
			return got, err
		}
		got++
		fmt.Printf("  got    %s\n", ref.Name)
	}
	return got, nil
}

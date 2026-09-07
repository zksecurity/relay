// Command relay moves MPC ceremony transcript artifacts between a local
// directory and S3-compatible object storage.
//
// It is deliberately outside the ceremony's trust boundary. It asks the
// ceremony CLI to authenticate definitions and chains, then verifies transported
// bytes against the returned digests. It contains no ceremony parser or
// signature implementation. A hostile bucket can therefore make this tool
// fail, never make it lie.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version":
		fmt.Printf("relay source commit: %s\n", launcherCommit())
		return
	case "role":
		err = runDockerRole(os.Args[2:])
	case "coordinator":
		err = runCoordinator(os.Args[2:])
	case "ceremony":
		err = runCeremony(os.Args[2:])
	case "participant":
		err = runParticipant(os.Args[2:])
	case "witness":
		err = runWitness(os.Args[2:])
	case "mirror":
		err = runMirror(os.Args[2:])
	case "auditor":
		err = runAuditor(os.Args[2:])
	case "release":
		err = runRelease(os.Args[2:])
	case "advanced":
		err = runAdvanced(os.Args[2:])
	case "enroll":
		err = runEnroll(os.Args[2:])
	case "participate":
		err = runParticipate(os.Args[2:])
	case "submit-evidence":
		err = runSubmitEvidence(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  relay ceremony setup NAME --role ROLE [saved launcher settings] -- TOOL ARGS...
  relay ceremony open NAME --role ROLE [--grant FILE] [--resume-candidate DIR]
  relay role --role ROLE --image DIGEST --work DIR [mount flags] -- TOOL ARGS...
  relay coordinator configure-storage [provider and ceremony flags] --out FILE
  relay coordinator grant --storage FILE --role ROLE --identity ID \
             --credential-ttl D --minimum-remaining D --out FILE
  relay coordinator candidates --storage FILE [--phase P]
  relay coordinator accept --storage FILE --candidate-key KEY \
             --coordinator-signing-key FILE [verification flags]
  relay coordinator evidence --storage FILE [--role ROLE]
  relay coordinator publish --storage FILE --chain FILE --chain-signature FILE [publish flags]
  relay ceremony enroll --storage FILE --phase P --root DIR \
             --ceremony FILE --ceremony-signature FILE --coordinator-key FILE \
             --signing-key FILE --environment FILE [--grant FILE] [--out FILE]
  relay ceremony init-config --home DIR --role ROLE --coordinator-key FILE \
             --tool-identity-receipt FILE [--storage FILE] \
             [role authentication flags] \
             [--execution-mode native|docker] [Docker flags] [--out FILE]
  relay participant status [--config FILE | status flags]
  relay participant run [--config FILE] --grant FILE [--resume-candidate DIR]
  relay witness run --config FILE [--interval D] [--once]
  relay witness submit --config FILE --grant FILE (--file FILE | --dir DIR)
  relay mirror run --config FILE
  relay mirror receipt --config FILE [receipt flags]
  relay mirror submit --config FILE --grant FILE (--file FILE | --dir DIR)
  relay auditor run --config FILE
  relay auditor submit --config FILE --grant FILE (--file FILE | --dir DIR)
  relay release run --config FILE --grant FILE (--file FILE | --dir DIR)

recovery and debugging:
  relay advanced push --chain FILE --chain-signature FILE --root DIR --ceremony FILE \
             --ceremony-signature FILE --coordinator-key FILE \
             --bucket NAME --endpoint URL [--profile P] [--verify]
  relay advanced pull --chain FILE --chain-signature FILE --root DIR --ceremony FILE \
             --ceremony-signature FILE --coordinator-key FILE \
             --bucket NAME --endpoint URL [--profile P]

--coordinator-key is the out-of-band trust anchor. It is never fetched from the
bucket: taking it from the same place as the artifacts it verifies would prove
only that the bucket agrees with itself.
--ceremony-binary defaults to mpc-ceremony and may pin an explicitly trusted path.

Artifacts are stored content-addressed at blob/sha256/<hex>. Uploads use
If-None-Match so an existing object is never overwritten.

--verify re-downloads every object after upload and re-hashes it, rather than
trusting the upload response. It costs a full round trip of the transcript and
is off by default.

mirror receipt drafts an ImmutableMirrorReceipt for one accepted head. It is a draft:
feed it to "mpc-ceremony ops prepare-mirror-receipt" to authenticate the chain
and mirror enrollment, then sign the exported canonical bytes offline.

This tool delegates signature checks to the ceremony CLI, then checks local and
transported bytes against its authenticated artifact projection.
`)
}

func runCoordinator(args []string) error {
	if len(args) == 0 {
		return errors.New("coordinator requires configure-storage, grant, candidates, accept, evidence, or publish")
	}
	switch args[0] {
	case "configure-storage":
		return runConfigureStorage(args[1:])
	case "grant":
		return runGrant(args[1:])
	case "candidates":
		return runCandidates(args[1:])
	case "accept":
		return runAcceptCandidate(args[1:])
	case "evidence":
		return runEvidenceInbox(args[1:])
	case "publish":
		return runPublish(args[1:])
	default:
		return fmt.Errorf("unknown coordinator command %q", args[0])
	}
}

func runParticipant(args []string) error {
	if len(args) == 0 {
		return errors.New("participant requires enroll, status, run")
	}
	switch args[0] {
	case "enroll":
		return runEnroll(args[1:])
	case "status":
		return runParticipantStatus(args[1:])
	case "run":
		return runParticipate(args[1:])
	default:
		return fmt.Errorf("unknown participant command %q", args[0])
	}
}

func runWitness(args []string) error {
	if len(args) == 0 {
		return errors.New("witness requires run, watch, or submit")
	}
	if args[0] == "run" || args[0] == "watch" {
		return runWatch(args[1:])
	}
	if args[0] == "submit" {
		return runSubmitEvidenceForRole(args[1:], access.RoleWitness)
	}
	return fmt.Errorf("unknown witness command %q", args[0])
}

func runMirror(args []string) error {
	if len(args) == 0 {
		return errors.New("mirror requires run, sync, or receipt")
	}
	switch args[0] {
	case "run", "sync":
		return runSync("mirror sync", args[1:])
	case "receipt":
		return runReceipt(args[1:])
	case "submit":
		return runSubmitEvidenceForRole(args[1:], access.RoleMirror)
	default:
		return fmt.Errorf("unknown mirror command %q", args[0])
	}
}

func runAuditor(args []string) error {
	if len(args) == 0 {
		return errors.New("auditor requires run, sync, or submit")
	}
	if args[0] == "run" || args[0] == "sync" {
		return runSync("auditor sync", args[1:])
	}
	if args[0] == "submit" {
		return runSubmitEvidenceForRole(args[1:], access.RoleAuditor)
	}
	return fmt.Errorf("unknown auditor command %q", args[0])
}

func runCeremony(args []string) error {
	if len(args) == 0 {
		return errors.New("ceremony requires setup, open, enroll, or init-config")
	}
	switch args[0] {
	case "setup":
		return runGuidedSetup(args[1:])
	case "open":
		return runGuidedOpen(args[1:])
	case "enroll":
		return runEnroll(args[1:])
	case "init-config":
		return runInitRoleConfig(args[1:])
	}
	return fmt.Errorf("unknown ceremony command %q", args[0])
}

func runRelease(args []string) error {
	if len(args) == 0 {
		return errors.New("release requires run or submit")
	}
	if args[0] == "run" || args[0] == "submit" {
		return runReleaseEvidence(args[1:])
	}
	return fmt.Errorf("unknown release command %q", args[0])
}

func runAdvanced(args []string) error {
	if len(args) == 0 {
		return errors.New("advanced requires push or pull")
	}
	switch args[0] {
	case "push":
		return runPush(args[1:])
	case "pull":
		return runPull(args[1:])
	case "verify-ceremony-pair":
		return runVerifyCeremonyPair(args[1:])
	default:
		return fmt.Errorf("unknown advanced command %q", args[0])
	}
}

type common struct {
	chainPath      string
	chainSignature string
	root           string
	ceremony       string
	ceremonySig    string
	coordinatorKey string
	ceremonyBinary string
	client         store.Client
	verify         bool
}

func bind(set *flag.FlagSet, args []string, withVerify bool) (common, error) {
	var c common
	set.StringVar(&c.chainPath, "chain", "", "path to a coordinator-signed chain document")
	set.StringVar(&c.chainSignature, "chain-signature", "", "path to the chain's detached signature")
	set.StringVar(&c.root, "root", "", "transcript root directory")
	set.StringVar(&c.ceremony, "ceremony", "", "path to the signed ceremony definition")
	set.StringVar(&c.ceremonySig, "ceremony-signature", "", "path to the definition's detached signature")
	set.StringVar(&c.coordinatorKey, "coordinator-key", "", "out-of-band trusted coordinator public key")
	set.StringVar(&c.ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted mpc-ceremony executable")
	set.StringVar(&c.client.Bucket, "bucket", "", "bucket name")
	set.StringVar(&c.client.Endpoint, "endpoint", "", "S3-compatible endpoint URL")
	set.StringVar(&c.client.Profile, "profile", "default", "AWS CLI profile holding the credentials")
	if withVerify {
		set.BoolVar(&c.verify, "verify", false, "re-download and re-hash every object after upload")
	}
	if err := set.Parse(args); err != nil {
		return c, err
	}
	for name, value := range map[string]string{
		"--chain": c.chainPath, "--chain-signature": c.chainSignature,
		"--root": c.root, "--ceremony": c.ceremony,
		"--ceremony-signature": c.ceremonySig, "--coordinator-key": c.coordinatorKey,
		"--bucket": c.client.Bucket, "--endpoint": c.client.Endpoint,
	} {
		if value == "" {
			return c, fmt.Errorf("%s is required", name)
		}
	}
	return c, nil
}

func (c common) inspector() transcript.Inspector {
	return transcript.Inspector{
		Executable:               c.ceremonyBinary,
		CeremonyPath:             c.ceremony,
		CeremonySignaturePath:    c.ceremonySig,
		CoordinatorPublicKeyPath: c.coordinatorKey,
		TranscriptRoot:           c.root,
	}
}

func runPush(args []string) error {
	opts, err := bind(flag.NewFlagSet("advanced push", flag.ContinueOnError), args, true)
	if err != nil {
		return err
	}
	chain, err := opts.inspector().Chain(opts.chainPath, opts.chainSignature)
	if err != nil {
		return err
	}
	files, err := transcript.TranscriptFiles(opts.root, chain)
	if err != nil {
		return err
	}
	fmt.Printf("ceremony %s  phase %s  %d files\n",
		chain.CeremonyID, chain.Phase, len(files))

	var uploaded, present int
	if err := runWithProgress("uploading authenticated transcript", func() error {
		for _, file := range files {
			local, err := transcript.Resolve(opts.root, file.Name)
			if err != nil {
				return err
			}
			sum, size, err := transcript.DigestFile(local)
			if err != nil {
				return fmt.Errorf("%s: %w", file.Name, err)
			}
			// Where a signed document states the digest, disagreement is a problem
			// here rather than something to discover in the bucket later. Files
			// with no signed digest (the chain document and the phase-ending
			// records) are keyed by their own hash, so a changed file becomes a
			// different object rather than overwriting one.
			if file.HasDigest() && (sum != file.Digest.SHA256 || size != file.Digest.Size) {
				return fmt.Errorf("%s: local file does not match the chain digest", file.Name)
			}

			fmt.Fprintf(os.Stderr, "  uploading %s (%s)\n", file.Name, formatBytes(size))
			key := store.Key(sum)
			switch err := opts.client.PutNoReplace(key, local); {
			case err == nil:
				uploaded++
				fmt.Printf("  put    %-46s %s\n", file.Name, key)
			case errors.Is(err, store.ErrExists):
				present++
				fmt.Printf("  exists %-46s %s\n", file.Name, key)
			default:
				return fmt.Errorf("%s: %w", file.Name, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("%d uploaded, %d already present\n", uploaded, present)

	if !opts.verify {
		fmt.Println("verification: skipped (pass --verify to re-download and re-hash)")
		return nil
	}
	return runWithProgress("verifying uploaded transcript", func() error {
		return verifyStored(opts, files)
	})
}

// verifyStored re-downloads every object and re-hashes it. A 200 response to a
// PUT is not evidence the right bytes landed; this is.
func verifyStored(opts common, files []transcript.File) error {
	temp, err := os.MkdirTemp("", "relay-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)

	for _, file := range files {
		source, err := transcript.Resolve(opts.root, file.Name)
		if err != nil {
			return err
		}
		expected, expectedSize, err := transcript.DigestFile(source)
		if err != nil {
			return err
		}
		key := store.Key(expected)
		local := filepath.Join(temp, "object")
		if err := opts.client.Get(key, local); err != nil {
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		sum, size, err := transcript.DigestFile(local)
		if err != nil {
			return err
		}
		if sum != expected || size != expectedSize {
			return fmt.Errorf("%s: stored object does not match the local file", file.Name)
		}
		_ = os.Remove(local)
		fmt.Printf("  ok     %-46s %s\n", file.Name, key)
	}
	fmt.Printf("verification: %d objects re-downloaded and re-hashed\n", len(files))
	return nil
}

func runPull(args []string) error {
	opts, err := bind(flag.NewFlagSet("advanced pull", flag.ContinueOnError), args, false)
	if err != nil {
		return err
	}
	chain, err := opts.inspector().Chain(opts.chainPath, opts.chainSignature)
	if err != nil {
		return err
	}
	fmt.Printf("ceremony %s  phase %s  %d artifacts\n",
		chain.CeremonyID, chain.Phase, len(chain.Artifacts))

	return runWithProgress("downloading authenticated transcript", func() error {
		for _, ref := range chain.Artifacts {
			local, err := transcript.Resolve(opts.root, ref.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
				return err
			}
			// Never overwrite. A transcript directory is append-only, and a pull
			// that would replace an existing artifact means the local copy and the
			// bucket disagree, which the operator must resolve deliberately.
			if _, err := os.Lstat(local); err == nil {
				sum, size, err := transcript.DigestFile(local)
				if err != nil {
					return err
				}
				if sum != ref.Digest.SHA256 || size != ref.Digest.Size {
					return fmt.Errorf("%s: existing local file does not match the chain digest", ref.Name)
				}
				fmt.Printf("  have   %-46s\n", ref.Name)
				continue
			}
			fmt.Fprintf(os.Stderr, "  downloading %s (%s)\n", ref.Name, formatBytes(ref.Digest.Size))
			if err := opts.client.Get(store.Key(ref.Digest.SHA256), local); err != nil {
				return fmt.Errorf("%s: %w", ref.Name, err)
			}
			sum, size, err := transcript.DigestFile(local)
			if err != nil {
				return err
			}
			if sum != ref.Digest.SHA256 || size != ref.Digest.Size {
				return fmt.Errorf("%s: downloaded object does not match the chain digest", ref.Name)
			}
			fmt.Printf("  got    %-46s\n", ref.Name)
		}
		return nil
	})
}

// runReceipt drafts a mirror receipt for one accepted head.
//
// It stops at a draft on purpose. The ceremony encodes records as canonical
// JSON with an exact field order and no trailing newline; reproducing that here
// would be a second implementation of a format whose entire point is that there
// is one. The ceremony CLI canonicalizes the draft, and the mirror operator
// signs those bytes offline with their own key.
func runReceipt(args []string) error {
	set := flag.NewFlagSet("mirror receipt", flag.ContinueOnError)
	var (
		chainPath      string
		chainSignature string
		root           string
		ceremony       string
		ceremonySig    string
		coordinatorKey string
		ceremonyBinary string
		index          int
		location       string
		storedAt       string
		out            string
		configPath     string
	)
	set.StringVar(&configPath, "config", "", "validated mirror role configuration")
	set.StringVar(&chainPath, "chain", "", "path to the coordinator-signed chain document")
	set.StringVar(&chainSignature, "chain-signature", "", "path to the chain's detached signature")
	set.StringVar(&root, "root", "", "transcript root directory")
	set.StringVar(&ceremony, "ceremony", "", "path to the signed ceremony definition")
	set.StringVar(&ceremonySig, "ceremony-signature", "", "path to the definition's detached signature")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "out-of-band trusted coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted mpc-ceremony executable")
	set.IntVar(&index, "index", 0, "one-based accepted head this receipt covers")
	set.StringVar(&location, "location", "", "storage location URI; only its SHA-256 is recorded")
	set.StringVar(&storedAt, "stored-at", "", "observed UTC time the copy was stored, RFC3339")
	set.StringVar(&out, "out", "", "write the draft here instead of stdout")
	if err := set.Parse(args); err != nil {
		return err
	}
	if configPath != "" {
		config, err := loadRoleConfig(configPath, access.RoleMirror)
		if err != nil {
			return err
		}
		root = config.Root
		ceremony = config.Ceremony
		ceremonySig = config.CeremonySignature
		coordinatorKey = config.CoordinatorKey
		ceremonyBinary = config.CeremonyBinary
	}
	if chainPath == "" || chainSignature == "" || root == "" || ceremony == "" ||
		ceremonySig == "" || coordinatorKey == "" || index < 1 || location == "" || storedAt == "" {
		return errors.New("--chain, --chain-signature, --root, --ceremony, --ceremony-signature, --coordinator-key, --index, --location and --stored-at are required")
	}

	inspector := transcript.Inspector{
		Executable:               ceremonyBinary,
		CeremonyPath:             ceremony,
		CeremonySignaturePath:    ceremonySig,
		CoordinatorPublicKeyPath: coordinatorKey,
		TranscriptRoot:           root,
	}
	chain, err := inspector.Chain(chainPath, chainSignature)
	if err != nil {
		return err
	}
	if index != chain.AcceptedCount() {
		return fmt.Errorf(
			"receipt index %d must equal the authenticated chain prefix length %d; use the exact chain prefix for that head",
			index, chain.AcceptedCount(),
		)
	}
	record, err := chain.RecordAt(index)
	if err != nil {
		return err
	}
	chainRef, chainSigRef, err := transcript.ChainPrefixRefs(chain)
	if err != nil {
		return err
	}
	draft := transcript.MirrorReceiptDraft{
		CeremonyID:            chain.CeremonyID,
		Phase:                 chain.Phase,
		Index:                 uint8(index),
		AcceptedHeadID:        record.RecordID,
		Files:                 transcript.MirrorReceiptFiles(record, chainRef, chainSigRef),
		StorageLocationSHA256: transcript.TaggedSHA256([]byte(location)),
		StoredAt:              storedAt,
	}
	encoded, err := draft.Encode()
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Printf("%s\n", encoded)
		return nil
	}
	// Never clobber: a receipt draft is an input to a signing round trip, and
	// silently replacing one that has already been exported would substitute
	// what the mirror operator is about to sign.
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return nil
}

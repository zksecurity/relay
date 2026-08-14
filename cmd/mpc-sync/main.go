// Command mpc-sync moves MPC ceremony transcript artifacts between a local
// directory and S3-compatible object storage.
//
// It is deliberately outside the ceremony's trust boundary. It verifies
// digests against the chain document it is given; it does not verify
// signatures, and it never decides whether a transcript is authentic. That
// judgement belongs to the ceremony CLI, which holds a coordinator public key
// obtained out of band. A hostile bucket can therefore make this tool fail,
// never make it lie.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/mpc-sync/internal/store"
	"github.com/zksecurity/mpc-sync/internal/transcript"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "push":
		err = runPush(os.Args[2:])
	case "pull":
		err = runPull(os.Args[2:])
	case "receipt":
		err = runReceipt(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "fetch":
		err = runFetch(os.Args[2:])
	case "publish":
		err = runPublish(os.Args[2:])
	case "submit":
		err = runSubmit(os.Args[2:])
	case "watch":
		err = runWatch(os.Args[2:])
	case "sync":
		err = runSync(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  mpc-sync push --chain FILE --root DIR --bucket NAME --endpoint URL [--profile P] [--verify]
  mpc-sync pull --chain FILE --root DIR --bucket NAME --endpoint URL [--profile P]
  mpc-sync receipt --chain FILE --index N --location URI --stored-at TIME [--out FILE]

role-scoped, discovering ceremony position from the bucket:
  mpc-sync status   --root DIR --ceremony FILE --phase P --bucket B --endpoint U [--role ID]
  mpc-sync fetch    --root DIR --ceremony FILE --phase P --bucket B --endpoint U --role ID \
                    --ceremony-signature FILE --coordinator-key FILE \
                    --signing-key FILE --environment FILE [--print]

--coordinator-key is the out-of-band trust anchor. It is never fetched from the
bucket: taking it from the same place as the artifacts it verifies would prove
only that the bucket agrees with itself.
  mpc-sync submit   --root DIR --ceremony FILE --role ID --candidate DIR --bucket B --endpoint U
  mpc-sync publish  --root DIR --ceremony FILE --chain FILE --bucket B --endpoint U [--closed] [--verify]
  mpc-sync watch    --root DIR --ceremony FILE --phase P --bucket B --endpoint U [--interval D] [--once]
  mpc-sync sync     --root DIR --ceremony FILE --phase P --bucket B --endpoint U

Artifacts are stored content-addressed at blob/sha256/<hex>. Uploads use
If-None-Match so an existing object is never overwritten.

--verify re-downloads every object after upload and re-hashes it, rather than
trusting the upload response. It costs a full round trip of the transcript and
is off by default.

receipt drafts an ImmutableMirrorReceipt for one accepted head. It is a draft:
feed it to "mpc-ceremony ops export-signing --record-type mirror-receipt" to
canonicalize it, then sign the canonical bytes offline with the mirror key.

This tool checks digests, not signatures. Authenticity is established by the
ceremony CLI against an out-of-band coordinator public key.
`)
}

type common struct {
	chainPath string
	root      string
	client    store.Client
	verify    bool
}

func bind(set *flag.FlagSet, args []string, withVerify bool) (common, error) {
	var c common
	set.StringVar(&c.chainPath, "chain", "", "path to a coordinator-signed chain document")
	set.StringVar(&c.root, "root", "", "transcript root directory")
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
		"--chain": c.chainPath, "--root": c.root,
		"--bucket": c.client.Bucket, "--endpoint": c.client.Endpoint,
	} {
		if value == "" {
			return c, fmt.Errorf("%s is required", name)
		}
	}
	return c, nil
}

func runPush(args []string) error {
	opts, err := bind(flag.NewFlagSet("push", flag.ContinueOnError), args, true)
	if err != nil {
		return err
	}
	chain, err := transcript.LoadChain(opts.chainPath)
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
	fmt.Printf("%d uploaded, %d already present\n", uploaded, present)

	if !opts.verify {
		fmt.Println("verification: skipped (pass --verify to re-download and re-hash)")
		return nil
	}
	return verifyStored(opts, files)
}

// verifyStored re-downloads every object and re-hashes it. A 200 response to a
// PUT is not evidence the right bytes landed; this is.
func verifyStored(opts common, files []transcript.File) error {
	temp, err := os.MkdirTemp("", "mpc-sync-verify-")
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
	opts, err := bind(flag.NewFlagSet("pull", flag.ContinueOnError), args, false)
	if err != nil {
		return err
	}
	chain, err := transcript.LoadChain(opts.chainPath)
	if err != nil {
		return err
	}
	fmt.Printf("ceremony %s  phase %s  %d artifacts\n",
		chain.CeremonyID, chain.Phase, len(chain.Artifacts))

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
}

// runReceipt drafts a mirror receipt for one accepted head.
//
// It stops at a draft on purpose. The ceremony encodes records as canonical
// JSON with an exact field order and no trailing newline; reproducing that here
// would be a second implementation of a format whose entire point is that there
// is one. The ceremony CLI canonicalizes the draft, and the mirror operator
// signs those bytes offline with their own key.
func runReceipt(args []string) error {
	set := flag.NewFlagSet("receipt", flag.ContinueOnError)
	var (
		chainPath string
		index     int
		location  string
		storedAt  string
		out       string
	)
	set.StringVar(&chainPath, "chain", "", "path to the coordinator-signed chain document")
	set.IntVar(&index, "index", 0, "one-based accepted head this receipt covers")
	set.StringVar(&location, "location", "", "storage location URI; only its SHA-256 is recorded")
	set.StringVar(&storedAt, "stored-at", "", "observed UTC time the copy was stored, RFC3339")
	set.StringVar(&out, "out", "", "write the draft here instead of stdout")
	if err := set.Parse(args); err != nil {
		return err
	}
	if chainPath == "" || index < 1 || location == "" || storedAt == "" {
		return errors.New("--chain, --index, --location and --stored-at are required")
	}

	chain, err := transcript.LoadChain(chainPath)
	if err != nil {
		return err
	}
	record, headID, err := chain.RecordAt(index)
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
		AcceptedHeadID:        headID,
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

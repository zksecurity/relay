package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zksecurity/mpc-sync/internal/state"
	"github.com/zksecurity/mpc-sync/internal/store"
	"github.com/zksecurity/mpc-sync/internal/transcript"
)

// runSubmit uploads a finished candidate directory.
//
// A candidate is not part of the signed transcript yet: the coordinator decides
// whether to accept it. So its files are uploaded content-addressed like
// everything else, but under names the participant asserts rather than names a
// chain already vouches for. The allowlist still applies, which is what stops a
// mis-pointed --candidate putting a signing key in the bucket.
func runSubmit(args []string) error {
	var o roleOpts
	set := flag.NewFlagSet("submit", flag.ContinueOnError)
	registerRole(set, &o, false)
	var candidateDir string
	set.StringVar(&candidateDir, "candidate", "", "candidate directory produced by contribute")
	if err := set.Parse(args); err != nil {
		return err
	}
	if err := checkRole(o); err != nil {
		return err
	}
	if o.role == "" || candidateDir == "" {
		return errors.New("--role and --candidate are required")
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	if err := reportTurn(o, pos); err != nil {
		return err
	}

	// The ceremony names candidate files by their position in the chain, so the
	// index decides the logical names. Using the position the tool derived,
	// rather than a flag, keeps a submission from being filed under someone
	// else's slot.
	prefix := fmt.Sprintf("%s/contributions/%04d", o.phase, pos.nextIndex)
	wanted := []string{
		"contribution.bin", "attestation.json", "attestation.sig",
		"erasure.json", "erasure.sig",
	}
	var uploaded int
	for _, base := range wanted {
		local := filepath.Join(candidateDir, base)
		if _, err := os.Lstat(local); err != nil {
			if base == "erasure.json" || base == "erasure.sig" {
				return fmt.Errorf(
					"%s is missing: run attest-erasure before submitting, "+
						"the coordinator will not accept a contribution without it", base)
			}
			return fmt.Errorf("%s is missing from the candidate directory", base)
		}
		name := prefix + "/" + base
		if err := transcript.CheckPublishable(name); err != nil {
			return err
		}
		sum, _, err := transcript.DigestFile(local)
		if err != nil {
			return err
		}
		switch err := o.client.PutNoReplace(store.Key(sum), local); {
		case err == nil:
			uploaded++
			fmt.Printf("  put    %s\n", name)
		case errors.Is(err, store.ErrExists):
			fmt.Printf("  exists %s\n", name)
		default:
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	fmt.Printf("submitted %d files for %s index %d\n", uploaded, o.role, pos.nextIndex)
	fmt.Println("tell the coordinator; they run phase verify to accept it")
	return nil
}

// runWatch blocks until a phase closure is published, then reports the timing a
// witness needs in order to decide whether signing a receipt is honest.
//
// It deliberately reports rather than signs. A witness attests that they saw a
// closure published before its beacon round existed; that is a claim about the
// world, and a tool cannot make it on their behalf.
func runWatch(args []string) error {
	var o roleOpts
	set := flag.NewFlagSet("watch", flag.ContinueOnError)
	registerRole(set, &o, false)
	var interval time.Duration
	var once bool
	set.DurationVar(&interval, "interval", 60*time.Second, "poll interval")
	set.BoolVar(&once, "once", false, "check a single time and exit")
	if err := set.Parse(args); err != nil {
		return err
	}
	if err := checkRole(o); err != nil {
		return err
	}

	for {
		pos, err := resolvePosition(o)
		if err != nil {
			return err
		}
		if pos.phaseClosed {
			fmt.Printf("%s is closed at index %d\n", o.phase, pos.accepted)
			fmt.Printf("chain     %s\n", pos.pointer.Chain.SHA256)
			fmt.Println()
			fmt.Println("fetch the closure record, confirm its beacon round has not yet occurred,")
			fmt.Println("and that the round is at least the definition's witness lead away.")
			fmt.Println("only then sign a receipt: you are attesting that you saw this")
			fmt.Println("published before its randomness existed.")
			return nil
		}
		fmt.Printf("%s open, %d accepted, waiting on %s\n", o.phase, pos.accepted, pos.nextID)
		if once {
			return nil
		}
		time.Sleep(interval)
	}
}

// runSync is the mirror's pull: fetch everything the transcript names and keep
// it. Unlike a participant's fetch it does not care whose turn it is.
func runSync(args []string) error {
	o, err := bindRole(flag.NewFlagSet("sync", flag.ContinueOnError), args, false)
	if err != nil {
		return err
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	files, err := transcript.TranscriptFiles(o.root, pos.chain)
	if err != nil {
		return err
	}
	var got, have int
	for _, file := range files {
		local, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			return err
		}
		if _, _, err := transcript.DigestFile(local); err == nil {
			have++
			continue
		}
		if !file.HasDigest() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
			return err
		}
		if err := o.client.Get(store.Key(file.Digest.SHA256), local); err != nil {
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		sum, size, err := transcript.DigestFile(local)
		if err != nil {
			return err
		}
		if sum != file.Digest.SHA256 || size != file.Digest.Size {
			_ = os.Remove(local)
			return fmt.Errorf("%s: fetched bytes do not match the chain digest", file.Name)
		}
		got++
		fmt.Printf("  got    %s\n", file.Name)
	}
	fmt.Printf("%d fetched, %d already held, %s at index %d\n", got, have, o.phase, pos.accepted)
	fmt.Println()
	fmt.Println("draft a receipt for each accepted head you now hold:")
	for index := 1; index <= pos.accepted; index++ {
		fmt.Printf("  mpc-sync receipt --chain %s --index %d --location <uri> --stored-at %s\n",
			pos.chainPath, index, time.Now().UTC().Format(time.RFC3339))
	}
	return nil
}

// pointerSummary is used by tests and by status to describe a pointer without
// reaching into the bucket.
func pointerSummary(p state.Pointer) string {
	parts := []string{p.Phase, fmt.Sprintf("index %d", p.Index)}
	if p.Closed {
		parts = append(parts, "closed")
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, " ")
}

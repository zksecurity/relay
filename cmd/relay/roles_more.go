package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
)

// runWatch blocks until a phase closure is published, then reports the timing a
// witness needs in order to decide whether signing a receipt is honest.
//
// It deliberately reports rather than signs. A witness attests that they saw a
// closure published before its beacon round existed; that is a claim about the
// world, and a tool cannot make it on their behalf.
func runWatch(args []string) error {
	var o roleOpts
	set := flag.NewFlagSet("witness watch", flag.ContinueOnError)
	var interval time.Duration
	var once bool
	var configPath string
	configured := hasNamedFlag(args, "config")
	if configured {
		set.StringVar(&configPath, "config", "", "validated witness role configuration")
	} else {
		registerRole(set, &o)
	}
	set.DurationVar(&interval, "interval", 60*time.Second, "poll interval")
	set.BoolVar(&once, "once", false, "check a single time and exit")
	if err := set.Parse(args); err != nil {
		return err
	}
	if configured {
		config, err := loadRoleConfig(configPath, access.RoleWitness)
		if err != nil {
			return err
		}
		o = configuredRoleOptions(config)
	} else {
		if err := checkRole(o); err != nil {
			return err
		}
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
			// A single check that observed nothing must not look like a
			// successful observation: the caller's next step is preparing a
			// signed witness receipt, and scripts gate their "saw the
			// closure" reporting on this exit status.
			return fmt.Errorf("no closure observed: %s is still open", o.phase)
		}
		time.Sleep(interval)
	}
}

// runSync fetches everything the transcript names for a mirror or auditor to
// keep. Unlike participation it does not care whose turn it is.
func runSync(commandName string, args []string) error {
	var o roleOpts
	if hasNamedFlag(args, "config") {
		set := flag.NewFlagSet(commandName, flag.ContinueOnError)
		var configPath string
		set.StringVar(&configPath, "config", "", "validated role configuration")
		if err := set.Parse(args); err != nil {
			return err
		}
		expectedRole := access.RoleMirror
		if strings.HasPrefix(commandName, "auditor") {
			expectedRole = access.RoleAuditor
		}
		config, err := loadRoleConfig(configPath, expectedRole)
		if err != nil {
			return err
		}
		o = configuredRoleOptions(config)
	} else {
		var err error
		o, err = bindRole(flag.NewFlagSet(commandName, flag.ContinueOnError), args)
		if err != nil {
			return err
		}
	}
	pos, err := resolvePosition(o)
	if err != nil {
		return err
	}
	files, err := mirrorSyncFiles(pos)
	if err != nil {
		return err
	}
	var got, have int
	if err := runWithProgress("syncing "+o.phase+" transcript and public inventory", func() error {
		for _, file := range files {
			local, err := transcript.Resolve(o.root, file.Name)
			if err != nil {
				return err
			}
			if err := checkMirrorDestination(o.root, local); err != nil {
				return err
			}
			_, err = os.Lstat(local)
			existed := err == nil
			if err := fetchVerified(o.client, state.Ref{Name: file.Name, SHA256: file.Digest.SHA256}, local); err != nil {
				return err
			}
			if file.Digest.Size >= 0 {
				_, size, err := transcript.DigestFile(local)
				if err != nil {
					return err
				}
				if size != file.Digest.Size {
					return fmt.Errorf("%s: retained size does not match signed reference", file.Name)
				}
			}
			if existed {
				have++
			} else {
				got++
			}
		}
		// Each historical prefix must authenticate under the separately trusted
		// coordinator key and match the already authenticated current history.
		for index := 0; index <= pos.accepted; index++ {
			path := filepath.Join(o.root, fmt.Sprintf("%s/chain-%04d.json", o.phase, index))
			sig := filepath.Join(o.root, fmt.Sprintf("%s/chain-%04d.sig", o.phase, index))
			prefix, err := o.inspector().Chain(path, sig)
			if err != nil {
				return err
			}
			if prefix.AcceptedCount() != index {
				return fmt.Errorf("historical prefix has the wrong index")
			}
			for j, record := range prefix.Records {
				if record.RecordID != pos.chain.Records[j].RecordID {
					return fmt.Errorf("historical prefix disagrees with authenticated current history")
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Println("Inventory hashes checked. Phase-ending records still require their protocol signature and evidence verification.")
	fmt.Printf("%d fetched, %d already held, %s at index %d\n", got, have, o.phase, pos.accepted)
	fmt.Println()
	fmt.Print(syncNextStep(commandName, pos.chainPath, pos.chain.ChainSignaturePath,
		pos.accepted, time.Now().UTC().Format(time.RFC3339)))
	return nil
}

func syncNextStep(commandName, chainPath, chainSignaturePath string, index int, storedAt string) string {
	if strings.HasPrefix(commandName, "auditor") {
		return "authenticated transcript synchronized and ready for independent audit.\n"
	}
	return fmt.Sprintf(
		"draft a receipt for the exact accepted chain prefix you now hold:\n"+
			"  relay mirror receipt --chain %s --chain-signature %s --index %d --location <uri> --stored-at %s\n",
		chainPath, chainSignaturePath, index, storedAt,
	)
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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

// runVerifyCeremonyPair is intentionally hidden under advanced. Release-kit
// assembly uses it to exercise the exact Relay and mpc-ceremony binaries
// against proof-tool's same-host tiny rehearsal. It never accesses storage and
// refuses non-rehearsal definitions.
func runVerifyCeremonyPair(args []string) error {
	set := flag.NewFlagSet("advanced verify-ceremony-pair", flag.ContinueOnError)
	var home, ceremonyBinary string
	set.StringVar(&home, "home", "", "fresh rehearsal root created by mpc-ceremony rehearsal init")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "", "exact mpc-ceremony release binary")
	if err := set.Parse(args); err != nil {
		return err
	}
	if home == "" || ceremonyBinary == "" {
		return errors.New("--home and --ceremony-binary are required")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("--home must be an absolute clean path")
	}
	if info, err := os.Lstat(ceremonyBinary); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("--ceremony-binary must be an executable non-symlink regular file")
	}

	root := filepath.Join(home, "public")
	o := roleOpts{
		root:           root,
		definition:     filepath.Join(root, "ceremony.json"),
		definitionSig:  filepath.Join(root, "ceremony.sig"),
		coordinatorKey: filepath.Join(root, "coordinator-public-key.hex"),
		ceremonyBinary: ceremonyBinary,
		phase:          "phase1",
		role:           "participant-01",
		signingKey:     filepath.Join(home, "keys", "participant-01.ed25519.private.hex"),
		envPath:        filepath.Join(home, "config", "environment.json"),
		outDir:         filepath.Join(home, "compatibility", "phase1-participant-01"),
	}
	inspector := transcript.Inspector{
		Executable: ceremonyBinary, CeremonyPath: o.definition,
		CeremonySignaturePath: o.definitionSig, CoordinatorPublicKeyPath: o.coordinatorKey,
		TranscriptRoot: root,
	}
	definition, err := inspector.Definition()
	if err != nil {
		return fmt.Errorf("inspect rehearsal definition: %w", err)
	}
	if definition.Mode != "rehearsal" {
		return fmt.Errorf("compatibility exercise requires rehearsal mode, found %q", definition.Mode)
	}
	participant, err := inspector.Participant(o.signingKey)
	if err != nil {
		return fmt.Errorf("inspect rehearsal participant: %w", err)
	}
	if participant.ParticipantID != o.role {
		return fmt.Errorf("rehearsal key belongs to %s, want %s", participant.ParticipantID, o.role)
	}

	chainPath := filepath.Join(root, "phase1", "chain-0000.json")
	chainSignaturePath := filepath.Join(root, "phase1", "chain-0000.sig")
	chain, err := inspector.Chain(chainPath, chainSignaturePath)
	if err != nil {
		return fmt.Errorf("inspect initial rehearsal chain: %w", err)
	}
	if chain.Phase != o.phase || chain.AcceptedCount() != 0 {
		return fmt.Errorf("initial rehearsal chain is %s with %d accepted contributions", chain.Phase, chain.AcceptedCount())
	}
	nextID, nextIndex, err := definition.NextContributor(o.phase, chain.AcceptedCount())
	if err != nil {
		return err
	}
	if nextID != o.role || nextIndex != 1 {
		return fmt.Errorf("initial rehearsal turn is %s at index %d, want %s at index 1", nextID, nextIndex, o.role)
	}
	if err := os.Mkdir(filepath.Dir(o.outDir), 0o700); err != nil {
		return fmt.Errorf("create compatibility output parent: %w", err)
	}
	pos := position{
		definition: definition, chain: chain, chainPath: chainPath,
		nextID: nextID, nextIndex: nextIndex,
	}
	contributedAt := time.Now().UTC().Truncate(time.Second)
	if err := runNextAt(o, pos, contributedAt); err != nil {
		return fmt.Errorf("run tiny rehearsal contribution: %w", err)
	}
	if err := runErasureAt(o, contributedAt.Add(time.Second)); err != nil {
		return fmt.Errorf("create tiny rehearsal erasure attestation: %w", err)
	}

	cmd := candidateVerificationCommand(
		o, chainPath, chainSignaturePath, o.outDir,
		filepath.Join(home, "keys", "coordinator.ed25519.private.hex"),
		defaultAcceptanceTimestamp(contributedAt.Add(2*time.Second)),
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := runWithProgress("verifying tiny rehearsal contribution", cmd.Run); err != nil {
		return err
	}
	accepted, err := inspector.Chain(
		filepath.Join(root, "phase1", "chain-0001.json"),
		filepath.Join(root, "phase1", "chain-0001.sig"),
	)
	if err != nil {
		return fmt.Errorf("inspect accepted rehearsal chain: %w", err)
	}
	if accepted.AcceptedCount() != 1 || accepted.Records[0].ParticipantID != o.role {
		return fmt.Errorf("accepted rehearsal chain does not contain %s at index 1", o.role)
	}
	fmt.Println("verified exact-binary phase1 contribution and acceptance")
	return nil
}

package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	workflowV4ClosePhase1  = "close-phase1"
	workflowV4ClosePhase2  = "close-phase2"
	workflowV4BeaconPhase1 = "record-phase1-beacon"
	workflowV4BeaconPhase2 = "record-phase2-beacon"
	workflowV4SealPhase1   = "seal-phase1"
	workflowV4StartPhase2  = "start-phase2"
	workflowV4Finalize     = "finalize-candidate"
)

const workflowV4QuicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

// workflowV4CoordinatorLifecycleAction selects ceremony-wide work only when no
// participant turn remains open. It does not infer completion from local files.
func workflowV4CoordinatorLifecycleAction(state transcript.CheckpointStateV4, protocol transcript.DefinitionProtocol) (string, string, error) {
	phase1, err := protocol.Definition.Schedule("phase1")
	if err != nil {
		return "", "", err
	}
	if int(state.Progress.Phase1.AcceptedCount) == len(phase1) && state.Progress.Phase1Closure == nil {
		return workflowV4ClosePhase1, "Replay every accepted Phase 1 contribution and commit the signed closure", nil
	}
	if state.Progress.Phase1Closure != nil && state.Progress.Phase1Beacon == nil {
		return workflowV4BeaconPhase1, "Fetch and verify the exact future beacon round committed by the Phase 1 closure", nil
	}
	if state.Progress.Phase1Beacon != nil && state.Progress.Phase1Seal == nil {
		return workflowV4SealPhase1, "Apply the authenticated Phase 1 beacon and commit the sealed Phase 1 transcript", nil
	}
	if state.Progress.Phase1Seal != nil && state.Progress.Phase2 == nil {
		return workflowV4StartPhase2, "Derive and commit the Phase 2 starting state from sealed Phase 1", nil
	}
	if state.Progress.Phase2 != nil {
		phase2, err := protocol.Definition.Schedule("phase2")
		if err != nil {
			return "", "", err
		}
		if int(state.Progress.Phase2.AcceptedCount) == len(phase2) && state.Progress.Phase2Closure == nil {
			return workflowV4ClosePhase2, "Replay every accepted Phase 2 contribution and commit the signed closure", nil
		}
		if state.Progress.Phase2Closure != nil && state.Progress.Phase2Beacon == nil {
			return workflowV4BeaconPhase2, "Fetch and verify the exact future beacon round committed by the Phase 2 closure", nil
		}
		if state.Progress.Phase2Beacon != nil && state.Progress.FinalCandidate == nil {
			return workflowV4Finalize, "Replay both completed phases and prepare the coordinator-signed final candidate", nil
		}
	}
	return "", "", nil
}

func runWorkflowV4CoordinatorLifecycle(ui *coordinatorWizard, action string, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, online, signer guidedProfile, inspector transcript.Inspector) error {
	if action == workflowV4BeaconPhase1 || action == workflowV4BeaconPhase2 {
		phase := "phase1"
		if action == workflowV4BeaconPhase2 {
			phase = "phase2"
		}
		return runWorkflowV4BeaconLifecycle(ui, phase, snapshot, online, signer, inspector)
	}
	if action == workflowV4SealPhase1 {
		return runWorkflowV4SealPhase1Lifecycle(ui, snapshot, online, signer)
	}
	if action == workflowV4StartPhase2 {
		return runWorkflowV4StartPhase2Lifecycle(ui, snapshot, online, signer)
	}
	if action == workflowV4Finalize {
		return runWorkflowV4FinalizeLifecycle(ui, snapshot, protocol, online, signer)
	}
	phase := "phase1"
	if action == workflowV4ClosePhase2 {
		phase = "phase2"
	} else if action != workflowV4ClosePhase1 {
		return errors.New("unsupported V4 lifecycle action")
	}
	state, err := snapshot.State()
	if err != nil {
		return err
	}
	phaseState := state.Progress.Phase1
	if phase == "phase2" {
		if state.Progress.Phase2 == nil || state.Progress.Phase1Seal == nil {
			return errors.New("authenticated Phase 2 state and Phase 1 seal are required")
		}
		phaseState = *state.Progress.Phase2
	}
	schedule, err := protocol.Definition.Schedule(phase)
	if err != nil {
		return err
	}
	if int(phaseState.AcceptedCount) != len(schedule) {
		return errors.New("phase cannot close before all scheduled contributions are accepted")
	}
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return err
	}
	if journey.BeaconRoundLeadSeconds == 0 {
		return errors.New("signed ceremony definition has no beacon lead time")
	}
	if err := ui.confirm(fmt.Sprintf("Replay all %s contributions and choose the signed future beacon round at least %d seconds ahead", phase, journey.BeaconRoundLeadSeconds), "CLOSE "+strings.ToUpper(phase)); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	closureDir := filepath.Join(root, phase, "closure")
	closureRecord := filepath.Join(closureDir, "record.json")
	closureSignature := filepath.Join(closureDir, "record.sig")
	if record, signature := regularPreparationFile(closureRecord), regularPreparationFile(closureSignature); record != signature {
		return errors.New("incomplete retained phase closure; preserve it for inspection")
	} else if !record {
		command, err := workflowV4CloseCommand(state, online, signer, phase, phaseState, journey.BeaconRoundLeadSeconds)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", phase, "lifecycle", "closed-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, phase+"-closed", closureRecord, closureSignature, nil, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, outputDir)
}

func runWorkflowV4FinalizeLifecycle(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, online, signer guidedProfile) error {
	state, err := snapshot.State()
	if err != nil {
		return err
	}
	if state.Progress.Phase1Closure == nil || state.Progress.Phase1Beacon == nil || state.Progress.Phase1Seal == nil || state.Progress.Phase2 == nil || state.Progress.Phase2Closure == nil || state.Progress.Phase2Beacon == nil || state.Progress.FinalCandidate != nil {
		return errors.New("final candidate requires both authenticated completed phases and no existing candidate")
	}
	if err := ui.confirm("Replay both phases, verify the public proof evidence, and create the exact coordinator-signed candidate", "FINALIZE CANDIDATE"); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	finalRoot := filepath.Join(root, "final")
	if err := os.MkdirAll(finalRoot, 0o700); err != nil {
		return err
	}
	preliminary := filepath.Join(finalRoot, "preliminary")
	if _, err := os.Lstat(preliminary); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4FinalizeCommand(state, online, signer, "prepare", preliminary, "", time.Now().UTC())
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	publicEvidence := filepath.Join(finalRoot, "public-finalization-evidence.json")
	if !regularPreparationFile(publicEvidence) {
		if protocol.Definition.Mode != "rehearsal" {
			return fmt.Errorf("public proof evidence is required before finalization; place the reviewed public artifact at %s and retry", publicEvidence)
		}
		command, err := workflowV4RehearsalEvidenceCommand(state.CeremonyID, online, signer, preliminary, publicEvidence)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	}
	candidate := filepath.Join(finalRoot, "candidate")
	if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4FinalizeCommand(state, online, signer, "complete", candidate, publicEvidence, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	record := filepath.Join(candidate, "candidate.json")
	signature := filepath.Join(candidate, "candidate.sig.json")
	evidence := []string{
		filepath.Join(candidate, "ownership.pk"),
		filepath.Join(candidate, "ownership.vk"),
		filepath.Join(candidate, "candidate-checksums.sha256"),
		filepath.Join(candidate, "public-finalization-evidence.json"),
	}
	for _, path := range append([]string{record, signature}, evidence...) {
		if !regularPreparationFile(path) {
			return errors.New("final candidate output is incomplete; preserve it for inspection")
		}
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", "final", "candidate-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, "final-candidate-recorded", record, signature, evidence, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, outputDir)
}

func workflowV4FinalizeCommand(state transcript.CheckpointStateV4, online, signer guidedProfile, action, outputDir, publicEvidence string, at time.Time) ([]string, error) {
	args, err := workflowV4ReplayArgs(state, online, signer)
	if err != nil {
		return nil, err
	}
	out, err := pathWithin(signer.Work, outputDir, "/work")
	if err != nil {
		return nil, err
	}
	command := append([]string{"mpc-ceremony", "finalize", action}, args...)
	command = append(command, "--coordinator-signing-key", "/keys/signing.hex")
	switch action {
	case "prepare":
		command = append(command, "--prepared-at", at.UTC().Format(time.RFC3339Nano))
	case "complete":
		evidence, err := pathWithin(signer.Work, publicEvidence, "/work")
		if err != nil {
			return nil, err
		}
		command = append(command, "--public-evidence", evidence, "--finalized-at", at.UTC().Format(time.RFC3339Nano))
	default:
		return nil, errors.New("unsupported finalization action")
	}
	return append(command, "--out-dir", out), nil
}

func workflowV4ReplayArgs(state transcript.CheckpointStateV4, online, signer guidedProfile) ([]string, error) {
	if state.Progress.Phase1Closure == nil || state.Progress.Phase1Beacon == nil || state.Progress.Phase1Seal == nil || state.Progress.Phase2 == nil || state.Progress.Phase2Closure == nil || state.Progress.Phase2Beacon == nil {
		return nil, errors.New("complete authenticated replay inputs required")
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	mapRef := func(ref transcript.ArtifactRef) (string, error) {
		return mapWork(filepath.Join(root, filepath.FromSlash(ref.Name)))
	}
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	transcriptRoot, _ := mapWork(root)
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	values := []struct {
		flag string
		ref  transcript.ArtifactRef
	}{
		{"--phase1-chain", state.Progress.Phase1.Chain.Record}, {"--phase1-chain-signature", state.Progress.Phase1.Chain.Signature},
		{"--phase1-close", state.Progress.Phase1Closure.Record}, {"--phase1-close-signature", state.Progress.Phase1Closure.Signature},
		{"--phase1-beacon", state.Progress.Phase1Beacon.Record}, {"--phase1-beacon-signature", state.Progress.Phase1Beacon.Signature},
		{"--phase1-seal", state.Progress.Phase1Seal.Record}, {"--phase1-seal-signature", state.Progress.Phase1Seal.Signature},
		{"--phase2-chain", state.Progress.Phase2.Chain.Record}, {"--phase2-chain-signature", state.Progress.Phase2.Chain.Signature},
		{"--phase2-close", state.Progress.Phase2Closure.Record}, {"--phase2-close-signature", state.Progress.Phase2Closure.Signature},
		{"--phase2-beacon", state.Progress.Phase2Beacon.Record}, {"--phase2-beacon-signature", state.Progress.Phase2Beacon.Signature},
	}
	args := []string{"--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--transcript-root", transcriptRoot}
	for _, value := range values {
		path, err := mapRef(value.ref)
		if err != nil {
			return nil, err
		}
		args = append(args, value.flag, path)
	}
	return args, nil
}

func workflowV4RehearsalEvidenceCommand(ceremonyID string, online, signer guidedProfile, preliminary, output string) ([]string, error) {
	keys, err := pathWithin(signer.Work, preliminary, "/work")
	if err != nil {
		return nil, err
	}
	out, err := pathWithin(signer.Work, output, "/work")
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"mpc-ceremony", "finalize", "rehearsal-evidence", "--keys-dir", keys, "--coordinator-public-key-file", coordinatorKey, "--ceremony-id", ceremonyID, "--out", out}, nil
}

func runWorkflowV4SealPhase1Lifecycle(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, online, signer guidedProfile) error {
	state, err := snapshot.State()
	if err != nil {
		return err
	}
	if state.Progress.Phase1Closure == nil || state.Progress.Phase1Beacon == nil || state.Progress.Phase1Seal != nil {
		return errors.New("Phase 1 seal requires an authenticated closure and beacon and no existing seal")
	}
	if err := ui.confirm("Replay sealed Phase 1 inputs and apply the exact authenticated beacon", "SEAL PHASE1"); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	sealDir := filepath.Join(root, "phase1", "sealed")
	sealRecord := filepath.Join(sealDir, "seal.json")
	sealSignature := filepath.Join(sealDir, "seal.sig")
	commons := filepath.Join(sealDir, "commons.bin")
	complete := regularPreparationFile(sealRecord) && regularPreparationFile(sealSignature) && regularPreparationFile(commons)
	if !complete {
		for _, path := range []string{sealRecord, sealSignature, commons} {
			if _, statErr := os.Lstat(path); statErr == nil {
				return errors.New("incomplete retained Phase 1 seal; preserve it for inspection")
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		}
		command, err := workflowV4SealCommand(online, signer, *state.Progress.Phase1Closure, *state.Progress.Phase1Beacon, sealDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", "phase1", "lifecycle", "sealed-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, "phase1-sealed", sealRecord, sealSignature, []string{commons}, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, outputDir)
}

func workflowV4SealCommand(online, signer guidedProfile, closure, beacon transcript.SignedArtifactRefs, outputDir string) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	transcriptRoot, _ := mapWork(root)
	closureRecord, _ := mapWork(filepath.Join(root, filepath.FromSlash(closure.Record.Name)))
	closureSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(closure.Signature.Name)))
	beaconRecord, _ := mapWork(filepath.Join(root, filepath.FromSlash(beacon.Record.Name)))
	beaconSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(beacon.Signature.Name)))
	out, err := mapWork(outputDir)
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"mpc-ceremony", "phase1", "seal", "--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--transcript-dir", transcriptRoot, "--closure", closureRecord, "--closure-signature", closureSignature, "--beacon", beaconRecord, "--beacon-signature", beaconSignature, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", out}, nil
}

func runWorkflowV4StartPhase2Lifecycle(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, online, signer guidedProfile) error {
	state, err := snapshot.State()
	if err != nil {
		return err
	}
	if state.Progress.Phase1Seal == nil || state.Progress.Phase2 != nil {
		return errors.New("Phase 2 initialization requires sealed Phase 1 and no existing Phase 2")
	}
	if err := ui.confirm("Derive the exact Phase 2 genesis and initial signed chain from sealed Phase 1", "START PHASE2"); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	phase2Dir := filepath.Join(root, "phase2")
	chain := filepath.Join(phase2Dir, "chain-0000.json")
	chainSignature := filepath.Join(phase2Dir, "chain-0000.sig")
	genesis := filepath.Join(phase2Dir, "genesis.bin")
	complete := regularPreparationFile(chain) && regularPreparationFile(chainSignature) && regularPreparationFile(genesis)
	if !complete {
		if _, statErr := os.Lstat(phase2Dir); statErr == nil {
			return errors.New("incomplete retained Phase 2 initialization; preserve it for inspection")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		command, err := workflowV4Phase2InitCommand(online, signer, *state.Progress.Phase1Seal, phase2Dir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", "phase2", "lifecycle", "initialized-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, "phase2-initialized", chain, chainSignature, []string{genesis}, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, outputDir)
}

func workflowV4Phase2InitCommand(online, signer guidedProfile, seal transcript.SignedArtifactRefs, outputDir string) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	transcriptRoot, _ := mapWork(root)
	sealRecord, _ := mapWork(filepath.Join(root, filepath.FromSlash(seal.Record.Name)))
	sealSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(seal.Signature.Name)))
	out, err := mapWork(outputDir)
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"mpc-ceremony", "phase2", "init", "--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--phase1-transcript-dir", transcriptRoot, "--phase1-seal", sealRecord, "--phase1-seal-signature", sealSignature, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", out}, nil
}

func runWorkflowV4BeaconLifecycle(ui *coordinatorWizard, phase string, snapshot storagefirst.SnapshotV4, online, signer guidedProfile, inspector transcript.Inspector) error {
	state, err := snapshot.State()
	if err != nil {
		return err
	}
	var closure *transcript.SignedArtifactRefs
	if phase == "phase1" {
		closure = state.Progress.Phase1Closure
	} else if phase == "phase2" {
		closure = state.Progress.Phase2Closure
	} else {
		return errors.New("unknown beacon phase")
	}
	if closure == nil {
		return errors.New("authenticated phase closure required before beacon retrieval")
	}
	journey, err := inspector.Journey()
	if err != nil {
		return fmt.Errorf("inspect signed closure timing: %w", err)
	}
	var phaseJourney *transcript.PhaseJourney
	for n := range journey.Phases {
		if journey.Phases[n].Phase == phase {
			phaseJourney = &journey.Phases[n]
		}
	}
	if phaseJourney == nil || !phaseJourney.Closed || phaseJourney.BeaconRound == 0 {
		return errors.New("proof-tool did not report a complete signed closure")
	}
	scheduled, err := time.Parse(time.RFC3339Nano, phaseJourney.BeaconScheduledAt)
	if err != nil {
		return errors.New("proof-tool reported an invalid beacon schedule")
	}
	now := time.Now().UTC()
	if now.Before(scheduled) {
		return fmt.Errorf("committed beacon round is not public yet; retry after %s UTC", scheduled.UTC().Format(time.RFC3339))
	}
	if err := ui.confirm(fmt.Sprintf("Download drand Quicknet round %d and let Proof-tool authenticate it against the signed closure", phaseJourney.BeaconRound), "RECORD "+strings.ToUpper(phase)+" BEACON"); err != nil {
		return err
	}
	responseDir := filepath.Join(online.Work, "workflow-v4", "beacons")
	if err := ensureWorkflowV4Directory(online.Work, responseDir); err != nil {
		return err
	}
	responsePath := filepath.Join(responseDir, fmt.Sprintf("%s-round-%d.json", phase, phaseJourney.BeaconRound))
	if err := fetchWorkflowV4QuicknetRound(phaseJourney.BeaconRound, responsePath); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	beaconRecord := filepath.Join(root, phase, "beacon", "record.json")
	beaconSignature := filepath.Join(root, phase, "beacon", "record.sig")
	if record, signature := regularPreparationFile(beaconRecord), regularPreparationFile(beaconSignature); record != signature {
		return errors.New("incomplete retained beacon record; preserve it for inspection")
	} else if !record {
		command, err := workflowV4BeaconCommand(online, signer, phase, *closure, responsePath, now)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	}
	rawResponse := filepath.Join(root, phase, "beacon", "raw-response.bin")
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", phase, "lifecycle", "beacon-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, phase+"-beacon-recorded", beaconRecord, beaconSignature, []string{rawResponse}, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, outputDir)
}

func fetchWorkflowV4QuicknetRound(round uint64, destination string) error {
	if round == 0 {
		return errors.New("beacon round must be positive")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("drand redirect refused") }}
	url := fmt.Sprintf("https://api.drand.sh/%s/public/%d", workflowV4QuicknetChainHash, round)
	response, err := client.Get(url) // #nosec G107 -- fixed HTTPS origin and validated integer round.
	if err != nil {
		return fmt.Errorf("download committed drand round: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("download committed drand round: HTTP %s", response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("drand response is empty or exceeds 1 MiB")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return setupWriteBytesNewOrExact(destination, raw, 0o600)
}

func workflowV4BeaconCommand(online, signer guidedProfile, phase string, closure transcript.SignedArtifactRefs, response string, publishedAt time.Time) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	closureRecord, _ := mapWork(filepath.Join(root, filepath.FromSlash(closure.Record.Name)))
	closureSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(closure.Signature.Name)))
	responsePath, err := mapWork(response)
	if err != nil {
		return nil, err
	}
	transcriptRoot, _ := mapWork(root)
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	command := []string{"mpc-ceremony", phase, "beacon", "--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--closure", closureRecord, "--closure-signature", closureSignature, "--raw-response", responsePath, "--published-at", publishedAt.UTC().Format(time.RFC3339Nano), "--coordinator-signing-key", "/keys/signing.hex", "--transcript-dir", transcriptRoot}
	return command, nil
}

func workflowV4CloseCommand(state transcript.CheckpointStateV4, online, signer guidedProfile, phase string, phaseState transcript.CheckpointPhaseState, lead uint32) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	transcriptRoot, _ := mapWork(root)
	chain, _ := mapWork(filepath.Join(root, filepath.FromSlash(phaseState.Chain.Record.Name)))
	chainSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(phaseState.Chain.Signature.Name)))
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	command := []string{"mpc-ceremony", phase, "close", "--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--transcript-dir", transcriptRoot, "--chain", chain, "--chain-signature", chainSignature, "--coordinator-signing-key", "/keys/signing.hex", "--beacon-round-lead", strconv.FormatUint(uint64(lead), 10)}
	if phase == "phase2" {
		if state.Progress.Phase1Seal == nil {
			return nil, errors.New("Phase 2 closure requires the authenticated Phase 1 seal")
		}
		seal, _ := mapWork(filepath.Join(root, filepath.FromSlash(state.Progress.Phase1Seal.Record.Name)))
		sealSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(state.Progress.Phase1Seal.Signature.Name)))
		command = append(command, "--phase1-seal", seal, "--phase1-seal-signature", sealSignature)
	}
	return command, nil
}

func workflowV4RecordCommand(snapshot storagefirst.SnapshotV4, online, signer guidedProfile, transition, record, signature string, evidence []string, outputDir string) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySignature, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	artifactRoot, _ := mapWork(root)
	headRecord, _ := mapWork(filepath.Join(root, filepath.FromSlash(snapshot.Head().Record.Name)))
	headSignature, _ := mapWork(filepath.Join(root, filepath.FromSlash(snapshot.Head().Signature.Name)))
	recordPath, err := mapWork(record)
	if err != nil {
		return nil, err
	}
	signaturePath, err := mapWork(signature)
	if err != nil {
		return nil, err
	}
	out, err := mapWork(outputDir)
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	command := []string{"mpc-ceremony", "checkpoint", "record-v4", "--ceremony", ceremony, "--ceremony-signature", ceremonySignature, "--coordinator-public-key-file", coordinatorKey, "--artifact-root", artifactRoot, "--checkpoint", headRecord, "--checkpoint-signature", headSignature, "--transition", transition, "--record", recordPath, "--record-signature", signaturePath}
	for _, path := range evidence {
		mapped, err := mapWork(path)
		if err != nil {
			return nil, err
		}
		command = append(command, "--evidence", mapped)
	}
	command = append(command, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", out)
	return command, nil
}

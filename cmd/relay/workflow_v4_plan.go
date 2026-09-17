package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

// prepareWorkflowV4Contribution freezes the completely verified public
// snapshot that proof-tool will authenticate again in the contributor process.
// It prepares no journal entry and starts no container.
func prepareWorkflowV4Contribution(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, binding workflowV4Binding, participant access.RoleConfig, now time.Time) (workflowV4OperationPlan, string, error) {
	var zero workflowV4OperationPlan
	if binding.Role != "participant" || participant.IdentityID != binding.IdentityID || now.IsZero() {
		return zero, "", errors.New("participant profile, identity and contribution time are required")
	}
	phase := participant.Phase
	view, err := snapshot.TurnV4(protocol, phase, binding.IdentityID)
	if err != nil {
		return zero, "", err
	}
	if view.Stage != storagefirst.TurnCandidateV4 || view.CandidateAttempt == nil {
		return zero, "", errors.New("authenticated ceremony state has no active candidate allocation for this participant")
	}
	id, err := randomID()
	if err != nil {
		return zero, "", err
	}
	inputRoot := filepath.Join(binding.Work, "workflow-v4", "inputs", id)
	if err := stageWorkflowV4Snapshot(binding.Work, participant.Root, inputRoot, snapshot.Files()); err != nil {
		return zero, "", err
	}
	stateView, err := snapshot.State()
	if err != nil {
		return zero, "", err
	}
	phaseState := stateView.Progress.Phase1
	if phase == "phase2" {
		if stateView.Progress.Phase2 == nil {
			return zero, "", errors.New("authenticated phase2 state is missing")
		}
		phaseState = *stateView.Progress.Phase2
	}
	allocation := snapshot.Head()
	if allocation.Record.Name == "" || allocation.Signature.Name == "" {
		return zero, "", errors.New("authenticated allocation checkpoint references are missing")
	}
	fullRefs := map[string]transcript.ArtifactRef{}
	add := func(ref transcript.ArtifactRef) { fullRefs[ref.Name] = ref }
	for _, ref := range []transcript.ArtifactRef{binding.Definition.Record, binding.Definition.Signature, phaseState.Chain.Record, phaseState.Chain.Signature, phaseState.HeadPayload, allocation.Record, allocation.Signature} {
		add(ref)
	}
	if phase == "phase2" {
		if stateView.Progress.Phase1Seal == nil {
			return zero, "", errors.New("phase2 contribution requires the authenticated phase1 seal")
		}
		add(stateView.Progress.Phase1Seal.Record)
		add(stateView.Progress.Phase1Seal.Signature)
	}
	// The signed allocation and its ancestry bind the complete frozen snapshot.
	// Retain only direct command/boundary references in the local journal; the
	// approved proof-tool walks and verifies every referenced artifact from
	// inputRoot in the same process immediately before it samples randomness.
	// Recording the whole growing history in every operation would make the
	// journal quadratic in the number of turns.
	snapshotRefs := make(map[string]state.ContentRef, len(snapshot.Files()))
	for _, ref := range snapshot.Files() {
		snapshotRefs[ref.Name] = ref
	}
	names := make([]string, 0, len(fullRefs))
	for name := range fullRefs {
		names = append(names, name)
	}
	slices.Sort(names)
	inputs := make([]workflowV4Input, 0, len(names)+2)
	for _, name := range names {
		artifact := fullRefs[name]
		ref, ok := snapshotRefs[name]
		if !ok || artifact.Digest.SHA256 != ref.SHA256 || artifact.Digest.Size != ref.Size {
			return zero, "", errors.New("verified snapshot reference differs from authenticated checkpoint state")
		}
		inputs = append(inputs, workflowV4Input{Path: filepath.Join(inputRoot, filepath.FromSlash(name)), Ref: artifact})
	}
	for _, local := range []struct {
		name string
		path string
	}{{"coordinator-public-key.hex", participant.CoordinatorKey}, {"environment.json", participant.Environment}} {
		ref, err := workflowV4LocalRef(local.name, local.path)
		if err != nil {
			return zero, "", err
		}
		inputs = append(inputs, workflowV4Input{Path: local.path, Ref: ref})
	}
	output := filepath.Join(participant.RunRoot, "candidates", fmt.Sprintf("%s-%02d-%s", phase, view.Scope.Index, view.CandidateAttempt.AttemptID))
	o := roleOpts{root: inputRoot, definition: filepath.Join(inputRoot, filepath.FromSlash(binding.Definition.Record.Name)), definitionSig: filepath.Join(inputRoot, filepath.FromSlash(binding.Definition.Signature.Name)), coordinatorKey: participant.CoordinatorKey, phase: phase, role: binding.IdentityID, signingKey: participant.SigningKey, envPath: participant.Environment, outDir: output, operationID: id, artifactRoot: inputRoot, checkpoint: filepath.Join(inputRoot, filepath.FromSlash(allocation.Record.Name)), checkpointSig: filepath.Join(inputRoot, filepath.FromSlash(allocation.Signature.Name)), attemptID: view.CandidateAttempt.AttemptID}
	if phase == "phase2" {
		o.phase1Seal = filepath.Join(inputRoot, filepath.FromSlash(stateView.Progress.Phase1Seal.Record.Name))
		o.phase1SealSig = filepath.Join(inputRoot, filepath.FromSlash(stateView.Progress.Phase1Seal.Signature.Name))
	}
	position := position{nextID: binding.IdentityID, nextIndex: int(view.Scope.Index), chainPath: filepath.Join(inputRoot, filepath.FromSlash(phaseState.Chain.Record.Name))}
	position.chain.ChainSignaturePath = filepath.Join(inputRoot, filepath.FromSlash(phaseState.Chain.Signature.Name))
	command := append([]string{"mpc-ceremony"}, contributionCommandArgs(o, position, now.UTC().Truncate(time.Second))...)
	for n, value := range command {
		if !filepath.IsAbs(value) {
			continue
		}
		command[n], err = workflowV4ContainerPath(binding.Runtimes["contributor"], value)
		if err != nil {
			return zero, "", err
		}
	}
	plan := workflowV4OperationPlan{ID: id, Kind: "contribute", Scope: view.Scope, Predecessor: phaseState.Chain, Allocation: allocation, AttemptID: view.CandidateAttempt.AttemptID, Runtime: binding.Runtimes["contributor"], Command: command, Inputs: inputs, Outputs: []string{output}}
	if err := validateWorkflowV4Plan(plan, binding); err != nil {
		return zero, "", err
	}
	scopePath := filepath.Join(binding.Work, "workflow-v4", "scopes", view.CandidateAttempt.AttemptID+".json")
	if err := writeWorkflowV4Scope(scopePath, view.Scope); err != nil {
		return zero, "", err
	}
	return plan, scopePath, nil
}

// prepareWorkflowV4Erasure binds cleanup signing to one reconciled
// contribution. It never asks proof-tool to generate contribution randomness.
func (j *workflowV4Journal) prepareWorkflowV4Erasure(contributionID, scopePath string, generated transcript.ComputationOutputFactsV4, destroyedAt time.Time) (workflowV4OperationPlan, error) {
	var zero workflowV4OperationPlan
	if j.lock == nil || j.writeErr != nil || destroyedAt.IsZero() {
		return zero, errors.New("active V4 workspace and cleanup confirmation time required")
	}
	var contribution *workflowV4Operation
	for n := range j.state.Operations {
		candidate := &j.state.Operations[n]
		if candidate.Plan.ID == contributionID {
			contribution = candidate
			break
		}
	}
	if contribution == nil || contribution.Status != "reconciled" || contribution.Plan.Kind != "contribute" {
		return zero, errors.New("reconciled contribution required before cleanup signing")
	}
	prior := contribution.Plan
	if generated.Scope != prior.Scope || generated.Predecessor != prior.Predecessor || len(generated.Files) != 3 {
		return zero, errors.New("verified computation output differs from the retained contribution")
	}
	for n, name := range []string{"attestation.json", "attestation.sig", "contribution.bin"} {
		if generated.Files[n].Name != name {
			return zero, errors.New("verified computation output has an unexpected inventory")
		}
	}
	var retainedScope transcript.ContributionScopeV4
	if err := readWorkflowV4JSON(scopePath, &retainedScope); err != nil || retainedScope != prior.Scope {
		return zero, errors.New("retained contribution scope differs from cleanup operation")
	}
	candidateDir := prior.Outputs[0]
	inputs := append([]workflowV4Input(nil), prior.Inputs...)
	for _, ref := range generated.Files {
		inputs = append(inputs, workflowV4Input{Path: filepath.Join(candidateDir, ref.Name), Ref: ref})
	}
	lifecycle, err := workflowV4LocalRef(dockerLifecycleLogName, filepath.Join(candidateDir, dockerLifecycleLogName))
	if err != nil {
		return zero, err
	}
	inputs = append(inputs, workflowV4Input{Path: filepath.Join(candidateDir, dockerLifecycleLogName), Ref: lifecycle})
	o, _, _, err := workflowV4ContributionOptions(prior)
	if err != nil {
		return zero, err
	}
	id, err := randomID()
	if err != nil {
		return zero, err
	}
	runtime := j.state.Marker.Binding.Runtimes["signer"]
	container := func(path string) (string, error) { return workflowV4ContainerPath(runtime, path) }
	definition, err := container(o.definition)
	if err != nil {
		return zero, err
	}
	definitionSig, err := container(o.definitionSig)
	if err != nil {
		return zero, err
	}
	coordinatorKey, err := container(o.coordinatorKey)
	if err != nil {
		return zero, err
	}
	candidateContainer, err := container(candidateDir)
	if err != nil {
		return zero, err
	}
	stamp := destroyedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	command := []string{"mpc-ceremony", prior.Scope.Phase, "attest-erasure", "--ceremony", definition, "--ceremony-signature", definitionSig, "--coordinator-public-key-file", coordinatorKey, "--participant-id", prior.Scope.ParticipantID, "--participant-signing-key", "/keys/signing.hex", "--candidate-dir", candidateContainer, "--destroyed-at", stamp}
	plan := workflowV4OperationPlan{ID: id, Kind: "attest-erasure", Scope: prior.Scope, Predecessor: prior.Predecessor, AttemptID: prior.AttemptID, Runtime: runtime, Command: command, Inputs: inputs, Outputs: []string{filepath.Join(candidateDir, "erasure.json"), filepath.Join(candidateDir, "erasure.sig")}}
	if err := validateWorkflowV4Plan(plan, j.state.Marker.Binding); err != nil {
		return zero, err
	}
	return plan, nil
}

func workflowV4LocalRef(name, path string) (transcript.ArtifactRef, error) {
	sha, blake, size, err := transcript.DigestFileBoth(path)
	if err != nil {
		return transcript.ArtifactRef{}, err
	}
	return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: sha, Blake2b256: blake, Size: size}}, nil
}

func writeWorkflowV4Scope(path string, scope transcript.ContributionScopeV4) error {
	raw, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	if err := ensureWorkflowV4Directory(filepath.Dir(filepath.Dir(filepath.Dir(path))), filepath.Dir(path)); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) != string(raw) {
			return errors.New("existing V4 scope file belongs to another turn")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func stageWorkflowV4Snapshot(workRoot, sourceRoot, destinationRoot string, refs []state.ContentRef) error {
	if len(refs) == 0 {
		return errors.New("authenticated V4 snapshot has no retained files")
	}
	if _, err := os.Lstat(destinationRoot); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fresh V4 contribution snapshot directory required")
	}
	parent := filepath.Dir(destinationRoot)
	if err := ensureWorkflowV4Directory(workRoot, parent); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".relay-v4-inputs-")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temporary)
		}
	}()
	for _, ref := range refs {
		source := filepath.Join(sourceRoot, filepath.FromSlash(ref.Name))
		destination := filepath.Join(temporary, filepath.FromSlash(ref.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, ref.Size+1))
		inputErr := input.Close()
		syncErr := output.Sync()
		outputErr := output.Close()
		if copyErr != nil || inputErr != nil || syncErr != nil || outputErr != nil {
			return errors.Join(copyErr, inputErr, syncErr, outputErr)
		}
		sha, size, err := transcript.DigestFile(destination)
		if err != nil || sha != ref.SHA256 || size != ref.Size {
			return errors.New("retained V4 snapshot file changed while freezing inputs")
		}
	}
	if err := os.Rename(temporary, destinationRoot); err != nil {
		return err
	}
	complete = true
	return syncDirectory(parent)
}

func ensureWorkflowV4Directory(root, target string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("V4 workspace directories must use absolute clean paths")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("V4 workspace directory escapes its root")
	}
	current := root
	for _, component := range append([]string{"."}, strings.Split(relative, string(filepath.Separator))...) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("V4 workspace path must contain only private real directories")
		}
	}
	return nil
}

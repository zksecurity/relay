package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

type workflowV4CoordinatorProgress struct {
	Local               storagefirst.LocalTurnV4
	GrantPath           string
	CandidateDir        string
	EnrollmentExpected  *transcript.ExpectedEnrollment
	EnrollmentGrant     *access.StorageFirstGrant
	EnrollmentGrantPath string
	EnrollmentDir       string
}

type workflowV4CoordinatorIntent struct {
	Schema      string                         `json:"schema"`
	Action      string                         `json:"action"`
	Scope       transcript.ContributionScopeV4 `json:"scope"`
	Predecessor transcript.SignedArtifactRefs  `json:"predecessor"`
	AttemptID   string                         `json:"attempt_id"`
	At          string                         `json:"at"`
	OutputDir   string                         `json:"output_dir"`
}

const workflowV4CoordinatorIntentSchema = "relay-workflow-v4-coordinator-intent-v1"

func workflowV4CoordinatorEnrollmentProgressFor(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, expected transcript.ExpectedEnrollment, binding workflowV4Binding, config access.StorageConfig, now time.Time) (workflowV4CoordinatorProgress, error) {
	progress := workflowV4CoordinatorProgress{EnrollmentExpected: &expected}
	base := filepath.Join(binding.Work, "workflow-v4", "coordinator", "enrollments", expected.Identity.ID)
	grantDir := filepath.Join(base, "grants")
	entries, err := os.ReadDir(grantDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return progress, err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(grantDir, entry.Name())
		grant, err := loadStorageFirstGrant(path)
		if err != nil {
			return progress, fmt.Errorf("read retained enrollment grant %s: %w", path, err)
		}
		if err := storagefirst.ValidateEnrollmentGrantV4At(snapshot, protocol, expected.Identity.ID, expected.Role, expected.RoleIndex, grant, destination, now); err != nil {
			continue
		}
		expires, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
		if progress.EnrollmentGrant == nil {
			copy := grant
			progress.EnrollmentGrant, progress.EnrollmentGrantPath = &copy, path
		} else {
			current, _ := time.Parse(time.RFC3339, progress.EnrollmentGrant.ExpiresAt)
			if expires.After(current) {
				copy := grant
				progress.EnrollmentGrant, progress.EnrollmentGrantPath = &copy, path
			}
		}
	}
	if progress.EnrollmentGrant != nil {
		progress.EnrollmentDir = filepath.Join(base, "received", progress.EnrollmentGrant.AttemptID)
	}
	return progress, nil
}

func workflowV4CoordinatorProgressFor(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, view storagefirst.TurnViewV4, binding workflowV4Binding, config access.StorageConfig, inspector transcript.Inspector, now time.Time) (workflowV4CoordinatorProgress, error) {
	progress := workflowV4CoordinatorProgress{Local: storagefirst.LocalTurnV4{Scope: view.Scope}}
	if view.Stage == storagefirst.TurnEnrollmentV4 {
		expected, err := workflowV4ExpectedEnrollment(protocol, view.Scope.ParticipantID)
		if err != nil {
			return progress, err
		}
		enrollment, err := workflowV4CoordinatorEnrollmentProgressFor(snapshot, protocol, expected, binding, config, now)
		enrollment.Local = progress.Local
		return enrollment, err
	}
	if view.CandidateAttempt == nil {
		return progress, nil
	}
	attempt := view.CandidateAttempt.AttemptID
	base := workflowV4CoordinatorTurnDir(binding.Work, view.Scope)
	grantDir := filepath.Join(base, "grants")
	progress.GrantPath = filepath.Join(grantDir, attempt+".json")
	entries, err := os.ReadDir(grantDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return progress, err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	maxRenewal := 0
	for _, entry := range entries {
		if entry.IsDir() || (entry.Name() != attempt+".json" && !strings.HasPrefix(entry.Name(), attempt+"-renewal-")) {
			continue
		}
		path := filepath.Join(grantDir, entry.Name())
		grant, err := loadStorageFirstGrant(path)
		if err != nil {
			return progress, fmt.Errorf("read retained grant %s: %w", path, err)
		}
		if err := storagefirst.ValidateGrantV4At(snapshot, protocol, view.Scope.ParticipantID, grant, destination, now); err == nil {
			expires, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
			if progress.Local.Grant == nil || expires.After(progress.Local.Grant.ExpiresAt) {
				progress.Local.Grant = &storagefirst.TurnGrantV4{AttemptID: grant.AttemptID, ExpiresAt: expires}
				progress.GrantPath = path
			}
		}
		if suffix, ok := strings.CutPrefix(strings.TrimSuffix(entry.Name(), ".json"), attempt+"-renewal-"); ok {
			if number, err := strconv.Atoi(suffix); err == nil && number > maxRenewal {
				maxRenewal = number
			}
		}
	}
	if progress.Local.Grant == nil {
		if _, err := os.Lstat(progress.GrantPath); err == nil {
			progress.GrantPath = filepath.Join(grantDir, fmt.Sprintf("%s-renewal-%02d.json", attempt, maxRenewal+1))
		} else if !errors.Is(err, os.ErrNotExist) {
			return progress, err
		}
	}
	progress.CandidateDir = filepath.Join(base, "candidates", attempt)
	if info, err := os.Lstat(progress.CandidateDir); err == nil {
		if !info.IsDir() {
			return progress, errors.New("retained candidate path is not a directory")
		}
		scopePath := filepath.Join(base, "scope.json")
		if err := writeWorkflowV4Scope(scopePath, view.Scope); err != nil {
			return progress, err
		}
		state, err := snapshot.State()
		if err != nil {
			return progress, err
		}
		phaseState := state.Progress.Phase1
		if view.Scope.Phase == "phase2" {
			if state.Progress.Phase2 == nil {
				return progress, errors.New("phase2 candidate has no authenticated phase state")
			}
			phaseState = *state.Progress.Phase2
		}
		chain := filepath.Join(inspector.TranscriptRoot, filepath.FromSlash(phaseState.Chain.Record.Name))
		signature := filepath.Join(inspector.TranscriptRoot, filepath.FromSlash(phaseState.Chain.Signature.Name))
		inventory, err := inspector.ContributionInventoryV4(chain, signature, scopePath, progress.CandidateDir, view.Scope, phaseState.Chain)
		if err != nil {
			return progress, fmt.Errorf("verify retained five-file candidate: %w", err)
		}
		progress.Local.CandidateInventory = &inventory
		progress.Local.ComputedCandidateID = inventory.ComputedCandidateID
		progress.Local.CandidateResultID = inventory.CandidateResultID
		progress.Local.CandidateReceivedAttemptID = attempt
	}
	return progress, nil
}

func workflowV4CoordinatorActionLabel(recommendation storagefirst.TurnRecommendationV4, progress workflowV4CoordinatorProgress) string {
	switch recommendation.Action {
	case "collect-participant-enrollment":
		if progress.EnrollmentGrant == nil {
			return "Create the participant's enrollment upload grant"
		}
		if !regularPreparationFile(filepath.Join(progress.EnrollmentDir, "enrollment.json")) {
			return "Check the private inbox for the participant's enrollment"
		}
		return "Verify and record the participant's enrollment"
	case "allocate-candidate-attempt", "allocate-replacement-attempt":
		return "Allocate the next candidate upload attempt"
	case "issue-candidate-grant":
		return "Create the participant's private upload grant"
	case "wait-for-candidate":
		return "Check the private inbox for this candidate"
	case "download-and-check-candidate":
		return "Download and verify the uploaded five-file candidate"
	case "verify-and-accept-candidate":
		return "Replay, verify and accept the exact candidate"
	}
	return ""
}

func runWorkflowV4CoordinatorAction(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, online, signer guidedProfile, inspector transcript.Inspector, recommendation storagefirst.TurnRecommendationV4, view storagefirst.TurnViewV4, progress workflowV4CoordinatorProgress) error {
	switch recommendation.Action {
	case "collect-participant-enrollment":
		return runWorkflowV4CoordinatorEnrollment(ui, snapshot, protocol, config, online, signer, inspector, view, progress)
	case "allocate-candidate-attempt", "allocate-replacement-attempt":
		return runWorkflowV4CoordinatorAllocation(ui, snapshot, online, signer, view)
	case "issue-candidate-grant":
		return runWorkflowV4CoordinatorGrant(ui, config, online, view, progress)
	case "wait-for-candidate", "download-and-check-candidate":
		return runWorkflowV4CoordinatorFetch(ui, config, online, snapshot, view, progress)
	case "verify-and-accept-candidate":
		return runWorkflowV4CoordinatorAcceptance(ui, snapshot, online, signer, view, progress)
	default:
		return fmt.Errorf("current signed state does not authorize a coordinator action: %s", recommendation.Reason)
	}
}

func runWorkflowV4CoordinatorAllocation(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, online, signer guidedProfile, view storagefirst.TurnViewV4) error {
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	intentPath := filepath.Join(workflowV4CoordinatorTurnDir(online.Work, view.Scope), "allocation-"+basis+"-intent.json")
	outputDir := workflowV4CoordinatorCheckpointDir(online.Work, view.Scope, "allocate", basis)
	intent, err := loadOrCreateWorkflowV4CoordinatorIntent(intentPath, "allocate", snapshot.Head(), view.Scope, "", outputDir)
	if err != nil {
		return err
	}
	if err := ui.confirm("Sign and publish one allocation for this exact participant and current transcript head", "ALLOCATE TURN"); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(intent.OutputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4CheckpointCommand(signer, online, snapshot.Head(), intent, "allocate-v4", "")
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, intent.OutputDir)
}

func runWorkflowV4CoordinatorGrant(ui *coordinatorWizard, config access.StorageConfig, online guidedProfile, view storagefirst.TurnViewV4, progress workflowV4CoordinatorProgress) error {
	if view.CandidateAttempt == nil || view.Commitment == nil {
		return errors.New("active authenticated allocation required")
	}
	var checkpointDigest string
	for _, allocation := range view.Commitment.Allocations {
		if allocation.AttemptID == view.CandidateAttempt.AttemptID {
			checkpointDigest = allocation.Checkpoint.Record.Digest.SHA256
		}
	}
	if checkpointDigest == "" {
		return errors.New("active attempt has no exact allocation checkpoint")
	}
	if err := os.MkdirAll(filepath.Dir(progress.GrantPath), 0o700); err != nil {
		return err
	}
	if err := ui.confirm("Create private upload access for only this participant and attempt", "CREATE GRANT"); err != nil {
		return err
	}
	storage, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
	out, _ := pathWithin(online.Work, progress.GrantPath, "/work")
	command := []string{"relay", "coordinator", "grant", "--storage", storage, "--role", access.RoleParticipant, "--identity", view.Scope.ParticipantID, "--credential-ttl", "1h", "--minimum-remaining", "15m", "--out", out, "--checkpoint-digest", checkpointDigest, "--submission-kind", access.SubmissionKindCandidate, "--phase", view.Scope.Phase, "--index", strconv.Itoa(int(view.Scope.Index)), "--attempt-id", view.CandidateAttempt.AttemptID}
	if err := runWorkflowV4ProfileCommand(online, command, true); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Give this private grant only to %s: %s\nIt is upload access, not a signing key.\n", view.Scope.ParticipantID, progress.GrantPath)
	return nil
}

func runWorkflowV4CoordinatorFetch(ui *coordinatorWizard, _ access.StorageConfig, online guidedProfile, snapshot storagefirst.SnapshotV4, view storagefirst.TurnViewV4, progress workflowV4CoordinatorProgress) error {
	if view.CandidateAttempt == nil {
		return errors.New("active candidate attempt required")
	}
	if _, err := os.Lstat(progress.CandidateDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ui.confirm("Check the private inbox and download this exact attempt if its manifest is present", "CHECK INBOX"); err != nil {
		return err
	}
	command, err := workflowV4OnlineBaseCommand(online, snapshot, "fetch-candidate-v4")
	if err != nil {
		return err
	}
	storage, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
	out, _ := pathWithin(online.Work, progress.CandidateDir, "/work")
	command = append(command, "--storage", storage, "--attempt-id", view.CandidateAttempt.AttemptID, "--out-dir", out)
	return runWorkflowV4ProfileCommand(online, command, true)
}

func runWorkflowV4CoordinatorAcceptance(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, online, signer guidedProfile, view storagefirst.TurnViewV4, progress workflowV4CoordinatorProgress) error {
	if view.CandidateAttempt == nil || progress.Local.CandidateInventory == nil {
		return errors.New("transport-checked and proof-tool-verified candidate required")
	}
	intentPath := filepath.Join(workflowV4CoordinatorTurnDir(online.Work, view.Scope), "acceptance-"+view.CandidateAttempt.AttemptID+"-intent.json")
	outputDir := workflowV4CoordinatorCheckpointDir(online.Work, view.Scope, "accept", view.CandidateAttempt.AttemptID)
	intent, err := loadOrCreateWorkflowV4CoordinatorIntent(intentPath, "accept", snapshot.Head(), view.Scope, view.CandidateAttempt.AttemptID, outputDir)
	if err != nil {
		return err
	}
	if err := ui.confirm("Replay the contribution mathematics, verify the exact five files and publish acceptance", "VERIFY AND ACCEPT"); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(intent.OutputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4CheckpointCommand(signer, online, snapshot.Head(), intent, "accept-candidate-v4", progress.CandidateDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return runWorkflowV4CommitCommand(online, intent.OutputDir)
}

func workflowV4CoordinatorTurnDir(work string, scope transcript.ContributionScopeV4) string {
	return filepath.Join(work, "workflow-v4", "coordinator", scope.Phase+"-"+fmt.Sprintf("%02d", scope.Index)+"-"+scope.ParticipantID)
}

func workflowV4CoordinatorCheckpointDir(work string, scope transcript.ContributionScopeV4, action, attempt string) string {
	name := action
	if attempt != "" {
		name += "-" + attempt
	}
	return filepath.Join(work, "ceremony", "public", "checkpoints", scope.Phase, fmt.Sprintf("%02d", scope.Index), name)
}

func loadOrCreateWorkflowV4CoordinatorIntent(path, action string, predecessor transcript.SignedArtifactRefs, scope transcript.ContributionScopeV4, attempt, outputDir string) (workflowV4CoordinatorIntent, error) {
	var intent workflowV4CoordinatorIntent
	if err := readWorkflowV4JSON(path, &intent); err == nil {
		if intent.Schema != workflowV4CoordinatorIntentSchema || intent.Action != action || intent.Scope != scope || intent.Predecessor != predecessor || intent.OutputDir != outputDir || (attempt != "" && intent.AttemptID != attempt) {
			return intent, errors.New("retained coordinator intent belongs to different authenticated state")
		}
		return intent, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return intent, err
	}
	if attempt == "" {
		var err error
		attempt, err = randomID()
		if err != nil {
			return intent, err
		}
	}
	stamp := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	intent = workflowV4CoordinatorIntent{Schema: workflowV4CoordinatorIntentSchema, Action: action, Scope: scope, Predecessor: predecessor, AttemptID: attempt, At: stamp, OutputDir: outputDir}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return intent, err
	}
	if err := os.MkdirAll(filepath.Dir(outputDir), 0o700); err != nil {
		return intent, err
	}
	if err := writeJSONNoReplace(path, intent, 0o600); err != nil {
		return intent, err
	}
	return intent, nil
}

func workflowV4CheckpointCommand(signer, online guidedProfile, head transcript.SignedArtifactRefs, intent workflowV4CoordinatorIntent, action, candidate string) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	paths := []string{filepath.Join(root, filepath.FromSlash(head.Record.Name)), filepath.Join(root, filepath.FromSlash(head.Signature.Name)), intent.OutputDir}
	if candidate != "" {
		paths = append(paths, candidate)
	}
	container := make([]string, len(paths))
	for n, path := range paths {
		mapped, err := pathWithin(signer.Work, path, "/work")
		if err != nil {
			return nil, err
		}
		container[n] = mapped
	}
	ceremony, _ := pathWithin(signer.Work, filepath.Join(root, "ceremony.json"), "/work")
	ceremonySig, _ := pathWithin(signer.Work, filepath.Join(root, "ceremony.sig"), "/work")
	coordinatorKey, _ := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	artifactRoot, _ := pathWithin(signer.Work, root, "/work")
	command := []string{"mpc-ceremony", "checkpoint", action, "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey, "--artifact-root", artifactRoot, "--checkpoint", container[0], "--checkpoint-signature", container[1], "--attempt-id", intent.AttemptID, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", container[2]}
	if action == "allocate-v4" {
		command = append(command, "--allocated-at", intent.At)
	} else {
		command = append(command, "--candidate-dir", container[3], "--accepted-at", intent.At)
	}
	return command, nil
}

func workflowV4OnlineBaseCommand(online guidedProfile, snapshot storagefirst.SnapshotV4, action string) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	head := snapshot.Head()
	values := []string{root, filepath.Join(root, filepath.FromSlash(head.Record.Name)), filepath.Join(root, filepath.FromSlash(head.Signature.Name)), filepath.Join(root, "ceremony.json"), filepath.Join(root, "ceremony.sig")}
	mapped := make([]string, len(values))
	for n, value := range values {
		var err error
		mapped[n], err = pathWithin(online.Work, value, "/work")
		if err != nil {
			return nil, err
		}
	}
	key, err := pathWithin(online.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"relay", "coordinator", action, "--artifact-root", mapped[0], "--checkpoint", mapped[1], "--checkpoint-signature", mapped[2], "--ceremony", mapped[3], "--ceremony-signature", mapped[4], "--coordinator-key", key}, nil
}

func runWorkflowV4CommitCommand(online guidedProfile, outputDir string) error {
	root := filepath.Join(online.Work, "ceremony", "public")
	checkpoint := filepath.Join(outputDir, "checkpoint.json")
	signature := filepath.Join(outputDir, "checkpoint.sig")
	values := []string{root, checkpoint, signature, filepath.Join(root, "ceremony.json"), filepath.Join(root, "ceremony.sig")}
	mapped := make([]string, len(values))
	for n, value := range values {
		var err error
		mapped[n], err = pathWithin(online.Work, value, "/work")
		if err != nil {
			return err
		}
	}
	key, err := pathWithin(online.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return err
	}
	command := []string{"relay", "coordinator", "commit-v4", "--artifact-root", mapped[0], "--checkpoint", mapped[1], "--checkpoint-signature", mapped[2], "--ceremony", mapped[3], "--ceremony-signature", mapped[4], "--coordinator-key", key}
	storage, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
	command = append(command, "--storage", storage)
	return runWorkflowV4ProfileCommand(online, command, true)
}

func runWorkflowV4ProfileCommand(profile guidedProfile, command []string, credentials bool) error {
	launch := []string{"role", "--role", profile.Role, "--image", profile.Image, "--platform", profile.Platform, "--work", profile.Work}
	for _, pair := range [][2]string{{"--trust", profile.Trust}, {"--keys", profile.Keys}} {
		if pair[1] != "" {
			launch = append(launch, pair[0], pair[1])
		}
	}
	if credentials {
		for _, pair := range [][2]string{{"--aws-credentials", profile.Credentials}, {"--r2-parent-credential", profile.R2Parent}, {"--r2-control-credential", profile.R2Control}} {
			if pair[1] != "" {
				launch = append(launch, pair[0], pair[1])
			}
		}
	}
	launch = append(launch, "--")
	launch = append(launch, command...)
	return executeGuidedChild(launch)
}

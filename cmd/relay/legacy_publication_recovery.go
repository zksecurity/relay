package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const expiredAWSRecoveryRelease = "1828c720da11a3f9a83ba905a6c3352b6ca06615"

var (
	legacyRecoveryLauncherCommit                   = launcherCommit
	legacyRecoveryInput                  io.Reader = os.Stdin
	legacyRecoveryOutput                 io.Writer = os.Stdout
	legacyRecoveryRemote                           = executeLegacyRemoteRecovery
	legacyRecoveryAfterCredentialRefresh           = func() error { return nil }
	legacyRecoverySave                             = saveJSONAtomic
	legacyRecoveryContextRoot                      = "/recovery"
	legacyRecoveryWorkRoot                         = "/work"
	legacyRecoveryTrustRoot                        = "/trust"
	legacyRecoveryStore                            = func(config access.StorageConfig) publicationStore {
		return coordinatorClient(config, config.PublishedBucket)
	}
)

func validateFrozenRecoveryProfile(p guidedProfile) error {
	if p.Schema != guidedSchema || p.Role != "coordinator" || p.ReleaseCommit != expiredAWSRecoveryRelease ||
		p.Name == "" || p.Image == "" || p.Platform == "" || p.Work == "" || p.Trust == "" || p.Keys == "" || p.Credentials == "" ||
		len(p.Command) != 0 || p.Config != "" || p.R2Parent != "" || p.R2Control != "" {
		return errors.New("saved profile is not the exact frozen 1828 coordinator runtime")
	}
	return nil
}

func retainedLegacyPublication(state roleFlowState) (*flowAttempt, error) {
	var found *flowAttempt
	for index := len(state.Attempts) - 1; index >= 0; index-- {
		a := &state.Attempts[index]
		if a.Stage == "storage" && a.Task == "publish" {
			found = a
			break
		}
	}
	if found == nil {
		return nil, errors.New("no retained storage-stage initial publication was found")
	}
	if found.OperationSchema != flowOperationSchema || found.RecoveryClass != recoveryPublication ||
		!strings.HasPrefix(found.ID, "flow-") || !validFlowAttemptID(strings.TrimPrefix(found.ID, "flow-")) {
		return nil, errors.New("retained publication metadata is not the recoverable 1828 operation schema")
	}
	if len(found.Command) != 10 || found.Command[0] != "relay" || found.Command[1] != "coordinator" || found.Command[2] != "publish" ||
		found.Command[3] != "--verify" || found.Command[4] != "--storage" || found.Command[6] != "--chain" || found.Command[8] != "--chain-signature" ||
		found.Command[5] != "/work/ceremony/config/relay-storage.json" || found.Command[7] != "/work/ceremony/public/phase1/chain-0000.json" || found.Command[9] != "/work/ceremony/public/phase1/chain-0000.sig" {
		return nil, errors.New("retained publication command is not the exact 1828 initial-head recipe")
	}
	wantBindings := map[string]bool{found.Command[5]: true, found.Command[7]: true, found.Command[9]: true}
	if len(wantBindings) != 3 || len(found.InputBindings) != len(wantBindings) {
		return nil, errors.New("retained publication does not bind the exact storage, chain and signature inputs")
	}
	for value := range wantBindings {
		if found.InputBindings[value] == "" {
			return nil, errors.New("retained publication is missing an input digest")
		}
	}
	return found, nil
}

func unresolvedLegacyPublication(state roleFlowState) (*flowAttempt, error) {
	found, err := retainedLegacyPublication(state)
	if err != nil {
		return nil, err
	}
	if found.Status != "running" && found.Status != "failed" {
		return nil, errors.New("the retained storage-stage publication is not failed or interrupted")
	}
	return found, nil
}

func validateFrozenRecoveryState(p guidedProfile, workflow roleFlowState) (*flowAttempt, error) {
	if err := validateFrozenRecoveryProfile(p); err != nil {
		return nil, err
	}
	if workflow.Schema != roleFlowSchema || workflow.Name != p.Name || workflow.Role != "coordinator" || !reflect.DeepEqual(workflow.Profile, p) {
		return nil, errors.New("retained workflow does not exactly match the frozen coordinator profile")
	}
	attempt, err := retainedLegacyPublication(workflow)
	if err != nil {
		return nil, err
	}
	if attempt.ImageDigest != p.Image || attempt.Platform != p.Platform {
		return nil, errors.New("retained publication names a different frozen runtime")
	}
	if len(attempt.Mounts) != 3 || attempt.Mounts["/work"] != p.Work || attempt.Mounts["/trust"] != p.Trust || attempt.Mounts["/keys"] != p.Keys ||
		len(attempt.ExpectedOutputs) != 0 || len(attempt.DirectoryBindings) != 0 || attempt.ReceiptScope != nil || attempt.TurnScope != nil {
		return nil, errors.New("retained publication runtime bindings are not the exact frozen coordinator profile")
	}
	return attempt, nil
}

func awsStorageUnchanged(configPath string, draft coordinatorDraft, f roleFlow) error {
	hostPath, err := f.publicHostPath(configPath)
	if err != nil {
		return err
	}
	config, err := loadStorageConfig(hostPath)
	if err != nil {
		return err
	}
	if config.Provider != "aws" || draft.Storage["provider"] != "aws" || draft.R2Parent != "" || draft.R2Control != "" {
		return errors.New("this hotfix supports AWS storage only; R2 credentials and settings are refused")
	}
	actual := map[string]string{
		"provider": config.Provider, "endpoint": config.Endpoint, "region": config.Region,
		"account-id": config.AccountID, "parent-access-key-id": config.ParentAccessKeyID,
		"published-bucket": config.PublishedBucket, "published-base-url": config.PublishedBaseURL,
		"inbox-bucket": config.InboxBucket, "profile": config.CoordinatorProfile,
		"issuer-profile": config.IssuerProfile, "grant-role-arn": config.GrantRoleARN,
		"grant-role-max-ttl": config.GrantRoleMaxTTL,
	}
	for field, value := range actual {
		if draft.Storage[field] != value {
			return fmt.Errorf("AWS storage field %q changed; only the credential snapshot may be refreshed", field)
		}
	}
	return nil
}

func validateFrozenRecoveryDraft(p guidedProfile, draft coordinatorDraft, credentialsRotated bool) error {
	if draft.Release != "role-images-"+expiredAWSRecoveryRelease || draft.Name != p.Name || draft.Work != p.Work || draft.Trust != p.Trust || draft.Keys != p.Keys ||
		draft.Credentials == "" || draft.R2Parent != "" || draft.R2Control != "" || draft.Storage["provider"] != "aws" {
		return errors.New("retained preparation differs from the frozen AWS coordinator profile")
	}
	if credentialsRotated && p.Credentials != draft.Credentials {
		return errors.New("refreshed credential reference is not checkpointed in the frozen profile")
	}
	return nil
}

func legacyRecoveryNote(attemptID, commit string) string {
	return "Recovered retained attempt " + strings.TrimPrefix(attemptID, "flow-") + " using compatible release " + commit + "."
}

func legacyRecoveryCompleted(workflow roleFlowState, attempt *flowAttempt) bool {
	if attempt == nil || attempt.Status != "succeeded" {
		return false
	}
	prefix := "Recovered retained attempt " + strings.TrimPrefix(attempt.ID, "flow-") + " using compatible release "
	for index := len(workflow.Attempts) - 1; index >= 0; index-- {
		event := workflow.Attempts[index]
		if event.Task == "publication-recovery" && event.Stage == attempt.Stage && event.Status == "succeeded" &&
			event.OperationSchema == flowOperationSchema && event.RecoveryClass == recoveryPublication && strings.HasPrefix(event.Note, prefix) && strings.HasSuffix(event.Note, ".") {
			commit := strings.TrimSuffix(strings.TrimPrefix(event.Note, prefix), ".")
			if launcherReleaseTag.MatchString("role-images-" + commit) {
				return true
			}
		}
	}
	return false
}

func markLegacyRecoveryComplete(workflow *roleFlowState, attemptID, commit, now string) error {
	var attempt *flowAttempt
	for index := range workflow.Attempts {
		if workflow.Attempts[index].ID == attemptID {
			attempt = &workflow.Attempts[index]
			attempt.Status = "succeeded"
			attempt.FinishedAt = now
			attempt.Note = "Reconciled by compatible release " + commit + "; all retained objects and the initial head were verified."
			break
		}
	}
	if attempt == nil {
		return errors.New("retained publication attempt disappeared before completion checkpoint")
	}
	eventID, err := randomID()
	if err != nil {
		return err
	}
	workflow.Attempts = append(workflow.Attempts, flowAttempt{ID: eventID, Task: "publication-recovery", Stage: attempt.Stage, Status: "succeeded", OperationSchema: flowOperationSchema, RecoveryClass: recoveryPublication, StartedAt: now, FinishedAt: now, Note: legacyRecoveryNote(attempt.ID, commit)})
	return nil
}

func persistLegacyRecoveryCompletion(path string, workflow roleFlowState, expectedProfile guidedProfile, attemptID string, save func(string, any) error) error {
	if err := save(path, workflow); err == nil {
		return nil
	} else {
		var retained roleFlowState
		if readErr := setupReadJSON(path, &retained); readErr == nil {
			attempt, validateErr := validateFrozenRecoveryState(expectedProfile, retained)
			if validateErr == nil && attempt.ID == attemptID && legacyRecoveryCompleted(retained, attempt) {
				return nil
			}
		}
		return fmt.Errorf("remote publication reconciled but local completion is not confirmed: %w", err)
	}
}

// runRecoverInitial1828 is reachable only inside the hotfix container. The
// host launcher mounts the locked, exact legacy profile and workflow read-only
// at /recovery; ordinary publish has no recovery switch.
func runRecoverInitial1828(args []string) error {
	set := flag.NewFlagSet("coordinator recover-initial-1828", flag.ContinueOnError)
	var attemptID string
	set.StringVar(&attemptID, "attempt-id", "", "exact retained guided-operation attempt")
	if err := set.Parse(args); err != nil {
		return err
	}
	if len(set.Args()) != 0 || !strings.HasPrefix(attemptID, "flow-") || !validFlowAttemptID(strings.TrimPrefix(attemptID, "flow-")) {
		return errors.New("--attempt-id must name the exact retained 1828 publication attempt")
	}
	profilePath := filepath.Join(legacyRecoveryContextRoot, "profile.json")
	var decoded guidedProfile
	if err := setupReadJSON(profilePath, &decoded); err != nil {
		return errors.New("the locked recovery profile is unavailable")
	}
	p, err := readGuidedProfile(profilePath, decoded.Name, "coordinator")
	if err != nil {
		return err
	}
	var workflow roleFlowState
	if err := setupReadJSON(filepath.Join(legacyRecoveryContextRoot, "workflow", "state.json"), &workflow); err != nil {
		return errors.New("the locked recovery workflow is unavailable")
	}
	attempt, err := validateFrozenRecoveryState(p, workflow)
	if err != nil {
		return err
	}
	if attempt.Status != "running" && attempt.Status != "failed" {
		return errors.New("mounted recovery attempt is not failed or interrupted")
	}
	if attempt.ID != attemptID {
		return errors.New("mounted recovery workflow does not contain the requested exact attempt")
	}
	for _, value := range []string{attempt.Command[5], attempt.Command[7], attempt.Command[9]} {
		local := filepath.Join(legacyRecoveryWorkRoot, strings.TrimPrefix(value, "/work/"))
		digest, err := setupFileHash(local)
		if err != nil || digest != attempt.InputBindings[value] {
			return fmt.Errorf("mounted retained input changed or is unavailable: %s", value)
		}
	}
	storagePath := filepath.Join(legacyRecoveryWorkRoot, strings.TrimPrefix(attempt.Command[5], "/work/"))
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	if config.Provider != "aws" || config.CeremonyPath != "/work/ceremony/public/ceremony.json" ||
		config.CeremonySignature != "/work/ceremony/public/ceremony.sig" || config.CoordinatorPublicKey != "/trust/coordinator-public-key.hex" {
		return errors.New("mounted recovery storage configuration is not the exact frozen AWS ceremony target")
	}
	workPath := func(value string) string {
		return filepath.Join(legacyRecoveryWorkRoot, strings.TrimPrefix(value, "/work/"))
	}
	trustPath := func(value string) string {
		return filepath.Join(legacyRecoveryTrustRoot, strings.TrimPrefix(value, "/trust/"))
	}
	o := roleOpts{root: workPath("/work/ceremony/public"), definition: workPath(config.CeremonyPath), definitionSig: workPath(config.CeremonySignature), phase: "phase1",
		coordinatorKey: trustPath(config.CoordinatorPublicKey), ceremonyBinary: config.CeremonyBinary, client: coordinatorClient(config, config.PublishedBucket)}
	if err := checkRole(o); err != nil {
		return err
	}
	return runWithProgress("reconciling retained authenticated publication", func() error {
		return recoverInitialPublicationWithStore(o, legacyRecoveryStore(config), workPath(attempt.Command[7]), workPath(attempt.Command[9]))
	})
}

func executeLegacyRemoteRecovery(p guidedProfile, draft coordinatorDraft, dir string, attempt *flowAttempt, commit string) error {
	tag := "role-images-" + commit
	image, _, err := verifiedReleaseImage(tag, "coordinator", p.Platform)
	if err != nil {
		return err
	}
	if err := prepareGuidedImage(image, p.Platform, "docker", true); err != nil {
		return err
	}
	command := []string{"relay", "coordinator", "recover-initial-1828", "--attempt-id", attempt.ID}
	options := p.options()
	options.image = image
	options.credentials = draft.Credentials
	options.recoveryContext = dir
	argv, err := dockerRoleArgs(options, command, os.Getuid(), os.Getgid())
	if err != nil {
		return err
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return err
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return err
	}
	fmt.Fprintln(legacyRecoveryOutput, "Reconciling the exact retained publication with create-only writes. Existing differing bytes will stop recovery.")
	if err := client.BindHost(endpoint).Attached(legacyRecoveryOutput, legacyRecoveryOutput, argv...); err != nil {
		return fmt.Errorf("retained publication was not reconciled: %w", err)
	}
	return nil
}

// runLegacyPublicationRecovery opens one deliberately narrow compatibility
// bridge. It never changes the frozen release, image, definition, command, or
// ceremony files in the old profile. The current image is used ephemerally to
// reconcile storage, after which the old workflow can resume.
func runLegacyPublicationRecovery(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony recover-publication NAME [--settings-root DIR]")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	set := flag.NewFlagSet("ceremony recover-publication", flag.ContinueOnError)
	set.StringVar(&root, "settings-root", root, "private saved-settings directory containing the retained workflow")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if len(set.Args()) != 0 {
		return errors.New("unexpected recovery arguments")
	}
	commit := legacyRecoveryLauncherCommit()
	if !launcherReleaseTag.MatchString("role-images-"+commit) || commit == expiredAWSRecoveryRelease {
		return errors.New("publication recovery requires an installed, attested hotfix launcher release")
	}
	dir, err := guidedDirectory(root, args[0], "coordinator")
	if err != nil {
		return err
	}
	profilePath := filepath.Join(dir, "profile.json")
	p, err := readGuidedProfile(profilePath, args[0], "coordinator")
	if err != nil {
		return err
	}
	if p.ReleaseCommit != expiredAWSRecoveryRelease {
		return fmt.Errorf("this recovery command only supports the affected release %s", expiredAWSRecoveryRelease)
	}
	draftPath := filepath.Join(p.Work, "coordinator-setup", "draft.json")
	var draft coordinatorDraft
	if err := setupReadJSON(draftPath, &draft); err != nil {
		return fmt.Errorf("load retained coordinator preparation: %w", err)
	}
	if err := validateFrozenRecoveryDraft(p, draft, false); err != nil {
		return err
	}
	statePath := filepath.Join(dir, "workflow", "state.json")
	var workflow roleFlowState
	if err := setupReadJSON(statePath, &workflow); err != nil {
		return fmt.Errorf("load retained workflow: %w", err)
	}
	attempt, err := validateFrozenRecoveryState(p, workflow)
	if err != nil {
		return err
	}
	f := roleFlow{state: workflow}
	if err := f.checkAttemptEvidence(attempt); err != nil {
		return fmt.Errorf("retained publication inputs are no longer exact: %w", err)
	}
	if err := awsStorageUnchanged(attempt.Command[5], draft, f); err != nil {
		return fmt.Errorf("validate unchanged AWS publication target: %w", err)
	}
	if legacyRecoveryCompleted(workflow, attempt) {
		fmt.Fprintln(legacyRecoveryOutput, "Recovery was already durably checkpointed. Resume the ceremony with its original 1828 start script.")
		return nil
	}
	if attempt.Status != "running" && attempt.Status != "failed" {
		return errors.New("the retained publication is not an unresolved recoverable attempt")
	}
	ui := coordinatorWizard{d: draft, draftPath: draftPath, input: bufio.NewReader(legacyRecoveryInput), output: legacyRecoveryOutput}
	fmt.Fprintf(legacyRecoveryOutput, "Recovering only retained attempt %s from release %s.\n", attempt.ID, expiredAWSRecoveryRelease)
	if err := ui.refreshWorkflowCredentialsExcept(dir, p, attempt.ID); err != nil {
		return fmt.Errorf("refresh only the credential-file reference: %w", err)
	}
	if err := legacyRecoveryAfterCredentialRefresh(); err != nil {
		return err
	}

	// Reload after the atomic credential checkpoint and then hold the workflow
	// lock through remote reconciliation and the final local checkpoint.
	p, err = readGuidedProfile(profilePath, args[0], "coordinator")
	if err != nil {
		return err
	}
	lock, err := acquireParticipantRunLock(statePath, filepath.Dir(statePath))
	if err != nil {
		return err
	}
	defer lock.release()
	if err := setupReadJSON(statePath, &workflow); err != nil {
		return err
	}
	var currentDraft coordinatorDraft
	if err := setupReadJSON(draftPath, &currentDraft); err != nil {
		return err
	}
	if !reflect.DeepEqual(currentDraft, draft) {
		return errors.New("coordinator preparation changed during credential rotation; stopped before remote recovery")
	}
	if err := validateFrozenRecoveryDraft(p, currentDraft, true); err != nil {
		return err
	}
	attempt, err = validateFrozenRecoveryState(p, workflow)
	if err != nil {
		return err
	}
	f = roleFlow{state: workflow}
	if err := f.checkAttemptEvidence(attempt); err != nil {
		return err
	}
	if err := awsStorageUnchanged(attempt.Command[5], currentDraft, f); err != nil {
		return fmt.Errorf("revalidate unchanged AWS publication target: %w", err)
	}
	if legacyRecoveryCompleted(workflow, attempt) {
		fmt.Fprintln(legacyRecoveryOutput, "Recovery was already durably checkpointed. Resume the ceremony with its original 1828 start script.")
		return nil
	}
	if attempt.Status != "running" && attempt.Status != "failed" {
		return errors.New("the retained publication changed state during credential rotation")
	}

	if err := legacyRecoveryRemote(p, currentDraft, dir, attempt, commit); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := markLegacyRecoveryComplete(&workflow, attempt.ID, commit, now); err != nil {
		return err
	}
	if err := persistLegacyRecoveryCompletion(statePath, workflow, p, attempt.ID, legacyRecoverySave); err != nil {
		return errors.Join(err, errors.New("preserve all files and rerun this command; it will verify whether the completion checkpoint landed"))
	}
	fmt.Fprintln(legacyRecoveryOutput, "Recovery complete. Resume the ceremony with its original 1828 start script; its signed definition and frozen runtime remain unchanged.")
	return nil
}

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const expiredAWSRecoveryRelease = "1828c720da11a3f9a83ba905a6c3352b6ca06615"

func unresolvedLegacyPublication(state roleFlowState) (*flowAttempt, error) {
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
	if found.Status != "running" && found.Status != "failed" {
		return nil, errors.New("the retained storage-stage publication is not failed or interrupted")
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
	commit := launcherCommit()
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
	if draft.Release != "role-images-"+expiredAWSRecoveryRelease || draft.Name != p.Name || draft.Work != p.Work || draft.Trust != p.Trust || draft.Keys != p.Keys {
		return errors.New("retained preparation and workflow differ; stopped without changing either")
	}
	if draft.Credentials == "" {
		return errors.New("no refreshed coordinator credential snapshot is saved; in coordinator preparation choose 6) Storage settings, then AWS and the same existing resources")
	}
	statePath := filepath.Join(dir, "workflow", "state.json")
	var workflow roleFlowState
	if err := setupReadJSON(statePath, &workflow); err != nil {
		return fmt.Errorf("load retained workflow: %w", err)
	}
	if workflow.Schema != roleFlowSchema || workflow.Name != p.Name || workflow.Role != "coordinator" || !sameProfileExceptCredentials(workflow.Profile, p) {
		return errors.New("retained workflow identity or immutable settings do not match the saved profile")
	}
	attempt, err := unresolvedLegacyPublication(workflow)
	if err != nil {
		return err
	}
	f := roleFlow{state: workflow}
	if err := f.checkAttemptEvidence(attempt); err != nil {
		return fmt.Errorf("retained publication inputs are no longer exact: %w", err)
	}
	if attempt.ImageDigest != p.Image {
		return errors.New("retained publication names a different frozen image")
	}
	if attempt.Platform != p.Platform {
		return errors.New("retained publication names a different frozen platform")
	}
	if len(attempt.Mounts) != 3 || attempt.Mounts["/work"] != p.Work || attempt.Mounts["/trust"] != p.Trust || attempt.Mounts["/keys"] != p.Keys ||
		len(attempt.ExpectedOutputs) != 0 || len(attempt.DirectoryBindings) != 0 || attempt.ReceiptScope != nil || attempt.TurnScope != nil {
		return errors.New("retained publication runtime bindings are not the exact frozen coordinator profile")
	}
	if err := awsStorageUnchanged(attempt.Command[5], draft, f); err != nil {
		return fmt.Errorf("validate unchanged AWS publication target: %w", err)
	}
	ui := coordinatorWizard{d: draft, draftPath: draftPath, input: bufio.NewReader(os.Stdin), output: os.Stdout}
	fmt.Printf("Recovering only retained attempt %s from release %s.\n", attempt.ID, expiredAWSRecoveryRelease)
	if err := ui.refreshWorkflowCredentialsExcept(dir, p, attempt.ID); err != nil {
		return fmt.Errorf("refresh only the credential-file reference: %w", err)
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
	attempt, err = unresolvedLegacyPublication(workflow)
	if err != nil {
		return err
	}
	f = roleFlow{state: workflow}
	if err := f.checkAttemptEvidence(attempt); err != nil {
		return err
	}

	tag := "role-images-" + commit
	image, _, err := verifiedReleaseImage(tag, "coordinator", p.Platform)
	if err != nil {
		return err
	}
	if err := prepareGuidedImage(image, p.Platform, "docker", true); err != nil {
		return err
	}
	command := append([]string(nil), attempt.Command...)
	command = append(command, "--recover-initial")
	options := p.options()
	options.image = image
	options.credentials = draft.Credentials
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
	fmt.Println("Reconciling the exact retained publication with create-only writes. Existing differing bytes will stop recovery.")
	if err := client.BindHost(endpoint).Attached(os.Stdout, os.Stderr, argv...); err != nil {
		return fmt.Errorf("retained publication was not reconciled: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for index := range workflow.Attempts {
		if workflow.Attempts[index].ID == attempt.ID {
			workflow.Attempts[index].Status = "succeeded"
			workflow.Attempts[index].FinishedAt = now
			workflow.Attempts[index].Note = "Reconciled by compatible release " + commit + "; all retained objects and the initial head were verified."
		}
	}
	eventID, err := randomID()
	if err != nil {
		return err
	}
	workflow.Attempts = append(workflow.Attempts, flowAttempt{ID: eventID, Task: "publication-recovery", Stage: attempt.Stage, Status: "succeeded", OperationSchema: flowOperationSchema, RecoveryClass: recoveryPublication, StartedAt: now, FinishedAt: now, Note: "Recovered retained attempt " + strings.TrimPrefix(attempt.ID, "flow-") + " using compatible release " + commit + "."})
	if err := saveJSONAtomic(statePath, workflow); err != nil {
		return errors.New("remote publication reconciled but the local checkpoint could not be saved; preserve all files and rerun this command to reconcile the checkpoint")
	}
	fmt.Println("Recovery complete. Resume the ceremony with its original 1828 start script; its signed definition and frozen runtime remain unchanged.")
	return nil
}

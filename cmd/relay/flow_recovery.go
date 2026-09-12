package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var flowAttemptIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validFlowAttemptID(value string) bool { return flowAttemptIDPattern.MatchString(value) }

func hasStableUploadIdentity(command []string) bool {
	attempt, completed := commandValue(command, "attempt-id"), commandValue(command, "completed-at")
	if !validFlowAttemptID(attempt) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, completed)
	if err != nil {
		return false
	}
	_, offset := parsed.Zone()
	return offset == 0
}

func prepareRecoveryCommand(task flowTask, command []string, operationID string, now time.Time) ([]string, error) {
	class := flowTaskRecoveryClass(task)
	if class != recoveryUpload && !(class == recoveryDocker && task.ID == "contribute") {
		return command, nil
	}
	attemptID := strings.TrimPrefix(operationID, "flow-")
	if !validFlowAttemptID(attemptID) {
		return nil, errors.New("cannot derive a stable operation attempt ID")
	}
	if class == recoveryDocker {
		return append(command, "--attempt-id", attemptID), nil
	}
	return append(command, "--attempt-id", attemptID, "--completed-at", now.UTC().Truncate(time.Second).Format(time.RFC3339)), nil
}

type flowRecoveryClass string

const (
	flowOperationSchema                    = "relay-guided-operation-v1"
	recoveryReadOnly     flowRecoveryClass = "read-only"
	recoveryCheckpoint   flowRecoveryClass = "local-checkpoint"
	recoveryLocalOutput  flowRecoveryClass = "local-output"
	recoveryDocker       flowRecoveryClass = "docker-lifecycle"
	recoveryGrant        flowRecoveryClass = "temporary-grant"
	recoveryUpload       flowRecoveryClass = "immutable-upload"
	recoveryPublication  flowRecoveryClass = "publication"
	recoveryDownload     flowRecoveryClass = "download"
	recoveryHumanHandoff flowRecoveryClass = "human-handoff"
	recoveryUnclassified flowRecoveryClass = ""
)

func (f *roleFlow) recoveryMetadata(task flowTask, command []string) (string, string, map[string]string, map[string]string, error) {
	image, platform := f.state.Profile.Image, f.state.Profile.Platform
	if task.Offline {
		// Unit/integration fixtures inject the executor directly and have no
		// launcher settings tree. Production role flows always set settingsRoot
		// and resolve the exact offline profile below.
		if f.settingsRoot == "" {
			return image, platform, nil, nil, nil
		}
		alias := offlineRoleAlias(f.state.Profile.Name, f.state.Profile.Role)
		dir, err := guidedDirectory(f.settingsRoot, alias, "decision-signer")
		if err != nil {
			return "", "", nil, nil, err
		}
		offline, err := readGuidedProfile(filepath.Join(dir, "profile.json"), alias, "decision-signer")
		if err != nil {
			return "", "", nil, nil, fmt.Errorf("load offline signing runtime: %w", err)
		}
		image, platform = offline.Image, offline.Platform
	} else if f.state.Role == "participant" {
		if configPath := commandValue(command, "config"); configPath != "" {
			config, err := loadRoleConfig(configPath, "participant")
			if err != nil {
				return "", "", nil, nil, err
			}
			image, platform = config.DockerImage, config.DockerPlatform
		}
	}
	mounts := map[string]string{}
	for container, host := range map[string]string{"/work": f.state.Profile.Work, "/trust": f.state.Profile.Trust, "/keys": f.state.Profile.Keys} {
		if host != "" {
			mounts[container] = host
		}
	}
	outputs := map[string]string{}
	for _, field := range task.Fields {
		if !flowOutputField(task, field) {
			continue
		}
		if value := commandValue(command, field.Flag); value != "" {
			outputs[field.Flag] = flowHostPath(f.state.Profile, value)
		}
	}
	if len(mounts) == 0 {
		mounts = nil
	}
	if len(outputs) == 0 {
		outputs = nil
	}
	return image, platform, mounts, outputs, nil
}

// flowTaskRecoveryClass is the closed V1 recovery registry for guided tasks.
// Adding a catalog task without a class fails tests rather than silently
// treating an unknown mutation as retryable.
func flowTaskRecoveryClass(task flowTask) flowRecoveryClass {
	if task.Handoff {
		return recoveryHumanHandoff
	}
	if len(task.Command) == 0 {
		return recoveryUnclassified
	}
	command := task.Command
	if command[0] == "status" {
		return recoveryCheckpoint
	}
	if command[0] == "run" {
		return recoveryDocker
	}
	if command[0] == "mpc-ceremony" {
		if len(command) >= 2 && command[1] == "inspect" {
			return recoveryReadOnly
		}
		if len(command) < 2 {
			return recoveryUnclassified
		}
		verb := command[1]
		if len(command) >= 3 {
			verb += " " + command[2]
		}
		switch verb {
		case "release verify", "ops verify", "decision verify":
			return recoveryReadOnly
		case "ops prepare-handoff", "ops prepare-receipt", "ops sign", "ops prepare-public-witness-receipt", "ops prepare-mirror-receipt", "ops prepare-bundle",
			"decision prepare", "decision sign", "phase1 close", "phase1 beacon", "phase1 seal", "phase2 close", "phase2 beacon", "phase2 init",
			"finalize prepare", "finalize rehearsal-evidence", "finalize complete", "release sign", "audit":
			return recoveryLocalOutput
		}
		return recoveryUnclassified
	}
	if command[0] != "relay" || len(command) < 3 {
		return recoveryUnclassified
	}
	switch command[1] + " " + command[2] {
	case "coordinator grant":
		return recoveryGrant
	case "coordinator accept", "coordinator publish":
		return recoveryPublication
	case "coordinator evidence":
		for _, field := range task.Fields {
			if field.Flag == "out-dir" {
				return recoveryDownload
			}
		}
		return recoveryReadOnly
	case "witness run", "mirror run", "auditor run":
		return recoveryDownload
	case "mirror receipt":
		return recoveryLocalOutput
	case "witness submit", "mirror submit", "auditor submit", "release submit":
		return recoveryUpload
	}
	return recoveryUnclassified
}

func (f *roleFlow) reconcilePrevious(task flowTask, previous *flowAttempt, savedRecipeErr error) ([]string, string, bool, error) {
	fmt.Fprintln(f.ui.output, "Checking the previous action…")
	class := flowTaskRecoveryClass(task)
	if class == recoveryUnclassified {
		return nil, "", false, errors.New("this action has no registered recovery rule; files are retained and Relay will not rerun it")
	}
	if class == recoveryGrant {
		deadline := "its provider-confirmed expiry is established"
		if started, startErr := time.Parse(time.RFC3339Nano, previous.StartedAt); startErr == nil {
			if ttl, ttlErr := time.ParseDuration(commandValue(previous.Command, "credential-ttl")); ttlErr == nil && ttl > 0 {
				deadline = started.Add(ttl+5*time.Minute).UTC().Format(time.RFC3339) + " (conservative local bound; provider confirmation is still required)"
			}
		}
		return nil, "", false, fmt.Errorf("a temporary grant may have been issued, but no complete protected grant file can be verified; it may remain valid until %s and Relay will not issue another automatically", deadline)
	}
	if class == recoveryDocker && f.state.Role == "participant" {
		return f.resumeParticipantCandidate(task, previous, savedRecipeErr)
	}
	if class != recoveryReadOnly && class != recoveryCheckpoint && class != recoveryUpload {
		return nil, "", false, fmt.Errorf("Relay cannot yet prove whether %q changed state after the interruption; its files are retained and the action will not be repeated", task.Label)
	}
	// Read-only inspection and authenticated local high-water checks are safe to
	// repeat. Immutable upload commands retain
	// their attempt ID and timestamp, use create-only object names, and verify
	// matching existing bytes before continuing to the manifest/notification.
	if savedRecipeErr != nil || len(previous.Command) == 0 {
		return nil, "", false, errors.New("the previous action recipe is incomplete or belongs to an older workflow; Relay will not reconstruct it implicitly")
	}
	if class == recoveryUpload && !hasStableUploadIdentity(previous.Command) {
		return nil, "", false, errors.New("the interrupted upload predates stable attempt IDs; Relay will not create a second remote submission automatically")
	}
	if err := f.checkAttemptEvidence(previous); err != nil {
		return nil, "", false, fmt.Errorf("the previous inspection inputs changed: %w", err)
	}
	if err := f.confirmAction(previous.Command); err != nil {
		return nil, "", false, err
	}
	return append([]string(nil), previous.Command...), previous.ID, true, nil
}

func replaceCommandValue(command []string, flag, value string) ([]string, error) {
	result := append([]string(nil), command...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == "--"+flag {
			result[index+1] = value
			return result, nil
		}
	}
	return nil, fmt.Errorf("saved command has no --%s field", flag)
}

func (f *roleFlow) resumeParticipantCandidate(task flowTask, previous *flowAttempt, savedRecipeErr error) ([]string, string, bool, error) {
	if savedRecipeErr != nil || len(previous.Command) == 0 {
		return nil, "", false, errors.New("the interrupted participant action belongs to an older workflow; Relay will not reconstruct it implicitly")
	}
	if err := f.checkAttemptEvidence(previous); err != nil {
		return nil, "", false, fmt.Errorf("the interrupted participant inputs changed: %w", err)
	}
	configPath := commandValue(previous.Command, "config")
	config, _, err := loadParticipantProfile(configPath)
	if err != nil {
		return nil, "", false, fmt.Errorf("load the retained participant profile: %w", err)
	}
	entries, err := os.ReadDir(config.CandidateParentDir)
	if err != nil {
		return nil, "", false, fmt.Errorf("inspect retained participant candidates: %w", err)
	}
	wantedAttempt := commandValue(previous.Command, "attempt-id")
	var candidate string
	for _, entry := range entries {
		if !entry.IsDir() || !validParticipantCandidateName(entry.Name(), config.Phase) {
			continue
		}
		if wantedAttempt != "" && !strings.HasSuffix(entry.Name(), "-"+wantedAttempt) {
			continue
		}
		path := filepath.Join(config.CandidateParentDir, entry.Name())
		if candidate != "" {
			return nil, "", false, errors.New("more than one retained candidate exists for this phase; Relay cannot choose between them")
		}
		candidate = path
	}
	if candidate == "" && wantedAttempt != "" {
		return nil, "", false, fmt.Errorf("the exact retained participant candidate for attempt %s is unavailable; Relay will not substitute or recompute another attempt", wantedAttempt)
	}
	if candidate == "" {
		return nil, "", false, errors.New("the participant action may have changed state, but no promoted candidate is available to resume; Relay will not recompute automatically")
	}
	accessPath, err := f.ui.required("Current Tessera connection or fresh role grant for uploading the retained candidate", commandValue(previous.Command, "grant"))
	if err != nil {
		return nil, "", false, err
	}
	command, err := replaceCommandValue(previous.Command, "grant", accessPath)
	if err != nil {
		return nil, "", false, err
	}
	if commandValue(command, "resume-candidate") == "" {
		insertAt := len(command)
		for index, value := range command {
			if value == "--attempt-id" {
				insertAt = index
				break
			}
		}
		command = append(command, "", "")
		copy(command[insertAt+2:], command[insertAt:len(command)-2])
		command[insertAt], command[insertAt+1] = "--resume-candidate", candidate
	} else if command, err = replaceCommandValue(command, "resume-candidate", candidate); err != nil {
		return nil, "", false, err
	}
	if err := validateFlowCommand(task, command); err != nil {
		return nil, "", false, err
	}
	f.ui.message(toneHeading, "Upload retained %s candidate\n", config.Phase)
	f.ui.message(toneMuted, "  %s\nThe contribution will not be recomputed. Relay reauthenticates its head, cleanup evidence and exact files before upload.\n", candidate)
	if err := f.confirmAction(command); err != nil {
		return nil, "", false, err
	}
	return command, previous.ID, true, nil
}

func validParticipantCandidateName(name, phase string) bool {
	prefix := phase + "-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := strings.TrimPrefix(name, prefix)
	if len(rest) != 4+1+32 || rest[4] != '-' || !validFlowAttemptID(rest[5:]) {
		return false
	}
	index, err := strconv.Atoi(rest[:4])
	return err == nil && index > 0
}

func (f *roleFlow) adoptWrittenGrant(task flowTask, previous *flowAttempt) (bool, error) {
	if flowTaskRecoveryClass(task) != recoveryGrant || (previous.Status != "running" && previous.Status != "failed") {
		return false, nil
	}
	out := previous.ExpectedOutputs["out"]
	if out == "" {
		return false, nil
	}
	info, err := os.Lstat(out)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("the retained grant output is not a safe regular file")
	}
	grant, err := loadGrant(out)
	if err != nil {
		return false, fmt.Errorf("the retained grant output is invalid: %w", err)
	}
	storagePath := flowHostPath(f.state.Profile, commandValue(previous.Command, "storage"))
	storage, err := loadStorageConfig(storagePath)
	if err != nil {
		return false, fmt.Errorf("authenticate the storage configuration for the retained grant: %w", err)
	}
	if grant.CeremonyID != storage.CeremonyID || grant.Provider != storage.Provider || grant.Endpoint != storage.Endpoint || grant.Region != storage.Region || grant.InboxBucket != storage.InboxBucket ||
		grant.Role != commandValue(previous.Command, "role") || grant.IdentityID != commandValue(previous.Command, "identity") {
		return false, errors.New("the retained grant does not match the saved ceremony, role, and identity")
	}
	ttl, ttlErr := time.ParseDuration(commandValue(previous.Command, "credential-ttl"))
	minimum, minimumErr := time.ParseDuration(commandValue(previous.Command, "minimum-remaining"))
	issued, issuedErr := time.Parse(time.RFC3339, grant.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, grant.ExpiresAt)
	started, startedErr := time.Parse(time.RFC3339Nano, previous.StartedAt)
	if ttlErr != nil || minimumErr != nil || issuedErr != nil || expiresErr != nil || startedErr != nil ||
		ttl <= 0 || minimum <= 0 || minimum > ttl || grant.MinimumRemaining != minimum.String() || issued.Before(started.UTC().Truncate(time.Second)) || expires.Sub(issued) > ttl {
		return false, errors.New("the retained grant timing does not match the saved issuance request")
	}
	previous.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if grant.CheckUsable(time.Now()) == nil {
		previous.Status = "succeeded"
		f.rememberSuccessfulOutputs(task, previous.Command)
		if err := f.save(); err != nil {
			return false, err
		}
		fmt.Fprintln(f.ui.output, "Verified the protected grant written by the previous action; no new credential was issued.")
		return true, nil
	}
	previous.Status = "expired"
	f.rememberSuccessfulOutputs(task, previous.Command)
	if err := f.save(); err != nil {
		return false, err
	}
	fmt.Fprintln(f.ui.output, "Verified that the previous action wrote a matching grant, but it no longer has the required time remaining. Review this action again to issue a fresh grant.")
	return true, nil
}

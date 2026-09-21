package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

func runWorkflowV4FinalReleaseLifecycle(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, online, signer guidedProfile) error {
	stateView, err := snapshot.State()
	if err != nil {
		return err
	}
	if stateView.Progress.ReleaseReview == nil || stateView.Progress.FinalRelease != nil {
		return errors.New("final release requires the current frozen review and no existing final release")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		return err
	}
	config, err := loadStorageConfig(filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"))
	if err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	releaseDir := filepath.Join(root, "final", "release")
	grantPath := ""
	if _, err := os.Lstat(releaseDir); errors.Is(err, os.ErrNotExist) {
		grant, retainedPath, err := workflowV4CurrentReleaseGrant(snapshot, protocol, config, online.Work, expected.Identity.ID, time.Now().UTC())
		if err != nil {
			return err
		}
		grantPath = retainedPath
		if grant == nil {
			return runWorkflowV4IssueReleaseGrant(ui, snapshot, config, online, expected)
		}
		received := filepath.Join(online.Work, "workflow-v4", "coordinator", "release", "received", grant.AttemptID)
		if _, err := os.Lstat(received); errors.Is(err, os.ErrNotExist) {
			if err := ui.confirm("Check the private inbox for the exact signed release package associated with the retained grant", "CHECK RELEASE INBOX"); err != nil {
				return err
			}
			storagePath, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
			out, _ := pathWithin(online.Work, received, "/work")
			command := []string{"relay", "coordinator", "fetch-release-v4", "--storage", storagePath, "--attempt-id", grant.AttemptID, "--out-dir", out}
			if err := runWorkflowV4ProfileCommand(online, command, true); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := ui.confirm("Authenticate the downloaded package against the signed release-signer assignment and frozen coordinator review, then record it", "VERIFY AND RECORD RELEASE"); err != nil {
			return err
		}
		if err := runWorkflowV4VerifyReleasePackage(online, received, expected.Identity.KeyID); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(releaseDir), 0o700); err != nil {
			return err
		}
		if err := os.Rename(received, releaseDir); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(releaseDir)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := runWorkflowV4VerifyReleasePackage(online, releaseDir, expected.Identity.KeyID); err != nil {
		return fmt.Errorf("verify retained release package: %w", err)
	}
	_, _, paths, err := workflowV4ReleaseFiles(releaseDir)
	if err != nil {
		return err
	}
	record := filepath.Join(releaseDir, "manifest.json")
	signature := filepath.Join(releaseDir, "manifest.sig")
	evidence, err := workflowV4FinalReleaseEvidence(paths)
	if err != nil {
		return err
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputDir := filepath.Join(root, "checkpoints", "final", "release-"+basis)
	if _, err := os.Lstat(filepath.Join(outputDir, "checkpoint.json")); errors.Is(err, os.ErrNotExist) {
		command, err := workflowV4RecordCommand(snapshot, online, signer, "final-release-recorded", record, signature, evidence, outputDir)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := runWorkflowV4CommitCommand(online, outputDir); err != nil {
		return err
	}
	if grantPath != "" {
		fmt.Fprintf(ui.output, "Final signed release checkpoint recorded. Retained private grant: %s. Public publication remains a separate action.\n", grantPath)
	} else {
		fmt.Fprintln(ui.output, "Final signed release checkpoint recorded. Public publication remains a separate action.")
	}
	return nil
}

func workflowV4FinalReleaseEvidence(paths map[string]string) ([]string, error) {
	names := []string{workflowV4ReleaseTranscriptFile, workflowV4ReleaseManifestPublicFile, workflowV4ReleaseChecksumsFile}
	evidence := make([]string, 0, len(names))
	for _, name := range names {
		path := paths[name]
		if path == "" {
			return nil, fmt.Errorf("verified release package lacks required checkpoint bootstrap %q", name)
		}
		evidence = append(evidence, path)
	}
	// Keep review output and generated commands deterministic.
	sort.Strings(evidence)
	return evidence, nil
}

func workflowV4ReleaseSignerAssignment(protocol transcript.DefinitionProtocol) (transcript.ExpectedEnrollment, error) {
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return transcript.ExpectedEnrollment{}, err
	}
	var result transcript.ExpectedEnrollment
	for _, expected := range journey.RequiredEnrollments {
		if expected.Role == "release-signer" {
			if result.Identity.ID != "" {
				return result, errors.New("signed definition has multiple release signers")
			}
			result = expected
		}
	}
	if result.Identity.ID == "" {
		return result, errors.New("signed definition has no release signer")
	}
	return result, nil
}

func workflowV4CurrentReleaseGrant(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, work, identity string, now time.Time) (*access.StorageFirstGrant, string, error) {
	grantDir := filepath.Join(work, "workflow-v4", "coordinator", "release", "grants")
	entries, err := os.ReadDir(grantDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	var selected *access.StorageFirstGrant
	selectedPath := ""
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(grantDir, entry.Name())
		grant, err := loadStorageFirstGrant(path)
		if err != nil {
			return nil, "", fmt.Errorf("read retained release grant %s: %w", path, err)
		}
		if err := storagefirst.ValidateReleaseGrantV4At(snapshot, protocol, identity, grant, destination, now); err != nil {
			continue
		}
		if selected == nil {
			copy := grant
			selected, selectedPath = &copy, path
		} else {
			current, _ := time.Parse(time.RFC3339, selected.ExpiresAt)
			candidate, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
			if candidate.After(current) {
				copy := grant
				selected, selectedPath = &copy, path
			}
		}
	}
	return selected, selectedPath, nil
}

func runWorkflowV4IssueReleaseGrant(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, config access.StorageConfig, online guidedProfile, expected transcript.ExpectedEnrollment) error {
	metadata, err := snapshot.Enrollments()
	if err != nil {
		return err
	}
	var enrollment *transcript.CommittedEnrollmentMetadataV4
	for n := range metadata.Enrollments {
		item := &metadata.Enrollments[n]
		if item.Enrollment.Role == "release-signer" && item.Enrollment.Identity.ID == expected.Identity.ID {
			enrollment = item
		}
	}
	if enrollment == nil {
		return errors.New("release signer enrollment is not committed in the current signed state")
	}
	attempt, err := randomID()
	if err != nil {
		return err
	}
	grantDir := filepath.Join(online.Work, "workflow-v4", "coordinator", "release", "grants")
	if err := os.MkdirAll(grantDir, 0o700); err != nil {
		return err
	}
	outPath := filepath.Join(grantDir, attempt+".json")
	if err := ui.confirm("Create private upload access for only the authenticated release signer and this frozen review checkpoint", "CREATE RELEASE GRANT"); err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	storagePath, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
	out, _ := pathWithin(online.Work, outPath, "/work")
	record, _ := pathWithin(online.Work, filepath.Join(root, filepath.FromSlash(enrollment.Refs.Record.Name)), "/work")
	signature, _ := pathWithin(online.Work, filepath.Join(root, filepath.FromSlash(enrollment.Refs.Signature.Name)), "/work")
	grantTTL, err := workflowV4GrantTTL(config)
	if err != nil {
		return err
	}
	command := []string{"relay", "coordinator", "grant", "--storage", storagePath, "--role", access.RoleRelease, "--identity", expected.Identity.ID, "--credential-ttl", grantTTL, "--minimum-remaining", "15m", "--enrollment", record, "--enrollment-signature", signature, "--out", out, "--checkpoint-digest", snapshot.Head().Record.Digest.SHA256, "--submission-kind", access.SubmissionKindRelease, "--phase", "release", "--index", strconv.Itoa(1), "--attempt-id", attempt}
	if err := runWorkflowV4ProfileCommand(online, command, true); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Give this private release upload grant only to %s: %s\nIt permits one immutable package upload and contains temporary storage credentials; it is not a signing key.\n", expected.Identity.ID, outPath)
	return nil
}

func runWorkflowV4VerifyReleasePackage(online guidedProfile, releaseDir, keyID string) error {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(online.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return err
	}
	ceremonySig, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	keys, err := mapWork(releaseDir)
	if err != nil {
		return err
	}
	publicKey, err := mapWork(filepath.Join(releaseDir, "manifest-public-key.hex"))
	if err != nil {
		return err
	}
	keyName := "setup-coordinator.hex"
	if online.Role == "release-signer" {
		keyName = "coordinator-public-key.hex"
	}
	coordinatorKey, err := pathWithin(online.Trust, filepath.Join(online.Trust, keyName), "/trust")
	if err != nil {
		return err
	}
	command := []string{"mpc-ceremony", "release", "verify", "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey, "--keys-dir", keys, "--manifest-public-key-file", publicKey, "--signature-key-id", keyID}
	return runWorkflowV4ProfileCommand(online, command, false)
}

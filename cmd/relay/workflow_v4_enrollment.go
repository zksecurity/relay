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
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

func workflowV4ExpectedEnrollment(protocol transcript.DefinitionProtocol, identity string) (transcript.ExpectedEnrollment, error) {
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return transcript.ExpectedEnrollment{}, err
	}
	var result transcript.ExpectedEnrollment
	for _, expected := range journey.RequiredEnrollments {
		if expected.Identity.ID == identity {
			if result.Identity.ID != "" {
				return result, errors.New("identity has multiple signed enrollment assignments")
			}
			result = expected
		}
	}
	if result.Identity.ID == "" {
		return result, errors.New("identity has no signed enrollment assignment")
	}
	return result, nil
}

func workflowV4NextRequiredEnrollment(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol) (*transcript.ExpectedEnrollment, error) {
	metadata, err := snapshot.Enrollments()
	if err != nil {
		return nil, err
	}
	committed := make(map[string]bool, len(metadata.Enrollments))
	for _, item := range metadata.Enrollments {
		committed[item.Enrollment.Identity.ID] = true
	}
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return nil, err
	}
	for _, expected := range journey.RequiredEnrollments {
		if !committed[expected.Identity.ID] {
			copy := expected
			return &copy, nil
		}
	}
	return nil, nil
}

func workflowV4EnrollmentCommitted(snapshot storagefirst.SnapshotV4, identity string) (bool, error) {
	metadata, err := snapshot.Enrollments()
	if err != nil {
		return false, err
	}
	for _, item := range metadata.Enrollments {
		if item.Enrollment.Identity.ID == identity {
			return true, nil
		}
	}
	return false, nil
}

func workflowV4GrantRoleForEnrollment(role string) (string, error) {
	switch role {
	case "participant":
		return access.RoleParticipant, nil
	case "release-signer":
		return access.RoleRelease, nil
	case "auditor":
		return access.RoleAuditor, nil
	case "public-witness":
		return access.RoleWitness, nil
	case "mirror-operator":
		return access.RoleMirror, nil
	default:
		return "", fmt.Errorf("role %q cannot receive an enrollment upload grant", role)
	}
}

func workflowV4LocalEnrollment(work, identity string, inspector transcript.Inspector, expected transcript.ExpectedEnrollment, ceremonyID string) (string, error) {
	base := filepath.Join(work, "my-enrollment")
	record := filepath.Join(base, "canonical.json")
	signature := filepath.Join(base, "enrollment.sig")
	disclosure := filepath.Join(base, "enrollments", identity, "disclosure.txt")
	inspection, err := inspector.Enrollment(record, signature)
	if err != nil {
		return "", fmt.Errorf("authenticate retained enrollment: %w", err)
	}
	if inspection.CeremonyID != ceremonyID || inspection.Identity != expected.Identity || inspection.Role != expected.Role || inspection.RoleIndex != expected.RoleIndex {
		return "", errors.New("retained enrollment differs from the signed assignment")
	}
	sha, size, err := transcript.DigestFile(disclosure)
	if err != nil {
		return "", err
	}
	if inspection.IndependenceDisclosure.Name != "enrollments/"+identity+"/disclosure.txt" || inspection.IndependenceDisclosure.Digest.SHA256 != sha || inspection.IndependenceDisclosure.Digest.Size != size {
		return "", errors.New("retained disclosure differs from the signed enrollment")
	}
	return base, nil
}

func runWorkflowV4OwnEnrollmentUpload(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, profile guidedProfile, config access.StorageConfig, inspector transcript.Inspector, identity setupIdentity) error {
	expected, err := workflowV4ExpectedEnrollment(protocol, identity.ID)
	if err != nil {
		return err
	}
	base, err := workflowV4LocalEnrollment(profile.Work, identity.ID, inspector, expected, protocol.Definition.CeremonyID)
	if err != nil {
		return err
	}
	grantPath, err := ui.required("Absolute path to the private enrollment upload grant received from the coordinator or Tessera", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(grantPath) || filepath.Clean(grantPath) != grantPath {
		return errors.New("private grant path must be absolute and clean")
	}
	grant, err := loadStorageFirstGrant(grantPath)
	if err != nil {
		return err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	if err := storagefirst.ValidateEnrollmentGrantV4At(snapshot, protocol, identity.ID, expected.Role, expected.RoleIndex, grant, destination, time.Now().UTC()); err != nil {
		return err
	}
	paths := map[string]string{
		"enrollment.json": filepath.Join(base, "canonical.json"),
		"enrollment.sig":  filepath.Join(base, "enrollment.sig"),
		"disclosure.txt":  filepath.Join(base, "enrollments", identity.ID, "disclosure.txt"),
	}
	sources := map[string]state.ContentRef{}
	for name, path := range paths {
		ref, err := workflowV4LocalRef(name, path)
		if err != nil {
			return err
		}
		sources[name] = state.ContentRef{Name: name, SHA256: ref.Digest.SHA256, Size: ref.Digest.Size}
	}
	temporary := filepath.Join(profile.Work, "workflow-v4", "temporary")
	if err := ensureWorkflowV4Directory(profile.Work, temporary); err != nil {
		return err
	}
	if err := ui.confirm("Upload only your signed public enrollment and disclosure; this does not upload your signing key", "UPLOAD ENROLLMENT"); err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: grant.CeremonyID, AttemptID: grant.AttemptID, Kind: access.SubmissionKindEnrollment}
	inventory := storagefirst.DeliveryInventory{"enrollment.json": 16 << 20, "enrollment.sig": 4096, "disclosure.txt": 1 << 20}
	if err := storagefirst.UploadDelivery(storageFirstGrantClient(grant), scope, inventory, sources, paths, temporary); err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "Enrollment upload completed. It remains pending until the coordinator verifies it and publishes a signed checkpoint that records it.")
	return nil
}

func runWorkflowV4ParticipantEnrollment(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, participant access.RoleConfig, config access.StorageConfig, inspector transcript.Inspector) error {
	expected, err := workflowV4ExpectedEnrollment(protocol, participant.IdentityID)
	if err != nil {
		return err
	}
	if expected.Role != "participant" {
		return errors.New("participant profile has a different signed enrollment role")
	}
	base := filepath.Join(filepath.Dir(participant.Root), "..", "my-enrollment")
	base = filepath.Clean(base)
	record := filepath.Join(base, "canonical.json")
	signature := filepath.Join(base, "enrollment.sig")
	disclosure := filepath.Join(base, "enrollments", participant.IdentityID, "disclosure.txt")
	inspection, err := inspector.Enrollment(record, signature)
	if err != nil {
		return fmt.Errorf("authenticate retained enrollment: %w", err)
	}
	if inspection.CeremonyID != protocol.Definition.CeremonyID || inspection.Identity != expected.Identity || inspection.Role != expected.Role || inspection.RoleIndex != expected.RoleIndex {
		return errors.New("retained enrollment differs from the signed assignment")
	}
	sha, size, err := transcript.DigestFile(disclosure)
	if err != nil {
		return err
	}
	if inspection.IndependenceDisclosure.Name != "enrollments/"+participant.IdentityID+"/disclosure.txt" || inspection.IndependenceDisclosure.Digest.SHA256 != sha || inspection.IndependenceDisclosure.Digest.Size != size {
		return errors.New("retained disclosure differs from the signed enrollment")
	}
	grantPath, err := ui.required("Absolute path to the private enrollment upload grant received from the coordinator or Tessera", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(grantPath) || filepath.Clean(grantPath) != grantPath {
		return errors.New("private grant path must be absolute and clean")
	}
	grant, err := loadStorageFirstGrant(grantPath)
	if err != nil {
		return err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	if err := storagefirst.ValidateEnrollmentGrantV4At(snapshot, protocol, participant.IdentityID, expected.Role, expected.RoleIndex, grant, destination, time.Now().UTC()); err != nil {
		return err
	}
	paths := map[string]string{"enrollment.json": record, "enrollment.sig": signature, "disclosure.txt": disclosure}
	sources := map[string]state.ContentRef{}
	for name, path := range paths {
		ref, err := workflowV4LocalRef(name, path)
		if err != nil {
			return err
		}
		sources[name] = state.ContentRef{Name: name, SHA256: ref.Digest.SHA256, Size: ref.Digest.Size}
	}
	temporary := filepath.Join(filepath.Dir(participant.Root), "..", "workflow-v4", "temporary")
	temporary = filepath.Clean(temporary)
	if err := ensureWorkflowV4Directory(filepath.Clean(filepath.Join(filepath.Dir(participant.Root), "..")), temporary); err != nil {
		return err
	}
	if err := ui.confirm("Upload only your signed public enrollment and disclosure; this does not upload your signing key", "UPLOAD ENROLLMENT"); err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: grant.CeremonyID, AttemptID: grant.AttemptID, Kind: access.SubmissionKindEnrollment}
	inventory := storagefirst.DeliveryInventory{"enrollment.json": 16 << 20, "enrollment.sig": 4096, "disclosure.txt": 1 << 20}
	if err := storagefirst.UploadDelivery(storageFirstGrantClient(grant), scope, inventory, sources, paths, temporary); err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "Enrollment upload completed. It remains pending until the coordinator verifies it and publishes a signed checkpoint that records it.")
	return nil
}

func runWorkflowV4CoordinatorEnrollment(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, online, signer guidedProfile, inspector transcript.Inspector, view storagefirst.TurnViewV4, progress workflowV4CoordinatorProgress) error {
	if progress.EnrollmentExpected == nil || progress.EnrollmentExpected.Identity.ID != view.Scope.ParticipantID {
		return errors.New("signed participant enrollment assignment is missing")
	}
	return runWorkflowV4CoordinatorExpectedEnrollment(ui, snapshot, protocol, config, online, signer, inspector, *progress.EnrollmentExpected, progress)
}

func runWorkflowV4CoordinatorExpectedEnrollment(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, online, signer guidedProfile, inspector transcript.Inspector, expected transcript.ExpectedEnrollment, progress workflowV4CoordinatorProgress) error {
	if progress.EnrollmentExpected == nil || *progress.EnrollmentExpected != expected {
		return errors.New("coordinator enrollment progress differs from the signed assignment")
	}
	if expected.Role == "coordinator" {
		base, err := workflowV4LocalEnrollment(online.Work, expected.Identity.ID, inspector, expected, protocol.Definition.CeremonyID)
		if err != nil {
			return err
		}
		if err := ui.confirm("Verify and record your coordinator enrollment from this protected workspace", "RECORD COORDINATOR ENROLLMENT"); err != nil {
			return err
		}
		return prepareAndCommitWorkflowV4Enrollment(snapshot, protocol, online, signer, expected, base)
	}
	if progress.EnrollmentGrant == nil {
		grantRole, err := workflowV4GrantRoleForEnrollment(expected.Role)
		if err != nil {
			return err
		}
		attempt, err := randomID()
		if err != nil {
			return err
		}
		grantDir := filepath.Join(online.Work, "workflow-v4", "coordinator", "enrollments", expected.Identity.ID, "grants")
		if err := os.MkdirAll(grantDir, 0o700); err != nil {
			return err
		}
		outPath := filepath.Join(grantDir, attempt+".json")
		if err := ui.confirm("Create private upload access for only this signed enrollment assignment", "CREATE ENROLLMENT GRANT"); err != nil {
			return err
		}
		storagePath, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
		out, _ := pathWithin(online.Work, outPath, "/work")
		grantTTL, err := workflowV4GrantTTL(config)
		if err != nil {
			return err
		}
		command := []string{"relay", "coordinator", "grant", "--storage", storagePath, "--role", grantRole, "--identity", expected.Identity.ID, "--credential-ttl", grantTTL, "--minimum-remaining", "15m", "--out", out, "--checkpoint-digest", snapshot.Head().Record.Digest.SHA256, "--submission-kind", access.SubmissionKindEnrollment, "--phase", "setup", "--index", strconv.Itoa(expected.RoleIndex), "--attempt-id", attempt}
		if err := runWorkflowV4ProfileCommand(online, command, true); err != nil {
			return err
		}
		fmt.Fprintf(ui.output, "Give this private enrollment grant only to %s: %s\nIt permits one immutable public-enrollment upload; it is not a signing key.\n", expected.Identity.ID, outPath)
		return nil
	}
	if !regularPreparationFile(filepath.Join(progress.EnrollmentDir, "enrollment.json")) {
		if err := ui.confirm("Check the private inbox for this exact enrollment attempt", "CHECK ENROLLMENT INBOX"); err != nil {
			return err
		}
		storagePath, _ := pathWithin(online.Work, filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"), "/work")
		out, _ := pathWithin(online.Work, progress.EnrollmentDir, "/work")
		command := []string{"relay", "coordinator", "fetch-enrollment-v4", "--storage", storagePath, "--attempt-id", progress.EnrollmentGrant.AttemptID, "--out-dir", out}
		return runWorkflowV4ProfileCommand(online, command, true)
	}
	receivedRecord := filepath.Join(progress.EnrollmentDir, "enrollment.json")
	receivedSignature := filepath.Join(progress.EnrollmentDir, "enrollment.sig")
	verified, err := inspector.Enrollment(receivedRecord, receivedSignature)
	if err != nil {
		return fmt.Errorf("authenticate downloaded enrollment: %w", err)
	}
	if verified.CeremonyID != protocol.Definition.CeremonyID || verified.Identity != expected.Identity || verified.Role != expected.Role || verified.RoleIndex != expected.RoleIndex {
		return errors.New("downloaded enrollment differs from the signed assignment")
	}
	if err := ui.confirm("Verify the signed enrollment and disclosure, then record them in the next signed ceremony update", "VERIFY AND RECORD ENROLLMENT"); err != nil {
		return err
	}
	return prepareAndCommitWorkflowV4Enrollment(snapshot, protocol, online, signer, expected, progress.EnrollmentDir)
}

func prepareAndCommitWorkflowV4Enrollment(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, online, signer guidedProfile, expected transcript.ExpectedEnrollment, received string) error {
	work := online.Work
	stagingParent := filepath.Join(work, "workflow-v4", "staging")
	if err := ensureWorkflowV4Directory(work, stagingParent); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(stagingParent, "enrollment-"+expected.Identity.ID+"-")
	if err != nil {
		return err
	}
	stage := filepath.Join(temporary, "artifacts")
	refs := snapshot.StructuralFiles()
	seen := map[string]bool{}
	for _, ref := range refs {
		seen[ref.Name] = true
	}
	for _, ref := range snapshot.Files() {
		if !seen[ref.Name] {
			refs = append(refs, ref)
			seen[ref.Name] = true
		}
	}
	publicRoot := filepath.Join(work, "ceremony", "public")
	if err := stageWorkflowV4Snapshot(work, publicRoot, stage, refs); err != nil {
		return err
	}
	enrollmentBase := filepath.Join("enrollments", expected.Identity.ID)
	sources, err := workflowV4EnrollmentSourcePaths(received, expected.Identity.ID)
	if err != nil {
		return err
	}
	logical := map[string]string{
		filepath.Join(enrollmentBase, "enrollment.json"): sources["enrollment.json"],
		filepath.Join(enrollmentBase, "enrollment.sig"):  sources["enrollment.sig"],
		filepath.Join(enrollmentBase, "disclosure.txt"):  sources["disclosure.txt"],
	}
	for name, source := range logical {
		limit := int64(16 << 20)
		if strings.HasSuffix(name, ".sig") {
			limit = 4096
		} else if strings.HasSuffix(name, "disclosure.txt") {
			limit = 1 << 20
		}
		raw, err := readTesseraRegularFile(source, limit, false)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(stage, name)), 0o700); err != nil {
			return err
		}
		if err := setupWriteBytesNewOrExact(filepath.Join(stage, name), raw, 0o600); err != nil {
			return err
		}
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outputRelative := filepath.Join("checkpoints", "enrollments", expected.Identity.ID, basis)
	output := filepath.Join(stage, outputRelative)
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	container := func(profile guidedProfile, path, mount string) (string, error) {
		return pathWithin(profile.Work, path, mount)
	}
	ceremony, err := container(signer, filepath.Join(stage, "ceremony.json"), "/work")
	if err != nil {
		return err
	}
	ceremonySig, _ := container(signer, filepath.Join(stage, "ceremony.sig"), "/work")
	artifactRoot, _ := container(signer, stage, "/work")
	headRecord, _ := container(signer, filepath.Join(stage, filepath.FromSlash(snapshot.Head().Record.Name)), "/work")
	headSignature, _ := container(signer, filepath.Join(stage, filepath.FromSlash(snapshot.Head().Signature.Name)), "/work")
	record, _ := container(signer, filepath.Join(stage, enrollmentBase, "enrollment.json"), "/work")
	signature, _ := container(signer, filepath.Join(stage, enrollmentBase, "enrollment.sig"), "/work")
	disclosure, _ := container(signer, filepath.Join(stage, enrollmentBase, "disclosure.txt"), "/work")
	out, _ := container(signer, output, "/work")
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(online.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return err
	}
	command := []string{"mpc-ceremony", "checkpoint", "record-v4", "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey, "--artifact-root", artifactRoot, "--checkpoint", headRecord, "--checkpoint-signature", headSignature, "--transition", "enrollment-recorded", "--record", record, "--record-signature", signature, "--evidence", disclosure, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", out}
	// This invocation owns a newly created staging attempt. At an older
	// workspace's migration boundary, retain the released allocation even
	// though this attempt has fresh output paths.
	limits, err := workflowV4LifecycleNewLimits(signer, snapshot.Head())
	if err != nil {
		return err
	}
	signer.Resources = &limits
	if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
		return err
	}
	for _, name := range []string{filepath.Join(enrollmentBase, "enrollment.json"), filepath.Join(enrollmentBase, "enrollment.sig"), filepath.Join(enrollmentBase, "disclosure.txt"), filepath.Join(outputRelative, "checkpoint.json"), filepath.Join(outputRelative, "checkpoint.sig")} {
		source := filepath.Join(stage, name)
		limit := int64(16 << 20)
		if strings.HasSuffix(name, ".sig") {
			limit = 4096
		} else if strings.HasSuffix(name, "disclosure.txt") {
			limit = 1 << 20
		}
		raw, err := readTesseraRegularFile(source, limit, false)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(publicRoot, name)), 0o700); err != nil {
			return err
		}
		if err := setupWriteBytesNewOrExact(filepath.Join(publicRoot, name), raw, 0o600); err != nil {
			return err
		}
	}
	return runWorkflowV4CommitCommand(online, filepath.Join(publicRoot, outputRelative))
}

// Local enrollment authoring uses proof-tool's canonical.json plus its nested
// disclosure path. Storage transport deliberately normalizes those public
// bytes to enrollment.json, enrollment.sig and disclosure.txt. Accept exactly
// one complete layout and never infer one file from a mixture of both.
func workflowV4EnrollmentSourcePaths(root, identity string) (map[string]string, error) {
	localRecord := filepath.Join(root, "canonical.json")
	transportRecord := filepath.Join(root, "enrollment.json")
	local := regularPreparationFile(localRecord)
	transport := regularPreparationFile(transportRecord)
	if local == transport {
		if local {
			return nil, errors.New("enrollment directory ambiguously contains local and transport record names")
		}
		return nil, errors.New("enrollment directory has no canonical or transported record")
	}
	if local {
		return map[string]string{
			"enrollment.json": localRecord,
			"enrollment.sig":  filepath.Join(root, "enrollment.sig"),
			"disclosure.txt":  filepath.Join(root, "enrollments", identity, "disclosure.txt"),
		}, nil
	}
	return map[string]string{
		"enrollment.json": transportRecord,
		"enrollment.sig":  filepath.Join(root, "enrollment.sig"),
		"disclosure.txt":  filepath.Join(root, "disclosure.txt"),
	}, nil
}

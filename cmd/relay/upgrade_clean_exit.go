package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/upgrade"
)

// Admission only: never call this when starting an already selected app or
// repairing its start script. Those operations must preserve ordinary recovery.
func upgradeRequireCleanExit(s upgradeSelectionV2, d upgrade.DeclarationV2, qualificationSchema string) error {
	if s.Setup == nil && d.Role == "release-signer" && d.OperatorSelected() && d.OnlineImage == "" {
		return upgradeRequireSignerCleanExit(s.Profile, d)
	}
	onlineReplacementAllowed := qualificationSchema == upgrade.OnlineCleanExitQualificationSchema || d.OperatorSelected()
	if s.Setup != nil || d.Role != "coordinator" || (!onlineReplacementAllowed && d.OnlineImage != d.OriginalImage) {
		return errors.New("this update supports only initialized coordinators with qualified online images")
	}
	p := s.Profile
	inv, err := upgradeV2Inventory(p, d)
	if err != nil {
		return err
	}
	activity, _, err := readAuditActivity(p.Work)
	if err != nil {
		return err
	}
	staleSignerImport := false
	for _, gap := range inv.HistoryGaps {
		if gap == "actions-without-recorded-completion" && upgradeOnlyPendingSignerEnrollmentImport(activity) {
			staleSignerImport = true
			continue
		}
		if gap == "partial-final-record" || gap == "actions-without-recorded-completion" {
			return errors.New("finish or resolve the interrupted action using your current Relay before updating")
		}
	}
	var journal workflowV4State
	if err := readWorkflowV4JSON(filepath.Join(p.Work, "workflow-v4/state.json"), &journal); err != nil {
		return err
	}
	for _, op := range journal.Operations {
		if !workflowV4OperationResolved(op.Status) {
			return fmt.Errorf("finish or resolve %s using your current Relay before updating", op.Plan.Kind)
		}
	}
	// Require an existing accepted-state anchor. Merely finding a signed proposal
	// is insufficient: it might never have been published. Opening an existing
	// anchor reads it; no synchronization or ceremony file writes occur here.
	id := journal.Marker.Binding.CeremonyID
	anchor := filepath.Join(p.Work, ".relay", strings.ReplaceAll(id, ":", "-"), "checkpoint-high-water.json")
	var seen state.CheckpointPosition
	var initialRoot *state.Root
	var recheck func() error
	if _, err := os.Lstat(anchor); errors.Is(err, os.ErrNotExist) {
		if !d.OperatorSelected() || d.SourceApp != d.OriginalRelease {
			return errors.New("open the current Relay and verify accepted ceremony progress before updating")
		}
		current, check, err := upgradeInitialPublishedRoot(p, id)
		if err != nil {
			return err
		}
		initialRoot, recheck = &current, check
		seen = state.CheckpointPosition{Sequence: 0, Digest: current.Checkpoint.SHA256}
	} else {
		if err != nil {
			return err
		}
		if !regularPreparationFile(anchor) {
			return errors.New("invalid accepted-state anchor")
		}
		water, err := state.OpenWorkspaceHighWater(p.Work, id)
		if err != nil {
			return err
		}
		var ok bool
		seen, ok, err = water.Seen()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no recorded accepted ceremony progress")
		}
	}
	root := filepath.Join(p.Work, "ceremony/public")
	var head string
	for _, f := range inv.Files {
		if strings.HasPrefix(f.Name, "ceremony/public/checkpoints/") && strings.HasSuffix(f.Name, "/checkpoint.json") && "sha256:"+f.SHA256 == seen.Digest {
			head = filepath.Join(p.Work, filepath.FromSlash(f.Name))
			break
		}
	}
	if head == "" {
		return errors.New("accepted checkpoint is missing; inspect it with your current Relay")
	}
	acceptedHead := head
	cli, err := exec.LookPath("docker")
	if err != nil {
		return err
	}
	driver := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: dockerCeremonyBinary, root: root, inspectionRoot: p.Work, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: filepath.Join(p.Trust, "setup-coordinator.hex"), client: osDockerCommandClient{binary: cli}}
	if err := driver.authenticateDaemon(); err != nil {
		return err
	}
	if err := upgradeCheckContainers(driver.client, p); err != nil {
		return err
	}
	inspector := driver.inspector()
	accepted := map[string]transcript.CheckpointInspectionV4{}
	files := map[string]transcript.ArtifactRef{}
	signature := filepath.Join(filepath.Dir(head), "checkpoint.sig")
	acceptedSignature := signature
	for count := 0; ; count++ {
		if count > transcript.MaxCheckpointSequenceV4 {
			return errors.New("checkpoint ancestry exceeds limit")
		}
		checked, err := inspector.StoredCheckpointV4(root, head, signature)
		if err != nil {
			return err
		}
		if checked.Checkpoint.CeremonyID != id {
			return errors.New("checkpoint belongs to another ceremony")
		}
		if count == 0 && (checked.CheckpointRefs.Record.Digest.SHA256 != seen.Digest || checked.Checkpoint.Sequence != seen.Sequence) {
			return errors.New("checkpoint differs from accepted-state anchor")
		}
		if count == 0 && initialRoot != nil {
			if err := upgradeMatchInitialRoot(*initialRoot, checked); err != nil {
				return err
			}
		}
		pair := checked.CheckpointRefs
		if _, exists := accepted[pair.Record.Name]; exists {
			return errors.New("cyclic checkpoint ancestry")
		}
		accepted[pair.Record.Name] = checked
		for _, ref := range []transcript.ArtifactRef{pair.Record, pair.Signature, checked.Checkpoint.Definition.Record, checked.Checkpoint.Definition.Signature} {
			files[ref.Name] = ref
		}
		refs, err := transcript.RequiredPublicArtifactsV4(checked)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			files[ref.Name] = ref
		}
		previous := checked.Checkpoint.PreviousCheckpoint
		if previous == nil {
			break
		}
		head = filepath.Join(root, filepath.FromSlash(previous.Record.Name))
		signature = filepath.Join(root, filepath.FromSlash(previous.Signature.Name))
	}
	if err := upgradeCheckCleanFiles(p, inv, accepted, files); err != nil {
		return err
	}
	if staleSignerImport {
		if err := upgradeCheckCommittedSignerEnrollment(inspector, root, acceptedHead, acceptedSignature, id, inv); err != nil {
			return fmt.Errorf("uncompleted signer enrollment activity is not covered by accepted progress: %w", err)
		}
	}
	if recheck != nil {
		return recheck()
	}
	return nil
}

// The activity log records a start before the signer-enrollment source prompt.
// Its missing completion cannot be called a success. It can, however, be
// carried forward as an explicit audit gap when this is the only pending local
// observation and the independently authenticated ceremony state is clean.
func upgradeOnlyPendingSignerEnrollmentImport(events []diagnosticEvent) bool {
	pending := map[string]diagnosticEvent{}
	seen := map[string]bool{}
	for _, event := range events {
		if event.OperationID == "" {
			continue
		}
		if event.Outcome == "started" {
			if seen[event.OperationID] {
				return false
			}
			seen[event.OperationID] = true
			pending[event.OperationID] = event
		} else {
			delete(pending, event.OperationID)
		}
	}
	if len(pending) != 1 {
		return false
	}
	for _, event := range pending {
		return event.Role == "coordinator" && event.Stage == "workflow-v4" && event.Action == "import-signer-enrollment"
	}
	return false
}

func upgradeCheckCommittedSignerEnrollment(inspector transcript.Inspector, root, head, signature, ceremonyID string, inv upgradeInventory) error {
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		return err
	}
	checkpoint, metadata, err := inspector.CheckpointGuidanceV4(root, head, signature)
	if err != nil {
		return err
	}
	if protocol.Definition.CeremonyID != ceremonyID || checkpoint.Checkpoint.CeremonyID != ceremonyID || metadata.Metadata.CeremonyID != ceremonyID {
		return errors.New("signed enrollment belongs to another ceremony")
	}
	expected, err := upgradeMatchCommittedSignerEnrollment(protocol, metadata)
	if err != nil {
		return err
	}
	return upgradeCheckSignerImportStaging(inv, expected.Identity.ID)
}

func upgradeMatchCommittedSignerEnrollment(protocol transcript.DefinitionProtocol, metadata transcript.EnrollmentMetadataInspectionV4) (transcript.ExpectedEnrollment, error) {
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		return expected, err
	}
	for _, item := range metadata.Metadata.Enrollments {
		enrollment := item.Enrollment
		base := filepath.Join("enrollments", expected.Identity.ID)
		if enrollment.Role == expected.Role && enrollment.RoleIndex == expected.RoleIndex && enrollment.Identity == expected.Identity &&
			item.Refs.Record.Name == filepath.Join(base, "enrollment.json") && item.Refs.Signature.Name == filepath.Join(base, "enrollment.sig") {
			return expected, nil
		}
	}
	return expected, errors.New("assigned release-signer enrollment is not in the accepted checkpoint")
}

// An import writes a fresh, never-reused staging directory and leaves it in
// place even after success. Keep those bytes in the inventory. In the narrow
// stale-activity case, any staged signer file must exactly match a public file
// already covered by the accepted checkpoint; an orphaned partial directory
// with no files is inert, but uncommitted or conflicting staged bytes block.
func upgradeCheckSignerImportStaging(inv upgradeInventory, identityID string) error {
	files := make(map[string]upgradeInventoryFile, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Name] = file
	}
	prefix := "workflow-v4/staging/enrollment-" + identityID + "-"
	for _, file := range inv.Files {
		if !strings.HasPrefix(file.Name, prefix) {
			continue
		}
		tail := strings.TrimPrefix(file.Name, prefix)
		marker := "/artifacts/"
		index := strings.Index(tail, marker)
		if index <= 0 || strings.Contains(tail[:index], "/") {
			return errors.New("unexpected retained signer enrollment staging file")
		}
		publicName := "ceremony/public/" + tail[index+len(marker):]
		public, ok := files[publicName]
		if !ok || public.SHA256 != file.SHA256 || public.Size != file.Size {
			return errors.New("signer enrollment staging file differs from accepted public output")
		}
	}
	return nil
}

// An offline signer has no coordinator high-water mark to replay. Require a
// normally closed local journal and complete activity history, then retain an
// exact inventory. The new launcher still uses the original signing image and
// authenticates the signed definition before the next signer operation.
func upgradeRequireSignerCleanExit(p guidedProfile, d upgrade.DeclarationV2) error {
	if p.Role != "release-signer" || d.Role != p.Role || d.OnlineImage != "" {
		return errors.New("signer update must retain the original signing runtime")
	}
	inv, err := upgradeV2Inventory(p, d)
	if err != nil {
		return err
	}
	if len(inv.Pending) != 0 {
		return errors.New("finish or resolve the release-signer action using the current Relay before updating")
	}
	for _, gap := range inv.HistoryGaps {
		if gap == "activity-log-missing" || gap == "partial-final-record" || gap == "actions-without-recorded-completion" {
			return errors.New("finish or resolve incomplete release-signer activity using the current Relay before updating")
		}
	}
	var journal workflowV4State
	if err := readWorkflowV4JSON(filepath.Join(p.Work, "workflow-v4/state.json"), &journal); err != nil {
		return fmt.Errorf("open release-signer journal before updating: %w", err)
	}
	if journal.Marker.Binding.Role != p.Role || journal.Marker.Binding.Work != p.Work || journal.Marker.Binding.Name != p.Name {
		return errors.New("release-signer journal belongs to another profile")
	}
	for _, op := range journal.Operations {
		if !workflowV4OperationResolved(op.Status) {
			return errors.New("finish or resolve the release-signer action using the current Relay before updating")
		}
	}
	return nil
}

func upgradeCheckCleanFiles(p guidedProfile, inv upgradeInventory, accepted map[string]transcript.CheckpointInspectionV4, public map[string]transcript.ArtifactRef) error {
	root := filepath.Join(p.Work, "ceremony/public")
	preliminary, err := upgradeCompletedPreliminaryFiles(inv, public)
	if err != nil {
		return err
	}
	unsignedDecision, err := upgradeLocalUnsignedDecisionFiles(p, inv)
	if err != nil {
		return err
	}
	for _, f := range inv.Files {
		path := filepath.Join(p.Work, filepath.FromSlash(f.Name))
		// Release grants and received release packages are cross-role handoffs.
		// Until a terminal release checkpoint covers them, they must be resolved
		// with the original runtime rather than carried into an application update.
		if strings.HasPrefix(f.Name, "workflow-v4/coordinator/release/") {
			return errors.New("release handoff is still retained; finish or resolve it with the original Relay before updating")
		}
		if strings.HasPrefix(f.Name, "ceremony/public/") {
			if preliminary[f.Name] || unsignedDecision[f.Name] {
				continue
			}
			name := strings.TrimPrefix(f.Name, "ceremony/public/")
			if name == "coordinator-public-key.hex" {
				if !upgradeSamePublicKey(path, filepath.Join(p.Trust, "setup-coordinator.hex")) {
					return errors.New("public coordinator key differs from trusted key")
				}
				continue
			}
			ref, ok := public[name]
			if !ok || ref.Digest.SHA256 != "sha256:"+f.SHA256 || ref.Digest.Size != f.Size {
				return fmt.Errorf("public output %s is not covered by recorded accepted progress; resolve it using current Relay", name)
			}
		}
		if strings.HasPrefix(f.Name, "workflow-v4/coordinator/") && strings.HasSuffix(f.Name, "-intent.json") {
			var intent workflowV4CoordinatorIntent
			if err := readWorkflowV4JSON(path, &intent); err != nil {
				return err
			}
			name, err := publicationNameV4(root, filepath.Join(intent.OutputDir, "checkpoint.json"))
			if err != nil {
				return err
			}
			child, ok := accepted[name]
			if !ok || child.Checkpoint.PreviousCheckpoint == nil || *child.Checkpoint.PreviousCheckpoint != intent.Predecessor {
				return errors.New("coordinator action has no matching accepted checkpoint; finish it before updating")
			}
			status := map[string]string{"allocate": "allocated", "accept": "accepted", "reject": "retired"}[intent.Action]
			matched := false
			for _, slot := range child.Checkpoint.Deliveries {
				if slot.Scope == intent.Scope && slot.AttemptID == intent.AttemptID && slot.Kind == "candidate" && slot.Status == status {
					matched = true
				}
			}
			if status == "" || !matched {
				return errors.New("retained coordinator action does not match accepted turn")
			}
		}
		if strings.HasPrefix(f.Name, "workflow-v4/commits/") && strings.HasSuffix(f.Name, ".json") {
			var record coordinatorCommitJournalRecord
			if err := readWorkflowV4JSON(path, &record); err != nil {
				return err
			}
			if err := record.validate(); err != nil {
				return err
			}
			if record.Stage != commitRootCASCommitted || record.AuthenticatedChild == nil {
				return errors.New("publication is unfinished or uncertain; resolve it using current Relay")
			}
			child, ok := accepted[record.AuthenticatedChild.Checkpoint.Name]
			if !ok || child.CheckpointRefs.Record.Digest.SHA256 != record.AuthenticatedChild.Checkpoint.SHA256 || child.CheckpointRefs.Signature.Digest.SHA256 != record.AuthenticatedChild.CheckpointSignature.SHA256 {
				return errors.New("completed publication does not match accepted history")
			}
		}
	}
	return nil
}

// Finalization leaves its preliminary key tree and public proof in the public
// workspace, but the accepted final candidate carries the authoritative copies.
// No later ceremony action reads the preliminary tree. Admit its fixed historical
// file set only after the keys and proof match the accepted candidate exactly;
// the remaining metadata/checksum files are retained as unused local history.
func upgradeCompletedPreliminaryFiles(inv upgradeInventory, public map[string]transcript.ArtifactRef) (map[string]bool, error) {
	const prefix = "ceremony/public/final/preliminary/"
	const evidence = "ceremony/public/final/public-finalization-evidence.json"
	files := map[string]upgradeInventoryFile{}
	var evidenceFile *upgradeInventoryFile
	for _, file := range inv.Files {
		if strings.HasPrefix(file.Name, prefix) {
			files[strings.TrimPrefix(file.Name, prefix)] = file
		} else if file.Name == evidence {
			copy := file
			evidenceFile = &copy
		}
	}
	if len(files) == 0 && evidenceFile == nil {
		return nil, nil
	}
	keys := []string{"ownership-destination.ccs", "ownership.pk", "ownership.vk", "cardano-vk.bin", "cardano-vk.hex", "cardano-vk-format.txt"}
	other := []string{"preliminary-final-keys.json", "preliminary-final-keys.sig.json", "preliminary-checksums.sha256"}
	if len(files) != len(keys)+len(other) {
		return nil, errors.New("preliminary final-key tree is incomplete or has unexpected files")
	}
	allowed := map[string]bool{}
	for _, name := range keys {
		file, ok := files[name]
		accepted, signed := public["final/candidate/"+name]
		if !ok || !signed || accepted.Digest.SHA256 != "sha256:"+file.SHA256 || accepted.Digest.Size != file.Size {
			return nil, fmt.Errorf("preliminary %s differs from the accepted final candidate", name)
		}
		allowed[prefix+name] = true
	}
	for _, name := range other {
		file, ok := files[name]
		if !ok || file.Size <= 0 || file.Size > 16<<20 {
			return nil, fmt.Errorf("preliminary %s is missing or oversized", name)
		}
		allowed[prefix+name] = true
	}
	acceptedEvidence, signed := public["final/candidate/public-finalization-evidence.json"]
	if evidenceFile == nil || !signed || acceptedEvidence.Digest.SHA256 != "sha256:"+evidenceFile.SHA256 || acceptedEvidence.Digest.Size != evidenceFile.Size {
		return nil, errors.New("preliminary public proof differs from the accepted final candidate")
	}
	allowed[evidence] = true
	return allowed, nil
}

func upgradeSamePublicKey(a, b string) bool {
	read := func(path string) ([]byte, error) {
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 256 {
			return nil, errors.New("invalid public key file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return nil, errors.New("invalid public key")
		}
		return key, nil
	}
	x, err := read(a)
	if err != nil {
		return false
	}
	y, err := read(b)
	return err == nil && bytes.Equal(x, y)
}

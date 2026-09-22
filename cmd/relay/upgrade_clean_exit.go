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
	onlineReplacementAllowed := qualificationSchema == upgrade.OnlineCleanExitQualificationSchema || d.OperatorSelected()
	if s.Setup != nil || d.Role != "coordinator" || (!onlineReplacementAllowed && d.OnlineImage != d.OriginalImage) {
		return errors.New("this update supports only initialized coordinators with qualified online images")
	}
	p := s.Profile
	inv, err := upgradeV2Inventory(p, d)
	if err != nil {
		return err
	}
	for _, gap := range inv.HistoryGaps {
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
	if recheck != nil {
		return recheck()
	}
	return nil
}

func upgradeCheckCleanFiles(p guidedProfile, inv upgradeInventory, accepted map[string]transcript.CheckpointInspectionV4, public map[string]transcript.ArtifactRef) error {
	root := filepath.Join(p.Work, "ceremony/public")
	for _, f := range inv.Files {
		path := filepath.Join(p.Work, filepath.FromSlash(f.Name))
		if strings.HasPrefix(f.Name, "ceremony/public/") {
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

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const workflowV4UploadRecordSchema = "relay-workflow-v4-upload-v1"

type workflowV4UploadRecord struct {
	Schema            string                         `json:"schema"`
	Scope             transcript.ContributionScopeV4 `json:"scope"`
	AttemptID         string                         `json:"attempt_id"`
	CandidateResultID string                         `json:"candidate_result_id"`
	ManifestKey       string                         `json:"manifest_key"`
	UploadedAt        string                         `json:"uploaded_at"`
}

func workflowV4CandidateDeliveryInventory() storagefirst.DeliveryInventory {
	return storagefirst.DeliveryInventory{"attestation.json": 16 << 20, "attestation.sig": 4096, "contribution.bin": 16 << 30, "erasure.json": 16 << 20, "erasure.sig": 4096}
}

func workflowV4CandidateFiles(candidateDir string, inventory transcript.ContributionInventoryFactsV4) (map[string]state.ContentRef, map[string]string, error) {
	if inventory.Complete == nil || inventory.CandidateResultID == "" || inventory.ComputedCandidateID == "" || inventory.ComputedCandidateID != inventory.CandidateResultID || inventory.Scope != inventory.Complete.Scope || len(inventory.Complete.Files) != 5 {
		return nil, nil, errors.New("complete verified five-file candidate inventory required")
	}
	limits := workflowV4CandidateDeliveryInventory()
	sources := make(map[string]state.ContentRef, len(limits))
	paths := make(map[string]string, len(limits))
	for _, ref := range inventory.Complete.Files {
		limit, ok := limits[ref.Name]
		if !ok || ref.Digest.Size <= 0 || ref.Digest.Size > limit || ref.Digest.SHA256 == "" || ref.Digest.Blake2b256 == "" {
			return nil, nil, errors.New("verified candidate inventory contains an unexpected file")
		}
		if _, duplicate := sources[ref.Name]; duplicate {
			return nil, nil, errors.New("verified candidate inventory repeats a file")
		}
		sources[ref.Name] = state.ContentRef{Name: ref.Name, SHA256: ref.Digest.SHA256, Size: ref.Digest.Size}
		paths[ref.Name] = filepath.Join(candidateDir, ref.Name)
	}
	if len(sources) != len(limits) {
		return nil, nil, errors.New("verified candidate inventory is incomplete")
	}
	return sources, paths, nil
}

func workflowV4CandidateDir(plan workflowV4OperationPlan) (string, error) {
	for _, input := range plan.Inputs {
		if input.Ref.Name == "contribution.bin" {
			return filepath.Dir(input.Path), nil
		}
	}
	return "", errors.New("retained upload plan has no candidate directory")
}

func (j *workflowV4Journal) prepareWorkflowV4Upload(cleanupID, activeAttemptID string, inventory transcript.ContributionInventoryFactsV4) (workflowV4OperationPlan, error) {
	var zero workflowV4OperationPlan
	if j.lock == nil || j.writeErr != nil {
		return zero, errors.New("active V4 workspace required")
	}
	var cleanup *workflowV4Operation
	for n := range j.state.Operations {
		if j.state.Operations[n].Plan.ID == cleanupID {
			cleanup = &j.state.Operations[n]
			break
		}
	}
	if cleanup == nil || cleanup.Status != "reconciled" || cleanup.Plan.Kind != "attest-erasure" || inventory.Scope != cleanup.Plan.Scope || inventory.Predecessor != cleanup.Plan.Predecessor {
		return zero, errors.New("reconciled cleanup and matching verified candidate inventory required")
	}
	if !validFlowAttemptID(activeAttemptID) {
		return zero, errors.New("active authenticated candidate attempt required")
	}
	if activeAttemptID != cleanup.Plan.AttemptID {
		return zero, errors.New("retained candidate belongs to a retired allocation; make a fresh contribution for the replacement attempt")
	}
	candidateDir := filepath.Dir(cleanup.Plan.Outputs[0])
	sources, paths, err := workflowV4CandidateFiles(candidateDir, inventory)
	if err != nil {
		return zero, err
	}
	inputs := make([]workflowV4Input, 0, 7)
	for _, input := range cleanup.Plan.Inputs {
		if input.Ref == cleanup.Plan.Predecessor.Record || input.Ref == cleanup.Plan.Predecessor.Signature {
			inputs = append(inputs, input)
		}
	}
	for _, ref := range inventory.Complete.Files {
		content := sources[ref.Name]
		if ref.Digest.SHA256 != content.SHA256 || ref.Digest.Size != content.Size || ref.Digest.Blake2b256 == "" {
			return zero, errors.New("verified candidate inventory digest differs from upload source")
		}
		inputs = append(inputs, workflowV4Input{Path: paths[ref.Name], Ref: ref})
	}
	id, err := randomID()
	if err != nil {
		return zero, err
	}
	marker := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "results", id+".json")
	// The candidate was computed under this exact allocation. A replacement
	// allocation must produce a fresh candidate because proof-tool verifies that
	// allocation predates its contribution.
	plan := workflowV4OperationPlan{ID: id, Kind: "upload-candidate", Scope: cleanup.Plan.Scope, Predecessor: cleanup.Plan.Predecessor, AttemptID: activeAttemptID, Runtime: j.state.Marker.Binding.Runtimes["online"], Command: []string{"relay-internal", "upload-candidate"}, Inputs: inputs, Outputs: []string{marker}}
	if err := validateWorkflowV4Plan(plan, j.state.Marker.Binding); err != nil {
		return zero, err
	}
	return plan, nil
}

func (j *workflowV4Journal) executePreparedCandidateUpload(id string, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, grant access.StorageFirstGrant, destination storagefirst.GrantDestination, inventory transcript.ContributionInventoryFactsV4, now time.Time) error {
	op, err := j.pending()
	if err != nil {
		return err
	}
	if op == nil || op.Plan.ID != id || op.Plan.Kind != "upload-candidate" || op.Status != "prepared" || inventory.Scope != op.Plan.Scope || inventory.Predecessor != op.Plan.Predecessor || inventory.CandidateResultID == "" {
		return errors.New("prepared candidate upload and verified inventory required")
	}
	if err := storagefirst.ValidateGrantV4At(snapshot, protocol, j.state.Marker.Binding.IdentityID, grant, destination, now); err != nil {
		return err
	}
	if grant.AttemptID != op.Plan.AttemptID {
		return errors.New("upload grant differs from the retained candidate attempt")
	}
	candidateDir, err := workflowV4CandidateDir(op.Plan)
	if err != nil {
		return err
	}
	sources, paths, err := workflowV4CandidateFiles(candidateDir, inventory)
	if err != nil {
		return err
	}
	temporary := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "temporary")
	if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, temporary); err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: op.Plan.Scope.CeremonyID, AttemptID: op.Plan.AttemptID, Kind: access.SubmissionKindCandidate}
	return j.runPrepared(id, func(plan workflowV4OperationPlan) error {
		return j.uploadCandidatePlan(plan, storageFirstGrantClient(grant), scope, sources, paths, inventory.CandidateResultID, grant.ManifestKey, temporary, now)
	})
}

// resumeCandidateUpload is the only running operation that may repeat a remote
// mutation. Candidate objects are immutable create-only writes; every existing
// object is compared with the retained bytes and the manifest is always last.
// Contribution and signing operations deliberately have no equivalent retry.
func (j *workflowV4Journal) resumeCandidateUpload(id string, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, grant access.StorageFirstGrant, destination storagefirst.GrantDestination, inventory transcript.ContributionInventoryFactsV4, now time.Time) error {
	op, err := j.pending()
	if err != nil {
		return err
	}
	if op == nil || op.Plan.ID != id || op.Plan.Kind != "upload-candidate" || op.Status != "running" || inventory.Scope != op.Plan.Scope || inventory.Predecessor != op.Plan.Predecessor || inventory.CandidateResultID == "" {
		return errors.New("uncertain exact candidate upload and verified inventory required")
	}
	if err := storagefirst.ValidateGrantV4At(snapshot, protocol, j.state.Marker.Binding.IdentityID, grant, destination, now); err != nil {
		return err
	}
	if grant.AttemptID != op.Plan.AttemptID {
		return errors.New("replacement grant differs from the retained upload attempt")
	}
	candidateDir, err := workflowV4CandidateDir(op.Plan)
	if err != nil {
		return err
	}
	sources, paths, err := workflowV4CandidateFiles(candidateDir, inventory)
	if err != nil {
		return err
	}
	if err := workflowV4InputsMatch(op.Plan); err != nil {
		return err
	}
	temporary := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "temporary")
	if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, temporary); err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: op.Plan.Scope.CeremonyID, AttemptID: op.Plan.AttemptID, Kind: access.SubmissionKindCandidate}
	if err := j.uploadCandidatePlan(op.Plan, storageFirstGrantClient(grant), scope, sources, paths, inventory.CandidateResultID, grant.ManifestKey, temporary, now); err != nil {
		return err
	}
	return j.transition(id, "returned-needs-verification")
}

func (j *workflowV4Journal) uploadCandidatePlan(plan workflowV4OperationPlan, objects storagefirst.ImmutableStore, scope storagefirst.DeliveryScope, sources map[string]state.ContentRef, paths map[string]string, resultID, manifestKey, temporary string, now time.Time) error {
	if err := storagefirst.UploadDelivery(objects, scope, workflowV4CandidateDeliveryInventory(), sources, paths, temporary); err != nil {
		return err
	}
	if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, filepath.Dir(plan.Outputs[0])); err != nil {
		return err
	}
	record := workflowV4UploadRecord{Schema: workflowV4UploadRecordSchema, Scope: plan.Scope, AttemptID: plan.AttemptID, CandidateResultID: resultID, ManifestKey: manifestKey, UploadedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339)}
	if err := writeJSONNoReplace(plan.Outputs[0], record, 0600); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("save verified upload result: %w", err)
		}
		var existing workflowV4UploadRecord
		if readErr := readWorkflowV4JSON(plan.Outputs[0], &existing); readErr != nil || !sameWorkflowV4Upload(existing, record) {
			return errors.New("existing upload result differs from the exact resumed candidate")
		}
	}
	return nil
}

func sameWorkflowV4Upload(a, b workflowV4UploadRecord) bool {
	if _, err := time.Parse(time.RFC3339, a.UploadedAt); err != nil {
		return false
	}
	return a.Schema == b.Schema && a.Scope == b.Scope && a.AttemptID == b.AttemptID && a.CandidateResultID == b.CandidateResultID && a.ManifestKey == b.ManifestKey
}

func (j *workflowV4Journal) reconcileCandidateUpload(id string, objects storagefirst.ObjectStore, inventory transcript.ContributionInventoryFactsV4) error {
	return j.reconcile(id, func(plan workflowV4OperationPlan) error {
		if plan.Kind != "upload-candidate" || inventory.Scope != plan.Scope || inventory.Predecessor != plan.Predecessor || inventory.CandidateResultID == "" {
			return errors.New("retained candidate upload differs from verified inventory")
		}
		candidateDir, err := workflowV4CandidateDir(plan)
		if err != nil {
			return err
		}
		sources, _, err := workflowV4CandidateFiles(candidateDir, inventory)
		if err != nil {
			return err
		}
		temporary := filepath.Join(j.state.Marker.Binding.Work, "workflow-v4", "temporary")
		if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, temporary); err != nil {
			return err
		}
		scope := storagefirst.DeliveryScope{CeremonyID: plan.Scope.CeremonyID, AttemptID: plan.AttemptID, Kind: access.SubmissionKindCandidate}
		download, err := storagefirst.FetchDelivery(objects, scope, workflowV4CandidateDeliveryInventory(), temporary)
		if err != nil {
			return err
		}
		defer os.RemoveAll(download)
		for name, expected := range sources {
			actual, err := regularFileRef(filepath.Join(download, name), name)
			if err != nil || actual.SHA256 != expected.SHA256 || actual.Size != expected.Size {
				return errors.New("uploaded candidate bytes differ from the retained verified inventory")
			}
		}
		var record workflowV4UploadRecord
		if err := readWorkflowV4JSON(plan.Outputs[0], &record); errors.Is(err, os.ErrNotExist) {
			prefix, prefixErr := scope.Prefix()
			if prefixErr != nil {
				return prefixErr
			}
			record = workflowV4UploadRecord{Schema: workflowV4UploadRecordSchema, Scope: plan.Scope, AttemptID: plan.AttemptID, CandidateResultID: inventory.CandidateResultID, ManifestKey: prefix + "/manifest.json", UploadedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
			if err := ensureWorkflowV4Directory(j.state.Marker.Binding.Work, filepath.Dir(plan.Outputs[0])); err != nil {
				return err
			}
			if err := writeJSONNoReplace(plan.Outputs[0], record, 0600); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		prefix, err := scope.Prefix()
		if err != nil {
			return err
		}
		if record.Schema != workflowV4UploadRecordSchema || record.Scope != plan.Scope || record.AttemptID != plan.AttemptID || record.CandidateResultID != inventory.CandidateResultID || record.ManifestKey != prefix+"/manifest.json" {
			return errors.New("retained upload result differs from the exact candidate")
		}
		return nil
	})
}

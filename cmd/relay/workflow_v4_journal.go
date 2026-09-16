package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

const workflowV4JournalSchema = "relay-workflow-v4-state-v1"
const workflowV4MarkerSchema = "relay-workflow-v4-workspace-v1"
const workflowV4MaximumOperations = 8192

type workflowV4Binding struct {
	CeremonyID string                        `json:"ceremony_id"`
	Definition transcript.SignedArtifactRefs `json:"definition"`
	Name       string                        `json:"name"`
	Role       string                        `json:"role"`
	IdentityID string                        `json:"identity_id"`
	Work       string                        `json:"work"`
	Runtimes   map[string]workflowV4Runtime  `json:"runtimes"`
}

type workflowV4Marker struct {
	Schema      string            `json:"schema"`
	WorkspaceID string            `json:"workspace_id"`
	StatePath   string            `json:"state_path"`
	Binding     workflowV4Binding `json:"binding"`
}

type workflowV4Runtime struct {
	Image    string            `json:"image"`
	Platform string            `json:"platform"`
	Mounts   map[string]string `json:"mounts"` // container destination -> original host path
}

type workflowV4Input struct {
	Path string                 `json:"path"`
	Ref  transcript.ArtifactRef `json:"ref"`
}

type workflowV4OperationPlan struct {
	ID                string                         `json:"id"`
	Kind              string                         `json:"kind"`
	Scope             transcript.ContributionScopeV4 `json:"scope"`
	Predecessor       transcript.SignedArtifactRefs  `json:"predecessor"`
	AttemptID         string                         `json:"attempt_id,omitempty"`
	Runtime           workflowV4Runtime              `json:"runtime"`
	Command           []string                       `json:"command"`
	Inputs            []workflowV4Input              `json:"inputs"`
	Outputs           []string                       `json:"outputs"`
	CommitJournalPath string                         `json:"commit_journal_path,omitempty"`
	CommitPlan        *coordinatorCommitPlan         `json:"commit_plan,omitempty"`
}

type workflowV4Operation struct {
	Plan     workflowV4OperationPlan `json:"plan"`
	Status   string                  `json:"status"`
	Prepared time.Time               `json:"prepared"`
	Started  *time.Time              `json:"started,omitempty"`
	Returned *time.Time              `json:"returned,omitempty"`
	Resolved *time.Time              `json:"resolved,omitempty"`
}

type workflowV4State struct {
	Schema     string                `json:"schema"`
	Marker     workflowV4Marker      `json:"marker"`
	Status     string                `json:"status"`
	Operations []workflowV4Operation `json:"operations"`
}

// The journal owns the workspace lock until close. It records execution
// boundaries only; even reconciled records must be reverified for guidance.
// It deliberately has no retry-running-operation method.
type workflowV4Journal struct {
	path     string
	state    workflowV4State
	lock     *participantRunLock
	save     func(string, any, int) error
	writeErr error
}

func openWorkflowV4Journal(protocol transcript.DefinitionProtocol, definition transcript.SignedArtifactRefs, binding workflowV4Binding) (*workflowV4Journal, error) {
	if !protocol.UsesV4() || protocol.Definition.CeremonyID != binding.CeremonyID || definition != binding.Definition {
		return nil, errors.New("V4 recovery requires the authenticated V4 ceremony definition")
	}
	journey, err := protocol.Definition.RequireJourney()
	if err != nil {
		return nil, err
	}
	assigned := false
	for _, enrollment := range journey.RequiredEnrollments {
		assigned = assigned || enrollment.Role == binding.Role && enrollment.Identity.ID == binding.IdentityID
	}
	if !assigned {
		return nil, errors.New("V4 workspace identity is not assigned this role in the authenticated definition")
	}
	if err := validateWorkflowV4Binding(binding); err != nil {
		return nil, err
	}
	lock, err := acquireParticipantRunLock("", binding.Work)
	if err != nil {
		return nil, err
	}
	j := &workflowV4Journal{path: filepath.Join(binding.Work, "workflow-v4", "state.json"), lock: lock, save: saveJSONAtomicWithLimit}
	ready := false
	defer func() {
		if !ready {
			_ = j.close()
		}
	}()
	if err := ensurePrivateDirectory(filepath.Dir(j.path)); err != nil {
		return nil, err
	}
	markerPath := filepath.Join(binding.Work, ".relay-workspace-v4.json")
	var marker workflowV4Marker
	markerErr := readWorkflowV4JSON(markerPath, &marker)
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, markerErr
	}
	err = readWorkflowV4JSON(j.path, &j.state)
	if errors.Is(err, os.ErrNotExist) {
		if markerErr == nil {
			return nil, errors.New("V4 workspace marker exists without its state; preserve and inspect this workspace")
		}
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		j.state = workflowV4State{Schema: workflowV4JournalSchema, Status: "initializing", Marker: workflowV4Marker{Schema: workflowV4MarkerSchema, WorkspaceID: id, StatePath: j.path, Binding: binding}}
		if err := j.persist(j.state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := validateWorkflowV4State(j.state, binding, j.path); err != nil {
		return nil, err
	}
	if markerErr == nil {
		if !reflect.DeepEqual(marker, j.state.Marker) {
			return nil, errors.New("V4 workspace marker does not match saved state")
		}
	} else {
		if j.state.Status != "initializing" {
			return nil, errors.New("V4 workspace marker is missing; preserve and inspect this workspace")
		}
		if err := writeJSONNoReplace(markerPath, j.state.Marker, 0600); err != nil {
			return nil, err
		}
	}
	if j.state.Status == "initializing" {
		next := j.state
		next.Status = "ready"
		if err := j.persist(next); err != nil {
			return nil, err
		}
	}
	ready = true
	return j, nil
}

func (j *workflowV4Journal) close() error {
	if j.lock == nil {
		return nil
	}
	err := j.lock.release()
	j.lock = nil
	return err
}

func (j *workflowV4Journal) persist(next workflowV4State) error {
	if j.lock == nil {
		return errors.New("V4 workspace lock is not held")
	}
	if j.writeErr != nil {
		return errors.New("V4 state save failed; close and reopen to inspect durable state before doing more work")
	}
	if err := validateWorkflowV4State(next, j.state.Marker.Binding, j.path); err != nil {
		return err
	}
	// Clone before saving: caller-owned slices/maps must not mutate a saved plan.
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	var copy workflowV4State
	if err := json.Unmarshal(raw, &copy); err != nil {
		return err
	}
	if err := j.save(j.path, copy, workflowV4MaximumBytes); err != nil {
		// A rename may have succeeded before directory fsync failed. Do not
		// let the old in-memory state authorize another execution in this process.
		j.writeErr = err
		return err
	}
	j.state = copy
	return nil
}

func (j *workflowV4Journal) pending() (*workflowV4Operation, error) {
	if j.lock == nil || j.writeErr != nil {
		return nil, errors.New("reopen the V4 workspace before inspecting saved operations")
	}
	for _, operation := range j.state.Operations {
		if operation.Status != "reconciled" && operation.Status != "abandoned" {
			raw, err := json.Marshal(operation)
			if err != nil {
				return nil, err
			}
			var copy workflowV4Operation
			if err := json.Unmarshal(raw, &copy); err != nil {
				return nil, err
			}
			return &copy, nil
		}
	}
	return nil, nil
}

func (j *workflowV4Journal) prepare(plan workflowV4OperationPlan) error {
	if j.state.Status != "ready" {
		return errors.New("V4 workspace initialization is incomplete")
	}
	if pending, err := j.pending(); err != nil {
		return err
	} else if pending != nil {
		return errors.New("inspect the pending V4 operation before preparing new work")
	}
	if err := validateWorkflowV4Plan(plan, j.state.Marker.Binding); err != nil {
		return err
	}
	for _, earlier := range j.state.Operations {
		if earlier.Status != "abandoned" && plan.Kind == "contribute" && earlier.Plan.Kind == plan.Kind && earlier.Plan.Scope == plan.Scope {
			return errors.New("this turn already has a computation operation; inspect its retained result instead of computing again")
		}
	}
	if err := workflowV4OutputsAbsent(plan); err != nil {
		return err
	}
	if err := workflowV4InputsMatch(plan); err != nil {
		return err
	}
	next := j.state
	next.Operations = append(append([]workflowV4Operation(nil), next.Operations...), workflowV4Operation{Plan: plan, Status: "prepared", Prepared: time.Now().UTC()})
	return j.persist(next)
}

// runPrepared persists running before invoking the child. Errors (including
// cancellation) retain running: process exit alone cannot establish no effects.
func (j *workflowV4Journal) runPrepared(id string, run func(workflowV4OperationPlan) error) error {
	operation, err := j.pending()
	if err != nil {
		return err
	}
	if operation == nil || operation.Plan.ID != id || operation.Status != "prepared" || run == nil {
		return errors.New("only a prepared V4 operation may start")
	}
	if err := workflowV4OutputsAbsent(operation.Plan); err != nil {
		return err
	}
	if err := workflowV4InputsMatch(operation.Plan); err != nil {
		return err
	}
	if err := j.transition(id, "running"); err != nil {
		return err
	}
	if err := run(operation.Plan); err != nil {
		return err
	}
	return j.transition(id, "returned-needs-verification")
}

func (j *workflowV4Journal) abandonPrepared(id string) error {
	operation, err := j.pending()
	if err != nil {
		return err
	}
	if operation == nil || operation.Plan.ID != id || operation.Status != "prepared" {
		return errors.New("only an unstarted operation may be abandoned")
	}
	if err := workflowV4OutputsAbsent(operation.Plan); err != nil {
		return err
	}
	return j.transition(id, "abandoned")
}

// verify must inspect exact retained artifacts (and publication for coordinator
// commits), never merely the child exit status. No automatic execution occurs.
func (j *workflowV4Journal) reconcile(id string, verify func(workflowV4OperationPlan) error) error {
	operation, err := j.pending()
	if err != nil {
		return err
	}
	if operation == nil || operation.Plan.ID != id || (operation.Status != "running" && operation.Status != "returned-needs-verification") || verify == nil {
		return errors.New("V4 reconciliation requires an uncertain operation and exact verification")
	}
	if err := verify(operation.Plan); err != nil {
		return err
	}
	if operation.Plan.CommitJournalPath != "" {
		var commit coordinatorCommitJournalRecord
		if err := readWorkflowV4JSON(operation.Plan.CommitJournalPath, &commit); err != nil {
			return err
		}
		if err := commit.validate(); err != nil {
			return err
		}
		if commit.Stage != commitRootCASCommitted || operation.Plan.CommitPlan == nil || !reflect.DeepEqual(commit.Plan, *operation.Plan.CommitPlan) {
			return errors.New("coordinator publication is not committed for this exact V4 operation")
		}
	}
	return j.transition(id, "reconciled")
}

func (j *workflowV4Journal) transition(id, status string) error {
	next := j.state
	next.Operations = append([]workflowV4Operation(nil), next.Operations...)
	if len(next.Operations) == 0 || next.Operations[len(next.Operations)-1].Plan.ID != id {
		return errors.New("V4 operation is not current")
	}
	op := &next.Operations[len(next.Operations)-1]
	now := time.Now().UTC()
	switch status {
	case "running":
		if op.Status != "prepared" {
			return errors.New("V4 operation has already started")
		}
		op.Started = &now
	case "returned-needs-verification":
		if op.Status != "running" {
			return errors.New("V4 operation is not running")
		}
		op.Returned = &now
	case "reconciled":
		if op.Status != "running" && op.Status != "returned-needs-verification" {
			return errors.New("V4 operation cannot be reconciled")
		}
		op.Resolved = &now
	case "abandoned":
		if op.Status != "prepared" {
			return errors.New("V4 operation may have run")
		}
		op.Resolved = &now
	default:
		return errors.New("unsupported V4 operation status")
	}
	op.Status = status
	return j.persist(next)
}

func validateWorkflowV4Binding(b workflowV4Binding) error {
	if !validCoordinatorCommitDigest(b.CeremonyID) || b.Name == "" || b.IdentityID == "" || (b.Role != "coordinator" && b.Role != "participant") {
		return errors.New("invalid V4 workspace ceremony or role binding")
	}
	if err := validateCommitLocalPath(b.Work); err != nil {
		return err
	}
	if err := validateETag("workspace name", b.Name); err != nil {
		return err
	}
	if err := validateETag("role identity", b.IdentityID); err != nil {
		return err
	}
	if len(b.Runtimes) < 1 || len(b.Runtimes) > 3 {
		return errors.New("V4 workspace requires its approved runtime profiles")
	}
	for class, runtime := range b.Runtimes {
		if class != "contributor" && class != "signer" && class != "online" {
			return errors.New("unknown V4 runtime class")
		}
		if err := validateWorkflowV4Runtime(runtime, b.Work); err != nil {
			return err
		}
	}
	return validateWorkflowV4Pair(b.Definition)
}

func validateWorkflowV4Pair(pair transcript.SignedArtifactRefs) error {
	if pair.Record.Name == pair.Signature.Name {
		return errors.New("V4 record and signature must be distinct")
	}
	if pair.Record.Digest.Size > 16<<20 || pair.Signature.Digest.Size > 4096 {
		return errors.New("V4 retained record or signature exceeds its size limit")
	}
	for _, ref := range []transcript.ArtifactRef{pair.Record, pair.Signature} {
		if err := validateWorkflowV4Ref(ref); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkflowV4Ref(ref transcript.ArtifactRef) error {
	if err := transcript.ValidateName(ref.Name); err != nil {
		return err
	}
	if !validCoordinatorCommitDigest(ref.Digest.SHA256) || !validCoordinatorCommitDigest(strings.Replace(ref.Digest.Blake2b256, "blake2b256:", "sha256:", 1)) || !strings.HasPrefix(ref.Digest.Blake2b256, "blake2b256:") || ref.Digest.Size < 1 || ref.Digest.Size > 16<<30 {
		return errors.New("invalid V4 retained file digest")
	}
	return nil
}

func validateWorkflowV4State(s workflowV4State, binding workflowV4Binding, path string) error {
	if s.Schema != workflowV4JournalSchema || s.Marker.Schema != workflowV4MarkerSchema || !validFlowAttemptID(s.Marker.WorkspaceID) || s.Marker.StatePath != path || !reflect.DeepEqual(s.Marker.Binding, binding) {
		return errors.New("V4 recovery state belongs to another workspace or definition")
	}
	if err := validateWorkflowV4Binding(binding); err != nil {
		return err
	}
	if (s.Status != "initializing" && s.Status != "ready") || (s.Status == "initializing" && len(s.Operations) != 0) || len(s.Operations) > workflowV4MaximumOperations {
		return errors.New("invalid or full V4 operation journal")
	}
	ids := make(map[string]bool)
	computations := make(map[transcript.ContributionScopeV4]bool)
	for n, op := range s.Operations {
		if ids[op.Plan.ID] {
			return errors.New("duplicate V4 operation ID")
		}
		ids[op.Plan.ID] = true
		if err := validateWorkflowV4Plan(op.Plan, binding); err != nil {
			return err
		}
		if op.Plan.Kind == "contribute" && op.Status != "abandoned" {
			if computations[op.Plan.Scope] {
				return errors.New("V4 journal repeats a computation for the same turn")
			}
			computations[op.Plan.Scope] = true
		}
		if op.Prepared.IsZero() {
			return errors.New("missing V4 operation preparation time")
		}
		switch op.Status {
		case "prepared":
			if op.Started != nil || op.Returned != nil || op.Resolved != nil {
				return errors.New("invalid prepared V4 operation")
			}
		case "running":
			if op.Started == nil || op.Returned != nil || op.Resolved != nil {
				return errors.New("invalid running V4 operation")
			}
		case "returned-needs-verification":
			if op.Started == nil || op.Returned == nil || op.Resolved != nil {
				return errors.New("invalid returned V4 operation")
			}
		case "reconciled":
			if op.Started == nil || op.Resolved == nil {
				return errors.New("invalid reconciled V4 operation")
			}
		case "abandoned":
			if op.Started != nil || op.Returned != nil || op.Resolved == nil {
				return errors.New("invalid abandoned V4 operation")
			}
		default:
			return errors.New("unknown V4 operation status")
		}
		previous := op.Prepared
		for _, stamp := range []*time.Time{&op.Prepared, op.Started, op.Returned, op.Resolved} {
			if stamp == nil {
				continue
			}
			_, offset := stamp.Zone()
			if stamp.IsZero() || stamp.Before(previous) || offset != 0 {
				return errors.New("invalid V4 operation timestamp ordering")
			}
			previous = *stamp
		}
		if n != len(s.Operations)-1 && op.Status != "reconciled" && op.Status != "abandoned" {
			return errors.New("new work follows an unresolved V4 operation")
		}
	}
	return nil
}

func validateWorkflowV4Plan(p workflowV4OperationPlan, b workflowV4Binding) error {
	if !validFlowAttemptID(p.ID) || p.Scope.CeremonyID != b.CeremonyID || !validCoordinatorCommitDigest(p.Scope.ParentHeadID) || (p.Scope.Phase != "phase1" && p.Scope.Phase != "phase2") || p.Scope.Index < 1 || p.Scope.Index > 20 || p.Scope.ParticipantID == "" || (b.Role == "participant" && p.Scope.ParticipantID != b.IdentityID) {
		return errors.New("invalid V4 operation turn")
	}
	if err := validateWorkflowV4Pair(p.Predecessor); err != nil {
		return err
	}
	wantRole, attemptBound, commit := "participant", false, false
	switch p.Kind {
	case "download-outbound", "upload-receipt", "upload-candidate":
		attemptBound = true
	case "sign-receipt", "contribute", "attest-erasure", "sign-return":
	case "download-receipt", "download-candidate", "issue-grant":
		wantRole, attemptBound = "coordinator", true
	case "sign-return-receipt":
		wantRole = "coordinator"
	case "commit-outbound", "commit-receipt", "commit-candidate":
		wantRole, attemptBound, commit = "coordinator", true, true
	default:
		return errors.New("unsupported V4 turn operation")
	}
	if b.Role != wantRole || (attemptBound && !validFlowAttemptID(p.AttemptID)) || (!attemptBound && p.AttemptID != "") {
		return errors.New("V4 operation role or delivery attempt mismatch")
	}
	if commit != (p.CommitJournalPath != "") || commit != (p.CommitPlan != nil) {
		return errors.New("V4 coordinator commit requires its exact publication journal")
	}
	if commit {
		if err := p.CommitPlan.validate(); err != nil {
			return err
		}
		if p.CommitPlan.OperationID != p.ID || p.CommitPlan.CeremonyID != b.CeremonyID {
			return errors.New("V4 publication plan differs from this operation")
		}
		if !reflect.DeepEqual(p.CommitPlan.InnerOutputPaths, p.Outputs) {
			return errors.New("V4 publication outputs differ from the saved operation")
		}
		if p.CommitJournalPath != filepath.Join(b.Work, "workflow-v4", "commits", p.ID+".json") {
			return errors.New("V4 publication journal must use its isolated operation path")
		}
		if _, err := pathWithin(b.Work, p.CommitJournalPath, "/work"); err != nil {
			return err
		}
		if err := validateCommitLocalPath(p.CommitJournalPath); err != nil {
			return err
		}
	}
	class := "online"
	if p.Kind == "contribute" {
		class = "contributor"
	}
	if p.Kind == "sign-receipt" || p.Kind == "sign-return" || p.Kind == "sign-return-receipt" || p.Kind == "attest-erasure" {
		class = "signer"
	}
	if expected, ok := b.Runtimes[class]; !ok || !reflect.DeepEqual(expected, p.Runtime) {
		return errors.New("V4 operation runtime differs from the approved role profile")
	}
	if err := validateWorkflowV4Runtime(p.Runtime, b.Work); err != nil {
		return err
	}
	if len(p.Command) == 0 || len(p.Command) > 256 || len(p.Inputs) < 2 || len(p.Inputs) > 64 || len(p.Outputs) == 0 || len(p.Outputs) > 16 {
		return errors.New("invalid V4 operation input/output bounds")
	}
	for _, arg := range p.Command {
		if strings.ContainsRune(arg, '\x00') || len(arg) > 64<<10 {
			return errors.New("invalid V4 command argument")
		}
	}
	if err := validateWorkflowV4PlanPaths(p, b); err != nil {
		return err
	}
	return validateWorkflowV4Command(p, b)
}

func validateWorkflowV4Runtime(runtime workflowV4Runtime, work string) error {
	if !roleImagePattern.MatchString(runtime.Image) || (runtime.Platform != "linux/amd64" && runtime.Platform != "linux/arm64") || runtime.Mounts["/work"] != work || len(runtime.Mounts) > 3 {
		return errors.New("V4 operation requires the original pinned Linux runtime and work mount")
	}
	for destination, source := range runtime.Mounts {
		if destination != "/work" && destination != "/trust" && destination != "/keys" {
			return errors.New("unsupported V4 runtime mount")
		}
		if err := validateCommitLocalPath(source); err != nil {
			return err
		}
		if destination != "/work" && workflowV4PathsOverlap(work, source) {
			return errors.New("V4 trust and key mounts must be separate from public work")
		}
	}
	if runtime.Mounts["/trust"] != "" && runtime.Mounts["/keys"] != "" && workflowV4PathsOverlap(runtime.Mounts["/trust"], runtime.Mounts["/keys"]) {
		return errors.New("V4 public trust and private key mounts must not overlap")
	}
	return nil
}

func validateWorkflowV4PlanPaths(p workflowV4OperationPlan, b workflowV4Binding) error {
	seen := make(map[string]bool)
	record, signature := false, false
	for _, input := range p.Inputs {
		if err := validateCommitLocalPath(input.Path); err != nil {
			return err
		}
		if err := validateWorkflowV4Ref(input.Ref); err != nil {
			return err
		}
		if seen[input.Path] {
			return errors.New("duplicate V4 input path")
		}
		seen[input.Path] = true
		inside := false
		for destination, source := range p.Runtime.Mounts {
			if destination != "/keys" {
				if _, err := pathWithin(source, input.Path, destination); err == nil {
					inside = true
				}
			}
		}
		if !inside {
			return errors.New("V4 input is outside retained public mounts")
		}
		retained := filepath.Join(b.Work, "workflow-v4", "inputs", p.ID, filepath.FromSlash(input.Ref.Name))
		record = record || (input.Ref == p.Predecessor.Record && input.Path == retained)
		signature = signature || (input.Ref == p.Predecessor.Signature && input.Path == retained)
	}
	if !record || !signature {
		return errors.New("V4 operation must retain exact predecessor files")
	}
	for _, output := range p.Outputs {
		if err := validateCommitLocalPath(output); err != nil {
			return err
		}
		if output == b.Work {
			return errors.New("V4 output cannot replace the workspace")
		}
		if _, err := pathWithin(b.Work, output, "/work"); err != nil {
			return err
		}
		rel, _ := filepath.Rel(b.Work, output)
		if strings.HasPrefix(rel, "workflow") || strings.HasPrefix(rel, ".relay-") {
			return errors.New("V4 output cannot replace recovery state")
		}
		for path := range seen {
			if workflowV4PathsOverlap(path, output) {
				return errors.New("V4 outputs overlap retained inputs or outputs")
			}
		}
		seen[output] = true
	}
	return nil
}

func workflowV4PathsOverlap(a, b string) bool {
	_, first := pathWithin(a, b, "/")
	_, second := pathWithin(b, a, "/")
	return first == nil || second == nil
}

func workflowV4OutputsAbsent(p workflowV4OperationPlan) error {
	paths := append([]string(nil), p.Outputs...)
	if p.CommitJournalPath != "" {
		paths = append(paths, p.CommitJournalPath)
	}
	for _, path := range paths {
		if err := workflowV4NoSymlinkPath(p.Runtime.Mounts["/work"], path, true); err != nil {
			return err
		}
		if _, err := os.Lstat(path); err == nil {
			return errors.New("V4 output already exists; inspect it without replaying the operation")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func workflowV4InputsMatch(p workflowV4OperationPlan) error {
	for _, input := range p.Inputs {
		checked := false
		for destination, source := range p.Runtime.Mounts {
			if destination == "/keys" {
				continue
			}
			if _, err := pathWithin(source, input.Path, destination); err == nil {
				if err := workflowV4NoSymlinkPath(source, input.Path, false); err != nil {
					return err
				}
				checked = true
				break
			}
		}
		if !checked {
			return errors.New("V4 input is outside retained public mounts")
		}
		info, err := os.Lstat(input.Path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != input.Ref.Digest.Size {
			return errors.New("V4 retained input is not a regular file")
		}
		if err := workflowV4HashInput(input, info); err != nil {
			return err
		}
	}
	return nil
}

func workflowV4HashInput(input workflowV4Input, before os.FileInfo) error {
	f, err := os.Open(input.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return errors.New("V4 retained input changed while opening")
	}
	sha := sha256.New()
	// SHA-256 binds the retained bytes here; approved proof-tool verifies the
	// complete signed reference before the plan is prepared/reconciled.
	n, err := io.Copy(sha, io.LimitReader(f, before.Size()+1))
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || "sha256:"+hex.EncodeToString(sha.Sum(nil)) != input.Ref.Digest.SHA256 {
		return fmt.Errorf("V4 retained input changed: %s", input.Ref.Name)
	}
	return nil
}

func workflowV4NoSymlinkPath(root, path string, allowMissing bool) error {
	if _, err := pathWithin(root, path, "/"); err != nil {
		return err
	}
	relative, _ := filepath.Rel(root, path)
	current := root
	components := append([]string{"."}, strings.Split(relative, string(filepath.Separator))...)
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("V4 retained paths must not contain symlinks")
		}
	}
	return nil
}

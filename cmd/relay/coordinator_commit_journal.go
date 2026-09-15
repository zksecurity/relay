package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

const coordinatorCommitJournalSchema = "relay-coordinator-commit-journal-v2"

type coordinatorCommitStage string

const (
	commitInnerSigningIntent      coordinatorCommitStage = "inner-signing-intent"
	commitInnerSigned             coordinatorCommitStage = "inner-signed"
	commitCheckpointSigningIntent coordinatorCommitStage = "checkpoint-signing-intent"
	commitCheckpointSigned        coordinatorCommitStage = "checkpoint-signed"
	commitChildAuthenticated      coordinatorCommitStage = "child-authenticated"
	commitRootCASIntent           coordinatorCommitStage = "root-cas-intent"
	commitRootCASCommitted        coordinatorCommitStage = "root-cas-committed"
)

// coordinatorCommitPlan is immutable for the lifetime of one commit. The
// connected coordinator must durably create this plan before asking the inner
// record signer to run. Object-store keys are recorded separately from local
// output paths so a resumed commit cannot redirect either one.
type coordinatorCommitPlan struct {
	OperationID         string               `json:"operation_id"`
	CeremonyID          string               `json:"ceremony_id"`
	PreviousRoot        *state.Root          `json:"previous_root,omitempty"`
	PreviousRootVersion *store.ObjectVersion `json:"previous_root_version,omitempty"`
	InnerOutputPaths    []string             `json:"inner_output_paths"`
}

// coordinatorCheckpointSigningIntent fixes the local and remote destinations
// before checkpoint signing. It is separate from the initial plan because a
// content-addressed checkpoint path may only be known after inner outputs are
// complete and hashed.
type coordinatorCheckpointSigningIntent struct {
	CheckpointOutputPath          string `json:"checkpoint_output_path"`
	CheckpointSignatureOutputPath string `json:"checkpoint_signature_output_path"`
	TargetCheckpointPath          string `json:"target_checkpoint_path"`
	TargetCheckpointSignaturePath string `json:"target_checkpoint_signature_path"`
}

type coordinatorRootCASIntent struct {
	RootPayloadOutputPath string `json:"root_payload_output_path"`
	TargetRootPath        string `json:"target_root_path"`
}

// coordinatorCommitOutput binds one local output path to the exact bytes that
// were produced there. Digests are supplied only after the caller hashes the
// completed regular file.
type coordinatorCommitOutput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// coordinatorAuthenticatedChild records the exact local inputs and immutable
// references that were successfully authenticated before root publication.
// A resumed caller must run AuthenticateRootChild again with these inputs; the
// recorded evidence result is a recovery boundary, not a substitute for proof
// verification.
type coordinatorAuthenticatedChild struct {
	ArtifactRoot        string                                `json:"artifact_root"`
	Checkpoint          state.ContentRef                      `json:"checkpoint"`
	CheckpointSignature state.ContentRef                      `json:"checkpoint_signature"`
	Evidence            coordinatorAuthenticatedChildEvidence `json:"evidence"`
}

type coordinatorAuthenticatedChildEvidence struct {
	CeremonyID       string `json:"ceremony_id"`
	Sequence         uint64 `json:"sequence"`
	CheckpointDigest string `json:"checkpoint_digest"`
	TransitionKind   string `json:"transition_kind"`
	FullyVerified    bool   `json:"fully_verified"`
}

type coordinatorCommitJournalRecord struct {
	Schema               string                              `json:"schema"`
	Stage                coordinatorCommitStage              `json:"stage"`
	Plan                 coordinatorCommitPlan               `json:"plan"`
	InnerOutputs         []coordinatorCommitOutput           `json:"inner_outputs,omitempty"`
	CheckpointIntent     *coordinatorCheckpointSigningIntent `json:"checkpoint_intent,omitempty"`
	Checkpoint           *coordinatorCommitOutput            `json:"checkpoint,omitempty"`
	CheckpointSignature  *coordinatorCommitOutput            `json:"checkpoint_signature,omitempty"`
	AuthenticatedChild   *coordinatorAuthenticatedChild      `json:"authenticated_child,omitempty"`
	RootIntent           *coordinatorRootCASIntent           `json:"root_intent,omitempty"`
	RootPayload          *coordinatorCommitOutput            `json:"root_payload,omitempty"`
	CommittedRootVersion *store.ObjectVersion                `json:"committed_root_version,omitempty"`
}

// coordinatorCommitJournal has no cloud behavior. Callers hold the exclusive
// coordinator-workspace lock while using it and perform signing/uploads/CAS
// only after the corresponding intent method has returned successfully.
type coordinatorCommitJournal struct {
	path   string
	record coordinatorCommitJournalRecord
}

// openOrCreateCoordinatorCommitJournal creates the durable inner-signing
// intent, or resumes an existing journal only when the complete plan matches.
func openOrCreateCoordinatorCommitJournal(path string, plan coordinatorCommitPlan) (*coordinatorCommitJournal, error) {
	if err := validateCoordinatorCommitJournalPath(path); err != nil {
		return nil, err
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}
	plan = cloneCoordinatorCommitPlan(plan)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	record, exists, err := readCoordinatorCommitJournal(path)
	if err != nil {
		return nil, err
	}
	if exists {
		if !reflect.DeepEqual(record.Plan, plan) {
			return nil, errors.New("existing coordinator commit journal does not exactly match the requested operation")
		}
		return &coordinatorCommitJournal{path: path, record: record}, nil
	}

	record = coordinatorCommitJournalRecord{
		Schema: coordinatorCommitJournalSchema,
		Stage:  commitInnerSigningIntent,
		Plan:   plan,
	}
	journal := &coordinatorCommitJournal{path: path}
	if err := journal.persist(record); err != nil {
		return nil, err
	}
	return journal, nil
}

func (j *coordinatorCommitJournal) stage() coordinatorCommitStage { return j.record.Stage }

// recordInnerSigned records the exact inner signed outputs. It must complete
// before checkpointSigningIntent can persist the next signing boundary.
func (j *coordinatorCommitJournal) recordInnerSigned(outputs []coordinatorCommitOutput) error {
	normalized, err := normalizeCommitOutputs(j.record.Plan.InnerOutputPaths, outputs)
	if err != nil {
		return err
	}
	if stageAtLeast(j.record.Stage, commitInnerSigned) {
		if !reflect.DeepEqual(j.record.InnerOutputs, normalized) {
			return errors.New("inner signing resume does not match the recorded output paths and digests")
		}
		return nil
	}
	if j.record.Stage != commitInnerSigningIntent {
		return invalidCommitTransition(j.record.Stage, commitInnerSigned)
	}
	next := j.record
	next.InnerOutputs = normalized
	next.Stage = commitInnerSigned
	return j.persist(next)
}

// checkpointSigningIntent is the durable boundary immediately before asking
// the checkpoint signer to run.
func (j *coordinatorCommitJournal) checkpointSigningIntent(intent coordinatorCheckpointSigningIntent) error {
	if err := intent.validate(); err != nil {
		return err
	}
	if err := validateCommitDestinations(j.record.Plan, &intent, j.record.RootIntent); err != nil {
		return err
	}
	if stageAtLeast(j.record.Stage, commitCheckpointSigningIntent) {
		if j.record.CheckpointIntent == nil || *j.record.CheckpointIntent != intent {
			return errors.New("checkpoint signing resume does not match the recorded intent")
		}
		return nil
	}
	if j.record.Stage != commitInnerSigned {
		return invalidCommitTransition(j.record.Stage, commitCheckpointSigningIntent)
	}
	next := j.record
	next.CheckpointIntent = &intent
	next.Stage = commitCheckpointSigningIntent
	return j.persist(next)
}

func (j *coordinatorCommitJournal) recordCheckpointSigned(checkpoint, signature coordinatorCommitOutput) error {
	if j.record.CheckpointIntent == nil {
		return errors.New("checkpoint signing intent is missing")
	}
	checkpoint, err := normalizeCommitOutput(j.record.CheckpointIntent.CheckpointOutputPath, checkpoint)
	if err != nil {
		return fmt.Errorf("checkpoint output: %w", err)
	}
	signature, err = normalizeCommitOutput(j.record.CheckpointIntent.CheckpointSignatureOutputPath, signature)
	if err != nil {
		return fmt.Errorf("checkpoint signature output: %w", err)
	}
	if stageAtLeast(j.record.Stage, commitCheckpointSigned) {
		if j.record.Checkpoint == nil || j.record.CheckpointSignature == nil || *j.record.Checkpoint != checkpoint || *j.record.CheckpointSignature != signature {
			return errors.New("checkpoint signing resume does not match the recorded output paths and digests")
		}
		return nil
	}
	if j.record.Stage != commitCheckpointSigningIntent {
		return invalidCommitTransition(j.record.Stage, commitCheckpointSigned)
	}
	next := j.record
	next.Checkpoint = &checkpoint
	next.CheckpointSignature = &signature
	next.Stage = commitCheckpointSigned
	return j.persist(next)
}

// recordAuthenticatedChild persists the exact inputs and result of the full
// child-evidence verification. Root publication must not be attempted before
// this boundary is durable. Recovery re-runs authentication from these exact
// inputs before reconstructing CommitRoot.
func (j *coordinatorCommitJournal) recordAuthenticatedChild(child coordinatorAuthenticatedChild) error {
	if err := child.validate(j.record.Plan, j.record.CheckpointIntent, j.record.Checkpoint, j.record.CheckpointSignature); err != nil {
		return err
	}
	if stageAtLeast(j.record.Stage, commitChildAuthenticated) {
		if j.record.AuthenticatedChild == nil || !reflect.DeepEqual(*j.record.AuthenticatedChild, child) {
			return errors.New("authenticated child resume does not match the recorded references and evidence")
		}
		return nil
	}
	if j.record.Stage != commitCheckpointSigned {
		return invalidCommitTransition(j.record.Stage, commitChildAuthenticated)
	}
	next := j.record
	next.AuthenticatedChild = &child
	next.Stage = commitChildAuthenticated
	return j.persist(next)
}

// rootCASIntent records the exact root payload before the caller attempts the
// compare-and-swap using Plan.PreviousRootVersion and intent.TargetRootPath.
func (j *coordinatorCommitJournal) rootCASIntent(intent coordinatorRootCASIntent, rootPayload coordinatorCommitOutput) error {
	if err := intent.validate(); err != nil {
		return err
	}
	if err := validateCommitDestinations(j.record.Plan, j.record.CheckpointIntent, &intent); err != nil {
		return err
	}
	rootPayload, err := normalizeCommitOutput(intent.RootPayloadOutputPath, rootPayload)
	if err != nil {
		return fmt.Errorf("root payload output: %w", err)
	}
	if stageAtLeast(j.record.Stage, commitRootCASIntent) {
		if j.record.RootIntent == nil || *j.record.RootIntent != intent || j.record.RootPayload == nil || *j.record.RootPayload != rootPayload {
			return errors.New("root CAS resume does not match the recorded payload path and digest")
		}
		return nil
	}
	if j.record.Stage != commitChildAuthenticated {
		return invalidCommitTransition(j.record.Stage, commitRootCASIntent)
	}
	next := j.record
	next.RootIntent = &intent
	next.RootPayload = &rootPayload
	next.Stage = commitRootCASIntent
	return j.persist(next)
}

func (j *coordinatorCommitJournal) recordRootCASCommitted(committed store.ObjectVersion) error {
	if err := validateCoordinatorRootVersion("committed root version", committed); err != nil {
		return err
	}
	if j.record.Stage == commitRootCASCommitted {
		if j.record.CommittedRootVersion == nil || *j.record.CommittedRootVersion != committed {
			return errors.New("root CAS resume supplied a different committed object version")
		}
		return nil
	}
	if j.record.Stage != commitRootCASIntent {
		return invalidCommitTransition(j.record.Stage, commitRootCASCommitted)
	}
	next := j.record
	next.CommittedRootVersion = &committed
	next.Stage = commitRootCASCommitted
	return j.persist(next)
}

func (j *coordinatorCommitJournal) persist(next coordinatorCommitJournalRecord) error {
	if err := next.validate(); err != nil {
		return err
	}
	if err := saveJSONAtomic(j.path, next); err != nil {
		return err
	}
	j.record = next
	return nil
}

func readCoordinatorCommitJournal(path string) (coordinatorCommitJournalRecord, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return coordinatorCommitJournalRecord{}, false, nil
	}
	if err != nil {
		return coordinatorCommitJournalRecord{}, false, err
	}
	if len(raw) > 1<<20 {
		return coordinatorCommitJournalRecord{}, false, errors.New("coordinator commit journal exceeds its size limit")
	}
	if err := rejectCommitJournalDuplicateFields(raw); err != nil {
		return coordinatorCommitJournalRecord{}, false, fmt.Errorf("decode coordinator commit journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record coordinatorCommitJournalRecord
	if err := decoder.Decode(&record); err != nil {
		return coordinatorCommitJournalRecord{}, false, fmt.Errorf("decode coordinator commit journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("unexpected trailing JSON value")
		}
		return coordinatorCommitJournalRecord{}, false, fmt.Errorf("decode coordinator commit journal: %w", err)
	}
	if err := record.validate(); err != nil {
		return coordinatorCommitJournalRecord{}, false, fmt.Errorf("validate coordinator commit journal: %w", err)
	}
	return record, true, nil
}

func (p coordinatorCommitPlan) validate() error {
	if !validFlowAttemptID(p.OperationID) {
		return errors.New("coordinator commit operation ID must be 32 lowercase hexadecimal characters")
	}
	if !validCoordinatorCommitDigest(p.CeremonyID) {
		return errors.New("coordinator commit ceremony ID must be a canonical SHA-256 digest")
	}
	if (p.PreviousRoot == nil) != (p.PreviousRootVersion == nil) {
		return errors.New("previous root and previous root version must be supplied together")
	}
	if p.PreviousRoot != nil {
		if err := p.PreviousRoot.Validate(); err != nil {
			return fmt.Errorf("previous root: %w", err)
		}
		if p.PreviousRoot.CeremonyID != p.CeremonyID {
			return errors.New("previous root belongs to another ceremony")
		}
		if err := validateCoordinatorRootVersion("previous root version", *p.PreviousRootVersion); err != nil {
			return err
		}
	}
	if len(p.InnerOutputPaths) == 0 || len(p.InnerOutputPaths) > 64 {
		return errors.New("coordinator commit must declare between 1 and 64 inner output paths")
	}
	seen := make(map[string]struct{}, len(p.InnerOutputPaths))
	for _, path := range p.InnerOutputPaths {
		if err := validateCommitLocalPath(path); err != nil {
			return err
		}
		if _, exists := seen[path]; exists {
			return fmt.Errorf("coordinator commit output path %q is repeated", path)
		}
		seen[path] = struct{}{}
	}
	return nil
}

func cloneCoordinatorCommitPlan(plan coordinatorCommitPlan) coordinatorCommitPlan {
	plan.InnerOutputPaths = append([]string(nil), plan.InnerOutputPaths...)
	if plan.PreviousRoot != nil {
		root := *plan.PreviousRoot
		plan.PreviousRoot = &root
	}
	if plan.PreviousRootVersion != nil {
		version := *plan.PreviousRootVersion
		plan.PreviousRootVersion = &version
	}
	return plan
}

func (c coordinatorAuthenticatedChild) validate(plan coordinatorCommitPlan, intent *coordinatorCheckpointSigningIntent, checkpoint, signature *coordinatorCommitOutput) error {
	if intent == nil || checkpoint == nil || signature == nil {
		return errors.New("checkpoint signing outputs are missing before child authentication")
	}
	if err := validateCommitLocalPath(c.ArtifactRoot); err != nil {
		return fmt.Errorf("artifact root: %w", err)
	}
	testRoot := state.Root{
		Schema: state.RootSchema, CeremonyID: plan.CeremonyID,
		Checkpoint: c.Checkpoint, CheckpointSignature: c.CheckpointSignature,
	}
	if err := testRoot.Validate(); err != nil {
		return fmt.Errorf("authenticated child references: %w", err)
	}
	if c.Checkpoint.SHA256 != checkpoint.SHA256 || c.CheckpointSignature.SHA256 != signature.SHA256 {
		return errors.New("authenticated child references do not match the exact signed checkpoint outputs")
	}
	if intent.TargetCheckpointPath != store.Key(c.Checkpoint.SHA256) || intent.TargetCheckpointSignaturePath != store.Key(c.CheckpointSignature.SHA256) {
		return errors.New("checkpoint upload targets do not match the authenticated content-addressed child references")
	}
	evidence := c.Evidence
	if !evidence.FullyVerified || evidence.CeremonyID != plan.CeremonyID ||
		evidence.CheckpointDigest != c.Checkpoint.SHA256 || evidence.TransitionKind == "" ||
		strings.TrimSpace(evidence.TransitionKind) != evidence.TransitionKind || strings.ContainsAny(evidence.TransitionKind, "\x00\r\n") {
		return errors.New("authenticated child evidence does not exactly match the commit ceremony and checkpoint")
	}
	if plan.PreviousRoot == nil {
		if evidence.Sequence != 0 {
			return errors.New("initial commit child evidence must have sequence zero")
		}
	} else {
		// The proof-tool-authenticated child is rechecked on resume; recording the
		// expected direct sequence here catches an accidentally mixed operation.
		if evidence.Sequence == 0 {
			return errors.New("non-initial commit child evidence must advance the previous root")
		}
	}
	return nil
}

func (i coordinatorCheckpointSigningIntent) validate() error {
	if err := validateCommitLocalPath(i.CheckpointOutputPath); err != nil {
		return err
	}
	if err := validateCommitLocalPath(i.CheckpointSignatureOutputPath); err != nil {
		return err
	}
	if i.CheckpointOutputPath == i.CheckpointSignatureOutputPath {
		return errors.New("checkpoint output paths must be distinct")
	}
	if err := validateCommitObjectPath("target checkpoint path", i.TargetCheckpointPath); err != nil {
		return err
	}
	if err := validateCommitObjectPath("target checkpoint signature path", i.TargetCheckpointSignaturePath); err != nil {
		return err
	}
	if i.TargetCheckpointPath == i.TargetCheckpointSignaturePath {
		return errors.New("checkpoint target paths must be distinct")
	}
	return nil
}

func (i coordinatorRootCASIntent) validate() error {
	if err := validateCommitLocalPath(i.RootPayloadOutputPath); err != nil {
		return err
	}
	return validateCommitObjectPath("target root path", i.TargetRootPath)
}

func (r coordinatorCommitJournalRecord) validate() error {
	if r.Schema != coordinatorCommitJournalSchema {
		return fmt.Errorf("journal schema %q, want %q", r.Schema, coordinatorCommitJournalSchema)
	}
	if err := r.Plan.validate(); err != nil {
		return err
	}
	rank, ok := commitStageRank(r.Stage)
	if !ok {
		return fmt.Errorf("unknown coordinator commit stage %q", r.Stage)
	}
	if rank >= 1 {
		if _, err := normalizeCommitOutputs(r.Plan.InnerOutputPaths, r.InnerOutputs); err != nil {
			return fmt.Errorf("recorded inner outputs: %w", err)
		}
	} else if len(r.InnerOutputs) != 0 {
		return errors.New("inner outputs were recorded before inner signing completed")
	}
	if rank >= 2 {
		if r.CheckpointIntent == nil {
			return errors.New("checkpoint signing intent is missing")
		}
		if err := r.CheckpointIntent.validate(); err != nil {
			return err
		}
	} else if r.CheckpointIntent != nil {
		return errors.New("checkpoint signing intent was recorded too early")
	}
	if rank >= 3 {
		if r.Checkpoint == nil || r.CheckpointSignature == nil {
			return errors.New("checkpoint outputs are missing after checkpoint signing")
		}
		if _, err := normalizeCommitOutput(r.CheckpointIntent.CheckpointOutputPath, *r.Checkpoint); err != nil {
			return err
		}
		if _, err := normalizeCommitOutput(r.CheckpointIntent.CheckpointSignatureOutputPath, *r.CheckpointSignature); err != nil {
			return err
		}
	} else if r.Checkpoint != nil || r.CheckpointSignature != nil {
		return errors.New("checkpoint outputs were recorded before checkpoint signing completed")
	}
	if rank >= 4 {
		if r.AuthenticatedChild == nil {
			return errors.New("authenticated child is missing after evidence verification")
		}
		if err := r.AuthenticatedChild.validate(r.Plan, r.CheckpointIntent, r.Checkpoint, r.CheckpointSignature); err != nil {
			return err
		}
	} else if r.AuthenticatedChild != nil {
		return errors.New("authenticated child was recorded before checkpoint evidence verification")
	}
	if rank >= 5 {
		if r.RootIntent == nil || r.RootPayload == nil {
			return errors.New("root payload is missing after root CAS intent")
		}
		if err := r.RootIntent.validate(); err != nil {
			return err
		}
		if _, err := normalizeCommitOutput(r.RootIntent.RootPayloadOutputPath, *r.RootPayload); err != nil {
			return err
		}
	} else if r.RootIntent != nil || r.RootPayload != nil {
		return errors.New("root payload was recorded before root CAS intent")
	}
	if err := validateCommitDestinations(r.Plan, r.CheckpointIntent, r.RootIntent); err != nil {
		return err
	}
	if rank == 6 {
		if r.CommittedRootVersion == nil {
			return errors.New("committed root version is missing after root CAS completed")
		}
		if err := validateCoordinatorRootVersion("committed root version", *r.CommittedRootVersion); err != nil {
			return err
		}
	} else if r.CommittedRootVersion != nil {
		return errors.New("committed root version was recorded before the root CAS completed")
	}
	return nil
}

func validateCommitDestinations(plan coordinatorCommitPlan, checkpoint *coordinatorCheckpointSigningIntent, root *coordinatorRootCASIntent) error {
	local := make(map[string]struct{}, len(plan.InnerOutputPaths)+3)
	for _, path := range plan.InnerOutputPaths {
		local[path] = struct{}{}
	}
	if checkpoint != nil {
		for _, path := range []string{checkpoint.CheckpointOutputPath, checkpoint.CheckpointSignatureOutputPath} {
			if _, exists := local[path]; exists {
				return fmt.Errorf("coordinator commit output path %q is repeated across intents", path)
			}
			local[path] = struct{}{}
		}
	}
	if root != nil {
		if _, exists := local[root.RootPayloadOutputPath]; exists {
			return fmt.Errorf("coordinator commit output path %q is repeated across intents", root.RootPayloadOutputPath)
		}
		if checkpoint != nil && (root.TargetRootPath == checkpoint.TargetCheckpointPath || root.TargetRootPath == checkpoint.TargetCheckpointSignaturePath) {
			return errors.New("root and checkpoint target paths must be distinct")
		}
		if root.TargetRootPath != state.RootKey(plan.CeremonyID) {
			return errors.New("root target path does not match the exact ceremony discovery root")
		}
	}
	return nil
}

func normalizeCommitOutputs(expectedPaths []string, outputs []coordinatorCommitOutput) ([]coordinatorCommitOutput, error) {
	if len(outputs) != len(expectedPaths) {
		return nil, fmt.Errorf("got %d outputs, want %d", len(outputs), len(expectedPaths))
	}
	byPath := make(map[string]coordinatorCommitOutput, len(outputs))
	for _, output := range outputs {
		if _, exists := byPath[output.Path]; exists {
			return nil, fmt.Errorf("output path %q is repeated", output.Path)
		}
		byPath[output.Path] = output
	}
	normalized := make([]coordinatorCommitOutput, 0, len(expectedPaths))
	for _, expected := range expectedPaths {
		output, ok := byPath[expected]
		if !ok {
			return nil, fmt.Errorf("missing output for %q", expected)
		}
		checked, err := normalizeCommitOutput(expected, output)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, checked)
	}
	return normalized, nil
}

func normalizeCommitOutput(expectedPath string, output coordinatorCommitOutput) (coordinatorCommitOutput, error) {
	if output.Path != expectedPath {
		return coordinatorCommitOutput{}, fmt.Errorf("output path %q, want %q", output.Path, expectedPath)
	}
	if !validCoordinatorCommitDigest(output.SHA256) {
		return coordinatorCommitOutput{}, fmt.Errorf("output %q has a malformed SHA-256 digest", output.Path)
	}
	return output, nil
}

func commitStageRank(stage coordinatorCommitStage) (int, bool) {
	switch stage {
	case commitInnerSigningIntent:
		return 0, true
	case commitInnerSigned:
		return 1, true
	case commitCheckpointSigningIntent:
		return 2, true
	case commitCheckpointSigned:
		return 3, true
	case commitChildAuthenticated:
		return 4, true
	case commitRootCASIntent:
		return 5, true
	case commitRootCASCommitted:
		return 6, true
	default:
		return 0, false
	}
}

func stageAtLeast(current, expected coordinatorCommitStage) bool {
	currentRank, currentOK := commitStageRank(current)
	expectedRank, expectedOK := commitStageRank(expected)
	return currentOK && expectedOK && currentRank >= expectedRank
}

func invalidCommitTransition(current, target coordinatorCommitStage) error {
	return fmt.Errorf("coordinator commit cannot move directly from %s to %s", current, target)
}

func validateCoordinatorCommitJournalPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("coordinator commit journal path must be absolute and clean")
	}
	return nil
}

func validateCommitLocalPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("coordinator commit output path %q must be absolute and clean", path)
	}
	return nil
}

func validateCommitObjectPath(label, path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || strings.HasPrefix(path, "../") || strings.Contains(path, "\\") {
		return fmt.Errorf("%s %q must be a safe relative object path", label, path)
	}
	return nil
}

func validCoordinatorCommitDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(value, "sha256:") {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateETag(label, value string) error {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) {
		return fmt.Errorf("%s is empty, too long, or invalid UTF-8", label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains control characters", label)
		}
	}
	return nil
}

func validateCoordinatorRootVersion(label string, version store.ObjectVersion) error {
	if err := validateETag(label+" ETag", version.ETag); err != nil {
		return err
	}
	if len(version.VersionID) > 1024 || !utf8.ValidString(version.VersionID) || strings.ContainsAny(version.VersionID, "\x00\r\n") {
		return fmt.Errorf("%s has an invalid version ID", label)
	}
	if version.Size <= 0 {
		return fmt.Errorf("%s has a non-positive size", label)
	}
	return nil
}

func rejectCommitJournalDuplicateFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := inspectCommitJournalJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func inspectCommitJournalJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := inspectCommitJournalJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := inspectCommitJournalJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

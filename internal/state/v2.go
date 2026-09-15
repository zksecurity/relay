package state

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
)

const (
	// RootSchema identifies the untrusted mutable discovery root. Everything it
	// names remains content addressed and must be authenticated by the caller.
	RootSchema = "relay-state-root-v2"

	// WorkspaceHighWaterSchema identifies the durable rollback/fork record kept
	// in one role workspace. It intentionally is not stored in the ceremony
	// bucket whose rollback it detects.
	WorkspaceHighWaterSchema = "relay-checkpoint-high-water-v1"
)

// Root is the only mutable discovery object in the v2 state layout. Its fields
// are hints, not authority: callers must digest-check and authenticate the
// checkpoint and detached signature before using any checkpoint contents.
type Root struct {
	Schema              string     `json:"schema"`
	CeremonyID          string     `json:"ceremony_id"`
	Checkpoint          ContentRef `json:"checkpoint"`
	CheckpointSignature ContentRef `json:"checkpoint_signature"`
}

// ContentRef is a fetchable immutable object. Size is authenticated by the
// signed checkpoint/root and lets Relay reject oversized objects before it
// allocates disk or asks proof-tool to parse them.
type ContentRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// RootKey returns the per-ceremony mutable discovery key. Root.Validate still
// has to be called before a value read from this key is trusted as well formed.
func RootKey(ceremonyID string) string {
	return "state/" + strings.TrimPrefix(ceremonyID, "sha256:") + "/root.json"
}

func (r Root) Validate() error {
	if r.Schema != RootSchema {
		return fmt.Errorf("root schema %q, want %q", r.Schema, RootSchema)
	}
	if !validDigest(r.CeremonyID) {
		return errors.New("root ceremony ID is not a canonical SHA-256 digest")
	}
	if err := validateContentRef("checkpoint", r.Checkpoint); err != nil {
		return err
	}
	if err := validateContentRef("checkpoint signature", r.CheckpointSignature); err != nil {
		return err
	}
	return nil
}

func DecodeRoot(raw []byte) (Root, error) {
	var root Root
	if err := decodeStrict(raw, &root); err != nil {
		return Root{}, fmt.Errorf("decode discovery root: %w", err)
	}
	return root, root.Validate()
}

func (r Root) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(r, "", "  ")
}

// PhaseHeadPosition is the furthest authenticated head retained by this
// workspace. A digest alone cannot distinguish a normal advancing head from a
// same-height fork, hence the explicit accepted index.
type PhaseHeadPosition struct {
	Index  uint64 `json:"index"`
	Digest string `json:"digest"`
	Closed bool   `json:"closed,omitempty"`
}

// TerminalPosition retains the absorbing GO/NO-GO decision. Later publication
// checkpoints keep this same terminal decision digest, so they do not look like
// a second decision or erase the first one.
type TerminalPosition struct {
	Outcome string `json:"outcome"`
	Digest  string `json:"digest"`
}

// CheckpointPosition is the authenticated checkpoint state that may advance a
// workspace high-water mark. PreviousDigest is used to prove the next direct
// step descends from the record already stored locally.
type CheckpointPosition struct {
	Sequence       uint64                       `json:"sequence"`
	Digest         string                       `json:"digest"`
	PreviousDigest string                       `json:"previous_digest,omitempty"`
	PhaseHeads     map[string]PhaseHeadPosition `json:"phase_heads,omitempty"`
	Terminal       *TerminalPosition            `json:"terminal,omitempty"`
}

func (p CheckpointPosition) Validate() error {
	if !validDigest(p.Digest) {
		return errors.New("checkpoint digest is not a canonical SHA-256 digest")
	}
	if p.PreviousDigest != "" && !validDigest(p.PreviousDigest) {
		return errors.New("previous checkpoint digest is not a canonical SHA-256 digest")
	}
	for phase, head := range p.PhaseHeads {
		if phase != "phase1" && phase != "phase2" {
			return fmt.Errorf("unknown phase head %q", phase)
		}
		if !validDigest(head.Digest) {
			return fmt.Errorf("%s head digest is not a canonical SHA-256 digest", phase)
		}
	}
	if p.Terminal != nil {
		if p.Terminal.Outcome != "go" && p.Terminal.Outcome != "no-go" {
			return fmt.Errorf("terminal outcome %q is not go or no-go", p.Terminal.Outcome)
		}
		if !validDigest(p.Terminal.Digest) {
			return errors.New("terminal decision digest is not a canonical SHA-256 digest")
		}
	}
	return nil
}

type workspaceHighWaterRecord struct {
	Schema     string             `json:"schema"`
	CeremonyID string             `json:"ceremony_id"`
	Position   CheckpointPosition `json:"position"`
}

// WorkspaceHighWater keeps rollback and fork state inside one role workspace.
// Different role workspaces therefore cannot accidentally suppress or advance
// each other's observations.
type WorkspaceHighWater struct {
	path       string
	ceremonyID string
	lock       func(string) (func(), error)
}

// OpenWorkspaceHighWater returns a workspace-scoped checkpoint high-water
// store. The workspace path is explicit; this API never falls back to HOME.
func OpenWorkspaceHighWater(workspace, ceremonyID string) (WorkspaceHighWater, error) {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return WorkspaceHighWater{}, errors.New("workspace must be an absolute clean path")
	}
	if !validDigest(ceremonyID) {
		return WorkspaceHighWater{}, errors.New("ceremony ID is not a canonical SHA-256 digest")
	}
	dir := filepath.Join(workspace, ".relay", strings.ReplaceAll(ceremonyID, ":", "-"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return WorkspaceHighWater{}, err
	}
	if err := rejectSymlinkDirectory(dir); err != nil {
		return WorkspaceHighWater{}, err
	}
	return WorkspaceHighWater{
		path: filepath.Join(dir, "checkpoint-high-water.json"), ceremonyID: ceremonyID,
		lock: lockWorkspaceHighWater,
	}, nil
}

// Seen returns the stored position and whether this workspace has recorded one.
func (h WorkspaceHighWater) Seen() (CheckpointPosition, bool, error) {
	return h.seenUnlocked()
}

func (h WorkspaceHighWater) seenUnlocked() (CheckpointPosition, bool, error) {
	raw, err := os.ReadFile(h.path)
	if errors.Is(err, os.ErrNotExist) {
		return CheckpointPosition{}, false, nil
	}
	if err != nil {
		return CheckpointPosition{}, false, err
	}
	var record workspaceHighWaterRecord
	if err := decodeStrict(raw, &record); err != nil {
		return CheckpointPosition{}, false, fmt.Errorf("decode workspace high-water: %w", err)
	}
	if record.Schema != WorkspaceHighWaterSchema {
		return CheckpointPosition{}, false, fmt.Errorf("workspace high-water schema %q, want %q", record.Schema, WorkspaceHighWaterSchema)
	}
	if record.CeremonyID != h.ceremonyID {
		return CheckpointPosition{}, false, errors.New("workspace high-water belongs to another ceremony")
	}
	if err := record.Position.Validate(); err != nil {
		return CheckpointPosition{}, false, fmt.Errorf("validate workspace high-water: %w", err)
	}
	return record.Position, true, nil
}

// Check rejects rollback, a same-sequence fork, a gap in the ancestry walk, a
// phase-head retreat/fork, reopening a closed phase, or replacing/forgetting a
// terminal decision. Callers walk and authenticate checkpoints one at a time.
func (h WorkspaceHighWater) Check(candidate CheckpointPosition) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	unlock, err := h.acquireLock()
	if err != nil {
		return err
	}
	defer unlock()
	seen, exists, err := h.seenUnlocked()
	if err != nil {
		return err
	}
	return checkHighWaterCandidate(seen, exists, candidate)
}

func checkHighWaterCandidate(seen CheckpointPosition, exists bool, candidate CheckpointPosition) error {
	if !exists {
		return nil
	}
	if candidate.Sequence < seen.Sequence {
		return fmt.Errorf("checkpoint sequence moved backwards from %d to %d", seen.Sequence, candidate.Sequence)
	}
	if candidate.Sequence == seen.Sequence {
		if candidate.Digest != seen.Digest {
			return fmt.Errorf("checkpoint sequence %d has a different digest: possible fork", candidate.Sequence)
		}
		if !reflect.DeepEqual(candidate, seen) {
			return errors.New("the same checkpoint digest was presented with different authenticated state")
		}
		return nil
	}
	if candidate.Sequence != seen.Sequence+1 {
		return fmt.Errorf("checkpoint sequence jumped from %d to %d; authenticate the missing ancestry first", seen.Sequence, candidate.Sequence)
	}
	if candidate.PreviousDigest != seen.Digest {
		return errors.New("checkpoint does not descend from the workspace high-water digest")
	}
	return compareRetainedState(seen, candidate)
}

// Record advances the high-water mark only after validation. The replacement
// is written and synced, atomically renamed, then the containing directory is
// synced so a reported success survives a normal process or machine restart.
func (h WorkspaceHighWater) Record(candidate CheckpointPosition) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	unlock, err := h.acquireLock()
	if err != nil {
		return err
	}
	defer unlock()
	seen, exists, err := h.seenUnlocked()
	if err != nil {
		return err
	}
	if err := checkHighWaterCandidate(seen, exists, candidate); err != nil {
		return err
	}
	if exists && reflect.DeepEqual(seen, candidate) {
		return nil
	}
	record := workspaceHighWaterRecord{Schema: WorkspaceHighWaterSchema, CeremonyID: h.ceremonyID, Position: candidate}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomicDurable(h.path, raw, 0o600)
}

func (h WorkspaceHighWater) acquireLock() (func(), error) {
	if h.lock == nil {
		return nil, errors.New("workspace high-water lock is not configured")
	}
	return h.lock(h.path + ".lock")
}

func compareRetainedState(seen, candidate CheckpointPosition) error {
	for phase, oldHead := range seen.PhaseHeads {
		newHead, ok := candidate.PhaseHeads[phase]
		if !ok {
			return fmt.Errorf("%s head disappeared from checkpoint state", phase)
		}
		if newHead.Index < oldHead.Index {
			return fmt.Errorf("%s head moved backwards from %d to %d", phase, oldHead.Index, newHead.Index)
		}
		if newHead.Index == oldHead.Index && newHead.Digest != oldHead.Digest {
			return fmt.Errorf("%s head index %d has a different digest: possible fork", phase, newHead.Index)
		}
		if oldHead.Closed && !newHead.Closed {
			return fmt.Errorf("%s retreated from closed to open", phase)
		}
	}
	if seen.Terminal != nil {
		if candidate.Terminal == nil {
			return errors.New("terminal decision disappeared from checkpoint state")
		}
		if candidate.Terminal.Outcome != seen.Terminal.Outcome || candidate.Terminal.Digest != seen.Terminal.Digest {
			return errors.New("terminal decision changed after it was recorded")
		}
	}
	return nil
}

func validateContentRef(label string, ref ContentRef) error {
	if ref.Name == "" || filepath.IsAbs(ref.Name) || filepath.Clean(ref.Name) != ref.Name || ref.Name == "." || strings.HasPrefix(ref.Name, "../") || strings.Contains(ref.Name, "\\") {
		return fmt.Errorf("root %s reference has an unsafe name", label)
	}
	if !validDigest(ref.SHA256) {
		return fmt.Errorf("root %s reference has a malformed SHA-256 digest", label)
	}
	if ref.Size <= 0 || ref.Size > 16<<20 {
		return fmt.Errorf("root %s reference has an invalid size", label)
	}
	return nil
}

func validDigest(value string) bool {
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

func decodeStrict(raw []byte, value any) error {
	if err := rejectDuplicateFields(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func rejectDuplicateFields(decoder *json.Decoder) error {
	if err := inspectJSONValue(decoder); err != nil {
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

func inspectJSONValue(decoder *json.Decoder) error {
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
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func rejectSymlinkDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("workspace high-water directory is not a regular directory")
	}
	return nil
}

func writeFileAtomicDurable(path string, raw []byte, mode os.FileMode) (result error) {
	dir := filepath.Dir(path)
	if err := rejectSymlinkDirectory(dir); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".checkpoint-high-water-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		if result != nil {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

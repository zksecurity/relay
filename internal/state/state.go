// Package state implements the mutable pointer layer that lets a participant
// discover where a ceremony has reached without being told over the phone.
//
// The pointers are unsigned and rewritable by anyone who can write the bucket,
// so they are scheduling hints and nothing more. Two rules keep that safe:
//
//   - A pointer only ever names content-addressed keys. Everything it names is
//     fetched, digest-checked and signature-verified before use, so a lying
//     pointer costs a round trip rather than corrupting a transcript.
//   - No pointer may appear in a signed ceremony record, and nothing may be
//     accepted because a pointer said so. Delete the whole state prefix and the
//     ceremony is still verifiable; you just have to ask a person where to look.
//
// The residual risk is denial of service: a pointer can roll back to an old
// head, vanish, or say different things to different readers. Rollback is the
// one worth defending against, because a stale head silently wastes hours of
// replay before the coordinator rejects the result. HighWater records the
// furthest position this machine has seen so a backwards pointer is refused.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	Schema       = "relay-state-v1"
	legacySchema = "mpc-sync-state-v1"
)

// Ref names a blob by its logical name and content hash. The hash is what
// locates the object; the name is for humans and for writing it back to disk.
type Ref struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Pointer is the published position of one phase.
type Pointer struct {
	Schema     string `json:"schema"`
	CeremonyID string `json:"ceremony_id"`
	Phase      string `json:"phase"`
	// Index is the number of accepted contributions, so the next contributor
	// is index+1. It is a claim, not a fact: the chain this pointer names is
	// the authority, and it is re-counted after fetching.
	Index          int    `json:"index"`
	Chain          Ref    `json:"chain"`
	ChainSignature Ref    `json:"chain_signature"`
	UpdatedAt      string `json:"updated_at"`
	// Closed is set once the phase closure has been published, so a witness can
	// tell there is something to observe without polling the whole transcript.
	Closed bool `json:"closed"`
	// Files lists every object this publish uploaded, by logical name and hash.
	//
	// It exists because parts of a transcript are unreachable from the chain: a
	// closure record names the head it seals, so the reference runs backwards,
	// and the compiled constraint system is named by the definition. A puller
	// walking the chain can never discover them, and without a digest it cannot
	// fetch them by content address either. Listing them here closes that gap.
	//
	// This does not make the pointer trusted. Every entry is fetched by its own
	// hash and re-hashed on arrival, so a wrong entry fails rather than
	// substituting content, and entries whose digest a signed document already
	// states are checked against that instead.
	Files []Ref `json:"files"`
}

// Key returns the object key for a phase pointer.
//
// The ceremony id is part of the path because one bucket may hold more than one
// ceremony, and a pointer is the only mutable object here. Without the
// namespace a second ceremony's publish silently overwrites the first's
// pointer: the blobs survive, being content-addressed and immutable, but
// nothing names them any more, so the earlier transcript becomes unreachable
// even though every byte of it is still stored.
//
// The tag separator is dropped so the id is a clean single path component.
func Key(ceremonyID, phase string) string {
	return "state/" + strings.TrimPrefix(ceremonyID, "sha256:") + "/" + phase + "/head.json"
}

func (p Pointer) Validate() error {
	if p.Schema != Schema && p.Schema != legacySchema {
		return fmt.Errorf("state schema %q, want %q", p.Schema, Schema)
	}
	if p.Phase != "phase1" && p.Phase != "phase2" {
		return fmt.Errorf("state phase %q is not phase1 or phase2", p.Phase)
	}
	if p.Index < 0 {
		return fmt.Errorf("state index %d is negative", p.Index)
	}
	for label, ref := range map[string]Ref{"chain": p.Chain, "chain_signature": p.ChainSignature} {
		if ref.Name == "" || !strings.HasPrefix(ref.SHA256, "sha256:") || len(ref.SHA256) != 71 {
			return fmt.Errorf("state %s reference is malformed", label)
		}
	}
	return nil
}

func Decode(raw []byte) (Pointer, error) {
	var p Pointer
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pointer{}, fmt.Errorf("decode state pointer: %w", err)
	}
	return p, p.Validate()
}

func (p Pointer) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

// HighWater is this machine's record of the furthest position it has seen for a
// ceremony phase. It lives locally on purpose: a rollback defence stored in the
// same bucket as the thing it defends against would be rolled back too.
type HighWater struct{ dir string }

func OpenHighWater(ceremonyID string) (HighWater, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return HighWater{}, err
	}
	// The ceremony id is a tagged hex hash, so it is already a safe path
	// component once the tag separator is removed.
	ceremonyDir := strings.ReplaceAll(ceremonyID, ":", "-")
	dir := filepath.Join(home, ".relay", ceremonyDir)
	legacyDir := filepath.Join(home, ".mpc-sync", ceremonyDir)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if _, legacyErr := os.Stat(legacyDir); legacyErr == nil {
			if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
				return HighWater{}, err
			}
			if err := os.Rename(legacyDir, dir); err != nil {
				return HighWater{}, fmt.Errorf("migrate high-water state to .relay: %w", err)
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return HighWater{}, err
	}
	return HighWater{dir: dir}, nil
}

func (h HighWater) path(phase string) string { return filepath.Join(h.dir, phase+".highwater") }

// Seen returns the furthest index recorded for a phase, or zero.
func (h HighWater) Seen(phase string) (int, error) {
	raw, err := os.ReadFile(h.path(phase))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var index int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &index); err != nil {
		return 0, fmt.Errorf("high-water file for %s is unreadable: %w", phase, err)
	}
	return index, nil
}

// Record advances the high-water mark. It never moves backwards, so a stale
// pointer cannot lower it and a later honest pointer is still accepted.
func (h HighWater) Record(phase string, index int) error {
	seen, err := h.Seen(phase)
	if err != nil {
		return err
	}
	if index <= seen {
		return nil
	}
	return os.WriteFile(h.path(phase), []byte(fmt.Sprintf("%d\n", index)), 0o600)
}

// CheckNotBehind refuses a pointer that claims less progress than this machine
// has already seen. That is the rollback case: the chain it names is genuine
// and verifies, so nothing downstream would catch it, and the cost is hours of
// replay against a head the coordinator has already moved past.
func (h HighWater) CheckNotBehind(phase string, index int) error {
	seen, err := h.Seen(phase)
	if err != nil {
		return err
	}
	if index < seen {
		return fmt.Errorf(
			"published state claims %s index %d but this machine has already seen %d; "+
				"the pointer has moved backwards, which means a stale or rewritten bucket",
			phase, index, seen,
		)
	}
	return nil
}

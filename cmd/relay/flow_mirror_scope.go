package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/zksecurity/relay/internal/transcript"
)

type flowReceiptScope struct {
	Schema     string `json:"schema"`
	CeremonyID string `json:"ceremony_id"`
	Phase      string `json:"phase"`
	Index      int    `json:"index"`
	Head       string `json:"accepted_head_id"`
	Mirror     struct {
		ID string `json:"id"`
	} `json:"mirror"`
	Digest          string `json:"record_digest,omitempty"`
	SignatureDigest string `json:"signature_digest,omitempty"`
}

func (f *roleFlow) mirrorReceiptScope(task flowTask, command []string) (*flowReceiptScope, error) {
	if f.state.Role != "mirror" || f.state.Profile.Work == "" || (task.ID != "sign-receipt" && task.ID != "submit") {
		return nil, nil
	}
	record := commandValue(command, "record")
	if task.ID == "submit" {
		record = filepath.Join(commandValue(command, "dir"), "canonical.json")
	}
	local, err := f.publicHostPath(record)
	if err != nil {
		return nil, err
	}
	var s flowReceiptScope
	raw, err := readEnrollmentPublicFile(filepath.Dir(local), filepath.Base(local))
	if err != nil {
		return nil, err
	}
	// Projection only: the signing/submission command verifies the exact record.
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Schema != "proof-tool-mpc-immutable-mirror-receipt-v1" || s.CeremonyID == "" || s.Phase != f.stages[f.state.Stage].ID || s.Index < 1 || s.Head == "" || s.Mirror.ID == "" {
		return nil, errors.New("receipt scope is missing or differs from this phase")
	}
	s.Digest, err = setupFileHash(local)
	if err == nil && task.ID == "submit" {
		s.SignatureDigest, err = setupFileHash(filepath.Join(filepath.Dir(local), "receipt.sig"))
	}
	return &s, err
}

func (f *roleFlow) chooseMirrorHead(task flowTask, best flowHead) (flowHead, error) {
	if f.state.Role != "mirror" || (task.ID != "draft-receipt" && task.ID != "receipt") {
		return best, nil
	}
	phase := best.Chain.Phase
	key := "mirror-index/" + phase
	selected := f.state.Values[key]
	if task.ID == "draft-receipt" {
		choices := []setupChoice{}
		for _, r := range best.Chain.Records {
			choices = append(choices, setupChoice{value: strconv.Itoa(int(r.Index)), label: fmt.Sprintf("Contribution %d — %s", r.Index, r.ParticipantID)})
		}
		if len(choices) == 0 {
			return flowHead{}, errors.New("no accepted contribution is available to retain")
		}
		var err error
		selected, err = f.ui.choose("Which accepted contribution did you retain?", "", choices)
		if err != nil {
			return flowHead{}, err
		}
		f.state.Values[key] = selected
	}
	index, err := strconv.Atoi(selected)
	if err != nil || index < 1 || index > len(best.Chain.Records) {
		return flowHead{}, errors.New("prepare a mirror draft for a selected accepted contribution first")
	}
	i, _, err := f.inspectionContext()
	if err != nil {
		return flowHead{}, err
	}
	chainPath := filepath.Join(filepath.Dir(best.Chain.ChainPath), fmt.Sprintf("chain-%04d.json", index))
	sigPath := filepath.Join(filepath.Dir(best.Chain.ChainPath), fmt.Sprintf("chain-%04d.sig", index))
	chain, err := i.Chain(chainPath, sigPath)
	if err != nil {
		return flowHead{}, err
	}
	if chain.CeremonyID != best.Chain.CeremonyID || chain.Phase != phase || !reflect.DeepEqual(chain.Records, best.Chain.Records[:index]) {
		return flowHead{}, errors.New("selected historical head is not an authenticated prefix of the current local head")
	}
	digest, err := setupFileHash(chainPath)
	return flowHead{Chain: chain, Digest: digest}, err
}

func (f *roleFlow) checkMirrorCoverage() error {
	if f.state.Role != "mirror" || f.state.Profile.Work == "" {
		return nil
	}
	phase := f.stages[f.state.Stage].ID
	if phase != "phase1" && phase != "phase2" {
		return nil
	}
	journey, err := f.authenticatedJourney()
	if err != nil {
		return err
	}
	closed := false
	for _, p := range journey.Phases {
		if p.Phase == phase {
			closed = p.Closed
		}
	}
	if !closed {
		return errors.New("keep mirroring: this phase is not closed in the authenticated local transcript")
	}
	head, err := f.discoverHead(phase, nil)
	if err != nil {
		return err
	}
	return mirrorCoverage(head.Chain, f.state.Attempts, f.checkAttemptEvidence)
}

func mirrorCoverage(chain transcript.Chain, attempts []flowAttempt, check func(*flowAttempt) error) error {
	phase := chain.Phase
	signed := map[string]bool{}
	uploaded := map[string]bool{}
	for n := range attempts {
		a := &attempts[n]
		s := a.ReceiptScope
		if a.Status != "succeeded" || a.Stage != phase || s == nil || s.CeremonyID != chain.CeremonyID || s.Phase != phase || s.Index < 1 || s.Index > len(chain.Records) || s.Head != chain.Records[s.Index-1].RecordID || s.Digest == "" || s.SignatureDigest == "" || s.Mirror.ID == "" {
			continue
		}
		if check(a) != nil {
			continue
		}
		key := s.Head + "/" + s.Mirror.ID + "/" + s.Digest + "/" + s.SignatureDigest
		if a.Task == "sign-receipt" {
			signed[key] = true
		}
		if a.Task == "submit" {
			uploaded[key] = true
		}
	}
	for _, record := range chain.Records {
		found := false
		for _, a := range attempts {
			s := a.ReceiptScope
			if s == nil || s.Head != record.RecordID {
				continue
			}
			key := s.Head + "/" + s.Mirror.ID + "/" + s.Digest + "/" + s.SignatureDigest
			found = found || (signed[key] && uploaded[key])
		}
		if !found {
			return fmt.Errorf("contribution %d still needs its matching signed and uploaded mirror receipt; choose that contribution in Draft a receipt", record.Index)
		}
	}
	return nil
}

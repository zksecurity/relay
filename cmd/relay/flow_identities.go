package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Public local identities are display hints. They never replace the protocol's
// signed roster, enrollment, or signing-key checks.
func (f *roleFlow) identityChoices(task flowTask, field flowField) ([]setupChoice, error) {
	var identities []setupIdentity
	if f.state.Role == "coordinator" && task.ID == "grant" && field.Flag == "identity" && f.state.Profile.Work != "" {
		var roster setupRoster
		err := setupReadJSON(filepath.Join(f.state.Profile.Work, "coordinator-setup/frozen/participants.json"), &roster)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for _, p := range roster.Roster {
			identities = append(identities, p.Identity)
		}
	} else if f.state.Profile.Keys != "" && (field.Flag == "auditor-id" || field.Flag == "signer-id" || (field.Flag == "signature-key-id" && f.state.Role == "release-signer")) {
		var id setupIdentity
		err := setupReadJSON(filepath.Join(f.state.Profile.Keys, "identity.json"), &id)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		identities = []setupIdentity{id}
	}
	var choices []setupChoice
	for _, id := range identities {
		if err := id.check(); err != nil {
			return nil, err
		}
		value := id.ID
		if field.Flag == "signature-key-id" {
			value = id.KeyID
		}
		choices = append(choices, setupChoice{value, id.DisplayName + " (" + id.ID + ")"})
	}
	return choices, nil
}

// scheduledTurnParticipant derives the one allowed participant reference from
// the authenticated definition and accepted-head scope. Both the outbound
// custody packet and the later grant must name that same participant. The
// complete ordered list is presentation context; it is not editable.
func (f *roleFlow) scheduledTurnParticipant(task flowTask, field flowField) ([]setupChoice, string, error) {
	isParticipantReference := (task.ID == "grant" && field.Flag == "identity") || (task.ID == "prepare-outbound-handoff" && field.Flag == "participant-id")
	if f.state.Role != "coordinator" || !isParticipantReference || f.turnScope == nil || !strings.HasSuffix(f.stages[f.state.Stage].ID, "-turns") {
		return nil, "", nil
	}
	phase := strings.TrimSuffix(f.stages[f.state.Stage].ID, "-turns")
	d, err := f.authenticatedDefinition()
	if err != nil {
		return nil, "", err
	}
	schedule, err := d.Schedule(phase)
	if err != nil {
		return nil, "", err
	}
	found := false
	choices := make([]setupChoice, 0, len(schedule))
	for index, id := range schedule {
		label := fmt.Sprintf("%d. %s", index+1, id)
		if id == f.turnScope.Participant {
			label += " — expected next"
			found = true
		}
		choices = append(choices, setupChoice{value: id, label: label})
	}
	if !found {
		return nil, "", errors.New("next participant is absent from the authenticated schedule")
	}
	return choices, f.turnScope.Participant, nil
}

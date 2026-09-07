package transcript

import "fmt"

// Definition is the authenticated projection emitted by mpc-ceremony inspect.
type Definition struct {
	Schema               string      `json:"schema"`
	CeremonyID           string      `json:"ceremony_id"`
	Mode                 string      `json:"mode"`
	Phase1Participants   []string    `json:"phase1_participants"`
	Phase2Participants   []string    `json:"phase2_participants"`
	HostWipeParticipants []string    `json:"host_wipe_participants,omitempty"`
	R1CSRef              ArtifactRef `json:"r1cs"`
}

// Schedule returns the ordered participant list for a phase.
func (d Definition) Schedule(phase string) ([]string, error) {
	switch phase {
	case "phase1":
		return d.Phase1Participants, nil
	case "phase2":
		return d.Phase2Participants, nil
	default:
		return nil, fmt.Errorf("unknown phase %q", phase)
	}
}

// NextContributor reports who is scheduled at the next open slot, given how
// many contributions have been accepted.
//
// This is the same arithmetic the ceremony performs, and it is a hint here
// rather than a decision: the participant list is a frozen order, so the
// ceremony rejects a contribution whose index does not match its position.
// Printing it lets a participant find out they are not up yet without spending
// hours discovering it.
func (d Definition) NextContributor(phase string, accepted int) (string, int, error) {
	schedule, err := d.Schedule(phase)
	if err != nil {
		return "", 0, err
	}
	if accepted >= len(schedule) {
		return "", 0, fmt.Errorf("%s already has all %d scheduled contributions accepted", phase, len(schedule))
	}
	return schedule[accepted], accepted + 1, nil
}

// SlotOf returns the one-based scheduled index of a participant in a phase.
func (d Definition) SlotOf(phase, participantID string) (int, error) {
	schedule, err := d.Schedule(phase)
	if err != nil {
		return 0, err
	}
	for index, id := range schedule {
		if id == participantID {
			return index + 1, nil
		}
	}
	return 0, fmt.Errorf("%q is not scheduled in %s", participantID, phase)
}

// RequiresHostWipe reports whether the signed ceremony policy makes this
// participant's accepted contributions provisional for final release until a
// post-wipe Mac attestation is verified.
func (d Definition) RequiresHostWipe(participantID string) bool {
	for _, id := range d.HostWipeParticipants {
		if id == participantID {
			return true
		}
	}
	return false
}

// R1CS returns the compiled constraint system reference.
//
// The chain cannot name it: the definition names the circuit, and the chain
// names contributions. A participant needs the file to contribute, and because
// the definition states its digest it can be fetched and verified like any
// other artifact rather than trusted by layout.
func (d Definition) R1CS() (ArtifactRef, error) {
	if d.R1CSRef.Name == "" {
		return ArtifactRef{}, fmt.Errorf("definition names no circuit r1cs")
	}
	return d.R1CSRef, validateRef(d.R1CSRef)
}

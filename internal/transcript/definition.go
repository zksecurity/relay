package transcript

import (
	"encoding/json"
	"fmt"
)

// Definition is the slice of the signed ceremony definition this tool needs:
// the ordered participant list per phase, which is what decides whose turn it
// is.
//
// Unlike the chain parser this decodes leniently, ignoring unknown fields. The
// definition is a large, evolving document and this tool reads two arrays out
// of it to answer a scheduling question. It never decides anything the ceremony
// decides: the CLI re-derives the same order from the same signed bytes and
// refuses a contribution at the wrong index regardless of what was printed
// here. Strict decoding would buy nothing and would break on every schema
// addition.
type Definition struct {
	CeremonyID   string          `json:"ceremony_id"`
	Mode         string          `json:"mode"`
	Circuit      circuitJSON     `json:"circuit"`
	Phase1Policy phasePolicyJSON `json:"phase1_policy"`
	Phase2Policy phasePolicyJSON `json:"phase2_policy"`
}

type circuitJSON struct {
	R1CS ArtifactRef `json:"r1cs"`
}

type phasePolicyJSON struct {
	Participants []string `json:"participants"`
	Minimum      int      `json:"minimum"`
}

const maxDefinitionBytes = 1 << 20

func LoadDefinition(path string) (Definition, error) {
	raw, err := readRegularBounded(path, maxDefinitionBytes)
	if err != nil {
		return Definition{}, err
	}
	var d Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return Definition{}, fmt.Errorf("decode definition %s: %w", path, err)
	}
	if d.CeremonyID == "" {
		return Definition{}, fmt.Errorf("definition %s has no ceremony_id", path)
	}
	if len(d.Phase1Policy.Participants) == 0 {
		return Definition{}, fmt.Errorf("definition %s has an empty phase1 participant list", path)
	}
	return d, nil
}

// Schedule returns the ordered participant list for a phase.
func (d Definition) Schedule(phase string) ([]string, error) {
	switch phase {
	case "phase1":
		return d.Phase1Policy.Participants, nil
	case "phase2":
		return d.Phase2Policy.Participants, nil
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

// R1CS returns the compiled constraint system reference.
//
// The chain cannot name it: the definition names the circuit, and the chain
// names contributions. A participant needs the file to contribute, and because
// the definition states its digest it can be fetched and verified like any
// other artifact rather than trusted by layout.
func (d Definition) R1CS() (ArtifactRef, error) {
	if d.Circuit.R1CS.Name == "" {
		return ArtifactRef{}, fmt.Errorf("definition names no circuit r1cs")
	}
	return d.Circuit.R1CS, validateRef(d.Circuit.R1CS)
}

package transcript

import (
	"os"
	"path/filepath"
	"testing"
)

const definitionJSON = `{
  "schema": "proof-tool-mpc-ceremony-definition-v1",
  "ceremony_id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "mode": "rehearsal",
  "some_future_field": {"the parser must ignore": true},
  "phase1_policy": {"participants": ["participant-01","participant-02","participant-03"], "minimum": 3},
  "phase2_policy": {"participants": ["participant-02","participant-03"], "minimum": 2}
}`

func writeDefinition(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ceremony.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadDefinitionIgnoresUnknownFields is deliberate, and the opposite of the
// chain parser's contract. The definition is large and evolving, and this reads
// two arrays out of it to answer a scheduling question; strict decoding would
// break on every schema addition and buy nothing, because the ceremony CLI
// re-derives the same order from the same signed bytes.
func TestLoadDefinitionIgnoresUnknownFields(t *testing.T) {
	d, err := LoadDefinition(writeDefinition(t, definitionJSON))
	if err != nil {
		t.Fatalf("LoadDefinition: %v", err)
	}
	if d.Mode != "rehearsal" || len(d.Phase1Policy.Participants) != 3 {
		t.Fatalf("parsed definition is wrong: %+v", d)
	}
}

func TestLoadDefinitionRejectsEmpty(t *testing.T) {
	for label, body := range map[string]string{
		"no ceremony id":  `{"phase1_policy":{"participants":["a"],"minimum":1}}`,
		"no participants": `{"ceremony_id":"sha256:aa","phase1_policy":{"participants":[],"minimum":0}}`,
		"not json":        `nope`,
	} {
		if _, err := LoadDefinition(writeDefinition(t, body)); err == nil {
			t.Errorf("LoadDefinition accepted a definition with %s", label)
		}
	}
}

func TestNextContributorFollowsFrozenOrder(t *testing.T) {
	d, err := LoadDefinition(writeDefinition(t, definitionJSON))
	if err != nil {
		t.Fatal(err)
	}
	for accepted, want := range map[int]string{
		0: "participant-01",
		1: "participant-02",
		2: "participant-03",
	} {
		id, index, err := d.NextContributor("phase1", accepted)
		if err != nil {
			t.Fatalf("accepted=%d: %v", accepted, err)
		}
		if id != want || index != accepted+1 {
			t.Errorf("accepted=%d gave %s at %d, want %s at %d", accepted, id, index, want, accepted+1)
		}
	}
	if _, _, err := d.NextContributor("phase1", 3); err == nil {
		t.Error("NextContributor returned a slot past the end of the schedule")
	}
}

// TestSlotOfUsesPerPhaseSchedule matters because the phases can have different
// rosters and orders: a participant's index in phase 1 says nothing about
// phase 2.
func TestSlotOfUsesPerPhaseSchedule(t *testing.T) {
	d, err := LoadDefinition(writeDefinition(t, definitionJSON))
	if err != nil {
		t.Fatal(err)
	}
	if slot, err := d.SlotOf("phase1", "participant-03"); err != nil || slot != 3 {
		t.Errorf("phase1 slot = %d, %v; want 3", slot, err)
	}
	if slot, err := d.SlotOf("phase2", "participant-03"); err != nil || slot != 2 {
		t.Errorf("phase2 slot = %d, %v; want 2", slot, err)
	}
	if _, err := d.SlotOf("phase2", "participant-01"); err == nil {
		t.Error("SlotOf found a participant that is not scheduled in phase2")
	}
}

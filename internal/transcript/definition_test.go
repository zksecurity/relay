package transcript

import "testing"

func testDefinition() Definition {
	return Definition{
		Schema:             definitionInspectionSchema,
		CeremonyID:         "ceremony-id",
		Mode:               "production",
		Phase1Participants: []string{"participant-01", "participant-02", "participant-03"},
		Phase2Participants: []string{"participant-02", "participant-03"},
		R1CSRef: ArtifactRef{
			Name: "ownership-destination.ccs",
			Digest: Digest{
				SHA256:     "sha256:" + hex64,
				Blake2b256: "blake2b256:" + hex64,
				Size:       1,
			},
		},
	}
}

func TestNextContributorFollowsInspectedOrder(t *testing.T) {
	d := testDefinition()
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

func TestSlotOfUsesInspectedPerPhaseSchedule(t *testing.T) {
	d := testDefinition()
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

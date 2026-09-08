package transcript

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestJourneyRejectsIncompleteOrInconsistentMetadata(t *testing.T) {
	valid := func() Journey {
		return Journey{Schema: "proof-tool-mpc-journey-inspection-v1", CeremonyID: "ceremony", Mode: "rehearsal", Depth: "metadata", Phases: []PhaseJourney{
			{Phase: "phase1", Started: true, AcceptedCount: 1, ScheduledTotal: 1, Closed: true, CloseID: "close", BeaconRound: 10, ClosedAt: "2026-09-08T00:00:00Z", WitnessObservationDeadline: "2026-09-08T00:01:00Z", BeaconScheduledAt: "2026-09-08T00:02:00Z"},
			{Phase: "phase2"},
		}}
	}
	for name, mutate := range map[string]func(*Journey){
		"valid":                   func(*Journey) {},
		"duplicate phase":         func(j *Journey) { j.Phases[1].Phase = "phase1" },
		"missing phase":           func(j *Journey) { j.Phases = j.Phases[:1] },
		"missing closure":         func(j *Journey) { j.Phases[0].CloseID = "" },
		"negative count":          func(j *Journey) { j.Phases[0].AcceptedCount = -1 },
		"count exceeds schedule":  func(j *Journey) { j.Phases[0].AcceptedCount = 2 },
		"invalid time":            func(j *Journey) { j.Phases[0].ClosedAt = "yesterday" },
		"deadline after beacon":   func(j *Journey) { j.Phases[0].WitnessObservationDeadline = "2026-09-08T00:03:00Z" },
		"deadline before closure": func(j *Journey) { j.Phases[0].WitnessObservationDeadline = "2026-09-07T23:59:00Z" },
		"unknown mode":            func(j *Journey) { j.Mode = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			j := valid()
			mutate(&j)
			i := testInspector()
			i.run = func(_ string, args ...string) ([]byte, []byte, error) {
				if len(args) < 3 || args[2] != "inspect" {
					t.Fatalf("unexpected arguments: %v", args)
				}
				b, err := json.Marshal(inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect", JourneyInspection: &j})
				return b, nil, err
			}
			_, err := i.Journey()
			if (err == nil) != (name == "valid") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	t.Run("verification failure", func(t *testing.T) {
		i := testInspector()
		i.run = func(string, ...string) ([]byte, []byte, error) { return nil, nil, errors.New("signature rejected") }
		if _, err := i.Journey(); err == nil {
			t.Fatal("accepted failed verification")
		}
	})
}

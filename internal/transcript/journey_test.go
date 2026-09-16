package transcript

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestDefinitionJourneyUsesAuthenticatedMinimums(t *testing.T) {
	valid := func(minimum int) Definition {
		j := &DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v1", MinimumPublicWitnesses: minimum, MinimumMirrorsPerAcceptedHead: minimum, ObserverRequirementSource: "verified operational requirements"}
		for _, role := range []string{"coordinator", "release-signer", "auditor", "participant"} {
			j.RequiredEnrollments = append(j.RequiredEnrollments, ExpectedEnrollment{Role: role, RoleIndex: 1, Identity: PublicIdentity{ID: role, KeyID: role, PublicKeyFingerprint: role}})
		}
		return Definition{Journey: j}
	}
	for _, minimum := range []int{1, 2, 3} {
		d := valid(minimum)
		j, err := d.RequireJourney()
		if err != nil || j.MinimumPublicWitnesses != minimum || j.MinimumMirrorsPerAcceptedHead != minimum {
			t.Fatal(minimum, j, err)
		}
	}
	for name, mutate := range map[string]func(*Definition){
		"zero witnesses":   func(d *Definition) { d.Journey.MinimumPublicWitnesses = 0 },
		"negative mirrors": func(d *Definition) { d.Journey.MinimumMirrorsPerAcceptedHead = -1 },
		"missing source":   func(d *Definition) { d.Journey.ObserverRequirementSource = "" },
		"no auditor": func(d *Definition) {
			d.Journey.RequiredEnrollments = append(d.Journey.RequiredEnrollments[:2], d.Journey.RequiredEnrollments[3:]...)
		},
		"duplicate": func(d *Definition) { d.Journey.RequiredEnrollments[3].Identity.ID = "auditor" },
		"bad index": func(d *Definition) { d.Journey.RequiredEnrollments[2].RoleIndex = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid(1)
			mutate(&d)
			if _, err := d.RequireJourney(); err == nil {
				t.Fatal(fmt.Sprint("accepted ", name))
			}
		})
	}
}

func TestDefinitionJourneyAllowsExplicitlyDisabledV2Assurance(t *testing.T) {
	j := &DefinitionJourney{
		Schema: "proof-tool-mpc-definition-journey-v2", ObserverRequirementSource: "signed ceremony assurance_policy",
		RequiredEnrollments: []ExpectedEnrollment{
			{Role: "coordinator", RoleIndex: 1, Identity: PublicIdentity{ID: "coordinator", KeyID: "coordinator-key", PublicKeyFingerprint: "coordinator-fingerprint"}},
			{Role: "release-signer", RoleIndex: 1, Identity: PublicIdentity{ID: "release", KeyID: "release-key", PublicKeyFingerprint: "release-fingerprint"}},
			{Role: "participant", RoleIndex: 1, Identity: PublicIdentity{ID: "participant", KeyID: "participant-key", PublicKeyFingerprint: "participant-fingerprint"}},
		},
	}
	if _, err := (Definition{Journey: j}).RequireJourney(); err != nil {
		t.Fatalf("zero-assurance journey rejected: %v", err)
	}
	j.MinimumPassingCeremonyAudits = 1
	if _, err := (Definition{Journey: j}).RequireJourney(); err == nil {
		t.Fatal("positive audit requirement accepted without an auditor enrollment")
	}
}

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

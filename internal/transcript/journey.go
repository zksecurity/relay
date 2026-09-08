package transcript

import (
	"errors"
	"time"
)

type ExpectedEnrollment struct {
	Role      string         `json:"role"`
	RoleIndex int            `json:"role_index"`
	Identity  PublicIdentity `json:"identity"`
}
type DefinitionJourney struct {
	Schema                        string               `json:"schema"`
	RequiredEnrollments           []ExpectedEnrollment `json:"required_enrollments"`
	MinimumPublicWitnesses        int                  `json:"minimum_public_witnesses"`
	MinimumMirrorsPerAcceptedHead int                  `json:"minimum_mirrors_per_accepted_head"`
	ObserverRequirementSource     string               `json:"observer_requirement_source"`
}
type PhaseJourney struct {
	Phase                      string   `json:"phase"`
	Started                    bool     `json:"started"`
	AcceptedCount              int      `json:"accepted_count"`
	ScheduledTotal             int      `json:"scheduled_total"`
	HeadRecordID               string   `json:"head_record_id"`
	NextParticipantID          string   `json:"next_participant_id,omitempty"`
	Closed                     bool     `json:"closed"`
	CloseID                    string   `json:"close_id,omitempty"`
	ClosedAt                   string   `json:"closed_at,omitempty"`
	BeaconRound                uint64   `json:"beacon_round,omitempty"`
	BeaconScheduledAt          string   `json:"beacon_scheduled_at,omitempty"`
	WitnessObservationDeadline string   `json:"witness_observation_deadline,omitempty"`
	MissingArtifacts           []string `json:"missing_artifacts"`
}
type Journey struct {
	Schema     string         `json:"schema"`
	CeremonyID string         `json:"ceremony_id"`
	Mode       string         `json:"mode"`
	Depth      string         `json:"depth"`
	Phases     []PhaseJourney `json:"phases"`
}

func (d Definition) RequireJourney() (DefinitionJourney, error) {
	if d.Journey == nil || d.Journey.Schema != "proof-tool-mpc-definition-journey-v1" {
		return DefinitionJourney{}, errors.New("approved proof-tool does not provide authenticated journey requirements; use a matching new release")
	}
	j := *d.Journey
	if j.MinimumPublicWitnesses < 2 || j.MinimumMirrorsPerAcceptedHead < 2 || j.ObserverRequirementSource == "" {
		return j, errors.New("incomplete observer requirements from proof-tool")
	}
	roles := map[string]int{}
	ids := map[string]bool{}
	for _, e := range j.RequiredEnrollments {
		roles[e.Role]++
		if e.RoleIndex != roles[e.Role] || e.Identity.ID == "" || ids[e.Identity.ID] || e.Identity.KeyID == "" || e.Identity.PublicKeyFingerprint == "" {
			return j, errors.New("incomplete or ambiguous required enrollment projection")
		}
		ids[e.Identity.ID] = true
	}
	if roles["coordinator"] != 1 || roles["release-signer"] != 1 || roles["auditor"] < 2 || roles["participant"] < 1 || len(roles) != 4 {
		return j, errors.New("required ceremony roster is incomplete")
	}
	return j, nil
}

func (i Inspector) Journey() (Journey, error) {
	result, err := i.execute("inspect", "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath, "--transcript-dir", i.TranscriptRoot)
	if err != nil {
		return Journey{}, err
	}
	if result.Command != "inspect" || result.JourneyInspection == nil {
		return Journey{}, errors.New("proof-tool did not return authenticated journey metadata")
	}
	j := *result.JourneyInspection
	if j.Schema != "proof-tool-mpc-journey-inspection-v1" || j.CeremonyID == "" || (j.Mode != "rehearsal" && j.Mode != "production") || j.Depth != "metadata" || len(j.Phases) != 2 {
		return Journey{}, errors.New("invalid journey inspection")
	}
	seen := map[string]bool{}
	for _, p := range j.Phases {
		if (p.Phase != "phase1" && p.Phase != "phase2") || seen[p.Phase] || p.AcceptedCount < 0 || p.AcceptedCount > p.ScheduledTotal {
			return Journey{}, errors.New("invalid phase journey inspection")
		}
		seen[p.Phase] = true
		if p.Closed {
			if !p.Started || p.CloseID == "" || p.BeaconRound == 0 {
				return Journey{}, errors.New("incomplete authenticated closure")
			}
			for _, value := range []string{p.ClosedAt, p.BeaconScheduledAt, p.WitnessObservationDeadline} {
				if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
					return Journey{}, errors.New("invalid authenticated ceremony time")
				}
			}
			closed, _ := time.Parse(time.RFC3339Nano, p.ClosedAt)
			beacon, _ := time.Parse(time.RFC3339Nano, p.BeaconScheduledAt)
			deadline, _ := time.Parse(time.RFC3339Nano, p.WitnessObservationDeadline)
			if !closed.Before(beacon) || deadline.After(beacon) || !deadline.After(closed) {
				return Journey{}, errors.New("inconsistent authenticated ceremony times")
			}
		}
	}
	return j, nil
}

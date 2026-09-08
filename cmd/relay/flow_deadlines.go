package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func stagePhase(id string) string {
	for _, phase := range []string{"phase1", "phase2"} {
		if id == phase || strings.HasPrefix(id, phase+"-") {
			return phase
		}
	}
	return ""
}

func showPhaseTiming(out io.Writer, p transcript.PhaseJourney, now time.Time) {
	fmt.Fprintf(out, "Authenticated local %s: %d of %d scheduled contributions; checked %s. Not proof of global freshness.\n", p.Phase, p.AcceptedCount, p.ScheduledTotal, now.UTC().Format(time.RFC3339))
	if !p.Closed {
		fmt.Fprintln(out, "No authenticated closure in this local copy. Arrange witness readiness before closure.")
		return
	}
	fmt.Fprintf(out, "Closure: %s\nWitness observation deadline (UTC): %s\nCommitted beacon round: %d at %s (UTC)\n", p.CloseID, p.WitnessObservationDeadline, p.BeaconRound, p.BeaconScheduledAt)
	deadline, err := time.Parse(time.RFC3339Nano, p.WitnessObservationDeadline)
	if err != nil {
		fmt.Fprintln(out, "Needs attention: invalid observation deadline.")
		return
	}
	if now.After(deadline) {
		fmt.Fprintln(out, "Observation window has closed. Do not start a new observation or backdate a claim. Investigate missing evidence with the coordinator; genuinely retained on-time observations may still be reviewed and signed.")
	}
	if len(p.MissingArtifacts) > 0 {
		fmt.Fprintf(out, "Waiting: %d referenced artifacts are missing or have the wrong size.\n", len(p.MissingArtifacts))
	}
}

func (f *roleFlow) showCurrentPhase() {
	phase := stagePhase(f.stages[f.state.Stage].ID)
	if phase == "" || f.state.Profile.Work == "" {
		return
	}
	j, err := f.authenticatedJourney()
	if err != nil {
		fmt.Fprintf(f.ui.output, "Timing/state not verified: %v\n", err)
		return
	}
	for _, p := range j.Phases {
		if p.Phase == phase {
			showPhaseTiming(f.ui.output, p, time.Now().UTC())
		}
	}
}

func (f *roleFlow) checkObservationWindow(task flowTask) error {
	if f.state.Role != "witness" || task.ID != "observe" || f.state.Profile.Work == "" {
		return nil
	}
	j, err := f.authenticatedJourney()
	if err != nil {
		return err
	}
	phase := stagePhase(f.stages[f.state.Stage].ID)
	for _, p := range j.Phases {
		if p.Phase != phase {
			continue
		}
		if !p.Closed {
			return errors.New("no authenticated closure is available: obtain and verify the published closure before recording an observation")
		}
		deadline, err := time.Parse(time.RFC3339Nano, p.WitnessObservationDeadline)
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("witness observation window expired: investigate retained observations with the coordinator; do not retry a new observation or backdate it")
		}
		return nil
	}
	return errors.New("authenticated inspection did not include the observation phase")
}

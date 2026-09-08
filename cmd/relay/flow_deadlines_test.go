package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestPhaseTimingDistinguishesDeadlineAndLocalFreshness(t *testing.T) {
	p := transcript.PhaseJourney{Phase: "phase1", ScheduledTotal: 3, AcceptedCount: 3, Closed: true, CloseID: "closure-1", WitnessObservationDeadline: "2026-09-08T00:01:00Z", BeaconScheduledAt: "2026-09-08T00:02:00Z", BeaconRound: 10}
	deadline, _ := time.Parse(time.RFC3339, p.WitnessObservationDeadline)
	for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
		var out bytes.Buffer
		showPhaseTiming(&out, p, deadline.Add(delta))
		if !strings.Contains(out.String(), "Not proof of global freshness") {
			t.Fatal(out.String())
		}
		if strings.Contains(out.String(), "Observation window has closed") != (delta > 0) {
			t.Fatal(out.String())
		}
	}
	p.Closed = false
	var out bytes.Buffer
	showPhaseTiming(&out, p, deadline)
	if !strings.Contains(out.String(), "No authenticated closure") || strings.Contains(out.String(), "Committed beacon round") {
		t.Fatal(out.String())
	}
}

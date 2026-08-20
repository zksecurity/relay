package main

import (
	"reflect"
	"testing"
	"time"
)

func TestDefaultAcceptanceTimestampPreservesSubsecondOrdering(t *testing.T) {
	destroyedAt := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	acceptedAt := destroyedAt.Add(time.Nanosecond)

	encoded := defaultAcceptanceTimestamp(acceptedAt)
	decoded, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.After(destroyedAt) {
		t.Fatalf("accepted_at %q is not strictly after destroyed_at %q", encoded, destroyedAt.Format(time.RFC3339Nano))
	}
	if !decoded.Equal(acceptedAt) {
		t.Fatalf("accepted_at = %q, want %q", encoded, acceptedAt.Format(time.RFC3339Nano))
	}
}

func TestCandidateVerificationCommandUsesOperationalCLI(t *testing.T) {
	o := roleOpts{
		root: "/ceremony", definition: "/ceremony/ceremony.json",
		definitionSig: "/ceremony/ceremony.sig", coordinatorKey: "/trust/coordinator.hex",
		ceremonyBinary: "/trusted/mpc-ceremony", phase: "phase2",
		phase1Seal: "/sealed/phase1.json", phase1SealSig: "/sealed/phase1.sig",
	}
	command := candidateVerificationCommand(
		o, "/ceremony/phase2/chain-0000.json", "/ceremony/phase2/chain-0000.sig",
		"/candidate", "/keys/coordinator.private.hex", "2026-08-20T12:00:02Z",
	)
	want := []string{
		"/trusted/mpc-ceremony", "phase2", "verify",
		"--ceremony", "/ceremony/ceremony.json",
		"--ceremony-signature", "/ceremony/ceremony.sig",
		"--coordinator-public-key-file", "/trust/coordinator.hex",
		"--transcript-dir", "/ceremony",
		"--chain", "/ceremony/phase2/chain-0000.json",
		"--chain-signature", "/ceremony/phase2/chain-0000.sig",
		"--candidate-dir", "/candidate",
		"--coordinator-signing-key", "/keys/coordinator.private.hex",
		"--accepted-at", "2026-08-20T12:00:02Z",
		"--phase1-seal", "/sealed/phase1.json",
		"--phase1-seal-signature", "/sealed/phase1.sig",
	}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("candidate verification argv = %#v, want %#v", command.Args, want)
	}
}

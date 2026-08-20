package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAttestation(t *testing.T, contributedAt string) string {
	t.Helper()
	dir := t.TempDir()
	body := `{"schema":"x","contributed_at":"` + contributedAt + `"}`
	if err := os.WriteFile(filepath.Join(dir, "attestation.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestErasureTimestampStrictlyAfterContribution(t *testing.T) {
	contributed := time.Date(2026, 8, 20, 15, 25, 51, 0, time.UTC)

	// Normal case: hours of compute already separate the two stamps.
	later := contributed.Add(time.Hour)
	dir := writeAttestation(t, contributed.Format(time.RFC3339))
	if got := erasureTimestamp(dir, later); !got.Equal(later) {
		t.Fatalf("later timestamp rewritten to %v", got)
	}

	// Same-second confirmation: the tiny circuit contributes in under a
	// second, so destroyed_at must be pushed to the next whole second.
	sameSecond := contributed.Add(400 * time.Millisecond)
	got := erasureTimestamp(dir, sameSecond)
	if !got.Truncate(time.Second).After(contributed.Truncate(time.Second)) {
		t.Fatalf("destroyed_at %v is not strictly after contributed_at %v", got, contributed)
	}

	// Unreadable metadata must not block erasure: fall back to now.
	if got := erasureTimestamp(t.TempDir(), later); !got.Equal(later) {
		t.Fatalf("missing attestation changed timestamp to %v", got)
	}
	badDir := writeAttestation(t, "not-a-timestamp")
	if got := erasureTimestamp(badDir, later); !got.Equal(later) {
		t.Fatalf("unparseable attestation changed timestamp to %v", got)
	}
}

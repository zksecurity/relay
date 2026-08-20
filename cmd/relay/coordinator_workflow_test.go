package main

import (
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

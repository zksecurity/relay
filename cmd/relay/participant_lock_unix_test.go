//go:build darwin || linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParticipantRunLockIsExclusivePerWorkspace(t *testing.T) {
	candidates := filepath.Join(t.TempDir(), "candidates")
	profile := filepath.Join(t.TempDir(), "participant.json")
	first, err := acquireParticipantRunLock(profile, candidates)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.release() })

	if _, err := acquireParticipantRunLock(profile, candidates); err == nil ||
		!strings.Contains(err.Error(), "another Relay helper or run is already active") {
		t.Fatalf("concurrent lock error = %v", err)
	}

	if _, err := acquireParticipantRunLock(filepath.Join(t.TempDir(), "other.json"), candidates); err == nil ||
		!strings.Contains(err.Error(), "another Relay helper or run is already active") {
		t.Fatalf("copied profile bypassed workspace lock: %v", err)
	}

	other, err := acquireParticipantRunLock(filepath.Join(t.TempDir(), "other.json"), filepath.Join(t.TempDir(), "candidates"))
	if err != nil {
		t.Fatalf("separate workspace was blocked: %v", err)
	}
	if err := other.release(); err != nil {
		t.Fatal(err)
	}

	if err := first.release(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := acquireParticipantRunLock(profile, candidates)
	if err != nil {
		t.Fatalf("released profile lock could not be reacquired: %v", err)
	}
	if err := reacquired.release(); err != nil {
		t.Fatal(err)
	}
}

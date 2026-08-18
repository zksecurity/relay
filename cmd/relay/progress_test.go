package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunWithProgressReportsHeartbeatAndCompletion(t *testing.T) {
	originalInterval, originalOutput := progressHeartbeatInterval, progressOutput
	t.Cleanup(func() {
		progressHeartbeatInterval = originalInterval
		progressOutput = originalOutput
	})
	progressHeartbeatInterval = time.Millisecond
	var output bytes.Buffer
	progressOutput = &output

	if err := runWithProgress("phase1 contribution", func() error {
		time.Sleep(5 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"phase1 contribution: started",
		"phase1 contribution: still running",
		"phase1 contribution: completed",
		"elapsed",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("progress output missing %q:\n%s", want, output.String())
		}
	}
}

func TestRunWithProgressReportsFailure(t *testing.T) {
	originalInterval, originalOutput := progressHeartbeatInterval, progressOutput
	t.Cleanup(func() {
		progressHeartbeatInterval = originalInterval
		progressOutput = originalOutput
	})
	progressHeartbeatInterval = time.Hour
	var output bytes.Buffer
	progressOutput = &output
	want := errors.New("boom")
	if got := runWithProgress("candidate verification", func() error { return want }); !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	if !strings.Contains(output.String(), "candidate verification: failed") {
		t.Fatalf("failure output missing:\n%s", output.String())
	}
}

func TestFormatBytes(t *testing.T) {
	for _, test := range []struct {
		size int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{5 << 20, "5.0 MiB"},
		{3 << 30, "3.0 GiB"},
	} {
		if got := formatBytes(test.size); got != test.want {
			t.Errorf("formatBytes(%d) = %q, want %q", test.size, got, test.want)
		}
	}
}

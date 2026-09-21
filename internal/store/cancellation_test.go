package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAWSCommandCancellationReapsDirectChild(t *testing.T) {
	// exec replaces the shell with sleep: this tests a direct provider process,
	// not unsupported termination of arbitrary wrapper descendants.
	dir := installConditionalAWS(t, `printf started > "$RELAY_TEST_AWS_STARTED"
exec sleep 30
`)
	marker := filepath.Join(dir, "started")
	t.Setenv("RELAY_TEST_AWS_STARTED", marker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := Client{Bucket: "test"}
	client := original.WithContext(ctx)
	done := make(chan error, 1)
	go func() { _, err := client.HeadVersion("blob/test"); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("AWS helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AWS process did not exit on cancellation")
	}
	if original.ctx != nil {
		t.Fatal("WithContext changed shared client")
	}
}

func TestAWSPreCancelledCommandDoesNotStart(t *testing.T) {
	dir := installConditionalAWS(t, `printf started > "$RELAY_TEST_AWS_STARTED"`)
	marker := filepath.Join(dir, "started")
	t.Setenv("RELAY_TEST_AWS_STARTED", marker)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Client{Bucket: "test"}).WithContext(ctx).HeadVersion("blob/test")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled command executed")
	}
}

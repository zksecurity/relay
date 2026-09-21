package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
)

type uploadProgressTestWriter struct {
	bytes.Buffer
	heartbeat chan struct{}
}

func (w *uploadProgressTestWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("still running")) {
		select {
		case w.heartbeat <- struct{}{}:
		default:
		}
	}
	return w.Buffer.Write(p)
}

func TestCandidateUploadProgressHeartbeatAndStop(t *testing.T) {
	for _, failure := range []bool{false, true} {
		out := &uploadProgressTestWriter{heartbeat: make(chan struct{}, 1)}
		observe, finish := startCandidateUploadProgress(out, time.Millisecond)
		for i := 0; i < 20; i++ {
			observe(storagefirst.DeliveryProgress{Stage: "uploading", Name: "contribution.bin", Size: 1024, TotalBytes: 2048})
		}
		select {
		case <-out.heartbeat:
		case <-time.After(5 * time.Second):
			finish(errors.New("timeout"))
			t.Fatal("missing heartbeat")
		}
		var err error
		if failure {
			err = errors.New("secret-provider-error-sentinel")
		}
		finish(err)
		saved := out.String()
		time.Sleep(3 * time.Millisecond)
		if saved != out.String() {
			t.Fatal("heartbeat survived finish")
		}
		for _, want := range []string{"contribution.bin", "1.0 KiB", "0 B / 2.0 KiB confirmed in storage", "still running", "elapsed"} {
			if !strings.Contains(saved, want) {
				t.Fatalf("missing %q: %s", want, saved)
			}
		}
		if strings.Contains(saved, "secret-provider-error-sentinel") {
			t.Fatal("provider error leaked")
		}
		if failure && strings.Contains(saved, "Candidate upload complete") {
			t.Fatal("failure reported as success")
		}
		if !failure && !strings.Contains(saved, "waiting for coordinator verification and signed acceptance") {
			t.Fatal("missing acceptance distinction")
		}
	}
}

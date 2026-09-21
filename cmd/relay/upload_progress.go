package main

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
)

// The delivery observer reports completed objects, not streaming network bytes.
// Only this reporter's goroutine and synchronous observer write to its output;
// the provider continues to capture its own output and errors separately.
func startCandidateUploadProgress(out io.Writer, interval time.Duration) (func(storagefirst.DeliveryProgress), func(error)) {
	started := time.Now()
	var mu sync.Mutex
	var current storagefirst.DeliveryProgress
	print := func(heartbeat bool) {
		name := current.Name
		if current.Manifest {
			name = "final upload manifest"
		}
		prefix := "Candidate upload"
		if heartbeat {
			prefix += " still running"
		}
		if name == "" {
			fmt.Fprintf(out, "%s: preparing (%s elapsed)\n", prefix, formatElapsed(time.Since(started)))
			return
		}
		fmt.Fprintf(out, "%s: %s %s (%s); %s / %s confirmed in storage (%s elapsed)\n", prefix, current.Stage, name, formatBytes(current.Size), formatBytes(current.ConfirmedBytes), formatBytes(current.TotalBytes), formatElapsed(time.Since(started)))
	}
	print(false)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				mu.Lock()
				print(true)
				mu.Unlock()
			}
		}
	}()
	observe := func(event storagefirst.DeliveryProgress) {
		mu.Lock()
		defer mu.Unlock()
		current = event
		print(false)
	}
	finish := func(err error) {
		close(stop)
		<-stopped
		if err != nil {
			fmt.Fprintf(out, "Candidate upload stopped; retained files can be checked for retry (%s elapsed).\n", formatElapsed(time.Since(started)))
		} else {
			fmt.Fprintf(out, "Candidate upload complete; waiting for coordinator verification and signed acceptance (%s elapsed).\n", formatElapsed(time.Since(started)))
		}
	}
	return observe, finish
}

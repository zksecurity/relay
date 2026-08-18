package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

var (
	progressHeartbeatInterval           = time.Minute
	progressOutput            io.Writer = os.Stderr
)

// runWithProgress surrounds a potentially long operation with timestamped
// lifecycle messages and emits an elapsed-time heartbeat while it is silent.
// The operation's own stdout and stderr remain untouched, so proof-tool's real
// replay counters continue to appear between these messages.
func runWithProgress(label string, operation func() error) error {
	started := time.Now()
	writeProgress(label, "started", started, 0)

	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(progressHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				writeProgress(label, "still running", now, now.Sub(started))
			case <-stop:
				return
			}
		}
	}()

	err := operation()
	close(stop)
	<-stopped
	finished := time.Now()
	state := "completed"
	if err != nil {
		state = "failed"
	}
	writeProgress(label, state, finished, finished.Sub(started))
	return err
}

func writeProgress(label, state string, now time.Time, elapsed time.Duration) {
	if elapsed == 0 {
		fmt.Fprintf(progressOutput, "[%s] %s: %s\n", now.UTC().Format(time.RFC3339), label, state)
		return
	}
	fmt.Fprintf(
		progressOutput,
		"[%s] %s: %s (%s elapsed)\n",
		now.UTC().Format(time.RFC3339),
		label,
		state,
		formatElapsed(elapsed),
	)
}

func formatElapsed(elapsed time.Duration) string {
	if elapsed < time.Second {
		return "<1s"
	}
	return elapsed.Round(time.Second).String()
}

func formatBytes(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, unit := range units {
		value /= 1024
		if value < 1024 || unit == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
	}
	return fmt.Sprintf("%d B", size)
}

// This build-time runner is not distributed as a Relay launcher command.
// Its integration-test executable must come from the reviewed candidate source.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zksecurity/relay/internal/upgrade"
)

func run() error {
	input := flag.String("request", "", "private exact-asset qualification request JSON")
	out := flag.String("out", "", "fresh public report path")
	timeout := flag.Duration("timeout", 2*time.Hour, "total qualification deadline")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *out == "" || *timeout <= 0 || *timeout > 24*time.Hour {
		return errors.New("request, fresh report path and bounded timeout required")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("invalid qualification request file")
	}
	var request upgrade.QualificationRequest
	d := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	d.DisallowUnknownFields()
	if err := d.Decode(&request); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing qualification input")
	}
	if _, err := os.Lstat(*out); !errors.Is(err, os.ErrNotExist) {
		return errors.New("report output must not exist")
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, *timeout)
	defer cancel()
	q, err := upgrade.RunQualification(ctx, request)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return err
	}
	// Create-only publication: failed execution never creates a passing report.
	result, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := result.Write(raw); err != nil {
		result.Close()
		return err
	}
	if err := result.Sync(); err != nil {
		result.Close()
		return err
	}
	return result.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

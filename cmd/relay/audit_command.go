package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

type auditInputs []string

func (v *auditInputs) String() string { return "audit report directories" }
func (v *auditInputs) Set(value string) error {
	if len(*v) >= 64 {
		return errors.New("at most 64 audit inputs allowed")
	}
	*v = append(*v, value)
	return nil
}
func runAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("audit requires export or combine")
	}
	f := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	out := f.String("out", "", "fresh absolute output directory for report.json and report.md")
	switch args[0] {
	case "export":
		work := f.String("work", "", "absolute role workspace (recorded observations are not authenticated)")
		key := f.String("coordinator-key-file", "", "independently trusted coordinator public key; enables checkpoint authentication")
		tool := f.String("mpc-ceremony", "mpc-ceremony", "local proof tool matching this Relay release pin; requires coordinator-key-file")
		record := f.String("checkpoint", "", "selected checkpoint path relative to ceremony/public; not assumed latest")
		signature := f.String("checkpoint-signature", "", "selected signature path relative to ceremony/public")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *work == "" || *out == "" {
			return errors.New("audit export requires --work and --out")
		}
		toolSet := false
		f.Visit(func(v *flag.Flag) { toolSet = toolSet || v.Name == "mpc-ceremony" })
		if *key == "" && (toolSet || *record != "" || *signature != "") {
			return errors.New("checkpoint verification requires an independent --coordinator-key-file")
		}
		if *key != "" && (*record == "" || *signature == "") {
			return errors.New("verification requires explicit --checkpoint and --checkpoint-signature")
		}
		report, err := buildAuditExport(*work)
		if err != nil {
			return err
		}
		var verificationErr error
		if *key != "" {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			report.Verification, verificationErr = verifyAuditCheckpoint(ctx, *work, *key, *tool, *record, *signature, report)
		}
		if err := writeAuditReport(*out, report); err != nil {
			return err
		}
		if verificationErr != nil {
			return fmt.Errorf("audit report written with failed verification: %w", verificationErr)
		}
		fmt.Fprintln(os.Stdout, "Audit report written. Local observations remain unauthenticated; inspect coverage gaps in report.md.")
		return nil
	case "combine":
		var inputs auditInputs
		f.Var(&inputs, "input", "absolute role export directory; repeat for each role")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || len(inputs) == 0 || *out == "" {
			return errors.New("audit combine requires --input and --out")
		}
		report, err := combineAuditExports(inputs)
		if err != nil {
			return err
		}
		if err = writeAuditReport(*out, report); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Combined audit written. Imported verification results are exporter claims, not independently reverified evidence.")
		return nil
	default:
		return errors.New("audit requires export or combine")
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/verification"
)

type verificationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type verificationReport struct {
	Schema     string              `json:"schema"`
	CeremonyID string              `json:"ceremony_id"`
	Passed     bool                `json:"passed"`
	Trust      string              `json:"trust"`
	Checks     []verificationCheck `json:"checks"`
	Limits     []string            `json:"not_established"`
}
type publicVerifyRunner func(args ...string) ([]byte, error)

func runVerifyCeremony(args []string) error {
	f := flag.NewFlagSet("verify-ceremony", flag.ContinueOnError)
	archive := f.String("archive", "", "public verification ZIP downloaded from Tessera")
	tool := f.String("mpc-ceremony", "mpc-ceremony", "locally installed proof tool; must match this release's pin")
	maxBytes := f.Int64("max-expanded-bytes", 64<<30, "maximum extracted bytes (raise explicitly for larger production archives)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *archive == "" || f.NArg() != 0 {
		return errors.New("--archive is required")
	}
	// This pin is compiled into the installed CLI, never supplied by the archive.
	measured, err := measuredReleaseTools(*tool)
	if err != nil {
		return fmt.Errorf("approved local verifier unavailable: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, measured.ProofPath, append([]string{"--format", "json"}, args...)...)
		var out limitedVerificationOutput
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return out.Bytes(), err
		}
		return out.Bytes(), nil
	}
	report, err := verifyCeremonyArchive(*archive, *maxBytes, run)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return err
}

// A broken verifier cannot fill memory with command output.
type limitedVerificationOutput struct{ bytes.Buffer }

func (b *limitedVerificationOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("verifier output exceeds 1 MiB")
	}
	return b.Buffer.Write(p)
}
func verifyCeremonyArchive(archive string, maxBytes int64, run publicVerifyRunner) (report verificationReport, err error) {
	report = verificationReport{Schema: "ceremony-verification-report-v1", Trust: "Ceremony identity and public keys supplied by the website hosting this archive.", Limits: []string{"Secret deletion and entropy quality", "Physical offline signing and host integrity", "Independence of people controlling different keys", "Truth of website progress claims beyond signed protocol evidence", "Whether this website snapshot is the latest"}}
	for _, name := range []string{"archive-integrity", "definition", "release", "full-replay", "production-approval"} {
		report.Checks = append(report.Checks, verificationCheck{Name: name, Status: "not-run"})
	}
	fail := func(index int, e error) (verificationReport, error) {
		report.Checks[index].Status = "failed"
		if errors.Is(e, os.ErrNotExist) || strings.Contains(e.Error(), "missing evidence") {
			report.Checks[index].Status = "missing-evidence"
		}
		report.Checks[index].Detail = e.Error()
		return report, e
	}
	root, m, e := verification.Extract(archive, maxBytes)
	if e != nil {
		return fail(0, e)
	}
	defer os.RemoveAll(root)
	report.CeremonyID = m.CeremonyID
	report.Checks[0].Status = "passed"
	p := func(name string) string { return filepath.Join(root, filepath.FromSlash(name)) }
	trust := []string{"--ceremony", p(m.Inputs["ceremony"]), "--ceremony-signature", p(m.Inputs["ceremony-signature"]), "--coordinator-public-key-file", p(m.Inputs["coordinator-public-key-file"])}
	inspector := transcript.Inspector{CeremonyPath: p(m.Inputs["ceremony"]), CeremonySignaturePath: p(m.Inputs["ceremony-signature"]), CoordinatorPublicKeyPath: p(m.Inputs["coordinator-public-key-file"]), Runner: func(_ string, args ...string) ([]byte, []byte, error) {
		if len(args) >= 2 && args[0] == "--format" {
			args = args[2:]
		}
		raw, e := run(args...)
		return raw, nil, e
	}}
	definition, e := inspector.Definition()
	if e != nil {
		return fail(1, e)
	}
	if definition.CeremonyID != m.CeremonyID {
		return fail(1, errors.New("archive identity differs from authenticated definition"))
	}
	if definition.Mode != "production" && definition.Mode != "rehearsal" {
		return fail(1, errors.New("unrecognized authenticated ceremony mode"))
	}
	report.Checks[1].Status = "passed"
	var releaseManifestSHA string
	check := func(index int, command []string, flags []string) error {
		raw, e := run(append(append(command, trust...), flags...)...)
		if e != nil {
			return fmt.Errorf("%s: %w", report.Checks[index].Name, e)
		}
		var result struct {
			Schema                string `json:"schema"`
			OK                    bool   `json:"ok"`
			Command               string `json:"command"`
			CeremonyID            string `json:"ceremony_id"`
			ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
			Decision              string `json:"decision"`
		}
		if e = json.Unmarshal(raw, &result); e != nil {
			return e
		}
		if result.Schema != "proof-tool-mpc-command-result-v1" || !result.OK || result.Command != strings.Join(command, " ") {
			return errors.New("verifier returned no matching successful result")
		}
		if result.CeremonyID != m.CeremonyID {
			return errors.New("replayed ceremony identity differs from archive")
		}
		if index == 2 {
			if !strings.HasPrefix(result.ReleaseManifestSHA256, "sha256:") || !sha256HexPattern.MatchString(strings.TrimPrefix(result.ReleaseManifestSHA256, "sha256:")) {
				return errors.New("verifier did not identify the released manifest")
			}
			releaseManifestSHA = result.ReleaseManifestSHA256
		}
		if index == 4 {
			if result.Decision != "GO" {
				return errors.New("production decision is not GO")
			}
			if result.ReleaseManifestSHA256 != releaseManifestSHA {
				return errors.New("production approval refers to another release")
			}
		}
		report.Checks[index].Status = "passed"
		return nil
	}
	if e = check(2, []string{"release", "verify"}, []string{"--keys-dir", p(m.Inputs["keys-dir"]), "--manifest-public-key-file", p(m.Inputs["manifest-public-key-file"]), "--signature-key-id", m.ReleaseKeyID}); e != nil {
		return fail(2, e)
	}
	replay := []string{"--candidate-bundle", p(m.Inputs["keys-dir"])}
	for _, key := range verification.RequiredInputs {
		if key == "transcript-root" || strings.HasPrefix(key, "phase") {
			replay = append(replay, "--"+key, p(m.Inputs[key]))
		}
	}
	if e = check(3, []string{"replay"}, replay); e != nil {
		return fail(3, e)
	}
	if m.Decision == nil {
		if definition.Mode == "production" {
			return fail(4, errors.New("missing evidence: production approval record and signatures"))
		}
		report.Checks[4].Status = "not-applicable"
		report.Checks[4].Detail = "Signed ceremony is a rehearsal; no production approval claimed."
	} else {
		decision := []string{"--decision", p(m.Decision.Record), "--evidence-root", p(m.Decision.EvidenceRoot)}
		for _, sig := range m.Decision.Signatures {
			decision = append(decision, "--signature", p(sig))
		}
		if e = check(4, []string{"decision", "verify"}, decision); e != nil {
			return fail(4, e)
		}
	}
	report.Passed = true
	return report, nil
}

var _ io.Writer = (*limitedVerificationOutput)(nil)

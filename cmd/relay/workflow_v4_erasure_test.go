package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

type erasureClientV4 struct {
	*dockerClientFake
	calls int
	fail  bool
}

func (f *erasureClientV4) BindHost(host string) dockerCommandClient { f.host = host; return f }
func (f *erasureClientV4) Attached(io.Writer, io.Writer, ...string) error {
	f.calls++
	if f.fail {
		return errors.New("lost child response")
	}
	return nil
}

func TestWorkflowV4ErasureExecutionDoesNotReplay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "returned", true: "interrupted"}[fail], func(t *testing.T) {
			protocol, binding := workflowV4TestBinding(t)
			p := workflowV4TestPlan(t, binding)
			prior := p
			j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			if err := j.prepare(prior); err != nil {
				t.Fatal(err)
			}
			if err := j.runPrepared(prior.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := j.reconcile(prior.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
				t.Fatal(err)
			}
			oldRoot := filepath.Join(binding.Work, "workflow-v4", "inputs", p.ID)
			p.ID = strings.Repeat("2", 32)
			newRoot := filepath.Join(binding.Work, "workflow-v4", "inputs", p.ID)
			p.Inputs = append([]workflowV4Input(nil), p.Inputs...)
			for n, in := range p.Inputs {
				if !strings.HasPrefix(in.Path, oldRoot+string(filepath.Separator)) {
					continue
				}
				data, err := os.ReadFile(in.Path)
				if err != nil {
					t.Fatal(err)
				}
				p.Inputs[n].Path = strings.Replace(in.Path, oldRoot, newRoot, 1)
				if err := os.MkdirAll(filepath.Dir(p.Inputs[n].Path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p.Inputs[n].Path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			p.Kind, p.Runtime = "attest-erasure", binding.Runtimes["signer"]
			root := "/work/workflow-v4/inputs/" + p.ID
			p.Command = []string{"mpc-ceremony", "phase1", "attest-erasure", "--ceremony", root + "/ceremony.json", "--ceremony-signature", root + "/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator.hex", "--participant-id", p.Scope.ParticipantID, "--participant-signing-key", "/keys/signing.hex", "--candidate-dir", "/work/candidate", "--destroyed-at", "2026-09-16T00:00:00Z"}
			candidate := filepath.Join(binding.Work, "candidate")
			if err := os.Mkdir(candidate, 0700); err != nil {
				t.Fatal(err)
			}
			p.Outputs = []string{filepath.Join(candidate, "erasure.json"), filepath.Join(candidate, "erasure.sig")}
			// Obtain realistic lifecycle facts from the existing isolated-driver fixture.
			o, pos, driver, original := dockerContributionFixture(t)
			o.operationID = prior.ID
			driver.executionIntentPath = workflowV4ContributorIntentPath(binding.Work, prior.ID)
			if err := runNextAt(o, pos, time.Now()); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(o.outDir, dockerLifecycleLogName))
			if err != nil {
				t.Fatal(err)
			}
			var receipt dockerLifecycleReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Image, receipt.Platform = p.Runtime.Image, p.Runtime.Platform
			var intent dockerActiveState
			if err := readWorkflowV4JSON(driver.executionIntentPath, &intent); err != nil {
				t.Fatal(err)
			}
			intent.Image = receipt.Image
			if err := writeJSONAtomic(driver.executionIntentPath, intent, 0600); err != nil {
				t.Fatal(err)
			}
			destination := sha256.Sum256([]byte(candidate))
			receipt.CandidateDirectorySHA256 = fmt.Sprintf("sha256:%x", destination)
			if runtime.GOOS == "darwin" {
				receipt.HostSwapStatus = dockerMacSwapUnassessed
			}
			receipt.ParticipantConfirmation = "CLEANUP PRECAUTIONS CONFIRMED"
			receipt.ConfirmedAt, receipt.ErasureDestroyedAt = "2026-09-16T00:00:00Z", "2026-09-16T00:00:00Z"
			receipt.CreatedAt, receipt.StartedAt = "2026-09-15T23:59:57Z", "2026-09-15T23:59:58Z"
			receipt.ExitedAt, receipt.RemovedAt = "2026-09-15T23:59:59Z", "2026-09-16T00:00:00Z"
			raw, _ = json.Marshal(receipt)
			files := []transcript.ArtifactRef{}
			for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", dockerLifecycleLogName} {
				contents := name
				if name == dockerLifecycleLogName {
					contents = string(raw)
				}
				path := filepath.Join(candidate, name)
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				ref := workflowV4TestRef(name, contents)
				p.Inputs = append(p.Inputs, workflowV4Input{Path: path, Ref: ref})
				if name != dockerLifecycleLogName {
					files = append(files, ref)
				}
			}
			if err := os.WriteFile(filepath.Join(p.Runtime.Mounts["/keys"], "signing.hex"), []byte("synthetic-key"), 0600); err != nil {
				t.Fatal(err)
			}
			i := transcript.Inspector{Executable: "approved-test-tool", CeremonyPath: p.Inputs[2].Path, CeremonySignaturePath: p.Inputs[3].Path, CoordinatorPublicKeyPath: p.Inputs[4].Path, TranscriptRoot: filepath.Dir(p.Inputs[2].Path)}
			i.Runner = func(string, ...string) ([]byte, []byte, error) {
				result := map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "inspect computation-output-v4", "computation_output_v4": transcript.ComputationOutputInspectionV4{Schema: "proof-tool-mpc-computation-output-inspection-v4", Depth: "computation-signatures-and-digests", SignaturesVerified: true, PayloadDigestVerified: true, Output: transcript.ComputationOutputFactsV4{Scope: p.Scope, Predecessor: p.Predecessor, Files: files}}}
				b, err := json.Marshal(result)
				return b, nil, err
			}
			if err := j.prepare(p); err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*dockerLifecycleReceipt){
				func(r *dockerLifecycleReceipt) { r.OperationID = strings.Repeat("f", 32) },
				func(r *dockerLifecycleReceipt) { r.CandidateDirectorySHA256 = "sha256:" + strings.Repeat("f", 64) },
				func(r *dockerLifecycleReceipt) { r.CreateArgsSHA256 = "sha256:" + strings.Repeat("f", 64) },
				func(r *dockerLifecycleReceipt) { r.WorkspaceID = "sha256:" + strings.Repeat("f", 64) },
			} {
				bad := receipt
				mutate(&bad)
				if err := j.validateCleanupContribution(p, bad, candidate); err == nil {
					t.Fatal("accepted unrelated lifecycle")
				}
			}
			f := &erasureClientV4{dockerClientFake: original, fail: fail}
			f.platform = p.Runtime.Platform
			wrong := i
			wrong.CoordinatorPublicKeyPath = "another-key"
			if err := j.runPreparedErasure(p.ID, wrong, "scope.json", f); err == nil || f.calls != 0 {
				t.Fatal("started cleanup with another trust anchor")
			}
			err = j.runPreparedErasure(p.ID, i, "scope.json", f)
			if (fail && (err == nil || !strings.Contains(err.Error(), "lost child response"))) || (!fail && err != nil) || f.calls != 1 {
				t.Fatalf("child boundary: calls=%d err=%v", f.calls, err)
			}
			op, err := j.pending()
			want := "returned-needs-verification"
			if fail {
				want = "running"
			}
			if err != nil || op == nil || op.Status != want {
				t.Fatalf("unexpected completion claim: %+v %v", op, err)
			}
			if err := j.close(); err != nil {
				t.Fatal(err)
			}
			j, err = openWorkflowV4Journal(protocol, binding.Definition, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			if err := j.runPreparedErasure(p.ID, i, "scope.json", f); err == nil || f.calls != 1 {
				t.Fatal("replayed uncertain cleanup")
			}
		})
	}
}

func TestWorkflowV4LifecycleChronology(t *testing.T) {
	r := dockerLifecycleReceipt{ExecutionMode: dockerExecutionMode, CreatedAt: "2026-09-16T00:00:00Z", StartedAt: "2026-09-16T00:00:01Z", ExitedAt: "2026-09-16T00:00:02Z", RemovedAt: "2026-09-16T00:00:03.1Z", ConfirmedAt: "2026-09-16T00:00:03.2Z", ErasureDestroyedAt: "2026-09-16T00:00:04Z"}
	if err := validateWorkflowV4LifecycleTimes(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*dockerLifecycleReceipt){
		func(r *dockerLifecycleReceipt) { r.ExecutionMode = "native" },
		func(r *dockerLifecycleReceipt) { r.ErasureDestroyedAt = "2026-09-16T00:00:03Z" },
		func(r *dockerLifecycleReceipt) { r.ConfirmedAt = "2026-09-16T00:00:03.05Z" },
		func(r *dockerLifecycleReceipt) { r.RemovedAt = "2026-09-16T00:00:01Z" },
		func(r *dockerLifecycleReceipt) { r.ErasureDestroyedAt = "2026-09-16T00:00:02Z" },
		func(r *dockerLifecycleReceipt) { r.StartedAt = "2026-09-16T00:00:01+00:00" },
	} {
		bad := r
		mutate(&bad)
		if err := validateWorkflowV4LifecycleTimes(bad); err == nil {
			t.Fatal("accepted invalid lifecycle chronology")
		}
	}
}

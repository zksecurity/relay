package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

// reconcileCandidateOperation verifies outputs without rerunning either child.
// Returned facts are for this exact scope and must be refreshed for later work.
func (j *workflowV4Journal) reconcileCandidateOperation(id, scopeFile, dockerCLI string) (storagefirst.LocalTurnV4, error) {
	var facts storagefirst.LocalTurnV4
	if j.lock == nil || j.writeErr != nil {
		return facts, errors.New("active healthy V4 workspace required")
	}
	var op *workflowV4Operation
	for n := range j.state.Operations {
		if j.state.Operations[n].Plan.ID == id {
			op = &j.state.Operations[n]
			break
		}
	}
	if op == nil || op.Plan.ID != id || (op.Plan.Kind != "contribute" && op.Plan.Kind != "attest-erasure") {
		return facts, errors.New("retained contribution or cleanup operation required")
	}
	if op.Status != "running" && op.Status != "returned-needs-verification" && op.Status != "reconciled" {
		return facts, errors.New("operation has not produced inspectable output")
	}
	if !filepath.IsAbs(dockerCLI) || filepath.Clean(dockerCLI) != dockerCLI {
		return facts, errors.New("exact local Docker CLI path required")
	}
	inspect := func(p workflowV4OperationPlan) error {
		if err := workflowV4InputsMatch(p); err != nil {
			return err
		}
		candidate := p.Outputs[0]
		if p.Kind == "attest-erasure" {
			candidate = filepath.Dir(candidate)
		}
		var receipt dockerLifecycleReceipt
		if err := readWorkflowV4JSON(filepath.Join(candidate, dockerLifecycleLogName), &receipt); err != nil {
			return err
		}
		if p.Kind == "contribute" {
			if err := validateWorkflowV4OrderedTimes(receipt.ExecutionMode, []string{receipt.CreatedAt, receipt.StartedAt, receipt.ExitedAt, receipt.RemovedAt}); err != nil {
				return err
			}
			if err := j.validateContributionLifecycle(p, receipt, candidate); err != nil {
				return err
			}
		} else {
			if err := j.validateCleanupContribution(p, receipt, candidate); err != nil {
				return err
			}
			if err := validateWorkflowV4LifecycleTimes(receipt); err != nil {
				return err
			}
			if receipt.ParticipantConfirmation != "CLEANUP PRECAUTIONS CONFIRMED" {
				return errors.New("missing recorded cleanup confirmation")
			}
			if err := workflowV4InputsMatch(p); err != nil {
				return err
			}
		}
		if !validDockerLifecycleSchema(receipt.Schema) || receipt.ExecutionMode != dockerExecutionMode || !receipt.RemovalVerified || receipt.ExitCode != 0 || !validContainerID(receipt.ContainerID) || !verifiedDaemonFacts(receipt.Daemon) || !verifiedLifecycleFacts(receipt.Schema, receipt.Security) || !verifiedHostSwapStatus(runtime.GOOS, receipt.HostSwapStatus) {
			return errors.New("retained contributor lifecycle is incomplete")
		}
		if err := validateLocalDockerEndpoint(receipt.Daemon.Endpoint); err != nil {
			return err
		}
		client := osDockerCommandClient{binary: dockerCLI}.BindHost(receipt.Daemon.Endpoint)
		d := &dockerDriver{client: client, daemon: receipt.Daemon}
		if err := d.authenticateDaemon(); err != nil {
			return err
		}
		stdout, _, err := d.client.Output("container", "ls", "--all", "--no-trunc", "--filter", "id="+receipt.ContainerID, "--format", "{{.ID}}")
		if err != nil || strings.TrimSpace(string(stdout)) != "" {
			return errors.New("original contributor absence is not verified")
		}
		i, err := workflowV4CandidateInspector(p, j.state.Marker.Binding, scopeFile, client, receipt.Daemon)
		if err != nil {
			return err
		}
		var chain, signature string
		for _, in := range p.Inputs {
			if in.Ref == p.Predecessor.Record {
				chain = in.Path
			}
			if in.Ref == p.Predecessor.Signature {
				signature = in.Path
			}
		}
		if chain == "" || signature == "" {
			return errors.New("exact retained predecessor missing")
		}
		generated, err := i.ComputationOutputV4(chain, signature, scopeFile, candidate, p.Scope, p.Predecessor)
		if err != nil {
			return err
		}
		facts.Scope = p.Scope
		facts.CandidateAttemptID = p.AttemptID
		facts.GeneratedOutput = &generated
		if p.Kind == "attest-erasure" {
			inventory, err := i.ContributionInventoryV4(chain, signature, scopeFile, candidate, p.Scope, p.Predecessor)
			if err != nil {
				return err
			}
			facts.CandidateInventory = &inventory
			facts.ComputedCandidateID = inventory.ComputedCandidateID
			facts.CandidateResultID = inventory.CandidateResultID
			if err := verifyWorkflowV4CleanupTime(p, receipt, inventory.Computed.Files[3]); err != nil {
				return err
			}
		}
		return nil
	}
	var err error
	if op.Status == "reconciled" {
		err = inspect(op.Plan)
	} else {
		err = j.reconcile(id, inspect)
	}
	if err != nil {
		return storagefirst.LocalTurnV4{}, err
	}
	return facts, nil
}

func verifyWorkflowV4CleanupTime(p workflowV4OperationPlan, r dockerLifecycleReceipt, ref transcript.ArtifactRef) error {
	var expected string
	for n, arg := range p.Command {
		if arg == "--destroyed-at" && n+1 < len(p.Command) {
			expected = p.Command[n+1]
		}
	}
	if expected == "" || expected != r.ErasureDestroyedAt || ref.Name != "erasure.json" || len(p.Outputs) != 2 {
		return errors.New("cleanup time differs from the saved operation")
	}
	raw, err := readTesseraRegularFile(p.Outputs[0], 16<<20, false)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if int64(len(raw)) != ref.Digest.Size || fmt.Sprintf("sha256:%x", sum) != ref.Digest.SHA256 {
		return errors.New("verified cleanup record changed")
	}
	var record struct {
		DestroyedAt string `json:"destroyed_at"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return err
	}
	if record.DestroyedAt != expected {
		return errors.New("signed cleanup record has another destruction time")
	}
	return nil
}

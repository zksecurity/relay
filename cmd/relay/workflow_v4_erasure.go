package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

// executePreparedErasure is the production entry point. Tests inject dependencies
// only into runPreparedErasure; callers here cannot substitute a verifier runner.
func (j *workflowV4Journal) executePreparedErasure(id, scopeFile, dockerCLI string) error {
	op, err := j.pending()
	if err != nil {
		return err
	}
	if op == nil || op.Plan.ID != id || op.Plan.Kind != "attest-erasure" {
		return errors.New("prepared cleanup operation required")
	}
	if !filepath.IsAbs(dockerCLI) || filepath.Clean(dockerCLI) != dockerCLI {
		return errors.New("exact local Docker CLI path required")
	}
	client := osDockerCommandClient{binary: dockerCLI}
	var receipt dockerLifecycleReceipt
	if len(op.Plan.Outputs) != 2 {
		return errors.New("cleanup output pair required")
	}
	if err := readWorkflowV4JSON(filepath.Join(filepath.Dir(op.Plan.Outputs[0]), dockerLifecycleLogName), &receipt); err != nil {
		return err
	}
	i, err := workflowV4CandidateInspector(op.Plan, j.state.Marker.Binding, scopeFile, client, receipt.Daemon)
	if err != nil {
		return err
	}
	return j.runPreparedErasure(id, i, scopeFile, client)
}

// runPreparedErasure executes only an already reviewed, persisted cleanup
// operation. The inspector must use the approved contributor runtime. It never
// supplies the operator confirmation or retries a started signing operation.
func (j *workflowV4Journal) runPreparedErasure(id string, inspector transcript.Inspector, scopeFile string, client dockerCommandClient) error {
	op, err := j.pending()
	if err != nil {
		return err
	}
	if op == nil || op.Plan.ID != id || op.Plan.Kind != "attest-erasure" || op.Status != "prepared" || client == nil {
		return errors.New("a prepared cleanup-signing operation is required")
	}
	p := op.Plan
	b := j.state.Marker.Binding
	if err := validateWorkflowV4Plan(p, b); err != nil {
		return err
	}
	if err := workflowV4InputsMatch(p); err != nil {
		return err
	}
	flags := map[string]string{}
	for n := 3; n < len(p.Command); n += 2 {
		flags[p.Command[n]] = p.Command[n+1]
	}
	host := func(container string) (string, error) {
		for destination, source := range p.Runtime.Mounts {
			if mapped, err := pathWithin(destination, container, source); err == nil {
				return mapped, nil
			}
		}
		return "", errors.New("cleanup path has no saved mount")
	}
	paths := map[string]string{}
	for _, flag := range []string{"--ceremony", "--ceremony-signature", "--coordinator-public-key-file", "--participant-signing-key", "--candidate-dir"} {
		paths[flag], err = host(flags[flag])
		if err != nil {
			return err
		}
	}
	if inspector.Runner == nil || inspector.CeremonyPath != paths["--ceremony"] || inspector.CeremonySignaturePath != paths["--ceremony-signature"] || inspector.CoordinatorPublicKeyPath != paths["--coordinator-public-key-file"] {
		return errors.New("cleanup requires the exact definition and container-backed inspector")
	}
	var chain, signature string
	for _, input := range p.Inputs {
		if input.Ref == p.Predecessor.Record {
			chain = input.Path
		}
		if input.Ref == p.Predecessor.Signature {
			signature = input.Path
		}
	}
	if chain == "" || signature == "" {
		return errors.New("cleanup lacks the exact predecessor")
	}
	if _, err := inspector.ComputationOutputV4(chain, signature, scopeFile, paths["--candidate-dir"], p.Scope, p.Predecessor); err != nil {
		return err
	}
	var receipt dockerLifecycleReceipt
	if err := readWorkflowV4JSON(filepath.Join(paths["--candidate-dir"], dockerLifecycleLogName), &receipt); err != nil {
		return err
	}
	contributor := b.Runtimes["contributor"]
	if err := j.validateCleanupContribution(p, receipt, paths["--candidate-dir"]); err != nil {
		return err
	}
	if err := validateWorkflowV4LifecycleTimes(receipt); err != nil {
		return err
	}
	when, _ := time.Parse(time.RFC3339, flags["--destroyed-at"])
	confirmed, confirmErr := time.Parse(time.RFC3339Nano, receipt.ConfirmedAt)
	if !validDockerLifecycleSchema(receipt.Schema) || receipt.Image != contributor.Image || receipt.Platform != contributor.Platform || !receipt.RemovalVerified || receipt.ExitCode != 0 || !validContainerID(receipt.ContainerID) || !verifiedDaemonFacts(receipt.Daemon) || !verifiedLifecycleFacts(receipt.Schema, receipt.Security) || !verifiedHostSwapStatus(runtime.GOOS, receipt.HostSwapStatus) || receipt.ParticipantConfirmation != "CLEANUP PRECAUTIONS CONFIRMED" || confirmErr != nil || confirmed.IsZero() || receipt.ErasureDestroyedAt != flags["--destroyed-at"] {
		return errors.New("cleanup requires the original verified lifecycle and recorded confirmation/time")
	}
	d := &dockerDriver{image: p.Runtime.Image, platform: p.Runtime.Platform, definition: paths["--ceremony"], definitionSig: paths["--ceremony-signature"], coordinatorKey: paths["--coordinator-public-key-file"], signingKey: paths["--participant-signing-key"], client: client, daemon: receipt.Daemon}
	if err := validateLocalDockerEndpoint(receipt.Daemon.Endpoint); err != nil {
		return err
	}
	d.client = client.BindHost(receipt.Daemon.Endpoint)
	if err := d.authenticateDaemon(); err != nil {
		return err
	}
	platform, _, err := d.client.Output("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", d.image)
	if err != nil || strings.TrimSpace(string(platform)) != d.platform {
		return errors.New("original cleanup signing image/platform is unavailable")
	}
	stdout, _, err := d.client.Output("container", "ls", "--all", "--no-trunc", "--filter", "id="+receipt.ContainerID, "--format", "{{.ID}}")
	if err != nil || strings.TrimSpace(string(stdout)) != "" {
		return errors.New("original contributor absence could not be confirmed")
	}
	command, err := d.erasureCommand(roleOpts{phase: p.Scope.Phase, role: p.Scope.ParticipantID, outDir: paths["--candidate-dir"]}, when)
	if err != nil {
		return err
	}
	// Retain the exact rewritten child invocation before the running boundary.
	intentPath := filepath.Join(b.Work, "workflow-v4", "execution-"+id+".json")
	if err := validateCommitLocalPath(intentPath); err != nil {
		return err
	}
	if _, err := os.Lstat(intentPath); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONNoReplace(intentPath, command, 0600); err != nil {
			return err
		}
	} else {
		var retained []string
		if err := readWorkflowV4JSON(intentPath, &retained); err != nil {
			return err
		}
		if !reflect.DeepEqual(retained, command) {
			return errors.New("cleanup invocation differs from retained intent")
		}
	}
	return j.runPrepared(id, func(workflowV4OperationPlan) error {
		return d.client.Attached(os.Stdout, os.Stderr, command...)
	})
}

func validateWorkflowV4LifecycleTimes(r dockerLifecycleReceipt) error {
	return validateWorkflowV4OrderedTimes(r.ExecutionMode, []string{r.CreatedAt, r.StartedAt, r.ExitedAt, r.RemovedAt, r.ConfirmedAt, r.ErasureDestroyedAt})
}

func validateWorkflowV4OrderedTimes(mode string, values []string) error {
	if mode != dockerExecutionMode {
		return errors.New("cleanup lifecycle must describe Docker execution")
	}
	var previous time.Time
	for _, value := range values {
		current, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || current.IsZero() || !strings.HasSuffix(value, "Z") {
			return errors.New("cleanup lifecycle requires UTC timestamps")
		}
		if !previous.IsZero() && current.Before(previous) {
			return errors.New("cleanup lifecycle timestamps are out of order")
		}
		previous = current
	}
	return nil
}

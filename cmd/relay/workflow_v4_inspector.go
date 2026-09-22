package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/zksecurity/relay/internal/transcript"
)

// workflowV4CandidateInspector uses the original contributor image for retained
// output inspection. Its mounts are public, read-only and limited to this
// operation's retained transcript, candidate, scope and definition trust files.
func workflowV4CandidateInspector(p workflowV4OperationPlan, b workflowV4Binding, scopeFile string, client dockerCommandClient, daemon dockerDaemonFacts) (transcript.Inspector, error) {
	var zero transcript.Inspector
	if client == nil {
		return zero, errors.New("Docker client required")
	}
	if err := validateWorkflowV4Plan(p, b); err != nil {
		return zero, err
	}
	if p.Kind != "contribute" && p.Kind != "attest-erasure" {
		return zero, errors.New("unsupported candidate inspection operation")
	}
	if err := validateCommitLocalPath(scopeFile); err != nil {
		return zero, err
	}
	if _, err := pathWithin(b.Work, scopeFile, "/work"); err != nil {
		return zero, err
	}
	r := b.Runtimes["contributor"]
	inputRoot, err := workflowV4PredecessorInputRoot(p, b.Work)
	if err != nil {
		return zero, err
	}
	d := &dockerDriver{image: r.Image, platform: r.Platform, root: inputRoot, inspectionRoot: b.Work, client: client}
	if daemon.Endpoint != "" {
		if err := validateLocalDockerEndpoint(daemon.Endpoint); err != nil {
			return zero, err
		}
		if !verifiedDaemonFacts(daemon) {
			return zero, errors.New("incomplete original Docker endpoint identity")
		}
		d.daemon = daemon
		d.client = client.BindHost(daemon.Endpoint)
	}
	for _, in := range p.Inputs {
		switch in.Ref {
		case b.Definition.Record:
			d.definition = in.Path
		case b.Definition.Signature:
			d.definitionSig = in.Path
		}
	}
	// The key path is taken from the validated saved command, not discovered
	// from storage or selected from arbitrary files in the transcript.
	for n, arg := range p.Command {
		if arg == "--coordinator-public-key-file" {
			for destination, source := range p.Runtime.Mounts {
				if path, err := pathWithin(destination, p.Command[n+1], source); err == nil {
					d.coordinatorKey = path
					break
				}
			}
		}
	}
	candidate := p.Outputs[0]
	if p.Kind == "attest-erasure" {
		candidate = filepath.Dir(candidate)
	}
	i := transcript.Inspector{Executable: "mpc-ceremony", CeremonyPath: d.definition, CeremonySignaturePath: d.definitionSig, CoordinatorPublicKeyPath: d.coordinatorKey, TranscriptRoot: d.root}
	i.Runner = func(executable string, args ...string) ([]byte, []byte, error) {
		if executable != "mpc-ceremony" || len(args) < 4 || !reflect.DeepEqual(args[:3], []string{"--format", "json", "inspect"}) || (args[3] != "computation-output-v4" && args[3] != "contribution-inventory-v4") {
			return nil, nil, errors.New("candidate inspector cannot execute another command")
		}
		if err := d.authenticateDaemon(); err != nil {
			return nil, nil, err
		}
		platform, stderr, err := d.client.Output("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", d.image)
		if err != nil || strings.TrimSpace(string(platform)) != d.platform {
			return nil, stderr, errors.New("saved contributor image/platform unavailable")
		}
		rewritten, mounts, err := d.rewriteArgs(args, map[string]string{candidate: "/relay/candidate", scopeFile: "/relay/scope.json"})
		if err != nil {
			return nil, nil, err
		}
		for n := range mounts {
			mounts[n].ReadOnly = true
		}
		command := append(d.baseRunArgs(true, mounts), d.image)
		command = append(command, rewritten...)
		stdout, stderr, err := d.client.Output(command...)
		if err != nil {
			return stdout, stderr, fmt.Errorf("inspect retained contribution in saved runtime: %w", err)
		}
		return stdout, stderr, nil
	}
	return i, nil
}

func workflowV4PredecessorInputRoot(p workflowV4OperationPlan, work string) (string, error) {
	inputRoot := filepath.Join(work, "workflow-v4", "inputs", p.ID)
	for _, input := range p.Inputs {
		if input.Ref != p.Predecessor.Record {
			continue
		}
		root := filepath.Clean(input.Path)
		for range strings.Split(input.Ref.Name, "/") {
			root = filepath.Dir(root)
		}
		if filepath.Join(root, filepath.FromSlash(input.Ref.Name)) != filepath.Clean(input.Path) {
			return "", errors.New("predecessor path does not match its authenticated name")
		}
		inputRoot = root
		return inputRoot, nil
	}
	return "", errors.New("retained predecessor record is missing")
}

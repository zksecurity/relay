package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type inspectionClientV4 struct {
	*dockerClientFake
	invocation []string
}

func (f *inspectionClientV4) BindHost(host string) dockerCommandClient { f.host = host; return f }
func (f *inspectionClientV4) Output(args ...string) ([]byte, []byte, error) {
	if len(args) > 0 && args[0] == "run" {
		f.invocation = append([]string(nil), args...)
		return []byte("{}"), nil, nil
	}
	return f.dockerClientFake.Output(args...)
}

func TestWorkflowV4CandidateInspectionMountsNoSecrets(t *testing.T) {
	_, b := workflowV4TestBinding(t)
	p := workflowV4TestPlan(t, b)
	if err := os.Mkdir(p.Outputs[0], 0700); err != nil {
		t.Fatal(err)
	}
	scope := filepath.Join(b.Work, "scope.json")
	if err := os.WriteFile(scope, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &inspectionClientV4{dockerClientFake: &dockerClientFake{platform: p.Runtime.Platform}}
	i, err := workflowV4CandidateInspector(p, b, scope, f, dockerDaemonFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := i.Runner("mpc-ceremony", "--format", "json", "phase1", "contribute"); err == nil {
		t.Fatal("inspector allowed computation")
	}
	args := []string{"--format", "json", "inspect", "computation-output-v4", "--ceremony", i.CeremonyPath, "--ceremony-signature", i.CeremonySignaturePath, "--coordinator-public-key-file", i.CoordinatorPublicKeyPath, "--transcript-root", i.TranscriptRoot, "--chain", p.Inputs[0].Path, "--chain-signature", p.Inputs[1].Path, "--scope", scope, "--candidate-dir", p.Outputs[0]}
	if _, _, err := i.Runner("mpc-ceremony", args...); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.invocation, " ")
	if strings.Contains(joined, b.Runtimes["signer"].Mounts["/keys"]) || strings.Contains(joined, "dst=/work,") {
		t.Fatal("inspection mounts private keys or entire work directory")
	}
	for n, arg := range f.invocation {
		if arg == "--mount" && !strings.Contains(f.invocation[n+1], "readonly") {
			t.Fatal("writable inspection mount")
		}
	}
	if !strings.Contains(joined, "--network none") || !strings.Contains(joined, p.Runtime.Image) {
		t.Fatal("missing network isolation or saved image")
	}
	// Changing the default context must not redirect restart verification.
	originalEndpoint := "unix:///var/run/original-relay-test.sock"
	daemon, err := inspectDockerDaemon(f, "original", originalEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.endpoint = "unix:///var/run/other-relay-test.sock"
	i, err = workflowV4CandidateInspector(p, b, scope, f, daemon)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := i.Runner("mpc-ceremony", args...); err != nil {
		t.Fatal(err)
	}
	if f.host != originalEndpoint {
		t.Fatal("inspection followed another Docker context")
	}
}

func TestWorkflowV4CleanupInspectionUsesContributionSnapshot(t *testing.T) {
	_, b := workflowV4TestBinding(t)
	p := workflowV4TestPlan(t, b)
	contributionRoot := filepath.Join(b.Work, "workflow-v4", "inputs", p.ID)
	p.ID = strings.Repeat("2", 32)
	root, err := workflowV4PredecessorInputRoot(p, b.Work)
	if err != nil {
		t.Fatal(err)
	}
	if root != contributionRoot {
		t.Fatalf("transcript root = %q, want retained contribution root %q", root, contributionRoot)
	}
}

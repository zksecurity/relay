package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowV4CleanupReconciliationBindsSignedTime(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "erasure.json")
	raw := `{"destroyed_at":"2026-09-16T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	p := workflowV4OperationPlan{Command: []string{"mpc-ceremony", "phase1", "attest-erasure", "--destroyed-at", "2026-09-16T00:00:00Z"}, Outputs: []string{path, filepath.Join(root, "erasure.sig")}}
	r := dockerLifecycleReceipt{ErasureDestroyedAt: "2026-09-16T00:00:00Z"}
	ref := workflowV4TestRef("erasure.json", raw)
	if err := verifyWorkflowV4CleanupTime(p, r, ref); err != nil {
		t.Fatal(err)
	}
	p.Command[4] = "2026-09-16T00:00:01Z"
	r.ErasureDestroyedAt = p.Command[4]
	if err := verifyWorkflowV4CleanupTime(p, r, ref); err == nil {
		t.Fatal("another signed cleanup time accepted")
	}
	p.Command[4] = "2026-09-16T00:00:00Z"
	r.ErasureDestroyedAt = p.Command[4]
	if err := os.WriteFile(path, []byte(raw+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyWorkflowV4CleanupTime(p, r, ref); err == nil {
		t.Fatal("changed verified bytes accepted")
	}
}

func TestWorkflowV4ReconciledOperationIsReinspected(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	p := workflowV4TestPlan(t, b)
	j, err := openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err := j.prepare(p); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(p.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := j.reconcile(p.ID, func(workflowV4OperationPlan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	j, err = openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	// A saved completion is only a locator. Reopening must inspect its actual
	// retained output and report its absence, not trust the completion marker
	// or reject inspection merely because there is no pending operation.
	_, err = j.reconcileCandidateOperation(p.ID, filepath.Join(b.Work, "scope.json"), "/nonexistent/docker")
	if err == nil || !strings.Contains(err.Error(), dockerLifecycleLogName) {
		t.Fatalf("did not inspect completed operation: %v", err)
	}
	if j.state.Operations[0].Status != "reconciled" {
		t.Fatal("read-only inspection changed saved operation")
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestLifecycleRetryRetainsTimestampAndRejectsChangedRuntime(t *testing.T) {
	p := guidedProfile{Work: t.TempDir(), Image: "approved-image", Platform: "linux/amd64"}
	head := transcript.SignedArtifactRefs{Record: workflowV4TestRef("checkpoint.json", "first"), Signature: workflowV4TestRef("checkpoint.sig", "signature")}
	out := filepath.Join(p.Work, "final", "preliminary")
	now := time.Date(2026, 9, 23, 0, 0, 0, 123, time.UTC)
	first, err := retainedWorkflowV4LifecycleTime(p, head, "finalize-preliminary", out, now)
	if err != nil {
		t.Fatal(err)
	}
	p.Resources = &dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	retry, err := retainedWorkflowV4LifecycleTime(p, head, "finalize-preliminary", out, now.Add(time.Hour))
	if err != nil || !first.Equal(retry) {
		t.Fatal("retry changed timestamp", err)
	}
	changed := p
	changed.Image = "replacement-image"
	if _, err := retainedWorkflowV4LifecycleTime(changed, head, "finalize-preliminary", out, now); err == nil {
		t.Fatal("changed runtime accepted")
	}
	next := head
	next.Record = workflowV4TestRef("checkpoint.json", "next")
	later, err := retainedWorkflowV4LifecycleTime(p, next, "finalize-preliminary", out, now.Add(time.Hour))
	if err != nil || !later.Equal(now.Add(time.Hour)) {
		t.Fatal("later predecessor reused prior timestamp", err)
	}
	path := filepath.Join(p.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(head, "finalize-preliminary")+".json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedWorkflowV4LifecycleTime(p, head, "finalize-preliminary", out, now); err == nil {
		t.Fatal("corrupt step replaced")
	}
}

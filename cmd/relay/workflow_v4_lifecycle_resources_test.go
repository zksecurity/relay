package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestLifecycleResourceMigrationAndInterruptedRetry(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		name := "legacy"
		if fresh {
			name = "fresh"
		}
		t.Run(name, func(t *testing.T) {
			p := guidedProfile{Work: t.TempDir(), Role: "decision-signer", Image: "approved-image", Platform: "linux/amd64", Resources: &dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}}
			head := transcript.SignedArtifactRefs{Record: workflowV4TestRef("head.json", "first"), Signature: workflowV4TestRef("head.sig", "signature")}
			if _, err := ensureWorkflowV4ResourceOrigin(p.Work, head, fresh); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(p.Work, "phase2")
			command := []string{"mpc-ceremony", "phase2", "init", "--out-dir", "/work/phase2"}
			previous := workflowV4ChildExecutor
			defer func() { workflowV4ChildExecutor = previous }()
			var launch []string
			interrupted := errors.New("simulated child interruption")
			workflowV4ChildExecutor = func(args []string) error { launch = append([]string(nil), args...); return interrupted }
			if err := runWorkflowV4LifecycleCommand(p, head, "derive-phase2", output, command); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			expected := "2"
			if fresh {
				expected = "6"
			}
			if commandValue(launch, "cpus") != expected {
				t.Fatal("incorrect migration allocation", launch)
			}
			p.Resources.CPUs = 4
			// A second startup cannot reclassify the original boundary as a fresh one.
			if _, err := ensureWorkflowV4ResourceOrigin(p.Work, head, true); err != nil {
				t.Fatal(err)
			}
			if err := runWorkflowV4LifecycleCommand(p, head, "derive-phase2", output, command); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			if commandValue(launch, "cpus") != expected {
				t.Fatal("retry allocation changed")
			}
			altered := append(append([]string(nil), command...), "--different")
			launch = nil
			if err := runWorkflowV4LifecycleCommand(p, head, "derive-phase2", output, altered); err == nil || launch != nil {
				t.Fatal("changed command was launched")
			}
			next := head
			next.Record = workflowV4TestRef("head.json", "later")
			if err := runWorkflowV4LifecycleCommand(p, next, "derive-phase2", output, command); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			if commandValue(launch, "cpus") != "4" {
				t.Fatal("later checkpoint did not select current resources")
			}
			// Separate recording step must not alias the derivation record.
			if err := runWorkflowV4LifecycleCommand(p, next, "record-phase2-genesis", output+"-checkpoint", []string{"mpc-ceremony", "checkpoint", "record-v4"}); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			path := filepath.Join(p.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(next, "derive-phase2")+".json")
			var saved workflowV4LifecycleStep
			if err := readWorkflowV4JSON(path, &saved); err != nil {
				t.Fatal(err)
			}
			saved.Resources = nil
			if err := writeJSONAtomic(path, saved, 0600); err != nil {
				t.Fatal(err)
			}
			if err := runWorkflowV4LifecycleCommand(p, next, "derive-phase2", output, command); err == nil {
				t.Fatal("missing resources accepted")
			}
		})
	}
}

func TestLifecycleLegacyTimestampMigrationAndCorruptOrigin(t *testing.T) {
	p := guidedProfile{Work: t.TempDir(), Image: "approved-image", Platform: "linux/amd64", Resources: &dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}}
	head := transcript.SignedArtifactRefs{Record: workflowV4TestRef("head.json", "first"), Signature: workflowV4TestRef("head.sig", "signature")}
	output := filepath.Join(p.Work, "preliminary")
	path := filepath.Join(p.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(head, "finalize-preliminary")+".json")
	at := "2026-09-23T00:00:00Z"
	old := workflowV4LifecycleStep{Schema: workflowV4LegacyLifecycleStepSchema, Predecessor: head, Step: "finalize-preliminary", Output: output, Image: p.Image, Platform: p.Platform, At: at}
	if err := writeJSONAtomic(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := retainedWorkflowV4LifecycleStep(p, head, old.Step, output, time.Now())
	if err != nil || saved.At != at || saved.Resources == nil || saved.Resources.CPUs != 2 {
		t.Fatal("legacy timestamp migration changed original state", err)
	}
	origin := filepath.Join(p.Work, "workflow-v4", "coordinator", "resource-origin.json")
	if err := os.WriteFile(origin, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedWorkflowV4LifecycleStep(p, head, "finalize-complete", output+"-next", time.Now()); err == nil {
		t.Fatal("corrupt origin bypassed")
	}
}

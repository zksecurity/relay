package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkflowV4CommandResourcesRetainExactRetry(t *testing.T) {
	p := guidedProfile{Work: t.TempDir(), Role: "decision-signer", Image: "original", Platform: "linux/amd64", Resources: &dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}}
	command := []string{"mpc-ceremony", "phase2", "init", "--out-dir", "/work/phase2"}
	first, err := retainedWorkflowV4CommandResources(p, command)
	if err != nil {
		t.Fatal(err)
	}
	p.Resources.CPUs = 4
	p.Credentials = "/rotated/storage/credentials"
	p.ReleaseCommit = "compatible-relay-update"
	p.Name = "renamed-display-profile"
	retry, err := retainedWorkflowV4CommandResources(p, command)
	if err != nil || retry != first {
		t.Fatalf("retry allocation changed: %+v %v", retry, err)
	}
	nextCommand := append(append([]string(nil), command...), "--new-operation")
	next, err := retainedWorkflowV4CommandResources(p, nextCommand)
	if err != nil || next.CPUs != 4 {
		t.Fatalf("new command did not use preferences: %+v %v", next, err)
	}
	p.Image = "other"
	other, err := retainedWorkflowV4CommandResources(p, command)
	if err != nil || other.CPUs != 4 {
		t.Fatalf("runtime identities conflated: %+v %v", other, err)
	}
}

func TestWorkflowV4CommandResourcesRejectCorruptRecord(t *testing.T) {
	for _, data := range []string{"{", `{"schema":"other","command_digest":"wrong","limits":{"cpus":6,"memory_gib":6,"go_memory_gib":4,"go_gc_percent":25}}`} {
		t.Run(data, func(t *testing.T) {
			p := guidedProfile{Work: t.TempDir()}
			command := []string{"mpc-ceremony", "phase2", "init"}
			if _, err := retainedWorkflowV4CommandResources(p, command); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(p.Work, "workflow-v4", "resources", "*.json"))
			if err != nil || len(paths) != 1 {
				t.Fatal("missing allocation record", err)
			}
			if err := os.WriteFile(paths[0], []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := retainedWorkflowV4CommandResources(p, command); err == nil {
				t.Fatal("corrupt allocation silently replaced")
			}
		})
	}
}

func TestWorkflowV4InspectionUsesCurrentPreferences(t *testing.T) {
	for _, command := range [][]string{{"mpc-ceremony", "inspect", "definition"}, {"mpc-ceremony", "release", "verify"}} {
		t.Run(command[1], func(t *testing.T) {
			previous := workflowV4ChildExecutor
			defer func() { workflowV4ChildExecutor = previous }()
			var got []string
			workflowV4ChildExecutor = func(args []string) error { got = append([]string(nil), args...); return nil }
			p := guidedProfile{Work: t.TempDir(), Role: "coordinator", Resources: &dockerRuntimeLimits{CPUs: 4, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}}
			if err := runWorkflowV4ProfileCommand(p, command, false); err != nil {
				t.Fatal(err)
			}
			p.Resources.CPUs = 6
			if err := runWorkflowV4ProfileCommand(p, command, false); err != nil {
				t.Fatal(err)
			}
			if commandValue(got, "cpus") != "6" {
				t.Fatal("read-only verification retained stale allocation")
			}
			if _, err := os.Stat(filepath.Join(p.Work, "workflow-v4", "resources")); !os.IsNotExist(err) {
				t.Fatal("read-only verification created operation record", err)
			}
		})
	}
}

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/zksecurity/relay/internal/teststore"
	"github.com/zksecurity/relay/internal/upgrade"
)

func TestUpgradeOnlineRuntimeRetry(t *testing.T) { runOnlineUpgradeScenario(t, "online-runtime-retry") }
func TestUpgradeOnlinePredecessorReentry(t *testing.T) {
	runOnlineUpgradeScenario(t, "predecessor-reentry")
}

func runOnlineUpgradeScenario(t *testing.T, scenario string) {
	t.Helper()
	path := os.Getenv("RELAY_UPGRADE_QUALIFICATION_REQUEST")
	if path == "" {
		t.Skip("exact released executables and images required")
	}
	var request upgrade.QualificationRequest
	if err := setupReadJSON(path, &request); err != nil {
		t.Fatal(err)
	}
	if request.QualificationSchema != upgrade.OnlineCleanExitQualificationSchema {
		t.Fatal("online completed-step qualification required")
	}
	runCleanExitScenario(t, scenario)
}

// Every v4 journey checks actual child command routing. The two extra scenarios
// fail publication inside the target image, then retry using the actual target
// or test old executable/container reentry first. Storage is the local adapter;
// this does not claim live-provider conformance.
func configureOnlineUpgradeScenario(t *testing.T, f upgradeRealFixture, hook *workflowV4LiveUpgradeHook, store *teststore.Server) {
	t.Helper()
	d := f.request.Declaration
	if d.OnlineImage == d.OriginalImage {
		t.Fatal("online qualification must replace the image")
	}
	scenario := os.Getenv("RELAY_UPGRADE_CLEAN_SCENARIO")
	inject := scenario == "online-runtime-retry" || scenario == "predecessor-reentry"
	if inject && store == nil {
		t.Fatal("controlled storage fault required")
	}
	observed, exercised, completedReentry := false, false, false
	value := func(args []string, key string) string {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == key {
				return args[i+1]
			}
		}
		return ""
	}
	hook.Execute = func(binary string, args []string, run func(string, []string) error) error {
		if hook.TargetWork == "" || value(args, "--work") != hook.TargetWork {
			return run(binary, args)
		}
		image := value(args, "--image")
		online := slices.Contains(args, "relay")
		if online {
			if binary != f.request.Candidate || image != d.OnlineImage {
				t.Fatal("online action did not use qualified target")
			}
			observed = true
		} else if image != d.OriginalImage && image != d.SigningImage {
			t.Fatal("cryptographic action changed original image")
		}
		// After the interrupted-state case, exercise a separate publication that
		// the target completes itself, then reopen that completed work with the old
		// executable/container. Success must be idempotent; refusal must be inert.
		if scenario == "predecessor-reentry" && exercised && !completedReentry && online && slices.Contains(args, "commit-v4") {
			previousRootWrites := store.PublicationFault(false).RootWrites
			if err := run(binary, args); err != nil {
				return err
			}
			rootWrites := store.PublicationFault(false).RootWrites
			if rootWrites != previousRootWrites+1 {
				t.Fatal("target did not complete a new publication before predecessor reentry")
			}
			publicBefore := cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony/public"))
			before := cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony"), filepath.Join(hook.TargetWork, "workflow-v4"))
			old := originalOnlineArgs(args, d.OriginalImage)
			oldErr := run(f.request.Predecessors[d.SourceApp], old)
			if store.PublicationFault(false).RootWrites != rootWrites || !reflect.DeepEqual(publicBefore, cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony/public"))) {
				t.Fatal("predecessor changed a completed target publication")
			}
			if oldErr != nil && !reflect.DeepEqual(before, cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony"), filepath.Join(hook.TargetWork, "workflow-v4"))) {
				t.Fatal("predecessor refusal changed completed target state", oldErr)
			}
			completedReentry = true
			return nil
		}
		if !inject || exercised || !online || !slices.Contains(args, "commit-v4") {
			return run(binary, args)
		}
		exercised = true
		store.ArmPublicationFault()
		err := run(binary, args)
		fault := store.PublicationFault(true)
		if err == nil || !fault.Failed || fault.Successful == "" {
			t.Fatal("target did not stop after a partial immutable publication", err)
		}
		if scenario == "predecessor-reentry" {
			old := originalOnlineArgs(args, d.OriginalImage)
			before := cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony"), filepath.Join(hook.TargetWork, "workflow-v4"))
			oldErr := run(f.request.Predecessors[d.SourceApp], old)
			if oldErr != nil && !reflect.DeepEqual(before, cleanExitTree(t, filepath.Join(hook.TargetWork, "ceremony"), filepath.Join(hook.TargetWork, "workflow-v4"))) {
				t.Fatal("predecessor neither reconciled nor refused without mutating retained ceremony state", oldErr)
			}
		}
		if err := run(binary, args); err != nil {
			return err
		}
		after := store.PublicationFault(false)
		if scenario == "online-runtime-retry" && after.Attempts[fault.Successful] != fault.Attempts[fault.Successful] {
			t.Fatal("retry retransmitted verified immutable body")
		}
		if after.RootWrites != 1 {
			t.Fatal("retry did not publish exactly one conditional root transition", after.RootWrites)
		}
		return nil
	}
	t.Cleanup(func() {
		if !observed {
			t.Error("no actual upgraded online action executed")
		}
		if scenario == "predecessor-reentry" && !completedReentry {
			t.Error("completed target-publication predecessor reentry did not execute")
		}
		if inject && !exercised {
			t.Error("publication retry/reentry scenario did not execute")
		}
	})
}

func originalOnlineArgs(args []string, image string) []string {
	old := append([]string{}, args...)
	for i := 0; i+1 < len(old); i++ {
		if old[i] == "--image" {
			old[i+1] = image
		}
	}
	return old
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkflowV4CommandRejectsPlanMismatch(t *testing.T) {
	for _, mutation := range []string{"executable", "verb", "output", "chain", "definition", "key", "extra-flag", "duplicate-flag", "participant", "runtime", "platform", "mount", "transcript-root"} {
		t.Run(mutation, func(t *testing.T) {
			_, binding := workflowV4TestBinding(t)
			plan := workflowV4TestPlan(t, binding)
			set := func(flag, value string) {
				for n := range plan.Command {
					if plan.Command[n] == flag {
						plan.Command[n+1] = value
						return
					}
				}
				t.Fatal("missing test flag", flag)
			}
			switch mutation {
			case "executable":
				plan.Command[0] = "sh"
			case "verb":
				plan.Command[2] = "init"
			case "output":
				set("--out-dir", "/work/other")
			case "chain":
				set("--chain", "/work/chain-current.json")
			case "definition":
				set("--ceremony", "/work/workflow-v4/inputs/"+plan.ID+"/environment.json")
			case "key":
				set("--participant-signing-key", "/work/key.hex")
			case "extra-flag":
				plan.Command = append(plan.Command, "--unexpected", "yes")
			case "duplicate-flag":
				plan.Command = append(plan.Command, "--out-dir", "/work/candidate")
			case "participant":
				set("--participant-id", "another")
			case "runtime":
				plan.Runtime.Image = "example.test/role@sha256:" + strings.Repeat("e", 64)
			case "platform":
				plan.Runtime.Platform = "linux/amd64"
			case "mount":
				plan.Runtime.Mounts["/trust"] = t.TempDir()
			case "transcript-root":
				set("--transcript-dir", "/work/unrelated")
			}
			if err := validateWorkflowV4Plan(plan, binding); err == nil {
				t.Fatal("accepted mismatched command/profile")
			}
		})
	}
}

func TestWorkflowV4CommandSigningBindsReviewedRecord(t *testing.T) {
	_, binding := workflowV4TestBinding(t)
	plan := workflowV4TestPlan(t, binding)
	plan.Kind = "sign-return"
	root := "/work/workflow-v4/inputs/" + plan.ID
	record := plan.Inputs[5] // synthetic canonical record for the command-binding test
	plan.Outputs = []string{filepath.Join(binding.Work, "return.sig")}
	plan.Command = []string{"mpc-ceremony", "ops", "sign", "--ceremony", root + "/ceremony.json", "--ceremony-signature", root + "/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator.hex", "--record-type", "handoff", "--record", root + "/environment.json", "--signing-key", "/keys/signing.hex", "--reviewed", "--reviewed-sha256", strings.TrimPrefix(record.Ref.Digest.SHA256, "sha256:"), "--out", "/work/return.sig"}
	if err := validateWorkflowV4Plan(plan, binding); err != nil {
		t.Fatal(err)
	}
	for n := range plan.Command {
		if plan.Command[n] == "--reviewed-sha256" {
			plan.Command[n+1] = strings.Repeat("0", 64)
		}
	}
	if err := validateWorkflowV4Plan(plan, binding); err == nil {
		t.Fatal("accepted different reviewed bytes")
	}
}

func TestWorkflowV4JournalRejectsForeignAuthorityAndReversedTime(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	wrongPair := binding.Definition
	wrongPair.Record.Digest.SHA256 = commitDigest("f")
	if _, err := openWorkflowV4Journal(protocol, wrongPair, binding); err == nil {
		t.Fatal("accepted different authenticated definition")
	}
	wrong := binding
	wrong.IdentityID = "not-assigned"
	if _, err := openWorkflowV4Journal(protocol, binding.Definition, wrong); err == nil {
		t.Fatal("accepted unassigned identity")
	}
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	state := j.state
	earlier := state.Operations[0].Prepared.Add(-time.Second)
	state.Operations[0].Status = "running"
	state.Operations[0].Started = &earlier
	if err := validateWorkflowV4State(state, binding, j.path); err == nil {
		t.Fatal("accepted reversed timestamp")
	}
}

func TestWorkflowV4JournalCoordinatorReceiptDownload(t *testing.T) {
	protocol, binding := workflowV4TestBinding(t)
	binding.Role, binding.IdentityID = "coordinator", "coordinator-test"
	j, err := openWorkflowV4Journal(protocol, binding.Definition, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	plan := workflowV4TestPlan(t, binding)
	plan.Kind, plan.AttemptID = "download-receipt", strings.Repeat("8", 32)
	plan.Command = []string{"relay-internal", "download-receipt"}
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	if err := j.runPrepared(plan.ID, func(p workflowV4OperationPlan) error { return os.WriteFile(p.Outputs[0], []byte("received"), 0600) }); err != nil {
		t.Fatal(err)
	}
	op, err := j.pending()
	if err != nil || op.Status != "returned-needs-verification" {
		t.Fatal("download claimed verification", err)
	}
}

func TestWorkflowV4CommandPhase2RequiresSealInputs(t *testing.T) {
	_, binding := workflowV4TestBinding(t)
	plan := workflowV4TestPlan(t, binding)
	plan.Scope.Phase = "phase2"
	plan.Command[1] = "phase2"
	if err := validateWorkflowV4Plan(plan, binding); err == nil {
		t.Fatal("accepted phase2 without seal")
	}
	for _, item := range []struct{ flag, name string }{{"--phase1-seal", "seal.json"}, {"--phase1-seal-signature", "seal.sig"}} {
		ref := workflowV4TestRef(item.name, item.name)
		plan.Inputs = append(plan.Inputs, workflowV4Input{Path: filepath.Join(binding.Work, item.name), Ref: ref})
		plan.Command = append(plan.Command, item.flag, "/work/"+item.name)
	}
	if err := validateWorkflowV4Plan(plan, binding); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowV4RuntimeRejectsOverlappingTrustAndKeys(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "equal", true: "nested"}[nested], func(t *testing.T) {
			_, binding := workflowV4TestBinding(t)
			runtime := binding.Runtimes["signer"]
			runtime.Mounts["/keys"] = runtime.Mounts["/trust"]
			if nested {
				runtime.Mounts["/keys"] = filepath.Join(runtime.Mounts["/trust"], "private")
			}
			if err := validateWorkflowV4Runtime(runtime, binding.Work); err == nil {
				t.Fatal("accepted ambiguous public/private mount mapping")
			}
		})
	}
}

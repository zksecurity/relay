package main

import (
	"fmt"
	"strings"
)

func (f *roleFlow) inspectedAssignmentFiles() []string {
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := f.state.Attempts[n]
		if a.Stage != "enrollments" || a.Task != "inspect" || a.Status != "succeeded" {
			continue
		}
		paths := []string{commandValue(a.Command, "ceremony"), commandValue(a.Command, "ceremony-signature"), commandValue(a.Command, "coordinator-public-key-file")}
		if paths[0] != "" && paths[1] != "" && paths[2] != "" {
			return paths
		}
	}
	return nil
}

// Human reports remain assertions, but reports about handing off an artifact
// must identify retained public bytes. They never replace the verifier step.
func (f *roleFlow) handoffFields(task flowTask) []flowField {
	if !task.Handoff {
		return nil
	}
	var paths []string
	if f.state.Role == "coordinator" {
		switch task.ID {
		case "assignments":
			paths = f.inspectedAssignmentFiles()
			if len(paths) == 0 {
				paths = []string{"/work/ceremony/public/ceremony.json", "/work/ceremony/public/ceremony.sig", "/work/ceremony/public/coordinator-public-key.hex"}
			}
		case "storage":
			paths = []string{"/work/ceremony/config/relay-storage.json"}
		case "public-proof":
			paths = []string{"/work/preliminary/ownership.pk", "/work/preliminary/ownership.vk"}
		case "audits", "signer":
			paths = []string{"/work/candidate/candidate.json", "/work/candidate/candidate.sig.json"}
		case "archive":
			paths = []string{"/work/release/manifest.json", "/work/release/manifest.sig"}
		case "observations":
			phase := strings.TrimSuffix(f.stages[f.state.Stage].ID, "-close")
			paths = []string{"/work/ceremony/public/" + phase + "/closure/record.json", "/work/ceremony/public/" + phase + "/closure/record.sig"}
		}
	}
	if task.ID == "deliver-decision" || task.ID == "receive-decision" || task.ID == "collect-decision-signatures" {
		paths = []string{"/work/decision.json"}
	}
	if task.ID == "return-decision-signature" {
		if a := f.last(flowTask{ID: "sign-decision"}); a != nil && a.Status == "succeeded" {
			paths = []string{commandValue(a.Command, "decision"), commandValue(a.Command, "out")}
		}
	}
	if f.state.Role == "release-signer" && task.ID == "handoff" {
		paths = []string{"/work/release/manifest.json", "/work/release/manifest.sig"}
	}
	if (f.state.Role == "witness" || f.state.Role == "mirror") && task.ID == "reconnect" {
		paths = []string{"/work/" + f.stages[f.state.Stage].ID + "-receipt/receipt.sig"}
	}
	if task.ID == "receive-audit-inputs" || task.ID == "receive-signing-inputs" {
		paths = []string{"/work/candidate/candidate.json", "/work/candidate/candidate.sig.json"}
	}
	if task.ID == "receive-release" {
		paths = []string{"/work/release/manifest.json", "/work/release/manifest.sig"}
	}
	fields := []flowField{}
	for _, path := range paths {
		if f.state.Role != "coordinator" || task.ID != "assignments" {
			path = f.rememberedOutputPath(path, true)
		}
		fields = append(fields, ff("record", "Public artifact to hand off", path))
	}
	return fields
}

func (f *roleFlow) showAssignmentFiles(task flowTask) {
	if f.state.Role != "coordinator" || task.ID != "assignments" {
		return
	}
	if len(f.inspectedAssignmentFiles()) == 0 {
		fmt.Fprintln(f.ui.output, "Default file locations below; no successful inspection paths were retained. Inspect these files first if you have not already verified them.")
	} else {
		fmt.Fprintln(f.ui.output, "Files selected in your last successful inspection:")
	}
	for _, field := range f.handoffFields(task) {
		fmt.Fprintf(f.ui.output, "  %s\n", flowHostPath(f.state.Profile, field.Default))
	}
	fmt.Fprintln(f.ui.output, "Share these individual public files, not your entire role folder. Report sharing only after you have sent them; collect and verify the returned enrollments next.")
	fmt.Fprintln(f.ui.output, "Send the three files together, named ceremony.json, ceremony.sig and coordinator-public-key.hex. Recipients can import them from one folder using setup action 3, then the recommended three-file import. Confirm your public-key fingerprint with them through the independent coordination channel.")
}

func (f *roleFlow) handoffBindings(task flowTask) (map[string]string, error) {
	fields := f.handoffFields(task)
	command := []string{}
	for _, field := range fields {
		command = append(command, "--record", field.Default)
	}
	return f.captureEvidence(flowTask{Fields: fields}, command)
}

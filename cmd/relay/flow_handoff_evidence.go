package main

import "strings"

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
			paths = []string{"/work/ceremony/public/ceremony.json", "/work/ceremony/public/ceremony.sig"}
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
	if f.state.Role == "release-signer" && task.ID == "handoff" {
		paths = []string{"/work/release/manifest.json", "/work/release/manifest.sig"}
	}
	if (f.state.Role == "witness" || f.state.Role == "mirror") && task.ID == "reconnect" {
		paths = []string{"/work/" + f.stages[f.state.Stage].ID + "-receipt/receipt.sig"}
	}
	fields := []flowField{}
	for _, path := range paths {
		fields = append(fields, ff("record", "Public artifact to hand off", f.rememberedOutputPath(path, true)))
	}
	return fields
}

func (f *roleFlow) handoffBindings(task flowTask) (map[string]string, error) {
	fields := f.handoffFields(task)
	command := []string{}
	for _, field := range fields {
		command = append(command, "--record", field.Default)
	}
	return f.captureEvidence(flowTask{Fields: fields}, command)
}

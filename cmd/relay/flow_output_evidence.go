package main

import (
	"os"
)

// Track generated PUBLIC artifacts as well as their inputs. Private grants
// are never hashed here. Command success without retained outputs is not a
// durable completion signal.
func (f *roleFlow) bindSuccessfulOutputs(task flowTask, command []string, a *flowAttempt) error {
	if f.state.Profile.Work == "" {
		return nil
	}
	if len(task.Command) > 2 && task.Command[0] == "relay" && task.Command[1] == "coordinator" && task.Command[2] == "grant" {
		return nil
	}
	if a.InputBindings == nil {
		a.InputBindings = map[string]string{}
	}
	if a.DirectoryBindings == nil {
		a.DirectoryBindings = map[string]string{}
	}
	for _, field := range task.Fields {
		if !flowOutputField(task, field) {
			continue
		}
		value := commandValue(command, field.Flag)
		if value == "" {
			continue
		}
		local, err := f.publicHostPath(value)
		if err != nil {
			return err
		}
		st, err := os.Lstat(local)
		if err != nil {
			return err
		}
		if st.IsDir() {
			// Later tasks may add signatures to a prepared output directory.
			// Preserve all emitted bytes without treating those additions as edits.
			flag := "transcript-dir"
			bindings, err := f.captureDirectories(flowTask{Fields: []flowField{ff(flag, "Public output", value)}}, []string{"--" + flag, value})
			if err != nil {
				return err
			}
			for path, digest := range bindings {
				a.DirectoryBindings[path] = digest
			}
		} else {
			digest, err := setupFileHash(local)
			if err != nil {
				return err
			}
			a.InputBindings[value] = digest
		}
	}
	return nil
}

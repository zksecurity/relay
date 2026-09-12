package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Readiness is local input guidance, never protocol authorization. Missing
// default paths may be corrected in the action's input review; the actual
// command must independently validate the selected inputs before execution.
type flowReadiness struct {
	Requirement, Source, Status string
	Missing                     []string
}

func (f *roleFlow) readiness(task flowTask) flowReadiness {
	r := flowReadiness{Requirement: "Required", Source: "Relay role procedure", Status: "Ready to review inputs"}
	if task.Optional {
		r.Requirement = "Optional"
	}
	if f.stages[f.state.Stage].ID == "decision" {
		r.Requirement, r.Source = "Required", "authenticated production policy"
		mode, err := f.decisionRequirement()
		if err != nil {
			r.Status, r.Missing = "Waiting", []string{"Authenticate the signed definition to determine applicability"}
			return r
		}
		if mode == "not-applicable" {
			r.Requirement, r.Status = "Not applicable", "Authenticated rehearsal"
			return r
		}
	}
	if a := f.last(task); a != nil {
		if err := f.checkAttemptEvidence(a); err != nil {
			r.Status, r.Missing = "Needs attention", []string{err.Error()}
			return r
		}
		switch a.Status {
		case "prepared":
			r.Status, r.Missing = "Ready to review inputs", []string{"The previous action stopped before launch; no command ran"}
			return r
		case "running", "failed", "reviewed-incomplete":
			class := flowTaskRecoveryClass(task)
			if class == recoveryReadOnly {
				r.Status, r.Missing = "Needs attention", []string{"Relay will recheck the previous read-only action"}
			} else if class == recoveryCheckpoint {
				r.Status, r.Missing = "Needs attention", []string{"Relay will reauthenticate the public state and safely update its local checkpoint"}
			} else if class == recoveryUpload {
				r.Status, r.Missing = "Needs attention", []string{"Relay will verify and continue the exact immutable upload"}
			} else if class == recoveryDocker && f.state.Role == "participant" {
				r.Status, r.Missing = "Needs attention", []string{"Relay will look for and verify the exact retained candidate; it will not recompute"}
			} else if class == recoveryGrant {
				r.Status, r.Missing = "Needs attention", []string{"Relay will adopt an exact protected grant if one was saved; otherwise it blocks possible duplicate issuance"}
			} else {
				r.Status, r.Missing = "Needs attention", []string{"The previous action may have changed state and will not be repeated automatically"}
			}
			return r
		case "succeeded":
			r.Status = "Command completed; scoped verification only"
			return r
		case "reported":
			if task.Handoff {
				r.Status = "Handoff reported; delivery not verified"
				return r
			}
			r.Status, r.Missing = "Waiting", []string{"An external report does not replace verification"}
			return r
		}
	}
	if f.state.Profile.Work == "" {
		return r
	}
	if task.Handoff {
		task.Fields = f.handoffFields(task)
	}
	if f.state.Role == "coordinator" && task.ID == "close" {
		if err := f.checkScheduledTurns(); err != nil {
			r.Status, r.Missing = "Waiting", []string{err.Error()}
			return r
		}
	}
	for index, field := range task.Fields {
		if field.Optional || (field.Kind != "path" && field.Kind != "host") || flowOutputField(task, field) {
			continue
		}
		value := field.Default
		if shared, ok := f.state.Values["shared/"+field.Flag]; ok {
			value = shared
		}
		key := f.stages[f.state.Stage].ID + "/" + task.ID + "/" + strconv.Itoa(index) + "/" + field.Flag
		if saved, ok := f.state.Values[key]; ok {
			value = saved
		}
		value = f.rememberedOutputPath(value, true)
		// Dynamic chains are authenticated and discovered when input review opens.
		if flowHeadPhase(field) != "" || strings.HasSuffix(field.Flag, "chain-signature") {
			continue
		}
		if value == "" {
			r.Missing = append(r.Missing, "Select "+field.Label)
			continue
		}
		local := value
		if field.Kind == "path" {
			local = flowHostPath(f.state.Profile, value)
		}
		st, err := os.Lstat(local)
		if err != nil {
			r.Missing = append(r.Missing, field.Label+": supply "+value)
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
			r.Missing = append(r.Missing, field.Label+": replace unsafe path")
			continue
		}
		if field.Flag == "grant" {
			path, err := f.publicHostPath(value)
			if err != nil {
				r.Missing = append(r.Missing, "Select a protected grant in your work folder")
				continue
			}
			grant, err := loadGrant(path)
			if err != nil || grant.CheckUsable(time.Now()) != nil {
				r.Missing = append(r.Missing, "Ask the coordinator for a fresh, valid role grant")
			}
		}
		if (field.Flag == "storage" || field.Flag == "config") && field.Kind == "path" {
			// Includes configuration validation and immutable ceremony trust binding.
			previous := f.state.PublicBindings
			f.state.PublicBindings = maps.Clone(previous)
			err := f.bindPublicInputs([]string{"relay", "--" + field.Flag, value})
			f.state.PublicBindings = previous
			if err != nil {
				r.Missing = append(r.Missing, field.Label+": configure and authenticate it first")
			}
		}
	}
	if len(r.Missing) != 0 {
		r.Status = "Waiting"
	}
	return r
}

func flowOutputField(task flowTask, field flowField) bool {
	return flowIndependentOutput(task, field) || field.Flag == "out-dir" || field.Flag == "release-dir"
}

func (r flowReadiness) summary() string {
	if len(r.Missing) == 0 {
		return r.Status
	}
	return fmt.Sprintf("%s: %s", r.Status, strings.Join(r.Missing, "; "))
}

// Public trees only. Never snapshot a role workspace root or credential tree.
func flowPublicDirectoryFlag(flag string) bool {
	switch flag {
	case "transcript-dir", "transcript-root", "phase1-transcript-dir", "candidate-bundle", "keys-dir", "evidence-root", "operational-evidence-root", "dir":
		return true
	}
	return false
}

func flowPrivateBasename(name string) bool {
	name = strings.ToLower(filepath.Base(name))
	return name == "signing.hex" || name == "credentials" || strings.HasSuffix(name, ".grant.json") || strings.HasSuffix(name, ".credentials")
}

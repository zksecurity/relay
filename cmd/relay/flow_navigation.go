package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func (f *roleFlow) taskProgress(task flowTask) string {
	return f.readiness(task).summary()
}

// taskWhy keeps the main menu as useful as the detailed task view.  The
// requirement source alone (for example, "Relay role procedure") is an
// implementation label, not an explanation an operator can act on.
func taskWhy(task flowTask, readiness flowReadiness) string {
	why := task.Help
	if readiness.Source == "authenticated production policy" {
		return "The authenticated production ceremony requires this decision before release authorization. " + why
	}
	return why
}

// openStage changes only the local view. It does not advance a ceremony stage,
// complete a task, or alter authenticated ceremony state.
func (f *roleFlow) openStage(index int) error {
	if index < 0 || index >= len(f.stages) {
		return errors.New("selected ceremony area is unavailable")
	}
	if index == f.state.Stage {
		return nil
	}
	f.state.ViewHistory = append(f.state.ViewHistory, f.state.Stage)
	f.state.Stage = index
	return f.save()
}

// goBack reverses only a prior local view jump. In particular, it never
// reverses a completed command or moves authenticated ceremony state backward.
func (f *roleFlow) goBack() error {
	if len(f.state.ViewHistory) == 0 {
		fmt.Fprintln(f.ui.output, "No earlier local view is available. Use the ceremony map to open another area.")
		return nil
	}
	index := f.state.ViewHistory[len(f.state.ViewHistory)-1]
	if index < 0 || index >= len(f.stages) {
		return errors.New("saved navigation history is invalid; preserve the workflow folder and contact the coordinator")
	}
	f.state.ViewHistory = f.state.ViewHistory[:len(f.state.ViewHistory)-1]
	f.state.Stage = index
	return f.save()
}

func (f *roleFlow) showRecordedResults(stage flowStage) {
	for _, task := range stage.Tasks {
		fmt.Fprintf(f.ui.output, "\n%s\n  %s\n", task.Label, f.taskProgress(task))
		if a := f.last(task); a != nil {
			fmt.Fprintf(f.ui.output, "  Last attempt: %s at %s\n", a.ID, a.FinishedAt)
		}
	}
}

// ceremonyMap is navigation, not workflow progress. The numbered entries are
// destinations; the letter commands are controls that apply everywhere.
func (f *roleFlow) ceremonyMap() (bool, error) {
	for {
		f.ui.message(toneHeading, "\nCEREMONY MAP\n")
		for i, stage := range f.stages {
			marker := ""
			if i == f.state.Stage {
				marker = " [current view]"
			}
			fmt.Fprintf(f.ui.output, "  %d) %s%s\n", i+1, stage.Label, marker)
		}
		fmt.Fprintln(f.ui.output, "\nChoosing an area changes only this screen. It does not complete earlier work or waive verification.")
		f.ui.message(toneMuted, "\nNAVIGATION\n")
		fmt.Fprintln(f.ui.output, "  [B] Back to previous view\n  [Q] Save and exit")
		value, err := f.ui.ask("Open area", "")
		if err == io.EOF || strings.EqualFold(value, "q") || value == "0" {
			return true, f.save()
		}
		if err != nil {
			return false, err
		}
		if strings.EqualFold(value, "b") {
			return false, f.goBack()
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > len(f.stages) {
			fmt.Fprintln(f.ui.output, "Choose a displayed number or letter.")
			continue
		}
		return false, f.openStage(n - 1)
	}
}

func (f *roleFlow) menu() error {
	for {
		if f.state.Stage >= len(f.stages) {
			return f.stageMenu()
		}
		stage := f.stages[f.state.Stage]
		f.ui.message(toneHeading, "\nRELAY | %s | %s\n------------------------------------------------------------\n%s\n", strings.ToUpper(f.state.Role), f.state.Name, stage.Label)
		f.showCurrentPhase()
		hidden := false
		if stage.ID == "decision" {
			requirement, err := f.decisionRequirement()
			if err != nil {
				f.ui.message(toneWarning, "Waiting: %v\n", err)
			} else {
				hidden = requirement == "not-applicable"
			}
		}
		selected := -1
		waiting := -1
		turnHint := ""
		if f.state.Role == "coordinator" && f.state.Profile.Work != "" && strings.HasSuffix(stage.ID, "-turns") {
			id, err := f.nextTurnAction()
			if err != nil {
				f.ui.message(toneWarning, "Waiting: %v\n", err)
			} else {
				turnHint = id
			}
		}
		if hidden {
			fmt.Fprintln(f.ui.output, "Production decision actions hidden: not applicable to this authenticated rehearsal.")
		} else {
			for n, task := range stage.Tasks {
				a := f.last(task)
				r := f.readiness(task)
				if r.Requirement == "Optional" || r.Requirement == "Not applicable" {
					continue
				}
				if a == nil || f.checkAttemptEvidence(a) != nil || (a.Status != "succeeded" && !(task.Handoff && a.Status == "reported")) {
					if r.Status == "Waiting" {
						if waiting < 0 {
							waiting = n
						}
						continue
					}
					selected = n
					break
				}
			}
		}
		if selected < 0 {
			selected = waiting
		}
		// The schedule answers who may act next; it does not prove that this
		// participant has received and acknowledged their outbound custody
		// handoff. Never let that convenience hint skip an earlier required
		// workflow task.
		if selected < 0 && turnHint != "" {
			for n, task := range stage.Tasks {
				if task.ID == turnHint {
					selected = n
					break
				}
			}
		}
		label := "Review requirements before opening the next area"
		if selected >= 0 {
			task := stage.Tasks[selected]
			label = task.Label
			r := f.readiness(task)
			f.ui.message(toneHeading, "\nNEXT REQUIRED ACTION\n  %s\n\nWHY THIS STEP IS NEEDED\n  %s\n\nSTATUS\n  %s\n", label, taskWhy(task, r), r.summary())
			if r.Status == "Waiting" {
				label = "Review missing inputs for: " + label
			}
		}
		f.ui.message(toneSuccess, "\nACTION\n")
		fmt.Fprintf(f.ui.output, "  1) %s\n", label)
		f.ui.message(toneMuted, "\nNAVIGATION\n")
		fmt.Fprintln(f.ui.output, "  [V] View this area's actions and requirements\n  [M] Ceremony map\n  [R] Review recorded results\n  [B] Back to previous view\n  [Q] Save and exit\n------------------------------------------------------------")
		value, err := f.ui.ask("Choose", "1")
		if err == io.EOF || strings.EqualFold(value, "q") || value == "0" {
			return f.save()
		}
		if err != nil {
			return err
		}
		switch strings.ToLower(value) {
		case "1":
			if selected >= 0 {
				err = f.execute(stage.Tasks[selected])
			} else {
				err = f.advance()
			}
		case "v", "2": // 2 is a compatibility alias for saved operator habits.
			return f.stageMenu()
		case "r", "3": // 3 is a compatibility alias for saved operator habits.
			f.showRecordedResults(stage)
		case "m", "4": // 4 is a compatibility alias for saved operator habits.
			var exit bool
			exit, err = f.ceremonyMap()
			if exit {
				return err
			}
		case "b":
			err = f.goBack()
		default:
			fmt.Fprintln(f.ui.output, "Choose a displayed number.")
		}
		if err != nil {
			fmt.Fprintf(f.ui.output, "Paused: %v\nFiles and progress retained.\n", err)
		}
	}
}

package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

func (f *roleFlow) taskProgress(task flowTask) string {
	return f.readiness(task).summary()
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
		if f.state.Role == "coordinator" && f.state.Profile.Work != "" && strings.HasSuffix(stage.ID, "-turns") {
			id, err := f.nextTurnAction()
			if err != nil {
				f.ui.message(toneWarning, "Waiting: %v\n", err)
			} else if id != "" {
				for n, task := range stage.Tasks {
					if task.ID == id {
						selected = n
						break
					}
				}
			}
		}
		label := "Review requirements before opening the next area"
		if selected >= 0 {
			task := stage.Tasks[selected]
			label = task.Label
			r := f.readiness(task)
			f.ui.message(toneHeading, "\nNEXT REQUIRED ACTION\n  %s\n  %s\n  %s: %s.\n", label, r.summary(), r.Requirement, r.Source)
			if r.Status == "Waiting" {
				label = "Review missing inputs for: " + label
			}
		}
		fmt.Fprintf(f.ui.output, "\n1) %s\n2) Show other actions and requirements\n3) Review recorded results\n4) Choose another ceremony area\n0) Save and exit\n------------------------------------------------------------\n", label)
		value, err := f.ui.ask("Choose", "1")
		if err == io.EOF || value == "0" {
			return f.save()
		}
		if err != nil {
			return err
		}
		switch value {
		case "1":
			if selected >= 0 {
				err = f.execute(stage.Tasks[selected])
			} else {
				err = f.advance()
			}
		case "2":
			return f.stageMenu()
		case "3":
			for _, task := range stage.Tasks {
				fmt.Fprintf(f.ui.output, "\n%s\n  %s\n", task.Label, f.taskProgress(task))
				if a := f.last(task); a != nil {
					fmt.Fprintf(f.ui.output, "  Last attempt: %s at %s\n", a.ID, a.FinishedAt)
				}
			}
		case "4":
			choices := []setupChoice{}
			for n, s := range f.stages {
				choices = append(choices, setupChoice{value: strconv.Itoa(n), label: s.Label})
			}
			fmt.Fprintln(f.ui.output, "Choosing an area changes navigation only. It does not complete earlier work or waive verification.")
			var area string
			area, err = f.ui.choose("Open ceremony area", "", choices)
			if err == nil {
				f.state.Stage, _ = strconv.Atoi(area)
				err = f.save()
			}
		default:
			fmt.Fprintln(f.ui.output, "Choose a displayed number.")
		}
		if err != nil {
			fmt.Fprintf(f.ui.output, "Paused: %v\nFiles and progress retained.\n", err)
		}
	}
}

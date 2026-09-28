package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func decisionGateQuestion(gate int, key string) bool {
	switch gate {
	case 1:
		return strings.HasPrefix(key, "source.")
	case 6:
		return strings.HasPrefix(key, "rehearsal.")
	case 7:
		return strings.HasPrefix(key, "deployment.")
	case 8:
		return strings.HasPrefix(key, "final.")
	case 9, 10, 11:
		topic := []string{"host", "entropy", "erasure"}[gate-9]
		return key == "assurance.coverage" || strings.HasPrefix(key, "assurance."+topic+".") ||
			(strings.HasPrefix(key, "contribution.") && (strings.HasSuffix(key, ".host_label") || strings.HasSuffix(key, ".details") || strings.Contains(key, "."+topic+".")))
	}
	return false
}

func decisionGateQuestions(answers workflowV4DecisionAnswers, gate int) []workflowV4DecisionQuestionV2 {
	var selected []workflowV4DecisionQuestionV2
	for _, question := range workflowV4DecisionQuestionsV2(answers) {
		if decisionGateQuestion(gate, question.key) {
			selected = append(selected, question)
		}
	}
	return selected
}

func decisionEditGate(ui *coordinatorWizard, work string, answers *workflowV4DecisionAnswers, gate int) (bool, error) {
	for {
		questions := decisionGateQuestions(*answers, gate)
		if len(questions) == 0 {
			return false, errors.New("this gate is determined by signed ceremony evidence, not questionnaire answers")
		}
		fmt.Fprintf(ui.output, "\nReview gate %d. Select one saved answer to change; examples are never saved.\n", gate)
		for i, question := range questions {
			value := answers.Answers[question.key]
			if value == "" {
				value = question.fallback
			}
			fmt.Fprintf(ui.output, "%d) %s\n   Saved: %q\n", i+1, question.prompt, value)
			if strings.HasSuffix(question.key, ".reviewer_date") && value != "Not established" {
				_, _, valid := workflowV4ReviewerDate(value)
				if !valid {
					fmt.Fprintln(ui.output, "   Derived: Not established (use Name; YYYY-MM-DD UTC for an actual review)")
				}
			}
			if question.key == "final.withhold" && value == "No" && !workflowV4Established(answers.Answers["final.findings"]) {
				fmt.Fprintln(ui.output, "   Derived: Unknown because final findings are not established")
			}
		}
		choice, err := ui.ask("Question number, :back, or :save", "")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case ":back", "":
			return false, nil
		case ":save":
			return false, errWorkflowV4DecisionQuestionnaireSaved
		}
		index, err := strconv.Atoi(choice)
		if err != nil || index < 1 || index > len(questions) {
			fmt.Fprintln(ui.output, "Choose a displayed question number or :back.")
			continue
		}
		question := questions[index-1]
		current := answers.Answers[question.key]
		if current == "" {
			current = question.fallback
		}
		fmt.Fprintf(ui.output, "\n%s\n", question.prompt)
		if question.example != "" {
			fmt.Fprintf(ui.output, "Example (not saved): %s\n", question.example)
		}
		for i, option := range question.choices {
			fmt.Fprintf(ui.output, "  %d) %s\n", i+1, option)
		}
		value, err := ui.ask("Answer; Enter keeps saved value, :cancel returns", current)
		if err != nil {
			return false, err
		}
		value = strings.TrimSpace(value)
		if strings.EqualFold(value, ":cancel") {
			continue
		}
		if len(value) == 0 || len(value) > 4096 {
			fmt.Fprintln(ui.output, "Enter a nonempty answer of at most 4096 bytes.")
			continue
		}
		if len(question.choices) != 0 {
			matched := false
			for i, option := range question.choices {
				if value == strconv.Itoa(i+1) || strings.EqualFold(value, option) {
					value, matched = option, true
					break
				}
			}
			if !matched {
				fmt.Fprintln(ui.output, "Choose one of the displayed options; this field was not changed.")
				continue
			}
		}
		if strings.HasSuffix(question.key, ".reviewer_date") && value != "Not established" {
			_, _, valid := workflowV4ReviewerDate(value)
			if !valid {
				fmt.Fprintln(ui.output, "Use Name; YYYY-MM-DD UTC, or Not established if the review did not happen.")
				continue
			}
		}
		if value == current {
			fmt.Fprintln(ui.output, "Saved answer unchanged.")
			return false, nil
		}
		answers.Answers[question.key] = value
		answers.DecidedAt = ""
		if err := saveJSONAtomic(workflowV4QuestionnairePath(work), answers); err != nil {
			return false, err
		}
		fmt.Fprintln(ui.output, "Answer saved. Relay will recalculate all decision gates before preparation.")
		return true, nil
	}
}

// An outcome can add or remove contribution-specific follow-up questions.
// Preserve existing answers, ask only newly applicable questions, and remove
// only answers that are no longer part of the canonical V2 question set.
func decisionCompleteChangedQuestions(ui *coordinatorWizard, work string, answers *workflowV4DecisionAnswers) error {
	for {
		questions := workflowV4DecisionQuestionsV2(*answers)
		allowed := make(map[string]bool, len(questions))
		for _, q := range questions {
			allowed[q.key] = true
		}
		removed := false
		for key := range answers.Answers {
			if !allowed[key] {
				delete(answers.Answers, key)
				removed = true
			}
		}
		if removed {
			answers.DecidedAt = ""
			if err := saveJSONAtomic(workflowV4QuestionnairePath(work), answers); err != nil {
				return err
			}
		}
		var missing *workflowV4DecisionQuestionV2
		for i := range questions {
			if answers.Answers[questions[i].key] == "" {
				missing = &questions[i]
				break
			}
		}
		if missing == nil {
			return nil
		}
		fmt.Fprintf(ui.output, "New follow-up required after that change: %s\n", missing.prompt)
		if missing.example != "" {
			fmt.Fprintf(ui.output, "Example (not saved): %s\n", missing.example)
		}
		for i, choice := range missing.choices {
			fmt.Fprintf(ui.output, "  %d) %s\n", i+1, choice)
		}
		value, err := ui.ask("Answer or :save", missing.fallback)
		if err != nil {
			return err
		}
		value = strings.TrimSpace(value)
		if strings.EqualFold(value, ":save") {
			return errWorkflowV4DecisionQuestionnaireSaved
		}
		if value == "" || len(value) > 4096 {
			fmt.Fprintln(ui.output, "Enter a nonempty answer of at most 4096 bytes.")
			continue
		}
		if len(missing.choices) > 0 {
			matched := false
			for i, choice := range missing.choices {
				if value == strconv.Itoa(i+1) || strings.EqualFold(value, choice) {
					value, matched = choice, true
					break
				}
			}
			if !matched {
				fmt.Fprintln(ui.output, "Choose one of the displayed options; this answer was not saved.")
				continue
			}
		}
		if strings.HasSuffix(missing.key, ".reviewer_date") && value != "Not established" {
			_, _, valid := workflowV4ReviewerDate(value)
			if !valid {
				fmt.Fprintln(ui.output, "Use Name; YYYY-MM-DD UTC, or Not established.")
				continue
			}
		}
		answers.Answers[missing.key] = value
		answers.DecidedAt = ""
		if err := saveJSONAtomic(workflowV4QuestionnairePath(work), answers); err != nil {
			return err
		}
	}
}

func decisionShowGoRequirements(ui *coordinatorWizard, answers workflowV4DecisionAnswers, gates []workflowV4DecisionGate) {
	decisionShowDowngrades(ui, answers)
	missing := 0
	for i, gate := range gates {
		if gate.Status == "PASS" || gate.Status == "NOT_REQUIRED" {
			continue
		}
		missing++
		fmt.Fprintf(ui.output, "  %d) %s — %s: %s\n", i+1, gate.Gate, gate.Status, gate.Rationale)
		for _, question := range decisionGateQuestions(answers, i+1) {
			value := answers.Answers[question.key]
			if value == "" {
				value = question.fallback
			}
			if value == "Unknown" || value == "Not established" || value == "Not assessed" || value == "Not reviewed" || value == "No" || value == "Rejected" || value == workflowV4ReviewBlocked {
				fmt.Fprintf(ui.output, "     %s: %q\n", question.key, value)
			}
			if strings.HasSuffix(question.key, ".reviewer_date") && value != "Not established" {
				_, _, valid := workflowV4ReviewerDate(value)
				if !valid {
					fmt.Fprintf(ui.output, "     %s: %q → Not established; use Name; YYYY-MM-DD UTC for an actual review\n", question.key, value)
				}
			}
		}
	}
	if missing == 0 {
		fmt.Fprintln(ui.output, "Mechanically derived GO preview — not approval. Relay has not established the truth of human reviews; both signers must review the exact evidence before signing.")
	} else {
		fmt.Fprintf(ui.output, "What remains for GO: %d gates need review. Select a gate number to edit actual answers; if a review did not happen, keep the truthful incomplete answer.\n", missing)
		if answers.Answers["final.withhold"] == "No" && !workflowV4Established(answers.Answers["final.findings"]) {
			fmt.Fprintln(ui.output, "  Final checklist: No becomes Unknown because final findings are Not assessed. Record actual findings and limits to keep the No answer.")
		}
	}
}

func decisionShowDowngrades(ui *coordinatorWizard, answers workflowV4DecisionAnswers) {
	expanded, err := workflowV4ExpandDecisionAnswersV2(answers)
	if err != nil {
		return
	}
	printed := false
	show := func(rawKey, derivedKey, why string) {
		raw, derived := answers.Answers[rawKey], expanded.Answers[derivedKey]
		if raw == "" || derived == "" || (raw != "No" && raw != workflowV4ReviewClear && raw != workflowV4RowCovered && raw != workflowV4RowSeparate) {
			return
		}
		if derived != "Unknown" && derived != "Incomplete or unknown" {
			return
		}
		if !printed {
			fmt.Fprintln(ui.output, "Answers downgraded during decision preparation:")
			printed = true
		}
		fmt.Fprintf(ui.output, "  %s: %q → %s: %q. %s\n", rawKey, raw, derivedKey, derived, why)
	}
	for _, prefix := range []string{"source", "rehearsal", "deployment"} {
		show(prefix+".status", prefix+".conclusion", "The reviewer/date, actual checks, findings, circuit match, or deployment details are missing; inspect this gate's questions.")
	}
	show("final.withhold", "final.withhold", "Record actual final findings and limits; Not assessed cannot support a No answer.")
	for _, scope := range answers.Accepted {
		row := "contribution." + scope.key()
		for _, topic := range []string{"host", "entropy", "erasure"} {
			show(row+"."+topic+".outcome", scope.key()+"."+topic+".reviewed", "Shared coverage or this contribution's host, checks, reviewer/date, or details are missing.")
		}
	}
}

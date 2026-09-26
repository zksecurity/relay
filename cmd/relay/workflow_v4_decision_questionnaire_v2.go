package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var errWorkflowV4DecisionQuestionnaireSaved = errors.New("decision questionnaire saved")

const (
	workflowV4ReviewClear   = "Accepted; no unresolved blocker"
	workflowV4ReviewBlocked = "Review accepted; blocker remains"
	workflowV4RowCovered    = "Covered and accepted; no unresolved blocker"
	workflowV4RowSeparate   = "Separately accepted; no unresolved blocker"
)

type workflowV4DecisionQuestionV2 struct {
	section, key, prompt, example, fallback string
	choices                                 []string
}

func workflowV4DecisionQuestionsV2(answers workflowV4DecisionAnswers) []workflowV4DecisionQuestionV2 {
	const unknown = "Unknown"
	const notEstablished = "Not established"
	q := []workflowV4DecisionQuestionV2{
		{"Pinned source release", "source.status", "What was the source-release review outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", "Not reviewed", unknown}},
		{"", "source.reviewer_date", "Who reviewed the pinned release, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "source.checks", "What source, build, and release checks were performed?", "Compared pinned commit, build inputs, and released image digests; noted any gaps", notEstablished, nil},
		{"", "source.findings", "What were the source review's findings and limits?", "No findings within the reviewed build scope", "Not assessed", nil},
		{"Exact circuit rehearsal", "rehearsal.match", "Did the reviewed rehearsal use this exact signed circuit?", "", unknown, []string{"Yes", "No", unknown}},
		{"", "rehearsal.status", "What was the exact-circuit rehearsal outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", "Not reviewed", unknown}},
		{"", "rehearsal.reviewer_date", "Who ran/reviewed the rehearsal, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "rehearsal.checks", "What ran, and what were the results?", "Full ceremony rehearsal with this circuit; proof and verification passed", notEstablished, nil},
		{"", "rehearsal.findings", "What differed, failed, or was not checked?", "No differences or failures found within the stated scope", "Not assessed", nil},
		{"Deployment and operation", "deployment.target", "Which network and application, contract, or service will receive the key?", "Cardano mainnet; Refund verifier service", notEstablished, nil},
		{"", "deployment.owners", "Who approves, prepares, and performs deployment?", "Approval: J. Smith; preparation: A. Lee; deployment: B. Kim", notEstablished, nil},
		{"", "deployment.verification", "How will they check signed GO, final release, and the exact key before deployment?", "Verify decision signatures and archive; compare key hash to transaction input", notEstablished, nil},
		{"", "deployment.activation", "What are the activation conditions and procedure?", "Activate only after signed GO and key comparison; submit reviewed transaction", notEstablished, nil},
		{"", "deployment.halt", "How can use be halted or rolled back, and what cannot be reversed?", "Pause off-chain use; on-chain transaction cannot be reversed", notEstablished, nil},
		{"", "deployment.postcheck", "Who checks the deployed result afterward, and how?", "J. Smith compares on-chain key and application state with release", notEstablished, nil},
		{"", "deployment.reviewer_date", "Who reviewed this plan, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "deployment.status", "What was the deployment-plan review outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", "Not reviewed", unknown}},
		{"", "deployment.findings", "What were the plan review's findings and limits?", "No unresolved findings; on-chain effects are irreversible", "Not assessed", nil},
		{"Participant assurance across both phases", "assurance.coverage", "Do the shared host, randomness, and cleanup reviews cover every listed contribution and event?", "", unknown, []string{"Yes", "No", unknown}},
		{"", "assurance.host.reviewer_date", "Who reviewed host security for all covered contributions, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "assurance.host.checks", "What host-security checks covered the listed contributions? Name hosts, findings, and limits.", "Host A for phase 1/2 participant 1; checked access, isolation, swap, and backup settings", notEstablished, nil},
		{"", "assurance.host.outcome", "What was the shared host-security review outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", unknown}},
		{"", "assurance.entropy.reviewer_date", "Who reviewed randomness for all covered contributions, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "assurance.entropy.checks", "What randomness source and fresh generation checks covered each contribution?", "Checked OS randomness and fresh generation for every listed contribution", notEstablished, nil},
		{"", "assurance.entropy.outcome", "What was the shared randomness review outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", unknown}},
		{"", "assurance.erasure.reviewer_date", "Who reviewed cleanup for all covered contributions, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil},
		{"", "assurance.erasure.checks", "What cleanup checks covered each contribution (snapshots, dumps, swap, backups, retained randomness)?", "Reviewed owner cleanup and host settings for every listed event; no retained copies reported", notEstablished, nil},
		{"", "assurance.erasure.outcome", "What was the shared cleanup review outcome?", "", unknown, []string{workflowV4ReviewClear, workflowV4ReviewBlocked, "Rejected", unknown}},
	}
	for _, scope := range answers.Accepted {
		prefix := "contribution." + scope.key()
		section := fmt.Sprintf("%s position %d — %s", scope.Phase, scope.Position, scope.ParticipantID)
		q = append(q,
			workflowV4DecisionQuestionV2{section, prefix + ".host_label", "Which host was used for this exact contribution?", "Participant 1's dedicated 16 GiB node", notEstablished, nil},
			workflowV4DecisionQuestionV2{"", prefix + ".host.outcome", "Was host security accepted for this contribution?", "", unknown, []string{workflowV4RowCovered, workflowV4RowSeparate, workflowV4ReviewBlocked, "Rejected", unknown}},
			workflowV4DecisionQuestionV2{"", prefix + ".entropy.outcome", "Was fresh randomness accepted for this contribution?", "", unknown, []string{workflowV4RowCovered, workflowV4RowSeparate, workflowV4ReviewBlocked, "Rejected", unknown}},
			workflowV4DecisionQuestionV2{"", prefix + ".erasure.outcome", "Was cleanup accepted for this contribution?", "", unknown, []string{workflowV4RowCovered, workflowV4RowSeparate, workflowV4ReviewBlocked, "Rejected", unknown}},
		)
		separate := false
		for _, topic := range []string{"host", "entropy", "erasure"} {
			outcome := answers.Answers[prefix+"."+topic+".outcome"]
			if outcome != workflowV4RowCovered && outcome != "Unknown" && outcome != "" {
				separate = true
			}
		}
		if separate {
			q = append(q,
				workflowV4DecisionQuestionV2{"", prefix + ".details", "What checks, findings, limits, or exceptions apply specifically to this contribution?", "Host changed; reviewed new swap and snapshot settings, fresh randomness, and cleanup", notEstablished, nil},
			)
			for _, topic := range []string{"host", "entropy", "erasure"} {
				outcome := answers.Answers[prefix+"."+topic+".outcome"]
				if outcome != workflowV4RowCovered && outcome != "Unknown" && outcome != "" {
					q = append(q, workflowV4DecisionQuestionV2{"", prefix + "." + topic + ".reviewer_date", "Who reviewed this contribution's " + topic + " outcome, and when (UTC)?", "J. Smith; 2026-09-26 UTC", notEstablished, nil})
				}
			}
		}
	}
	q = append(q,
		workflowV4DecisionQuestionV2{"Final review", "final.withhold", "After reviewing every contribution, is there another known reason to withhold GO?", "", unknown, []string{"Yes", "No", unknown}},
		workflowV4DecisionQuestionV2{"", "final.findings", "What are the final findings and limits?", "No additional findings within the recorded review scope", "Not assessed", nil},
	)
	return q
}

func workflowV4AskDecisionQuestionsV2(ui *coordinatorWizard, work string, answers *workflowV4DecisionAnswers, reviewAgain ...bool) error {
	fmt.Fprintln(ui.output, "Numbered choices accept a number or its text. [value] is the saved answer or actual default; Enter accepts it. Examples are guidance only and are never saved. Type :back to revise the previous question or :save to exit without preparing.")
	index := 0
	if len(reviewAgain) == 0 || !reviewAgain[0] {
		for _, question := range workflowV4DecisionQuestionsV2(*answers) {
			if answers.Answers[question.key] == "" {
				break
			}
			index++
		}
	}
	for {
		questions := workflowV4DecisionQuestionsV2(*answers)
		if index >= len(questions) {
			allowed := map[string]bool{}
			for _, question := range questions {
				allowed[question.key] = true
			}
			for key := range answers.Answers {
				if !allowed[key] {
					delete(answers.Answers, key)
				}
			}
			return saveJSONAtomic(workflowV4QuestionnairePath(work), answers)
		}
		question := questions[index]
		if question.section != "" {
			fmt.Fprintf(ui.output, "\n%s\n", question.section)
		}
		if question.example != "" {
			fmt.Fprintf(ui.output, "Example (not saved): %s\n", question.example)
		}
		for i, choice := range question.choices {
			fmt.Fprintf(ui.output, "  %d) %s\n", i+1, choice)
		}
		current := answers.Answers[question.key]
		if current == "" {
			current = question.fallback
		}
		value, err := ui.ask(question.prompt, current)
		if err != nil {
			return err
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(value) {
		case ":save":
			return errWorkflowV4DecisionQuestionnaireSaved
		case ":back":
			if index > 0 {
				index--
			} else {
				fmt.Fprintln(ui.output, "Already at the first question.")
			}
			continue
		}
		if value == "" || len(value) > 4096 {
			fmt.Fprintln(ui.output, "Enter a nonempty answer of at most 4096 bytes, or :save to continue later.")
			continue
		}
		if len(question.choices) != 0 {
			matched := false
			for i, choice := range question.choices {
				if value == fmt.Sprint(i+1) || strings.EqualFold(value, choice) {
					value, matched = choice, true
					break
				}
			}
			if !matched {
				fmt.Fprintln(ui.output, "Choose one of the displayed numbers or responses; this answer was not saved.")
				continue
			}
		}
		answers.Answers[question.key] = value
		answers.DecidedAt = ""
		if err := saveJSONAtomic(workflowV4QuestionnairePath(work), answers); err != nil {
			return err
		}
		index++
	}
}

func workflowV4Established(value string) bool {
	return value != "" && value != "Not established" && value != "Not assessed" && value != "Not specified"
}

func workflowV4ReviewerDate(value string) (string, string, bool) {
	parts := strings.SplitN(value, ";", 2)
	if len(parts) != 2 || !workflowV4Established(strings.TrimSpace(parts[0])) || !workflowV4Established(strings.TrimSpace(parts[1])) {
		return "Not established", "Not established", false
	}
	date := strings.TrimSpace(parts[1])
	parsed, err := time.Parse("2006-01-02 UTC", date)
	if err != nil || parsed.After(time.Now().UTC()) {
		return "Not established", "Not established", false
	}
	return strings.TrimSpace(parts[0]), date, true
}

func workflowV4ExpandDecisionAnswersV2(answers workflowV4DecisionAnswers) (workflowV4DecisionAnswers, error) {
	if answers.DecidedAt == "" || len(answers.Accepted) == 0 {
		return answers, errors.New("unfinished guided decision questionnaire")
	}
	questions := workflowV4DecisionQuestionsV2(answers)
	if len(answers.Answers) != len(questions) {
		return answers, errors.New("V2 questionnaire has missing or unexpected answers")
	}
	seen := map[string]bool{}
	for _, question := range questions {
		if seen[question.key] {
			return answers, errors.New("duplicate V2 questionnaire field")
		}
		seen[question.key] = true
		value := answers.Answers[question.key]
		if value == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
			return answers, fmt.Errorf("invalid V2 questionnaire field %q", question.key)
		}
		if len(question.choices) != 0 && !slices.Contains(question.choices, value) {
			return answers, fmt.Errorf("invalid V2 choice %q", question.key)
		}
	}
	old := answers
	old.Schema = workflowV4LegacyDecisionQuestionsSchema
	old.Answers = map[string]string{}
	read := func(key string) string { return answers.Answers[key] }
	putReview := func(prefix, outcome, reviewerDate, checks, findings string, established bool) {
		reviewer, date, reviewerKnown := workflowV4ReviewerDate(reviewerDate)
		if !reviewerKnown || !workflowV4Established(checks) || !workflowV4Established(findings) || !established {
			if outcome == workflowV4ReviewClear {
				outcome = "Unknown"
			}
		}
		reviewed, conclusion, blocker := "Unknown", "Incomplete or unknown", "Unknown"
		if outcome == workflowV4ReviewClear {
			reviewed, conclusion, blocker = "Yes", "Accept", "No"
		} else if outcome == workflowV4ReviewBlocked {
			reviewed, conclusion, blocker = "Yes", "Accept", "Yes"
		} else if outcome == "Rejected" {
			reviewed, conclusion, blocker = "Yes", "Reject", "Yes"
		}
		old.Answers[prefix+".reviewed"] = reviewed
		old.Answers[prefix+".reviewer"] = reviewer
		old.Answers[prefix+".date"] = date
		old.Answers[prefix+".scope"] = checks
		old.Answers[prefix+".findings"] = findings
		old.Answers[prefix+".conclusion"] = conclusion
		old.Answers[prefix+".blocker"] = blocker
	}
	putReview("source", read("source.status"), read("source.reviewer_date"), read("source.checks"), read("source.findings"), true)
	putReview("rehearsal", read("rehearsal.status"), read("rehearsal.reviewer_date"), read("rehearsal.checks"), read("rehearsal.findings"), read("rehearsal.match") == "Yes")
	old.Answers["rehearsal.matching_circuit"] = read("rehearsal.match")
	putReview("deployment", read("deployment.status"), read("deployment.reviewer_date"), read("deployment.verification"), read("deployment.findings"), true)
	delete(old.Answers, "deployment.scope")
	target := strings.SplitN(read("deployment.target"), ";", 2)
	if len(target) == 2 && workflowV4Established(strings.TrimSpace(target[0])) && workflowV4Established(strings.TrimSpace(target[1])) {
		old.Answers["deployment.network"] = strings.TrimSpace(target[0])
		old.Answers["deployment.application"] = strings.TrimSpace(target[1])
	} else {
		old.Answers["deployment.network"] = read("deployment.target")
		old.Answers["deployment.application"] = "Not established"
		if old.Answers["deployment.conclusion"] == "Accept" {
			old.Answers["deployment.reviewed"] = "Unknown"
			old.Answers["deployment.conclusion"] = "Incomplete or unknown"
			old.Answers["deployment.blocker"] = "Unknown"
		}
	}
	for _, field := range []string{"owners", "verification", "activation", "halt", "postcheck"} {
		old.Answers["deployment."+field] = read("deployment." + field)
		if !workflowV4Established(read("deployment."+field)) && old.Answers["deployment.conclusion"] == "Accept" {
			old.Answers["deployment.reviewed"] = "Unknown"
			old.Answers["deployment.conclusion"] = "Incomplete or unknown"
			old.Answers["deployment.blocker"] = "Unknown"
		}
	}
	// The legacy generator has no deployment.reviewed field. Keep that guard
	// private to the conversion and rely on its downgraded conclusion.
	delete(old.Answers, "deployment.reviewed")
	old.Answers["final.withhold"] = read("final.withhold")
	old.Answers["final.findings"] = read("final.findings")
	if !workflowV4Established(read("final.findings")) && old.Answers["final.withhold"] == "No" {
		old.Answers["final.withhold"] = "Unknown"
	}
	for _, scope := range answers.Accepted {
		row := "contribution." + scope.key()
		for _, topic := range []string{"host", "entropy", "erasure"} {
			outcome, reviewerDate, checks, findings, established := "Unknown", "Not established", "Not established", "Not assessed", false
			switch read(row + "." + topic + ".outcome") {
			case workflowV4RowCovered:
				outcome = read("assurance." + topic + ".outcome")
				reviewerDate = read("assurance." + topic + ".reviewer_date")
				checks = read("assurance."+topic+".checks") + "; host: " + read(row+".host_label") + "; applies to " + scope.key()
				findings = read("assurance." + topic + ".checks")
				established = read("assurance.coverage") == "Yes" && workflowV4Established(read("assurance."+topic+".checks")) && workflowV4Established(read(row+".host_label"))
			case workflowV4RowSeparate:
				outcome = workflowV4ReviewClear
				reviewerDate = read(row + "." + topic + ".reviewer_date")
				checks = read(row+".details") + "; host: " + read(row+".host_label") + "; contribution: " + scope.key()
				findings = read(row + ".details")
				established = workflowV4Established(read(row+".details")) && workflowV4Established(read(row+".host_label"))
			case workflowV4ReviewBlocked, "Rejected":
				outcome = read(row + "." + topic + ".outcome")
				reviewerDate = read(row + "." + topic + ".reviewer_date")
				checks = read(row+".details") + "; host: " + read(row+".host_label") + "; contribution: " + scope.key()
				findings = read(row + ".details")
			}
			putReview(scope.key()+"."+topic, outcome, reviewerDate, checks, findings, established)
		}
	}
	if err := workflowV4ValidateDecisionAnswers(old); err != nil {
		return answers, err
	}
	return old, nil
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const workflowV4DecisionQuestionsSchema = "relay-guided-decision-answers-v1"

type workflowV4AcceptedReviewScope struct {
	Phase         string `json:"phase"`
	Position      uint8  `json:"position"`
	ParticipantID string `json:"participant_id"`
}

func (s workflowV4AcceptedReviewScope) key() string {
	return fmt.Sprintf("%s.%02d.%s", s.Phase, s.Position, s.ParticipantID)
}

type workflowV4DecisionAnswers struct {
	Schema           string                          `json:"schema"`
	CeremonyID       string                          `json:"ceremony_id"`
	CandidateID      string                          `json:"candidate_id"`
	CheckpointSHA256 string                          `json:"checkpoint_sha256"`
	PolicySHA256     string                          `json:"policy_sha256"`
	CoordinatorID    string                          `json:"coordinator_id"`
	DecidedAt        string                          `json:"decided_at"`
	Accepted         []workflowV4AcceptedReviewScope `json:"accepted"`
	Answers          map[string]string               `json:"answers"`
}

func workflowV4QuestionnairePath(work string) string {
	return filepath.Join(work, "workflow-v4", "decision-questionnaire.json")
}

func workflowV4AcceptedReviewScopes(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol) ([]workflowV4AcceptedReviewScope, error) {
	commitments, err := snapshot.Commitments()
	if err != nil {
		return nil, err
	}
	accepted := []workflowV4AcceptedReviewScope{}
	for _, turn := range commitments.Turns {
		if turn.AcceptedChain == nil {
			continue
		}
		if turn.Scope.CeremonyID != protocol.Definition.CeremonyID || turn.Scope.Index == 0 || turn.Scope.ParticipantID == "" {
			return nil, errors.New("invalid authenticated accepted contribution scope")
		}
		accepted = append(accepted, workflowV4AcceptedReviewScope{Phase: turn.Scope.Phase, Position: turn.Scope.Index, ParticipantID: turn.Scope.ParticipantID})
	}
	slices.SortFunc(accepted, func(a, b workflowV4AcceptedReviewScope) int {
		if a.Phase != b.Phase {
			return strings.Compare(a.Phase, b.Phase)
		}
		return int(a.Position) - int(b.Position)
	})
	expected := []workflowV4AcceptedReviewScope{}
	for _, phase := range []string{"phase1", "phase2"} {
		roster, err := protocol.Definition.Schedule(phase)
		if err != nil {
			return nil, err
		}
		for index, id := range roster {
			expected = append(expected, workflowV4AcceptedReviewScope{Phase: phase, Position: uint8(index + 1), ParticipantID: id})
		}
	}
	if !slices.Equal(accepted, expected) {
		return nil, errors.New("authenticated accepted contributions do not exactly cover the signed schedule")
	}
	return accepted, nil
}

func workflowV4CandidateID(snapshot storagefirst.SnapshotV4, work string) (string, error) {
	const name = "final/release/candidate.json"
	var refFound bool
	var want string
	var size int64
	for _, ref := range snapshot.Files() {
		if ref.Name == name {
			refFound, want, size = true, ref.SHA256, ref.Size
			break
		}
	}
	if !refFound || size <= 0 || size > 16<<20 {
		return "", errors.New("authenticated final release candidate is absent or oversized")
	}
	path := filepath.Join(work, "ceremony", "public", filepath.FromSlash(name))
	got, _, err := workflowV4FileSHA256(path, size)
	if err != nil || got != want {
		return "", errors.New("retained final release candidate differs from authenticated storage")
	}
	raw, err := readTesseraRegularFile(path, size, false)
	if err != nil {
		return "", err
	}
	var candidate struct {
		CandidateID string `json:"candidate_id"`
	}
	if json.Unmarshal(raw, &candidate) != nil {
		return "", errors.New("invalid final release candidate")
	}
	if _, err := workflowV4HandoffHex(candidate.CandidateID); err != nil {
		return "", err
	}
	return candidate.CandidateID, nil
}

type workflowV4DecisionDefinitionFields struct {
	CeremonyID      string          `json:"ceremony_id"`
	AssurancePolicy json.RawMessage `json:"assurance_policy"`
	Circuit         json.RawMessage `json:"circuit"`
	Software        struct {
		SourceCommit string `json:"source_commit"`
	} `json:"software"`
}

func workflowV4DecisionDefinition(protocol transcript.DefinitionProtocol, work string) (workflowV4DecisionDefinitionFields, string, error) {
	var definition workflowV4DecisionDefinitionFields
	path := filepath.Join(work, "ceremony", "public", "ceremony.json")
	sha, _, err := workflowV4FileSHA256(path, 16<<20)
	if err != nil || sha != protocol.DefinitionRefs.Record.Digest.SHA256 {
		return definition, "", errors.New("retained definition differs from authenticated bytes")
	}
	raw, err := readTesseraRegularFile(path, 16<<20, false)
	if err != nil || json.Unmarshal(raw, &definition) != nil || definition.CeremonyID != protocol.Definition.CeremonyID || len(definition.AssurancePolicy) == 0 || len(definition.Circuit) == 0 || len(definition.Software.SourceCommit) != 40 {
		return definition, "", errors.New("incomplete authenticated V5 decision definition")
	}
	var policy struct {
		PublicWitnessesPerPhase      int `json:"public_witnesses_per_phase"`
		MirrorsPerAcceptedHead       int `json:"mirrors_per_accepted_head"`
		PassingCeremonyAudits        int `json:"passing_ceremony_audits"`
		ExternalSecurityAuditSignoff int `json:"external_security_audit_signoffs"`
	}
	if json.Unmarshal(definition.AssurancePolicy, &policy) != nil || policy.PublicWitnessesPerPhase != 0 || policy.MirrorsPerAcceptedHead != 0 || policy.PassingCeremonyAudits != 0 || policy.ExternalSecurityAuditSignoff != 0 {
		return definition, "", errors.New("the first guided questionnaire supports only signed policies with zero optional audit, witness, and mirror requirements; use the reviewed manual V5 draft for this policy")
	}
	digest := sha256.Sum256(definition.AssurancePolicy)
	return definition, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func workflowV4LoadDecisionAnswers(work string, binding workflowV4DecisionAnswers) (workflowV4DecisionAnswers, error) {
	path := workflowV4QuestionnairePath(work)
	var saved workflowV4DecisionAnswers
	if err := setupReadJSON(path, &saved); err == nil {
		if saved.Schema != binding.Schema || saved.CeremonyID != binding.CeremonyID || saved.CandidateID != binding.CandidateID || saved.CheckpointSHA256 != binding.CheckpointSHA256 || saved.PolicySHA256 != binding.PolicySHA256 || saved.CoordinatorID != binding.CoordinatorID || !slices.Equal(saved.Accepted, binding.Accepted) || saved.DecidedAt == "" || saved.Answers == nil {
			return saved, errors.New("retained questionnaire belongs to different authenticated inputs")
		}
		return saved, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return saved, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return binding, err
	}
	binding.DecidedAt = time.Now().UTC().Format(time.RFC3339)
	binding.Answers = map[string]string{}
	return binding, saveJSONAtomic(path, binding)
}

func workflowV4AskDecisionAnswer(ui *coordinatorWizard, work string, answers *workflowV4DecisionAnswers, key, prompt string, choices []string) error {
	if len(choices) != 0 {
		prompt += " (" + strings.Join(choices, " / ") + ")"
	}
	value, err := ui.ask(prompt, answers.Answers[key])
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4096 {
		return fmt.Errorf("answer %s must be nonempty and at most 4096 bytes", key)
	}
	if len(choices) != 0 {
		matched := false
		for _, choice := range choices {
			if strings.EqualFold(value, choice) {
				value = choice
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("answer %s must be one of %s", key, strings.Join(choices, ", "))
		}
	}
	answers.Answers[key] = value
	return saveJSONAtomic(workflowV4QuestionnairePath(work), answers)
}

func workflowV4AskDecisionQuestions(ui *coordinatorWizard, work string, answers *workflowV4DecisionAnswers) error {
	q := func(key, prompt string, choices ...string) error {
		return workflowV4AskDecisionAnswer(ui, work, answers, key, prompt, choices)
	}
	review := []string{"Yes", "No", "Unknown", "Not reviewed yet"}
	conclusion := []string{"Accept", "Reject", "Incomplete or unknown"}
	blocking := []string{"Yes", "No", "Unknown"}
	groups := []struct {
		Prefix string
		Title  string
		Items  []struct {
			Key, Prompt string
			Choices     []string
		}
	}{
		{"source", "Pinned source release", []struct {
			Key, Prompt string
			Choices     []string
		}{
			{"reviewed", "Was the displayed pinned source release reviewed?", review},
			{"reviewer", "Who reviewed the source release?", nil},
			{"date", "When was it reviewed (UTC date)?", nil},
			{"scope", "What source, build, and release checks were performed?", nil},
			{"findings", "What were the findings, limits, and exceptions?", nil},
			{"conclusion", "Reviewer conclusion for this release (Accept/Reject/Incomplete or unknown)", conclusion},
			{"blocker", "Is any source or release issue still blocking its use?", blocking},
		}},
		{"rehearsal", "Exact circuit rehearsal", []struct {
			Key, Prompt string
			Choices     []string
		}{
			{"reviewed", "Was this exact signed circuit rehearsed and reviewed?", review},
			{"reviewer", "Who ran and reviewed the rehearsal?", nil},
			{"date", "When was it reviewed (UTC date)?", nil},
			{"matching_circuit", "Did the reviewed rehearsal use the displayed exact circuit binding?", blocking},
			{"scope", "What was run and what were the results?", nil},
			{"conclusion", "Rehearsal outcome (Accept=pass, Reject=fail, Incomplete or unknown)", conclusion},
			{"findings", "What differed, failed, or was not checked?", nil},
			{"blocker", "Is any rehearsal finding still blocking production use?", blocking},
		}},
		{"deployment", "Mainnet deployment and operation", []struct {
			Key, Prompt string
			Choices     []string
		}{
			{"network", "Which network will use this verifying key?", nil},
			{"application", "Which application, contract, or service will receive it?", nil},
			{"owners", "Who approves, prepares, and performs deployment?", nil},
			{"verification", "How will signed GO, final release, and the exact key be checked before deployment?", nil},
			{"activation", "What are the activation conditions and procedure?", nil},
			{"halt", "How can use be halted or rolled back, and what cannot be reversed?", nil},
			{"postcheck", "Who checks the deployed key and application afterward, and how?", nil},
			{"reviewer", "Who reviewed this procedure?", nil},
			{"date", "When was it reviewed (UTC date)?", nil},
			{"findings", "What were the review findings and limits?", nil},
			{"conclusion", "Reviewer conclusion for this procedure (Accept/Reject/Incomplete or unknown)", conclusion},
			{"blocker", "Is any deployment or operational issue still blocking production use?", blocking},
		}},
	}
	for _, group := range groups {
		fmt.Fprintf(ui.output, "\n%s review\n", group.Title)
		for _, item := range group.Items {
			if err := q(group.Prefix+"."+item.Key, item.Prompt, item.Choices...); err != nil {
				return err
			}
		}
	}
	for _, scope := range answers.Accepted {
		fmt.Fprintf(ui.output, "\nAccepted %s position %d: %s\n", scope.Phase, scope.Position, scope.ParticipantID)
		for _, topic := range []struct{ Key, Title, Checks string }{
			{"host", "host security", "What host security was checked, and what remains unverified?"},
			{"entropy", "randomness", "What randomness source and generation process were checked, and what remains unverified?"},
			{"erasure", "cleanup", "What was checked about snapshots, memory dumps, swap, backups, and retained randomness? What remains unverified?"},
		} {
			prefix := scope.key() + "." + topic.Key
			if err := q(prefix+".reviewed", "Was this contribution's "+topic.Title+" reviewed?", review...); err != nil {
				return err
			}
			if err := q(prefix+".reviewer", "Who reviewed it?", nil...); err != nil {
				return err
			}
			if err := q(prefix+".date", "When was it reviewed (UTC date)?", nil...); err != nil {
				return err
			}
			if err := q(prefix+".scope", topic.Checks); err != nil {
				return err
			}
			if err := q(prefix+".findings", "What were the findings, accepted limits, and exceptions?"); err != nil {
				return err
			}
			if err := q(prefix+".conclusion", "Reviewer conclusion (Accept/Reject/Incomplete or unknown)", conclusion...); err != nil {
				return err
			}
			if err := q(prefix+".blocker", "Is any issue still blocking use?", blocking...); err != nil {
				return err
			}
		}
	}
	if err := q("final.withhold", "Is there any other known reason to withhold GO?", blocking...); err != nil {
		return err
	}
	return q("final.findings", "Describe the final GO/NO-GO findings and limits; write none if there are none")
}

type workflowV4DecisionPreparationIntent struct {
	Schema           string            `json:"schema"`
	CeremonyID       string            `json:"ceremony_id"`
	CandidateID      string            `json:"candidate_id"`
	CheckpointSHA256 string            `json:"checkpoint_sha256"`
	QuestionnaireSHA string            `json:"questionnaire_sha256"`
	DraftSHA         string            `json:"draft_sha256"`
	EvidenceSHA      map[string]string `json:"evidence_sha256"`
}

func workflowV4RetainDecisionPreparationIntent(work string, answers workflowV4DecisionAnswers, files map[string][]byte, draft []byte) error {
	formRaw, err := readTesseraRegularFile(workflowV4QuestionnairePath(work), 16<<20, false)
	if err != nil {
		return err
	}
	digest := func(value []byte) string { sum := sha256.Sum256(value); return "sha256:" + hex.EncodeToString(sum[:]) }
	intent := workflowV4DecisionPreparationIntent{Schema: "relay-guided-decision-preparation-v1", CeremonyID: answers.CeremonyID, CandidateID: answers.CandidateID, CheckpointSHA256: answers.CheckpointSHA256, QuestionnaireSHA: digest(formRaw), DraftSHA: digest(draft), EvidenceSHA: map[string]string{}}
	for name, raw := range files {
		intent.EvidenceSHA[name] = digest(raw)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	path := filepath.Join(work, "workflow-v4", "decision", "intent.json")
	if err := workflowV4HandoffEnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return setupWriteBytesNewOrExact(path, raw, 0600)
}

func runWorkflowV4GuidedDecision(ui *coordinatorWizard, online, signer guidedProfile, identity setupIdentity, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4, common []string, decisionHost, evidenceHost string) error {
	state, err := snapshot.State()
	if err != nil || state.Progress.FinalRelease == nil {
		return errors.New("record the signed final release before preparing a production decision")
	}
	if _, err := os.Lstat(decisionHost); err == nil {
		if err := requireDecisionEvidence(decisionHost, evidenceHost, protocol.Definition.CeremonyID, ui); err != nil {
			return fmt.Errorf("retained decision needs reviewed recovery: %w", err)
		}
		fmt.Fprintln(ui.output, "An existing decision is retained. Choose D → 2 to review it and let pinned proof-tool verify it before any signature; Relay will not prepare it again.")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := requireFreshDecisionOutput(decisionHost); err != nil {
		return err
	}
	definition, policySHA, err := workflowV4DecisionDefinition(protocol, online.Work)
	if err != nil {
		return err
	}
	candidateID, err := workflowV4CandidateID(snapshot, online.Work)
	if err != nil {
		return err
	}
	accepted, err := workflowV4AcceptedReviewScopes(snapshot, protocol)
	if err != nil {
		return err
	}
	binding := workflowV4DecisionAnswers{Schema: workflowV4DecisionQuestionsSchema, CeremonyID: protocol.Definition.CeremonyID, CandidateID: candidateID, CheckpointSHA256: snapshot.Head().Record.Digest.SHA256, PolicySHA256: policySHA, CoordinatorID: identity.ID, Accepted: accepted}
	answers, err := workflowV4LoadDecisionAnswers(online.Work, binding)
	if err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Guided V5 production decision\nCeremony: %s\nFinal checkpoint: %s\nCandidate: %s\nPinned source: %s\nAccepted contributions: %d\nRelay records your attributed answers; it does not verify whether a human review happened. Do not enter keys, randomness, credentials, or private host details.\n", binding.CeremonyID, binding.CheckpointSHA256, binding.CandidateID, definition.Software.SourceCommit, len(accepted))
	if err := workflowV4AskDecisionQuestions(ui, online.Work, &answers); err != nil {
		return err
	}
	files, draft, err := workflowV4BuildDecisionArtifacts(answers, definition, snapshot.Head())
	if err != nil {
		return err
	}
	var view struct {
		Decision string                   `json:"decision"`
		Gates    []workflowV4DecisionGate `json:"gates"`
	}
	if err := json.Unmarshal(draft, &view); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "\nGenerated decision: %s\n", view.Decision)
	for _, gate := range view.Gates {
		fmt.Fprintf(ui.output, "  %s: %s — %s\n", gate.Gate, gate.Status, gate.Rationale)
	}
	keys := make([]string, 0, len(answers.Answers))
	for key := range answers.Answers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	fmt.Fprintln(ui.output, "\nReview every attributed answer before preparation:")
	for _, key := range keys {
		fmt.Fprintf(ui.output, "  %s: %q\n", key, answers.Answers[key])
	}
	if err := ui.confirm("Prepare the displayed decision and reports; this does not sign them", "PREPARE DECISION"); err != nil {
		return err
	}
	if err := workflowV4RetainDecisionPreparationIntent(online.Work, answers, files, draft); err != nil {
		return err
	}
	stage, preparedHost, err := workflowV4StageDecisionArtifacts(online.Work, files, draft)
	if err != nil {
		return err
	}
	draftHost := filepath.Join(stage, "draft.json")
	mappedDraft, err := pathWithin(signer.Work, draftHost, "/work")
	if err != nil {
		return err
	}
	checkDir, err := os.MkdirTemp(filepath.Join(online.Work, "workflow-v4", "decision"), ".prepare-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(checkDir)
	checkHost := filepath.Join(checkDir, "decision.json")
	mappedOut, err := pathWithin(signer.Work, checkHost, "/work")
	if err != nil {
		return err
	}
	mappedEvidence, err := pathWithin(signer.Work, stage, "/work")
	if err != nil {
		return err
	}
	command := append([]string{"mpc-ceremony", "decision", "prepare"}, common...)
	command = append(command, "--draft", mappedDraft, "--evidence-root", mappedEvidence, "--out", mappedOut)
	if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
		return err
	}
	preparedBytes, err := readTesseraRegularFile(checkHost, 16<<20, false)
	if err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(preparedHost, preparedBytes, 0600); err != nil {
		return fmt.Errorf("staged decision differs from deterministic proof-tool output; retain it for reviewed recovery: %w", err)
	}
	root, _ := snapshot.Root()
	if err := workflowV4HandoffDecisionRelease(preparedHost, candidateID, snapshot.Head().Record.Digest.SHA256, root); err != nil {
		return fmt.Errorf("staged decision is incomplete or differs; retain it for reviewed recovery: %w", err)
	}
	if err := requireDecisionEvidence(preparedHost, stage, protocol.Definition.CeremonyID, ui); err != nil {
		return fmt.Errorf("staged decision evidence differs: %w", err)
	}
	if err := requireFreshDecisionOutput(decisionHost); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Dir(decisionHost)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("canonical decision directory already exists; retain it for reviewed recovery")
	}
	if err := os.Rename(filepath.Join(stage, "decision"), filepath.Dir(decisionHost)); err != nil {
		return fmt.Errorf("promote complete staged decision: %w", err)
	}
	if err := syncDirectory(evidenceHost); err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "Prepared decision and evidence were promoted together. Choose D → 2 to review and sign the exact canonical files.")
	return nil
}

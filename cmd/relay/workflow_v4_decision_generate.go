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

	"github.com/zksecurity/relay/internal/transcript"
	"golang.org/x/crypto/blake2b"
)

type workflowV4DecisionGate struct {
	Gate      string                   `json:"gate"`
	Status    string                   `json:"status"`
	Evidence  []transcript.ArtifactRef `json:"evidence"`
	Rationale string                   `json:"rationale"`
}

type workflowV4GeneratedDecisionDraft struct {
	Schema          string          `json:"schema"`
	CeremonyID      string          `json:"ceremony_id"`
	AssurancePolicy json.RawMessage `json:"assurance_policy"`
	Release         struct {
		FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		CandidateID            string                        `json:"candidate_id"`
	} `json:"release"`
	SourceRelease struct {
		SourceCommit       string                 `json:"source_commit"`
		VerificationReport transcript.ArtifactRef `json:"verification_report"`
	} `json:"source_release"`
	Auditors         []any `json:"auditors"`
	ExternalAudits   []any `json:"external_audits"`
	CircuitRehearsal struct {
		Circuit  json.RawMessage        `json:"circuit"`
		Evidence transcript.ArtifactRef `json:"evidence"`
	} `json:"circuit_rehearsal"`
	MainnetDeploymentPlan transcript.ArtifactRef   `json:"mainnet_deployment_plan"`
	FormalChecklist       transcript.ArtifactRef   `json:"formal_checklist"`
	Gates                 []workflowV4DecisionGate `json:"gates"`
	Decision              string                   `json:"decision"`
	DecidedAt             string                   `json:"decided_at"`
}

func workflowV4DecisionReviewStatus(answers map[string]string, prefix string) (string, string) {
	if answers[prefix+".blocker"] == "Yes" || answers[prefix+".conclusion"] == "Reject" || answers[prefix+".reviewed"] == "No" || answers[prefix+".matching_circuit"] == "No" {
		return "FAIL", "The attributed review reports a failed conclusion or unresolved blocker."
	}
	if (prefix != "deployment" && answers[prefix+".reviewed"] != "Yes") || answers[prefix+".conclusion"] != "Accept" || answers[prefix+".blocker"] != "No" || answers[prefix+".matching_circuit"] == "Unknown" {
		return "PENDING", "The attributed review is incomplete or unknown."
	}
	for _, field := range []string{"reviewer", "date", "findings"} {
		if strings.TrimSpace(answers[prefix+"."+field]) == "" {
			return "PENDING", "The attributed review lacks required reviewer, date, or findings."
		}
	}
	if prefix != "deployment" && strings.TrimSpace(answers[prefix+".scope"]) == "" {
		return "PENDING", "The attributed review lacks its specific checks or scope."
	}
	if prefix == "deployment" {
		for _, field := range []string{"network", "application", "owners", "verification", "activation", "halt", "postcheck"} {
			if strings.TrimSpace(answers[prefix+"."+field]) == "" {
				return "PENDING", "The deployment review lacks " + field + "."
			}
		}
	}
	return "PASS", ""
}

func workflowV4AggregateReviewStatus(answers workflowV4DecisionAnswers, topic string) (string, string) {
	status := "PASS"
	for _, scope := range answers.Accepted {
		itemStatus, _ := workflowV4DecisionReviewStatus(answers.Answers, scope.key()+"."+topic)
		if itemStatus == "FAIL" {
			return "FAIL", "An accepted contribution has a failed or blocked " + topic + " review."
		}
		if itemStatus == "PENDING" {
			status = "PENDING"
		}
	}
	if status == "PENDING" {
		return status, "At least one accepted contribution lacks a completed " + topic + " review."
	}
	return "PASS", ""
}

func workflowV4GeneratedRef(name string, raw []byte) transcript.ArtifactRef {
	sha := sha256.Sum256(raw)
	blake := blake2b.Sum256(raw)
	return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: "sha256:" + hex.EncodeToString(sha[:]), Blake2b256: "blake2b256:" + hex.EncodeToString(blake[:]), Size: int64(len(raw))}}
}

func workflowV4DecisionReport(title string, answers workflowV4DecisionAnswers, prefixes ...string) []byte {
	var text strings.Builder
	fmt.Fprintf(&text, "# %s\n\nCeremony: %s  \nCandidate: %s  \nFinal checkpoint: %s  \nCoordinator answerer: %s  \nRecorded: %s\n\nThese are attributed human answers. Relay records them; it cannot determine whether they are true.\n", title, answers.CeremonyID, answers.CandidateID, answers.CheckpointSHA256, answers.CoordinatorID, answers.DecidedAt)
	for _, prefix := range prefixes {
		fmt.Fprintf(&text, "\n## %s\n", prefix)
		keys := []string{}
		for key := range answers.Answers {
			if strings.HasPrefix(key, prefix+".") {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		for _, key := range keys {
			fmt.Fprintf(&text, "- %s: %q\n", strings.TrimPrefix(key, prefix+"."), answers.Answers[key])
		}
	}
	return []byte(text.String())
}

func workflowV4BuildDecisionArtifacts(answers workflowV4DecisionAnswers, definition workflowV4DecisionDefinitionFields, checkpoint transcript.SignedArtifactRefs) (map[string][]byte, []byte, error) {
	if answers.Schema != workflowV4DecisionQuestionsSchema || answers.CeremonyID != definition.CeremonyID || len(answers.Accepted) == 0 || len(answers.Answers) == 0 {
		return nil, nil, errors.New("incomplete bound decision questionnaire")
	}
	if err := workflowV4ValidateDecisionAnswers(answers); err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	ref := func(name string, raw []byte) transcript.ArtifactRef {
		files[name] = raw
		return workflowV4GeneratedRef(name, raw)
	}
	sourceRaw, err := json.Marshal(struct {
		Schema           string            `json:"schema"`
		CeremonyID       string            `json:"ceremony_id"`
		CandidateID      string            `json:"candidate_id"`
		SourceCommit     string            `json:"source_commit"`
		CoordinatorID    string            `json:"coordinator_answerer"`
		Answers          map[string]string `json:"attributed_answers"`
		MechanicallyTrue bool              `json:"mechanically_verified_human_claims"`
	}{"relay-guided-source-review-v1", answers.CeremonyID, answers.CandidateID, definition.Software.SourceCommit, answers.CoordinatorID, map[string]string{}, false})
	if err != nil {
		return nil, nil, err
	}
	var source map[string]any
	if err := json.Unmarshal(sourceRaw, &source); err != nil {
		return nil, nil, err
	}
	attributed := map[string]string{}
	for key, value := range answers.Answers {
		if strings.HasPrefix(key, "source.") {
			attributed[strings.TrimPrefix(key, "source.")] = value
		}
	}
	source["attributed_answers"] = attributed
	sourceRaw, err = json.MarshalIndent(source, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	sourceRef := ref("decision/evidence/source-release.json", sourceRaw)
	rehearsalRef := ref("decision/evidence/exact-circuit-rehearsal-review.md", workflowV4DecisionReport("Exact circuit rehearsal review", answers, "rehearsal"))
	deploymentRef := ref("decision/evidence/mainnet-deployment-plan.md", workflowV4DecisionReport("Mainnet deployment plan and review", answers, "deployment"))
	assuranceRefs := map[string]transcript.ArtifactRef{}
	for _, topic := range []struct{ Key, Name string }{{"host", "participant-host-security"}, {"entropy", "participant-entropy"}, {"erasure", "participant-erasure"}} {
		prefixes := []string{}
		for _, scope := range answers.Accepted {
			prefixes = append(prefixes, scope.key()+"."+topic.Key)
		}
		assuranceRefs[topic.Key] = ref("decision/evidence/"+topic.Name+".md", workflowV4DecisionReport("Accepted-contribution "+topic.Name+" review", answers, prefixes...))
	}
	gate := func(name, status, rationale string, evidence ...transcript.ArtifactRef) workflowV4DecisionGate {
		if evidence == nil {
			evidence = []transcript.ArtifactRef{}
		}
		return workflowV4DecisionGate{Gate: name, Status: status, Evidence: evidence, Rationale: rationale}
	}
	sourceStatus, sourceReason := workflowV4DecisionReviewStatus(answers.Answers, "source")
	rehearsalStatus, rehearsalReason := workflowV4DecisionReviewStatus(answers.Answers, "rehearsal")
	deploymentStatus, deploymentReason := workflowV4DecisionReviewStatus(answers.Answers, "deployment")
	if answers.Answers["rehearsal.matching_circuit"] != "Yes" && rehearsalStatus == "PASS" {
		rehearsalStatus, rehearsalReason = "PENDING", "The exact signed circuit match has not been confirmed."
	}
	hostStatus, hostReason := workflowV4AggregateReviewStatus(answers, "host")
	entropyStatus, entropyReason := workflowV4AggregateReviewStatus(answers, "entropy")
	erasureStatus, erasureReason := workflowV4AggregateReviewStatus(answers, "erasure")
	checklistStatus, checklistReason := "PASS", ""
	if answers.Answers["final.withhold"] == "Yes" {
		checklistStatus, checklistReason = "FAIL", "A known additional reason to withhold GO was reported."
	} else if answers.Answers["final.withhold"] != "No" {
		checklistStatus, checklistReason = "PENDING", "The final withholding review is unknown."
	}
	gates := []workflowV4DecisionGate{
		gate("source-release", sourceStatus, sourceReason, sourceRef),
		gate("signed-release", "PASS", ""),
		gate("operational-evidence", "PASS", ""),
		gate("independent-audits", "NOT_REQUIRED", "The signed assurance policy requires zero passing ceremony audits."),
		gate("third-party-security-audit", "NOT_REQUIRED", "The signed assurance policy requires zero external security audit signoffs."),
		gate("exact-circuit-rehearsal", rehearsalStatus, rehearsalReason, rehearsalRef),
		gate("mainnet-deployment-plan", deploymentStatus, deploymentReason, deploymentRef),
		gate("formal-go-no-go-checklist", checklistStatus, checklistReason),
		gate("participant-host-security", hostStatus, hostReason, assuranceRefs["host"]),
		gate("participant-entropy", entropyStatus, entropyReason, assuranceRefs["entropy"]),
		gate("participant-erasure", erasureStatus, erasureReason, assuranceRefs["erasure"]),
		gate("public-witnessing", "NOT_REQUIRED", "The signed assurance policy requires zero public witnesses."),
		gate("immutable-independent-mirrors", "NOT_REQUIRED", "The signed assurance policy requires zero independent mirrors."),
	}
	var checklist strings.Builder
	fmt.Fprintf(&checklist, "# Formal GO/NO-GO checklist\n\nCeremony: %s  \nCandidate: %s  \nRecorded by: %s  \nRecorded at: %s\n\n", answers.CeremonyID, answers.CandidateID, answers.CoordinatorID, answers.DecidedAt)
	for _, g := range gates {
		fmt.Fprintf(&checklist, "- %s: %s; %s\n", g.Gate, g.Status, g.Rationale)
		for _, evidence := range g.Evidence {
			fmt.Fprintf(&checklist, "  - %s — %s\n", evidence.Name, evidence.Digest.SHA256)
		}
	}
	fmt.Fprintf(&checklist, "\nOther known reason to withhold: %q\nFinal findings: %q\n\nThis checklist records the coordinator's answers and mechanically derived gate labels. Decision signers must review the full evidence.\n", answers.Answers["final.withhold"], answers.Answers["final.findings"])
	checklistRef := ref("decision/evidence/formal-go-no-go-checklist.md", []byte(checklist.String()))
	gates[7].Evidence = []transcript.ArtifactRef{checklistRef}
	decision := "GO"
	for _, g := range gates {
		if g.Status != "PASS" && g.Status != "NOT_REQUIRED" {
			decision = "NO-GO"
			break
		}
	}
	draft := workflowV4GeneratedDecisionDraft{Schema: "proof-tool-mpc-production-decision-draft-v5", CeremonyID: answers.CeremonyID, AssurancePolicy: definition.AssurancePolicy, Auditors: []any{}, ExternalAudits: []any{}, MainnetDeploymentPlan: deploymentRef, FormalChecklist: checklistRef, Gates: gates, Decision: decision, DecidedAt: answers.DecidedAt}
	draft.Release.FinalReleaseCheckpoint = checkpoint
	draft.Release.CandidateID = answers.CandidateID
	draft.SourceRelease.SourceCommit = definition.Software.SourceCommit
	draft.SourceRelease.VerificationReport = sourceRef
	draft.CircuitRehearsal.Circuit = definition.Circuit
	draft.CircuitRehearsal.Evidence = rehearsalRef
	for name, raw := range files {
		if len(raw) == 0 || len(raw) > 16<<20 || !strings.HasPrefix(name, "decision/evidence/") {
			return nil, nil, fmt.Errorf("invalid generated evidence %q", name)
		}
	}
	draftRaw, err := json.Marshal(draft)
	if err != nil || len(draftRaw) > 16<<20 {
		return nil, nil, errors.New("generated V5 decision draft exceeds its bound")
	}
	return files, draftRaw, nil
}

func workflowV4ValidateDecisionAnswers(answers workflowV4DecisionAnswers) error {
	required := map[string]bool{}
	add := func(prefix string, fields ...string) {
		for _, field := range fields {
			required[prefix+"."+field] = true
		}
	}
	add("source", "reviewed", "reviewer", "date", "scope", "findings", "conclusion", "blocker")
	add("rehearsal", "reviewed", "reviewer", "date", "matching_circuit", "scope", "conclusion", "findings", "blocker")
	add("deployment", "network", "application", "owners", "verification", "activation", "halt", "postcheck", "reviewer", "date", "findings", "conclusion", "blocker")
	add("final", "withhold", "findings")
	seen := map[string]bool{}
	for _, scope := range answers.Accepted {
		if scope.Phase != "phase1" && scope.Phase != "phase2" || scope.Position == 0 || scope.ParticipantID == "" || seen[scope.key()] {
			return errors.New("invalid or duplicated accepted review scope")
		}
		seen[scope.key()] = true
		for _, topic := range []string{"host", "entropy", "erasure"} {
			add(scope.key()+"."+topic, "reviewed", "reviewer", "date", "scope", "findings", "conclusion", "blocker")
		}
	}
	if len(answers.Answers) != len(required) {
		return errors.New("questionnaire has missing or unexpected answers")
	}
	for key := range required {
		value, ok := answers.Answers[key]
		if !ok || value == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
			return fmt.Errorf("missing or invalid questionnaire answer %q", key)
		}
		switch {
		case strings.HasSuffix(key, ".reviewed"):
			if !slices.Contains([]string{"Yes", "No", "Unknown", "Not reviewed yet"}, value) {
				return fmt.Errorf("invalid reviewed answer %q", key)
			}
		case strings.HasSuffix(key, ".conclusion"):
			if !slices.Contains([]string{"Accept", "Reject", "Incomplete or unknown"}, value) {
				return fmt.Errorf("invalid conclusion answer %q", key)
			}
		case strings.HasSuffix(key, ".blocker") || key == "final.withhold" || key == "rehearsal.matching_circuit":
			if !slices.Contains([]string{"Yes", "No", "Unknown"}, value) {
				return fmt.Errorf("invalid structured answer %q", key)
			}
		}
	}
	return nil
}

func workflowV4StageDecisionArtifacts(work string, files map[string][]byte, draft []byte) (string, string, error) {
	stage := filepath.Join(work, "workflow-v4", "decision", "staging")
	if err := workflowV4HandoffEnsureDir(stage); err != nil {
		return "", "", err
	}
	decisionDir := filepath.Join(stage, "decision")
	if err := workflowV4HandoffEnsureDir(decisionDir); err != nil {
		return "", "", err
	}
	evidenceDir := filepath.Join(decisionDir, "evidence")
	if err := workflowV4HandoffEnsureDir(evidenceDir); err != nil {
		return "", "", err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		path := filepath.Join(stage, filepath.FromSlash(name))
		if filepath.Dir(path) != evidenceDir {
			return "", "", errors.New("invalid generated evidence path")
		}
		if err := setupWriteBytesNewOrExact(path, files[name], 0600); err != nil {
			return "", "", err
		}
	}
	if err := setupWriteBytesNewOrExact(filepath.Join(stage, "draft.json"), draft, 0600); err != nil {
		return "", "", err
	}
	if err := setupWriteBytesNewOrExact(filepath.Join(work, "decision-draft.json"), draft, 0600); err != nil {
		return "", "", err
	}
	allowed := map[string]bool{"draft.json": true, "decision": true, "decision/evidence": true, "decision/decision.json": true}
	for _, name := range names {
		allowed[name] = true
	}
	if err := filepath.WalkDir(stage, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == stage {
			return nil
		}
		relative, err := filepath.Rel(stage, path)
		if err != nil || !allowed[filepath.ToSlash(relative)] || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected staged decision file %s", path)
		}
		isDirectory := relative == "decision" || filepath.ToSlash(relative) == "decision/evidence"
		if entry.IsDir() != isDirectory {
			return fmt.Errorf("invalid staged decision file type %s", path)
		}
		return nil
	}); err != nil {
		return "", "", err
	}
	return stage, filepath.Join(decisionDir, "decision.json"), nil
}

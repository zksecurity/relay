package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// An unsigned guided decision is a local preparation made after the signed
// final-release checkpoint. It cannot appear in that checkpoint's artifact
// projection. Inventory its exact, fixed files as local observations during an
// operator-selected upgrade; D -> 8 reauthenticates them with pinned proof-tool
// before any replacement. This exception never admits signatures or handoff.
func upgradeLocalUnsignedDecisionFiles(p guidedProfile, inv upgradeInventory) (map[string]bool, error) {
	allowed := map[string]bool{}
	if p.Role != "coordinator" {
		return allowed, nil
	}
	intentPath := filepath.Join(p.Work, "workflow-v4", "decision", "intent.json")
	if _, err := os.Lstat(intentPath); errors.Is(err, os.ErrNotExist) {
		return allowed, nil
	} else if err != nil {
		return nil, err
	}
	var intent workflowV4DecisionPreparationIntent
	if err := setupReadJSON(intentPath, &intent); err != nil {
		return nil, err
	}
	if intent.Schema != "relay-guided-decision-preparation-v1" || len(intent.EvidenceSHA) == 0 || len(intent.EvidenceSHA) > 32 {
		return nil, errors.New("invalid retained guided decision intent")
	}
	form, err := readTesseraRegularFile(workflowV4QuestionnairePath(p.Work), 16<<20, false)
	if err != nil {
		return nil, err
	}
	var answers workflowV4DecisionAnswers
	if json.Unmarshal(form, &answers) != nil || answers.Schema != workflowV4DecisionQuestionsSchema || answers.CeremonyID != intent.CeremonyID || answers.CandidateID != intent.CandidateID || answers.CheckpointSHA256 != intent.CheckpointSHA256 || decisionReplacementDigest(form) != intent.QuestionnaireSHA {
		return nil, errors.New("retained guided questionnaire differs from preparation intent")
	}
	for _, name := range []string{"decision-draft.json", "workflow-v4/decision/staging/draft.json"} {
		raw, err := readTesseraRegularFile(filepath.Join(p.Work, filepath.FromSlash(name)), 16<<20, false)
		if err != nil || decisionReplacementDigest(raw) != intent.DraftSHA {
			return nil, errors.New("retained guided decision draft differs from preparation intent")
		}
	}
	private, err := os.ReadDir(filepath.Join(p.Work, "workflow-v4", "decision"))
	if err != nil || len(private) != 2 || private[0].Name() != "intent.json" || private[1].Name() != "staging" || !private[1].IsDir() {
		return nil, errors.New("decision signing may already have begun")
	}
	staging, err := os.ReadDir(filepath.Join(p.Work, "workflow-v4", "decision", "staging"))
	if err != nil || len(staging) != 1 || staging[0].Name() != "draft.json" || !staging[0].Type().IsRegular() {
		return nil, errors.New("guided decision staging is not complete")
	}
	for _, path := range []string{workflowV4HandoffManifestPath(p.Work), filepath.Join(p.Work, "workflow-v4", "publication", "go-ceremony.zip"), filepath.Join(p.Work, "workflow-v4", "publication", "no-go-trial-ceremony.zip")} {
		if _, err := os.Lstat(path); err == nil {
			return nil, errors.New("decision handoff or publication may already have begun")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if entries, err := os.ReadDir(filepath.Join(filepath.Dir(p.Work), "private-decision-grants")); err == nil && len(entries) != 0 {
		return nil, errors.New("decision transfer grant already exists")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dir := filepath.Join(p.Work, "ceremony", "public", "decision")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return allowed, nil
	} // Preparation intent may precede promotion.
	if err != nil || len(entries) != 2 || entries[0].Name() != "decision.json" || !entries[0].Type().IsRegular() || entries[1].Name() != "evidence" || !entries[1].IsDir() {
		return nil, errors.New("unsigned public decision has unexpected files")
	}
	var decision struct {
		CeremonyID string                   `json:"ceremony_id"`
		Decision   string                   `json:"decision"`
		Gates      []workflowV4DecisionGate `json:"gates"`
	}
	decisionRaw, err := readTesseraRegularFile(filepath.Join(dir, "decision.json"), 16<<20, false)
	if err != nil || json.Unmarshal(decisionRaw, &decision) != nil || decision.CeremonyID != intent.CeremonyID || (decision.Decision != "GO" && decision.Decision != "NO-GO") || len(decision.Gates) != 13 {
		return nil, errors.New("unsigned public decision differs from guided intent")
	}
	allowed["ceremony/public/decision/decision.json"] = true
	evidenceEntries, err := os.ReadDir(filepath.Join(dir, "evidence"))
	if err != nil || len(evidenceEntries) != len(intent.EvidenceSHA) {
		return nil, errors.New("unsigned decision evidence inventory differs")
	}
	for _, entry := range evidenceEntries {
		name := "decision/evidence/" + entry.Name()
		want := intent.EvidenceSHA[name]
		if !entry.Type().IsRegular() || want == "" || strings.ContainsAny(entry.Name(), "/\\") {
			return nil, errors.New("unsigned decision contains unexpected evidence")
		}
		raw, err := readTesseraRegularFile(filepath.Join(dir, "evidence", entry.Name()), 16<<20, false)
		if err != nil || decisionReplacementDigest(raw) != want {
			return nil, fmt.Errorf("unsigned decision evidence differs: %s", name)
		}
		allowed["ceremony/public/"+name] = true
	}
	seen := map[string]bool{}
	for _, f := range inv.Files {
		if allowed[f.Name] {
			seen[f.Name] = true
		}
	}
	if len(seen) != len(allowed) {
		return nil, errors.New("unsigned decision files differ from upgrade inventory")
	}
	return allowed, nil
}

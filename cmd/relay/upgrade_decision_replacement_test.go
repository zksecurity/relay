package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeFullCleanCheckAdmitsOnlyUnsignedGuidedDecision(t *testing.T) {
	s, declaration := testUpgradeV2(t, "coordinator")
	work := s.Profile.Work
	answers := testGuidedDecisionAnswersV2(2)
	form, err := json.Marshal(answers)
	if err != nil {
		t.Fatal(err)
	}
	formPath := workflowV4QuestionnairePath(work)
	if err := os.MkdirAll(filepath.Dir(formPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(formPath, form, 0600); err != nil {
		t.Fatal(err)
	}
	draft := []byte(`{"guided":"draft"}`)
	for _, path := range []string{filepath.Join(work, "decision-draft.json"), filepath.Join(work, "workflow-v4", "decision", "staging", "draft.json")} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, draft, 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicDecision := filepath.Join(work, "ceremony", "public", "decision")
	evidencePath := filepath.Join(publicDecision, "evidence", "review.md")
	if err := os.MkdirAll(filepath.Dir(evidencePath), 0700); err != nil {
		t.Fatal(err)
	}
	evidence := []byte("Synthetic review evidence")
	if err := os.WriteFile(evidencePath, evidence, 0600); err != nil {
		t.Fatal(err)
	}
	decision := struct {
		CeremonyID string                   `json:"ceremony_id"`
		Decision   string                   `json:"decision"`
		Gates      []workflowV4DecisionGate `json:"gates"`
	}{answers.CeremonyID, "NO-GO", make([]workflowV4DecisionGate, 13)}
	decisionRaw, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(publicDecision, "decision.json"), decisionRaw, 0600); err != nil {
		t.Fatal(err)
	}
	intent := workflowV4DecisionPreparationIntent{Schema: "relay-guided-decision-preparation-v1", CeremonyID: answers.CeremonyID, CandidateID: answers.CandidateID, CheckpointSHA256: answers.CheckpointSHA256, QuestionnaireSHA: decisionReplacementDigest(form), DraftSHA: decisionReplacementDigest(draft), EvidenceSHA: map[string]string{"decision/evidence/review.md": decisionReplacementDigest(evidence)}}
	if err := writeJSONNoReplace(filepath.Join(work, "workflow-v4", "decision", "intent.json"), intent, 0600); err != nil {
		t.Fatal(err)
	}
	inv, err := upgradeV2Inventory(s.Profile, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err != nil {
		t.Fatalf("full upgrade check rejected exact unsigned guided decision: %v", err)
	}
	if err := os.WriteFile(filepath.Join(publicDecision, "coordinator.sig"), []byte("signed"), 0600); err != nil {
		t.Fatal(err)
	}
	inv, err = upgradeV2Inventory(s.Profile, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("signed decision passed unsigned admission")
	}
	if err := os.Remove(filepath.Join(publicDecision, "coordinator.sig")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("altered"), 0600); err != nil {
		t.Fatal(err)
	}
	inv, err = upgradeV2Inventory(s.Profile, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("altered decision evidence passed unsigned admission")
	}
}

func TestUpgradeSyntheticUnsignedDecisionAndRetiredHistory(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "active"
		if retired {
			name = "retired"
		}
		t.Run(name, func(t *testing.T) {
			s, declaration := testUpgradeV2(t, "coordinator")
			m := replacementFixtureAt(t, s.Profile.Work)
			if retired {
				for _, item := range m.Items {
					from := filepath.Join(s.Profile.Work, filepath.FromSlash(item.Source))
					to := decisionReplacementRetiredPath(s.Profile.Work, m, item.Source)
					if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(from, to); err != nil {
						t.Fatal(err)
					}
				}
				if err := writeJSONNoReplace(filepath.Join(decisionReplacementRoot(s.Profile.Work), m.Generation, "committed"), map[string]string{"decision_sha256": m.OldDecisionSHA256}, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				// An older release has the active guided files but no replacement
				// intent yet. The new upgrade must admit those fixed paths.
				if err := os.RemoveAll(decisionReplacementRoot(s.Profile.Work)); err != nil {
					t.Fatal(err)
				}
			}
			paths := decisionReplacementPaths(s.Profile.Work)
			if retired {
				for i, item := range m.Items {
					paths[i] = decisionReplacementRetiredPath(s.Profile.Work, m, item.Source)
				}
			}
			before := make([][]decisionReplacementFile, len(paths))
			for i, path := range paths {
				files, _, err := decisionReplacementTree(path)
				if err != nil {
					t.Fatal(err)
				}
				before[i] = files
			}
			inv, err := upgradeV2Inventory(s.Profile, declaration)
			if err != nil {
				t.Fatalf("synthetic retained-state upgrade inventory: %v", err)
			}
			s.Kinds, s.InventorySHA256 = inv.Kinds, inv.digest()
			if err := upgradeV2Activate(s, ""); err != nil {
				t.Fatalf("synthetic upgrade activation: %v", err)
			}
			for i, path := range paths {
				after, _, err := decisionReplacementTree(path)
				if err != nil {
					t.Fatal(err)
				}
				if !decisionReplacementSameFiles(before[i], after) {
					t.Fatal("upgrade changed retained decision bytes")
				}
			}
			if retired {
				state, err := decisionReplacementReadState(s.Profile.Work)
				if err != nil || !state.Awaiting {
					t.Fatalf("retired state changed during upgrade: %+v, %v", state, err)
				}
			}
		})
	}
}

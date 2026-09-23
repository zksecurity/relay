package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

// The V5 decision is a separate authorization after the signed release. The
// proof-tool, not menu progress or file presence, validates its exact evidence
// and required signer threshold.
func runWorkflowV4DecisionMenu(ui *coordinatorWizard, online, signer guidedProfile, identity setupIdentity, protocol transcript.DefinitionProtocol) error {
	if protocol.DefinitionSchema != "proof-tool-mpc-ceremony-definition-v5" || protocol.Definition.Mode != "production" {
		return errors.New("the authenticated ceremony is not a V5 production ceremony")
	}
	if online.Role != "coordinator" && online.Role != "auditor" && online.Role != "release-signer" {
		return errors.New("this role cannot make a production decision")
	}
	if signer.Role != "decision-signer" || signer.Work != online.Work || signer.Trust != online.Trust || signer.Keys != online.Keys || signer.ReleaseCommit != online.ReleaseCommit {
		return errors.New("the approved offline decision signer does not match this role")
	}
	base := filepath.Join(online.Work, "ceremony", "public")
	trustName := "coordinator-public-key.hex"
	if online.Role == "coordinator" {
		trustName = "setup-coordinator.hex"
	}
	ceremony, err := pathWithin(signer.Work, filepath.Join(base, "ceremony.json"), "/work")
	if err != nil {
		return err
	}
	ceremonySig, err := pathWithin(signer.Work, filepath.Join(base, "ceremony.sig"), "/work")
	if err != nil {
		return err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(signer.Trust, trustName), "/trust")
	if err != nil {
		return err
	}
	common := []string{"--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey}
	decisionHost := filepath.Join(base, "decision", "decision.json")
	evidenceHost := base
	legacyDecision := filepath.Join(online.Work, "decision.json")
	if regularPreparationFile(legacyDecision) && !regularPreparationFile(decisionHost) {
		// Preserve the location of decisions already started with an older
		// guide. Fresh decisions live directly in the public evidence tree so
		// the reviewed package is ready for exact archive export.
		decisionHost = legacyDecision
		evidenceHost = filepath.Join(online.Work, "decision-evidence")
	}
	fmt.Fprintln(ui.output, "Production decision for the exact signed release. Review the decision and complete evidence before signing.")
	if online.Role == "coordinator" {
		fmt.Fprintln(ui.output, "1) Prepare a canonical decision from decision-draft.json\n2) Review evidence and sign my decision\n3) Verify all required decision signatures\n0) Back")
	} else {
		fmt.Fprintln(ui.output, "2) Review evidence and sign my decision\n0) Back")
	}
	choice, err := ui.ask("Choose a decision action", "")
	if err != nil {
		return err
	}
	switch choice {
	case "", "0":
		return nil
	case "1":
		if online.Role != "coordinator" {
			return errors.New("only the coordinator prepares the canonical decision")
		}
		draftHost := filepath.Join(online.Work, "decision-draft.json")
		if _, err := readTesseraRegularFile(draftHost, 16<<20, false); err != nil {
			return fmt.Errorf("reviewed decision draft: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(decisionHost), 0o700); err != nil {
			return err
		}
		if err := requireFreshDecisionOutput(decisionHost); err != nil {
			return err
		}
		draft, err := pathWithin(signer.Work, draftHost, "/work")
		if err != nil {
			return err
		}
		out, err := pathWithin(signer.Work, decisionHost, "/work")
		if err != nil {
			return err
		}
		if err := ui.confirm("Prepare the exact reviewed production decision; this does not sign it", "PREPARE DECISION"); err != nil {
			return err
		}
		command := append([]string{"mpc-ceremony", "decision", "prepare"}, common...)
		command = append(command, "--draft", draft, "--out", out)
		return runWorkflowV4ProfileCommand(signer, command, false)
	case "2":
		if err := requireDecisionEvidence(decisionHost, evidenceHost, protocol.Definition.CeremonyID, ui); err != nil {
			return err
		}
		role := online.Role
		if role == "release-signer" {
			role = "release_signer"
		}
		outName := online.Role + ".sig"
		if online.Role == "auditor" {
			outName = "auditor-" + identity.ID + ".sig"
		}
		outDir := filepath.Dir(decisionHost)
		if decisionHost == legacyDecision {
			outDir = online.Work
			outName = "decision-" + online.Role + ".sig"
			if online.Role == "auditor" {
				outName = "decision-auditor-" + identity.ID + ".sig"
			}
		}
		outHost := filepath.Join(outDir, outName)
		if err := requireFreshDecisionOutput(outHost); err != nil {
			return err
		}
		decision, err := pathWithin(signer.Work, decisionHost, "/work")
		if err != nil {
			return err
		}
		evidence, err := pathWithin(signer.Work, evidenceHost, "/work")
		if err != nil {
			return err
		}
		out, err := pathWithin(signer.Work, outHost, "/work")
		if err != nil {
			return err
		}
		key, err := pathWithin(signer.Keys, filepath.Join(signer.Keys, "signing.hex"), "/keys")
		if err != nil {
			return err
		}
		if err := ui.confirm("Sign only after independently reviewing the displayed decision and exact evidence; the approved proof-tool checks evidence before using your key", "SIGN DECISION"); err != nil {
			return err
		}
		command := append([]string{"mpc-ceremony", "decision", "sign"}, common...)
		command = append(command, "--decision", decision, "--evidence-root", evidence, "--role", role, "--signer-id", identity.ID, "--signing-key", key, "--out", out)
		if err := retainDecisionSigningAttempt(ui, online.Work, online.Role, identity.ID, decisionHost, outHost); err != nil {
			return err
		}
		return runWorkflowV4ProfileCommand(signer, command, false)
	case "3":
		if online.Role != "coordinator" {
			return errors.New("only the coordinator collects and verifies decision signatures")
		}
		if err := requireDecisionEvidence(decisionHost, evidenceHost, protocol.Definition.CeremonyID, ui); err != nil {
			return err
		}
		decision, err := pathWithin(signer.Work, decisionHost, "/work")
		if err != nil {
			return err
		}
		evidence, err := pathWithin(signer.Work, evidenceHost, "/work")
		if err != nil {
			return err
		}
		command := append([]string{"mpc-ceremony", "decision", "verify"}, common...)
		command = append(command, "--decision", decision, "--evidence-root", evidence)
		fmt.Fprintln(ui.output, "Enter every accountable signer's signature path inside this role's work folder. Press Enter after the last one. The proof-tool checks the exact required set, including any auditors.")
		count := 0
		for {
			path, err := ui.ask(fmt.Sprintf("Signature file %d (absolute path, blank when done)", count+1), "")
			if err != nil {
				return err
			}
			if path == "" {
				break
			}
			if _, err := readTesseraRegularFile(path, 16<<20, false); err != nil {
				return fmt.Errorf("decision signature: %w", err)
			}
			mapped, err := pathWithin(signer.Work, path, "/work")
			if err != nil {
				return err
			}
			command = append(command, "--signature", mapped)
			count++
			if count > 64 {
				return errors.New("too many decision signatures")
			}
		}
		if count == 0 {
			return errors.New("at least one decision signature is required")
		}
		if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
			return err
		}
		fmt.Fprintln(ui.output, "The pinned proof-tool verified the exact decision, evidence, and required signatures. Retain this verification result before release authorization.")
		return nil
	default:
		return errors.New("unknown decision action")
	}
}

type decisionSigningAttempt struct {
	Schema         string `json:"schema"`
	Role           string `json:"role"`
	SignerID       string `json:"signer_id"`
	DecisionSHA256 string `json:"decision_sha256"`
	Output         string `json:"output"`
	StartedAt      string `json:"started_at"`
}

func retainDecisionSigningAttempt(ui *coordinatorWizard, work, role, signerID, decisionPath, output string) error {
	decision, err := readTesseraRegularFile(decisionPath, 16<<20, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(decision)
	dir := filepath.Join(work, "workflow-v4", "decision")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "signing-attempt-"+role+".json")
	if raw, err := readTesseraRegularFile(path, 1<<20, false); err == nil {
		var saved decisionSigningAttempt
		if err := json.Unmarshal(raw, &saved); err != nil || saved.Schema != "relay-decision-signing-attempt-v1" || saved.Role != role || saved.SignerID != signerID || saved.DecisionSHA256 != hex.EncodeToString(digest[:]) || saved.Output != output {
			return errors.New("retained decision signing attempt differs; preserve it for investigation")
		}
		return ui.confirm("An earlier signing attempt may have used your key but produced no complete output. Inspect its retained state before explicitly retrying the same decision", "RETRY DECISION SIGNING")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeJSONNoReplace(path, decisionSigningAttempt{Schema: "relay-decision-signing-attempt-v1", Role: role, SignerID: signerID, DecisionSHA256: hex.EncodeToString(digest[:]), Output: output, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}, 0o600)
}

func workflowV4DecisionAvailable(protocol transcript.DefinitionProtocol, state transcript.CheckpointStateV4, role string) bool {
	return protocol.DefinitionSchema == "proof-tool-mpc-ceremony-definition-v5" &&
		protocol.Definition.Mode == "production" && state.Progress.FinalRelease != nil &&
		state.Progress.Terminal == nil && (role == "coordinator" || role == "auditor" || role == "release-signer")
}

func requireFreshDecisionOutput(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("output already exists; preserve and review it before any retry: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func requireDecisionEvidence(decisionPath, evidenceRoot, ceremonyID string, ui *coordinatorWizard) error {
	raw, err := readTesseraRegularFile(decisionPath, 16<<20, false)
	if err != nil {
		return fmt.Errorf("canonical decision: %w", err)
	}
	var view struct {
		CeremonyID string `json:"ceremony_id"`
		Decision   string `json:"decision"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		return fmt.Errorf("canonical decision: %w", err)
	}
	if view.CeremonyID != ceremonyID || (view.Decision != "GO" && view.Decision != "NO-GO") {
		return errors.New("decision does not match the authenticated ceremony or a supported outcome")
	}
	info, err := os.Lstat(evidenceRoot)
	if err != nil {
		return fmt.Errorf("decision evidence root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("decision evidence root must be a real directory")
	}
	digest := sha256.Sum256(raw)
	fmt.Fprintf(ui.output, "Decision: %s\nCeremony: %s\nExact decision SHA-256: %s\nReview: %s\nEvidence: %s\n", view.Decision, view.CeremonyID, hex.EncodeToString(digest[:]), decisionPath, evidenceRoot)
	return nil
}

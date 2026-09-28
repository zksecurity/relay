package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	decisionReplacementSchema               = "relay-unsigned-decision-replacement-v1"
	decisionReplacementMaxGenerations       = 16
	decisionReplacementMaxBytes       int64 = 4 << 30
)

type decisionReplacementFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type decisionReplacementItem struct {
	Source string                    `json:"source"`
	Files  []decisionReplacementFile `json:"files"`
}

type decisionReplacementManifest struct {
	Schema            string                    `json:"schema"`
	Generation        string                    `json:"generation"`
	Sequence          int                       `json:"sequence"`
	CeremonyID        string                    `json:"ceremony_id"`
	CandidateID       string                    `json:"candidate_id"`
	CheckpointSHA256  string                    `json:"checkpoint_sha256"`
	PolicySHA256      string                    `json:"policy_sha256"`
	CoordinatorID     string                    `json:"coordinator_id"`
	OldDecisionSHA256 string                    `json:"old_decision_sha256"`
	Reason            string                    `json:"reason"`
	CreatedAt         string                    `json:"created_at"`
	Items             []decisionReplacementItem `json:"items"`
}

type decisionReplacementState struct {
	Committed []decisionReplacementManifest
	Pending   *decisionReplacementManifest
	Awaiting  bool
}

func decisionReplacementRoot(work string) string {
	return filepath.Join(work, "workflow-v4", "decision-replacements")
}

func decisionReplacementPaths(work string) []string {
	return []string{
		filepath.Join(work, "ceremony", "public", "decision"),
		filepath.Join(work, "workflow-v4", "decision"),
		workflowV4QuestionnairePath(work),
		filepath.Join(work, "decision-draft.json"),
	}
}

func decisionReplacementDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decisionReplacementTree(path string) ([]decisionReplacementFile, int64, error) {
	var files []decisionReplacementFile
	var total int64
	root, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if root.Mode()&os.ModeSymlink != 0 || (!root.IsDir() && !root.Mode().IsRegular()) {
		return nil, 0, errors.New("replacement source must be a real directory or regular file")
	}
	err = filepath.WalkDir(path, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("replacement source contains a symbolic link or unreadable file")
		}
		rel, err := filepath.Rel(path, name)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("replacement source escapes its directory")
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 16<<20 || info.Size() > decisionReplacementMaxBytes-total || len(files) >= 512 {
			return errors.New("replacement source exceeds its file or size limit")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
			return errors.New("replacement source contains a hard-linked or unsupported file")
		}
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(f, 16<<20+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n != info.Size() {
			return errors.New("replacement source changed while hashing")
		}
		total += n
		files = append(files, decisionReplacementFile{Name: filepath.ToSlash(rel), SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: n})
		return nil
	})
	if err != nil || len(files) == 0 {
		if err == nil {
			err = errors.New("replacement source is empty")
		}
		return nil, 0, err
	}
	return files, total, nil
}

func decisionReplacementSameFiles(a, b []decisionReplacementFile) bool {
	return slices.EqualFunc(a, b, func(x, y decisionReplacementFile) bool { return x == y })
}

func decisionReplacementReadState(work string) (decisionReplacementState, error) {
	var state decisionReplacementState
	root := decisionReplacementRoot(work)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil || len(entries) > decisionReplacementMaxGenerations {
		return state, errors.New("decision replacement history is unavailable or exceeds its limit")
	}
	seenDigest := map[string]bool{}
	seenSequence := map[int]bool{}
	ceremonyID, checkpointSHA := "", ""
	expectedSources := make([]string, 0, 4)
	for _, source := range decisionReplacementPaths(work) {
		rel, err := filepath.Rel(work, source)
		if err != nil {
			return state, err
		}
		expectedSources = append(expectedSources, filepath.ToSlash(rel))
	}
	var total int64
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return state, errors.New("unexpected decision replacement entry")
		}
		var manifest decisionReplacementManifest
		dir := filepath.Join(root, entry.Name())
		generationEntries, err := os.ReadDir(dir)
		if err != nil {
			return state, err
		}
		for _, child := range generationEntries {
			if child.Name() != "manifest.json" && child.Name() != "committed" && child.Name() != "retired" {
				return state, errors.New("unexpected decision replacement generation file")
			}
		}
		if err := setupReadJSON(filepath.Join(dir, "manifest.json"), &manifest); err != nil {
			return state, fmt.Errorf("replacement manifest %s: %w", entry.Name(), err)
		}
		if manifest.Schema != decisionReplacementSchema || manifest.Generation != entry.Name() || manifest.Sequence < 1 || manifest.Sequence > decisionReplacementMaxGenerations || manifest.CeremonyID == "" || manifest.CheckpointSHA256 == "" || len(manifest.Reason) == 0 || len(manifest.Reason) > 1024 || len(manifest.OldDecisionSHA256) != 71 || seenSequence[manifest.Sequence] || seenDigest[manifest.OldDecisionSHA256] || len(manifest.Items) != len(expectedSources) {
			return state, errors.New("invalid or duplicate decision replacement generation")
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(manifest.OldDecisionSHA256, "sha256:")); err != nil || !strings.HasPrefix(manifest.OldDecisionSHA256, "sha256:") {
			return state, errors.New("invalid retired decision digest")
		}
		if ceremonyID == "" {
			ceremonyID, checkpointSHA = manifest.CeremonyID, manifest.CheckpointSHA256
		}
		if ceremonyID != manifest.CeremonyID || checkpointSHA != manifest.CheckpointSHA256 {
			return state, errors.New("replacement generations differ in ceremony or final checkpoint")
		}
		seenSequence[manifest.Sequence], seenDigest[manifest.OldDecisionSHA256] = true, true
		for i, item := range manifest.Items {
			if item.Source != expectedSources[i] || len(item.Files) == 0 || len(item.Files) > 512 {
				return state, errors.New("replacement manifest has unexpected source inventory")
			}
			seenFiles := map[string]bool{}
			for _, file := range item.Files {
				if file.Name == "" || filepath.IsAbs(file.Name) || file.Name != filepath.ToSlash(filepath.Clean(file.Name)) || strings.HasPrefix(file.Name, "../") || seenFiles[file.Name] || len(file.SHA256) != 71 || !strings.HasPrefix(file.SHA256, "sha256:") || file.Size < 0 || file.Size > decisionReplacementMaxBytes-total {
					return state, errors.New("retired decision history exceeds its limit")
				}
				seenFiles[file.Name] = true
				total += file.Size
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, "committed")); err == nil {
			var committed map[string]string
			if err := setupReadJSON(filepath.Join(dir, "committed"), &committed); err != nil || len(committed) != 1 || committed["decision_sha256"] != manifest.OldDecisionSHA256 {
				return state, errors.New("replacement commit marker differs from manifest")
			}
			state.Committed = append(state.Committed, manifest)
		} else if errors.Is(err, os.ErrNotExist) && state.Pending == nil {
			copy := manifest
			state.Pending = &copy
		} else {
			return state, errors.New("multiple unfinished or unreadable decision replacements")
		}
	}
	if state.Pending != nil && len(state.Committed) > 0 {
		for _, previous := range state.Committed {
			if previous.CeremonyID != state.Pending.CeremonyID || previous.CheckpointSHA256 != state.Pending.CheckpointSHA256 {
				return state, errors.New("replacement generations differ in ceremony or final checkpoint")
			}
		}
	}
	if len(state.Committed) > 0 && state.Pending == nil {
		if _, err := os.Lstat(filepath.Join(work, "ceremony", "public", "decision", "decision.json")); errors.Is(err, os.ErrNotExist) {
			state.Awaiting = true
		} else if err != nil {
			return state, err
		}
	}
	for seq := 1; seq <= len(entries); seq++ {
		if !seenSequence[seq] {
			return state, errors.New("decision replacement history has a missing sequence")
		}
	}
	return state, nil
}

func decisionReplacementRetiredPath(work string, m decisionReplacementManifest, source string) string {
	return filepath.Join(decisionReplacementRoot(work), m.Generation, "retired", filepath.FromSlash(source))
}

func decisionReplacementResume(work string, m decisionReplacementManifest) error {
	for _, item := range m.Items {
		from := filepath.Join(work, filepath.FromSlash(item.Source))
		to := decisionReplacementRetiredPath(work, m, item.Source)
		_, fromErr := os.Lstat(from)
		_, toErr := os.Lstat(to)
		if fromErr == nil && errors.Is(toErr, os.ErrNotExist) {
			files, _, err := decisionReplacementTree(from)
			if err != nil || !decisionReplacementSameFiles(files, item.Files) {
				return errors.New("active decision files changed during replacement")
			}
			if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
				return err
			}
			if err := requireOfflineRealPath(filepath.Dir(to)); err != nil {
				return err
			}
			if err := os.Rename(from, to); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(from)); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(to)); err != nil {
				return err
			}
		} else if errors.Is(fromErr, os.ErrNotExist) && toErr == nil {
			files, _, err := decisionReplacementTree(to)
			if err != nil || !decisionReplacementSameFiles(files, item.Files) {
				return errors.New("retired decision files changed during replacement")
			}
		} else {
			return errors.New("decision replacement has duplicate or missing source files")
		}
	}
	return writeJSONNoReplace(filepath.Join(decisionReplacementRoot(work), m.Generation, "committed"), map[string]string{"decision_sha256": m.OldDecisionSHA256}, 0600)
}

func decisionReplacementSeedQuestionnaire(work string, latest decisionReplacementManifest) error {
	path := workflowV4QuestionnairePath(work)
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	retired := decisionReplacementRetiredPath(work, latest, "workflow-v4/decision-questionnaire.json")
	var prior workflowV4DecisionAnswers
	if err := setupReadJSON(retired, &prior); err != nil {
		return err
	}
	if prior.Schema != workflowV4DecisionQuestionsSchema || prior.CeremonyID != latest.CeremonyID || prior.CandidateID != latest.CandidateID || prior.CheckpointSHA256 != latest.CheckpointSHA256 || prior.PolicySHA256 != latest.PolicySHA256 || prior.CoordinatorID != latest.CoordinatorID {
		return errors.New("retired questionnaire does not match current release")
	}
	prior.DecidedAt = ""
	return writeJSONNoReplace(path, prior, 0600)
}

func decisionReplacementLatest(state decisionReplacementState) (decisionReplacementManifest, bool) {
	var latest decisionReplacementManifest
	for _, m := range state.Committed {
		if m.Sequence > latest.Sequence {
			latest = m
		}
	}
	return latest, latest.Sequence != 0
}

func decisionReplacementPrepare(ui *coordinatorWizard, online, signer guidedProfile, identity setupIdentity, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4, state decisionReplacementState) error {
	if state.Pending != nil {
		if err := decisionReplacementResume(online.Work, *state.Pending); err != nil {
			return err
		}
		fmt.Fprintln(ui.output, "Completed the previously confirmed unsigned decision retirement. Choose D → 1 to review a new questionnaire.")
		return nil
	}
	if state.Awaiting {
		return errors.New("a replacement questionnaire is pending; choose D → 1")
	}
	if len(state.Committed) >= decisionReplacementMaxGenerations {
		return errors.New("unsigned decision replacement reached its generation limit")
	}
	if err := decisionReplacementEligible(ui, online, signer, identity, protocol, snapshot); err != nil {
		return err
	}
	oldPath := filepath.Join(online.Work, "ceremony", "public", "decision", "decision.json")
	oldRaw, err := readTesseraRegularFile(oldPath, 16<<20, false)
	if err != nil {
		return err
	}
	var answers workflowV4DecisionAnswers
	if err := setupReadJSON(workflowV4QuestionnairePath(online.Work), &answers); err != nil {
		return err
	}
	seq := len(state.Committed) + 1
	id, err := randomID()
	if err != nil {
		return err
	}
	m := decisionReplacementManifest{Schema: decisionReplacementSchema, Generation: fmt.Sprintf("%02d-%s", seq, id), Sequence: seq, CeremonyID: answers.CeremonyID, CandidateID: answers.CandidateID, CheckpointSHA256: answers.CheckpointSHA256, PolicySHA256: answers.PolicySHA256, CoordinatorID: answers.CoordinatorID, OldDecisionSHA256: decisionReplacementDigest(oldRaw), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var total int64
	for _, prior := range state.Committed {
		for _, item := range prior.Items {
			for _, file := range item.Files {
				total += file.Size
			}
		}
	}
	for _, path := range decisionReplacementPaths(online.Work) {
		files, size, err := decisionReplacementTree(path)
		if err != nil {
			return err
		}
		if size > decisionReplacementMaxBytes-total {
			return errors.New("retired decision bytes exceed limit")
		}
		total += size
		rel, err := filepath.Rel(online.Work, path)
		if err != nil {
			return err
		}
		m.Items = append(m.Items, decisionReplacementItem{Source: filepath.ToSlash(rel), Files: files})
	}
	if err := ui.confirm("Preserve this exact unsigned decision privately and open a new editable questionnaire; this does not sign or publish either decision", "REPLACE UNSIGNED DECISION"); err != nil {
		return err
	}
	if err := ui.confirm("Confirm this unsigned decision has not been copied, sent, or shown to anyone outside this coordinator workspace; Relay cannot detect manual copies", "NOT CIRCULATED"); err != nil {
		return err
	}
	reason, err := ui.ask("Reason for replacing this local unsigned decision (kept only in private recovery state)", "")
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > 1024 {
		return errors.New("replacement reason must be 1–1024 bytes")
	}
	m.Reason = reason
	dir := filepath.Join(decisionReplacementRoot(online.Work), m.Generation)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := requireOfflineRealPath(dir); err != nil {
		return err
	}
	if err := writeJSONNoReplace(filepath.Join(dir, "manifest.json"), m, 0600); err != nil {
		return err
	}
	if err := decisionReplacementResume(online.Work, m); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Unsigned decision %s preserved privately. Choose D → 1 to review corrected answers; no new decision has been prepared.\n", m.OldDecisionSHA256)
	return nil
}

func decisionReplacementEligible(ui *coordinatorWizard, online, signer guidedProfile, identity setupIdentity, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	state, err := snapshot.State()
	if err != nil || state.Progress.FinalRelease == nil || state.Progress.Terminal != nil || snapshot.Head().Record.Digest.SHA256 != state.Progress.FinalRelease.Record.Digest.SHA256 {
		return errors.New("replacement requires the authenticated signed final-release checkpoint")
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
	var answers workflowV4DecisionAnswers
	questionnaireRaw, err := readTesseraRegularFile(workflowV4QuestionnairePath(online.Work), 16<<20, false)
	if err != nil || json.Unmarshal(questionnaireRaw, &answers) != nil || answers.Schema != workflowV4DecisionQuestionsSchema || answers.CeremonyID != protocol.Definition.CeremonyID || answers.CandidateID != candidateID || answers.CheckpointSHA256 != snapshot.Head().Record.Digest.SHA256 || answers.PolicySHA256 != policySHA || answers.CoordinatorID != identity.ID || !slices.Equal(answers.Accepted, accepted) {
		return errors.New("unsigned decision questionnaire differs from authenticated release")
	}
	files, draft, err := workflowV4BuildDecisionArtifacts(answers, definition, snapshot.Head())
	if err != nil {
		return fmt.Errorf("regenerate unsigned decision evidence: %w", err)
	}
	var intent workflowV4DecisionPreparationIntent
	if err := setupReadJSON(filepath.Join(online.Work, "workflow-v4", "decision", "intent.json"), &intent); err != nil {
		return err
	}
	if intent.Schema != "relay-guided-decision-preparation-v1" || intent.CeremonyID != answers.CeremonyID || intent.CandidateID != answers.CandidateID || intent.CheckpointSHA256 != answers.CheckpointSHA256 || intent.QuestionnaireSHA != decisionReplacementDigest(questionnaireRaw) || intent.DraftSHA != decisionReplacementDigest(draft) || len(intent.EvidenceSHA) != len(files) {
		return errors.New("unsigned decision preparation intent differs from questionnaire")
	}
	for name, raw := range files {
		if intent.EvidenceSHA[name] != decisionReplacementDigest(raw) {
			return errors.New("unsigned decision evidence intent differs")
		}
		got, err := readTesseraRegularFile(filepath.Join(online.Work, "ceremony", "public", filepath.FromSlash(name)), 16<<20, false)
		if err != nil || decisionReplacementDigest(got) != intent.EvidenceSHA[name] {
			return errors.New("unsigned decision evidence differs from retained intent")
		}
	}
	for _, path := range []string{filepath.Join(online.Work, "decision-draft.json"), filepath.Join(online.Work, "workflow-v4", "decision", "staging", "draft.json")} {
		got, err := readTesseraRegularFile(path, 16<<20, false)
		if err != nil || string(got) != string(draft) {
			return errors.New("unsigned decision draft differs from retained intent")
		}
	}
	decisionDir := filepath.Join(online.Work, "ceremony", "public", "decision")
	entries, err := os.ReadDir(decisionDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "decision.json" && entry.Name() != "evidence" {
			return errors.New("decision is signed or contains an unexpected file")
		}
	}
	evidenceDir := filepath.Join(decisionDir, "evidence")
	evidenceEntries, err := os.ReadDir(evidenceDir)
	if err != nil || len(evidenceEntries) != len(files) {
		return errors.New("decision evidence inventory differs from guided reports")
	}
	for _, entry := range evidenceEntries {
		if !entry.Type().IsRegular() || strings.Contains(entry.Name(), string(filepath.Separator)) || files["decision/evidence/"+entry.Name()] == nil {
			return errors.New("decision evidence has an unexpected file")
		}
	}
	privateEntries, err := os.ReadDir(filepath.Join(online.Work, "workflow-v4", "decision"))
	if err != nil {
		return err
	}
	for _, entry := range privateEntries {
		if entry.Name() != "intent.json" && entry.Name() != "staging" {
			return errors.New("decision signing or unknown private action has begun")
		}
	}
	stage := filepath.Join(online.Work, "workflow-v4", "decision", "staging")
	stageEntries, err := os.ReadDir(stage)
	if err != nil || len(stageEntries) != 1 || stageEntries[0].Name() != "draft.json" || !stageEntries[0].Type().IsRegular() {
		return errors.New("guided decision staging has unexpected retained files")
	}
	for _, path := range []string{workflowV4HandoffManifestPath(online.Work), filepath.Join(online.Work, "workflow-v4", "publication", "go-ceremony.zip"), filepath.Join(online.Work, "workflow-v4", "publication", "no-go-trial-ceremony.zip"), filepath.Join(online.Work, "decision.json")} {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("decision handoff, publication, or older manual decision may already exist")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	grantDir := filepath.Join(filepath.Dir(online.Work), "private-decision-grants")
	if entries, err := os.ReadDir(grantDir); err == nil && len(entries) != 0 {
		return errors.New("a private decision transfer grant already exists")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, dir := range []string{filepath.Join(online.Work, "workflow-v4", "decision-handoff"), filepath.Join(online.Work, "workflow-v4", "publication")} {
		if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
			return errors.New("decision handoff or publication may already have begun")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	decisionPath := filepath.Join(decisionDir, "decision.json")
	if err := requireDecisionEvidence(decisionPath, filepath.Join(online.Work, "ceremony", "public"), answers.CeremonyID, &coordinatorWizard{output: io.Discard}); err != nil {
		return err
	}
	root, _ := snapshot.Root()
	if err := workflowV4HandoffDecisionRelease(decisionPath, candidateID, snapshot.Head().Record.Digest.SHA256, root); err != nil {
		return err
	}
	decisionRaw, err := readTesseraRegularFile(decisionPath, 16<<20, false)
	if err != nil {
		return err
	}
	var decision struct {
		Decision string `json:"decision"`
	}
	var preview struct {
		Decision string                   `json:"decision"`
		Gates    []workflowV4DecisionGate `json:"gates"`
	}
	if json.Unmarshal(decisionRaw, &decision) != nil || json.Unmarshal(draft, &preview) != nil || decision.Decision != preview.Decision {
		return errors.New("canonical decision outcome differs from guided answers")
	}
	if err := decisionReplacementCheckPinnedPreparation(online, signer, snapshot, decisionRaw); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Current unsigned decision: %s (%s). Its exact bytes and guided evidence match the authenticated final release.\n", decisionReplacementDigest(decisionRaw), decision.Decision)
	for _, gate := range preview.Gates {
		if gate.Status != "PASS" && gate.Status != "NOT_REQUIRED" {
			fmt.Fprintf(ui.output, "  %s: %s — %s\n", gate.Gate, gate.Status, gate.Rationale)
		}
	}
	fmt.Fprintln(ui.output, "The public decision tree, private preparation, questionnaire, and root draft will be preserved in a private recovery directory. No signature or remote copy can be withdrawn by this action.")
	return nil
}

func decisionReplacementCheckPinnedPreparation(online, signer guidedProfile, snapshot storagefirst.SnapshotV4, canonical []byte) error {
	public := filepath.Join(online.Work, "ceremony", "public")
	stageEvidence, verifyEvidence, err := workflowV4DecisionPrepareEvidenceRoot(online.Work, snapshot.Files(), public)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageEvidence)
	checkDir, err := os.MkdirTemp(online.Work, ".decision-replacement-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(checkDir)
	mapWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(public, "ceremony.json"))
	if err != nil {
		return err
	}
	ceremonySig, err := mapWork(filepath.Join(public, "ceremony.sig"))
	if err != nil {
		return err
	}
	key, err := pathWithin(signer.Trust, filepath.Join(signer.Trust, "setup-coordinator.hex"), "/trust")
	if err != nil {
		return err
	}
	draft, err := mapWork(filepath.Join(online.Work, "decision-draft.json"))
	if err != nil {
		return err
	}
	evidence, err := mapWork(stageEvidence)
	if err != nil {
		return err
	}
	outHost := filepath.Join(checkDir, "decision.json")
	out, err := mapWork(outHost)
	if err != nil {
		return err
	}
	command := []string{"mpc-ceremony", "decision", "prepare", "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", key, "--draft", draft, "--evidence-root", evidence, "--out", out}
	prepareErr := runWorkflowV4ProfileCommand(signer, command, false)
	if err := verifyEvidence(); err != nil {
		return fmt.Errorf("decision inputs changed during pinned re-preparation: %w", err)
	}
	if prepareErr != nil {
		return fmt.Errorf("pinned decision preparation failed: %w", prepareErr)
	}
	actual, err := readTesseraRegularFile(outHost, 16<<20, false)
	if err != nil || string(actual) != string(canonical) {
		return errors.New("current decision differs from pinned deterministic preparation")
	}
	return nil
}
